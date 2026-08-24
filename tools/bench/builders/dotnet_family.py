"""Build the .NET corpus: managed CIL assemblies and their native counterparts.

Two different problems share this family. A framework-dependent or self-contained
build ships **CIL**, and its ground truth is the assembly's own metadata table of
method bodies. A **NativeAOT** or ReadyToRun build ships machine code, so it lands
in the x86/ARM64 path with .NET metadata sitting beside it — a candidate source
that a native disassembler may or may not be reading. They are kept as separate
cells because scoring them together would average two unrelated questions.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from typing import Dict, List, Optional

from bench.builders.truth import elfFunctionStarts, writeTruth

PROGRAM = """using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Bench
{
    public interface IShape
    {
        double Area();
        string Describe();
    }

    public abstract class Shape : IShape
    {
        public abstract double Area();
        public virtual string Describe() => $"{GetType().Name}({Area():F2})";
    }

    public sealed class Circle : Shape
    {
        private readonly double radius;
        public Circle(double radius) => this.radius = radius;
        public override double Area() => Math.PI * radius * radius;
    }

    public sealed class Rect : Shape
    {
        private readonly double width;
        private readonly double height;
        public Rect(double width, double height) { this.width = width; this.height = height; }
        public override double Area() => width * height;
        public override string Describe() => $"Rect({width}x{height})";
    }

    public static class Pipeline
    {
        public static IEnumerable<T> Sorted<T>(IEnumerable<T> source) where T : IComparable<T>
        {
            var buffer = source.ToList();
            buffer.Sort();
            return buffer;
        }

        public static string Join(IEnumerable<string> parts)
        {
            var builder = new StringBuilder();
            foreach (var part in parts)
            {
                builder.Append(part).Append(';');
            }
            return builder.ToString();
        }
    }

    public static class Program
    {
        private static int Checked(int value)
        {
            try
            {
                return checked(value * 2);
            }
            catch (OverflowException)
            {
                return -1;
            }
        }

        public static int Main(string[] args)
        {
            IShape[] shapes = { new Circle(2.0), new Rect(3.0, 4.0), new Circle(0.5) };
            var described = shapes.Select(shape => shape.Describe()).ToArray();
            var joined = Pipeline.Join(Pipeline.Sorted(described));
            Console.WriteLine(joined);
            Console.WriteLine(Checked(args.Length + 21));
            return 0;
        }
    }
}
"""

PROJECT = """<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net8.0</TargetFramework>
    <Nullable>disable</Nullable>
    <ImplicitUsings>disable</ImplicitUsings>
    <AssemblyName>bench</AssemblyName>
    <RootNamespace>Bench</RootNamespace>
    <InvariantGlobalization>true</InvariantGlobalization>
    <SatelliteResourceLanguages>en</SatelliteResourceLanguages>
  </PropertyGroup>
</Project>
"""

#: (label, publish arguments, which artifact to score)
MODES = [
    ("framework-dependent", ["-c", "Release"], "cil"),
    ("self-contained", ["-c", "Release", "-r", "linux-x64", "--self-contained", "true"], "cil"),
    (
        "readytorun",
        ["-c", "Release", "-r", "linux-x64", "--self-contained", "true", "-p:PublishReadyToRun=true"],
        "cil",
    ),
    (
        "single-file",
        ["-c", "Release", "-r", "linux-x64", "--self-contained", "true", "-p:PublishSingleFile=true"],
        "cil",
    ),
    ("nativeaot", ["-c", "Release", "-r", "linux-x64", "-p:PublishAot=true"], "native"),
]


def cilMethodStarts(path: str) -> Dict[str, object]:
    """Method-body RVAs from an assembly's metadata, as SMDA's CIL backend sees them.

    The CIL backend reports method bodies by RVA, so the truth is the set of
    non-zero body RVAs the metadata declares. An abstract or extern method has
    RVA 0 and no body, and is not a function anyone can detect.
    """
    import dnfile

    assembly = dnfile.dnPE(path)
    if assembly.net is None:
        raise RuntimeError(f"not a managed assembly: {path}")
    table = assembly.net.mdtables.MethodDef
    if table is None:
        raise RuntimeError(f"assembly has no MethodDef table: {path}")
    starts = set()
    for row in table.rows:
        if row.Rva:
            starts.add(row.Rva)
    return {"starts": sorted(starts), "plt": [], "bitness": 32, "source": "dnfile MethodDef.Rva"}


def _writeProject(work_dir: str) -> str:
    project_dir = os.path.join(work_dir, "bench")
    os.makedirs(project_dir, exist_ok=True)
    with open(os.path.join(project_dir, "Program.cs"), "w", encoding="utf-8") as source:
        source.write(PROGRAM)
    with open(os.path.join(project_dir, "bench.csproj"), "w", encoding="utf-8") as project:
        project.write(PROJECT)
    return project_dir


def _findArtifact(publish_dir: str, kind: str) -> Optional[str]:
    if kind == "native":
        candidate = os.path.join(publish_dir, "bench")
        return candidate if os.path.isfile(candidate) else None
    candidate = os.path.join(publish_dir, "bench.dll")
    return candidate if os.path.isfile(candidate) else None


def build(out_dir: str, work_dir: str, dotnet_root: str = "") -> Dict[str, object]:
    binary_dir = os.path.join(out_dir, "binary")
    truth_dir = os.path.join(out_dir, "truth")
    os.makedirs(work_dir, exist_ok=True)
    os.makedirs(binary_dir, exist_ok=True)
    dotnet = os.path.join(dotnet_root, "dotnet") if dotnet_root else shutil.which("dotnet")
    cells: List[Dict[str, object]] = []
    if not dotnet or not os.path.isfile(dotnet):
        manifest = {"family": "dotnet", "cells": [{"status": "sdk_unavailable"}], "ok": 0, "failed": 1}
        with open(os.path.join(out_dir, "manifest.json"), "w", encoding="utf-8") as manifest_file:
            json.dump(manifest, manifest_file, indent=1, sort_keys=True)
        return manifest
    project_dir = _writeProject(work_dir)
    environment = {
        **os.environ,
        "DOTNET_CLI_TELEMETRY_OPTOUT": "1",
        "DOTNET_NOLOGO": "1",
        "DOTNET_ROOT": dotnet_root or os.path.dirname(dotnet),
    }
    for label, arguments, kind in MODES:
        publish_dir = os.path.join(work_dir, "publish", label)
        shutil.rmtree(publish_dir, ignore_errors=True)
        command = [dotnet, "publish", *arguments, "-o", publish_dir]
        completed = subprocess.run(
            command, cwd=project_dir, capture_output=True, text=True, timeout=2400, env=environment
        )
        record = {"mode": label, "kind": kind}
        if completed.returncode != 0:
            record.update({"status": "publish_failed", "error": (completed.stdout + completed.stderr)[-600:]})
            cells.append(record)
            continue
        artifact = _findArtifact(publish_dir, kind)
        if artifact is None:
            record.update({"status": "artifact_missing", "publish_dir": publish_dir})
            cells.append(record)
            continue
        name = f"bench_{label}"
        try:
            truth = cilMethodStarts(artifact) if kind == "cil" else elfFunctionStarts(artifact)
        except (RuntimeError, OSError, ImportError) as failure:
            record.update({"status": "truth_failed", "error": str(failure)[:300]})
            cells.append(record)
            continue
        if not truth["starts"]:
            record.update({"status": "truth_empty"})
            cells.append(record)
            continue
        measured = os.path.join(binary_dir, name)
        shutil.copyfile(artifact, measured)
        if kind == "native":
            subprocess.run(["strip", measured], capture_output=True, text=True)
        writeTruth(
            truth_dir,
            name,
            list(truth["starts"]),
            {
                "plt": truth.get("plt", []),
                "bitness": truth.get("bitness", 64),
                "kind": kind,
                "mode": label,
                "truth_source": truth["source"],
            },
        )
        record.update(
            {"status": "ok", "name": name, "truth_functions": len(truth["starts"]), "size": os.path.getsize(measured)}
        )
        cells.append(record)
    manifest = {
        "family": "dotnet",
        "sdk_version": subprocess.run(
            [dotnet, "--version"], capture_output=True, text=True, env=environment
        ).stdout.strip(),
        "cells": cells,
        "ok": sum(1 for cell in cells if cell.get("status") == "ok"),
        "failed": sum(1 for cell in cells if cell.get("status") != "ok"),
    }
    with open(os.path.join(out_dir, "manifest.json"), "w", encoding="utf-8") as manifest_file:
        json.dump(manifest, manifest_file, indent=1, sort_keys=True)
    return manifest
