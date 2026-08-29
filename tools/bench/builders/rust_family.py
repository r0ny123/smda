"""Build the Rust corpus: one binary per (crate, target, profile) cell.

Rust is worth its own family because a release build monomorphizes `core::fmt`
into thousands of near-identical bodies, plants panic landing pads that no call
reaches, and — under LTO — merges functions that the symbol table still names
separately. Ground truth is the unstripped link's symbol table; the corpus keeps
the stripped twin.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import Dict, List

from bench.builders.truth import elfFunctionStarts, peFunctionStarts, writeTruth


@dataclass
class RustTarget:
    key: str
    triple: str
    container: str
    bitness: int
    strip: str


TARGETS: Dict[str, RustTarget] = {
    "linux-gnu-x64": RustTarget("linux-gnu-x64", "x86_64-unknown-linux-gnu", "elf", 64, "strip"),
    "windows-gnu-x64": RustTarget("windows-gnu-x64", "x86_64-pc-windows-gnu", "pe", 64, "x86_64-w64-mingw32-strip"),
    "windows-gnu-x86": RustTarget("windows-gnu-x86", "i686-pc-windows-gnu", "pe", 32, "i686-w64-mingw32-strip"),
}

#: (label, cargo profile, extra [profile] settings). LTO is on its own axis
#: because merging functions is precisely what makes a symbol-derived truth and
#: a disassembler's view disagree.
PROFILES = [
    ("debug", "dev", {}),
    ("release", "release", {"lto": "false"}),
    ("release-lto", "release", {"lto": "true", "codegen-units": "1"}),
    ("release-panic-abort", "release", {"lto": "false", "panic": '"abort"'}),
]

CRATES: Dict[str, Dict[str, str]] = {
    "fmtheavy": {
        "main.rs": """use std::collections::BTreeMap;
use std::fmt::Write as _;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Node {
    Leaf(i64),
    Pair(Box<Node>, Box<Node>),
}

trait Describe {
    fn describe(&self) -> String;
}

impl Describe for Node {
    fn describe(&self) -> String {
        match self {
            Node::Leaf(value) => format!("leaf({value})"),
            Node::Pair(left, right) => format!("pair({}, {})", left.describe(), right.describe()),
        }
    }
}

fn render<T: std::fmt::Debug>(items: &[T]) -> String {
    let mut out = String::new();
    for (index, item) in items.iter().enumerate() {
        let _ = write!(out, "{index}:{item:?};");
    }
    out
}

fn build(depth: u32) -> Node {
    if depth == 0 {
        Node::Leaf(depth as i64)
    } else {
        Node::Pair(Box::new(build(depth - 1)), Box::new(Node::Leaf(depth as i64)))
    }
}

fn main() {
    let tree = build(6);
    let mut index: BTreeMap<String, usize> = BTreeMap::new();
    index.insert(tree.describe(), 1);
    index.insert(render(&[1u8, 2, 3]), 2);
    index.insert(render(&["a", "b"]), 3);
    index.insert(render(&[1.5f64, 2.5]), 4);
    let total: usize = index.values().sum();
    println!("{total} {}", index.len());
}
""",
    },
    "panicheavy": {
        "main.rs": """use std::collections::HashMap;

#[derive(Debug)]
enum Failure {
    Empty,
    TooLarge(usize),
}

impl std::fmt::Display for Failure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Failure::Empty => write!(formatter, "empty"),
            Failure::TooLarge(size) => write!(formatter, "too large: {size}"),
        }
    }
}

impl std::error::Error for Failure {}

fn checked(values: &[usize]) -> Result<usize, Failure> {
    if values.is_empty() {
        return Err(Failure::Empty);
    }
    let total: usize = values.iter().sum();
    if total > 1000 {
        return Err(Failure::TooLarge(total));
    }
    Ok(total)
}

fn tabulate(rows: &[(&str, usize)]) -> HashMap<String, usize> {
    rows.iter().map(|(name, value)| ((*name).to_string(), *value)).collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let table = tabulate(&[("a", 1), ("b", 2), ("c", 3)]);
    let mut values: Vec<usize> = table.values().copied().collect();
    values.sort_unstable();
    let outcome = checked(&values)?;
    let recovered = std::panic::catch_unwind(|| values[values.len() - 1]);
    println!("{outcome} {:?}", recovered.is_ok());
    Ok(())
}
""",
    },
}


def _writeCrate(work_dir: str, name: str, files: Dict[str, str]) -> str:
    crate_dir = os.path.join(work_dir, name)
    os.makedirs(os.path.join(crate_dir, "src"), exist_ok=True)
    for filename, body in files.items():
        with open(os.path.join(crate_dir, "src", filename), "w", encoding="utf-8") as source:
            source.write(body)
    with open(os.path.join(crate_dir, "Cargo.toml"), "w", encoding="utf-8") as manifest:
        manifest.write(f'[package]\nname = "{name}"\nversion = "0.1.0"\nedition = "2021"\n\n[dependencies]\n')
    return crate_dir


def _profileFlags(profile: str, settings: Dict[str, str]) -> List[str]:
    flags: List[str] = []
    for key, value in settings.items():
        flags += ["--config", f"profile.{profile}.{key}={value}"]
    return flags


def build(out_dir: str, work_dir: str, cargo: str = "cargo") -> Dict[str, object]:
    binary_dir = os.path.join(out_dir, "binary")
    truth_dir = os.path.join(out_dir, "truth")
    os.makedirs(work_dir, exist_ok=True)
    os.makedirs(binary_dir, exist_ok=True)
    installed = subprocess.run(["rustup", "target", "list", "--installed"], capture_output=True, text=True)
    available = set(installed.stdout.split())
    cells: List[Dict[str, object]] = []
    crates = {name: _writeCrate(work_dir, name, files) for name, files in CRATES.items()}
    for crate_name, crate_dir in crates.items():
        for target in TARGETS.values():
            if target.triple not in available:
                cells.append({"crate": crate_name, "target": target.key, "status": "target_not_installed"})
                continue
            for label, profile, settings in PROFILES:
                name = f"{crate_name}_{target.key}_{label}"
                command = [cargo, "build", "--target", target.triple, "--target-dir", os.path.join(work_dir, "target")]
                if profile != "dev":
                    command += ["--profile", profile]
                command += _profileFlags(profile, settings)
                environment = {**os.environ, "CARGO_TERM_COLOR": "never"}
                completed = subprocess.run(
                    command, cwd=crate_dir, capture_output=True, text=True, timeout=2400, env=environment
                )
                record = {"crate": crate_name, "target": target.key, "profile": label}
                if completed.returncode != 0:
                    record.update({"status": "build_failed", "error": completed.stderr[-500:]})
                    cells.append(record)
                    continue
                suffix = ".exe" if target.container == "pe" else ""
                produced = os.path.join(
                    work_dir, "target", target.triple, "debug" if profile == "dev" else profile, crate_name + suffix
                )
                if not os.path.isfile(produced):
                    record.update({"status": "artifact_missing", "expected": produced})
                    cells.append(record)
                    continue
                try:
                    truth = elfFunctionStarts(produced) if target.container == "elf" else peFunctionStarts(produced)
                except (RuntimeError, OSError) as failure:
                    record.update({"status": "truth_failed", "error": str(failure)[:300]})
                    cells.append(record)
                    continue
                if not truth["starts"]:
                    record.update({"status": "truth_empty"})
                    cells.append(record)
                    continue
                measured = os.path.join(binary_dir, name)
                shutil.copyfile(produced, measured)
                stripper = target.strip if shutil.which(target.strip) else "strip"
                stripped = subprocess.run([stripper, measured], capture_output=True, text=True)
                if stripped.returncode != 0:
                    os.remove(measured)
                    record.update({"status": "strip_failed", "error": stripped.stderr[-300:]})
                    cells.append(record)
                    continue
                writeTruth(
                    truth_dir,
                    name,
                    list(truth["starts"]),
                    {
                        "plt": truth.get("plt", []),
                        "bitness": truth["bitness"],
                        "container": target.container,
                        "image_base": truth.get("image_base", 0),
                        "crate": crate_name,
                        "target": target.key,
                        "profile": label,
                        "truth_source": truth["source"],
                    },
                )
                record.update(
                    {
                        "status": "ok",
                        "name": name,
                        "truth_functions": len(truth["starts"]),
                        "size": os.path.getsize(measured),
                    }
                )
                cells.append(record)
    manifest = {
        "family": "rust",
        "rustc_version": subprocess.run(["rustc", "--version"], capture_output=True, text=True).stdout.strip(),
        "cells": cells,
        "ok": sum(1 for cell in cells if cell.get("status") == "ok"),
        "failed": sum(1 for cell in cells if cell.get("status") != "ok"),
    }
    with open(os.path.join(out_dir, "manifest.json"), "w", encoding="utf-8") as manifest_file:
        json.dump(manifest, manifest_file, indent=1, sort_keys=True)
    return manifest
