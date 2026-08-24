"""Ghidra engine adapter driving `analyzeHeadless` with a function-dump script.

Ghidra is treated the same way SMDA is: a container-format binary is imported by
its loader, a headerless dump is imported as raw bytes at a stated base address,
and the recovered entry points are read back as a set of addresses. Which of
those entry points count is decided here rather than in the Ghidra script, so
the filter is visible next to the metric.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from typing import Dict, List, Optional, Set, Tuple

SCRIPT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ghidra_scripts")
SCRIPT_NAME = "DumpFunctionStarts.java"
VERSION_RE = re.compile(r"(\d+\.\d+(?:\.\d+)?)")

LANGUAGE_BY_BITNESS = {32: "x86:LE:32:default", 64: "x86:LE:64:default"}


class GhidraEngine:
    name = "ghidra"

    def __init__(self, install_dir: str = "", timeout: int = 600) -> None:
        install_dir = install_dir or os.environ.get("GHIDRA_INSTALL_DIR", "")
        if not install_dir:
            raise RuntimeError("Ghidra install directory unknown; pass --ghidra-dir or set GHIDRA_INSTALL_DIR")
        self.install_dir = install_dir
        self.headless = os.path.join(install_dir, "support", "analyzeHeadless")
        if not os.path.isfile(self.headless):
            raise RuntimeError(f"analyzeHeadless not found at {self.headless}")
        self.timeout = timeout
        self.version = self._readVersion()

    def _readVersion(self) -> str:
        properties = os.path.join(self.install_dir, "Ghidra", "application.properties")
        if os.path.isfile(properties):
            with open(properties, encoding="utf-8", errors="replace") as properties_file:
                for line in properties_file:
                    if line.startswith("application.version="):
                        return line.split("=", 1)[1].strip()
        match = VERSION_RE.search(os.path.basename(self.install_dir.rstrip("/")))
        return match.group(1) if match else "unknown"

    def describe(self) -> Dict[str, object]:
        return {"engine": self.name, "version": self.version, "install_dir": self.install_dir, "timeout": self.timeout}

    def _command(self, project_dir: str, binary: str, output: str, base_addr: Optional[int], bitness: Optional[int]):
        command: List[str] = [
            self.headless,
            project_dir,
            "bench",
            "-import",
            binary,
            "-scriptPath",
            SCRIPT_DIR,
            "-postScript",
            SCRIPT_NAME,
            output,
            "-deleteProject",
            "-noanalysis" if False else "-analysisTimeoutPerFile",
            str(self.timeout),
        ]
        if base_addr is not None:
            language = LANGUAGE_BY_BITNESS.get(bitness or 32, LANGUAGE_BY_BITNESS[32])
            command += [
                "-loader",
                "BinaryLoader",
                "-loader-baseAddr",
                f"0x{base_addr:x}",
                "-processor",
                language,
                "-cspec",
                "windows",
            ]
        return command

    def run(self, path: str, base_addr: Optional[int] = None, bitness: Optional[int] = None) -> Tuple[Set[int], Dict]:
        project_dir = tempfile.mkdtemp(prefix="ghidra-bench-")
        output = os.path.join(project_dir, "functions.json")
        started = time.time()
        status = "ok"
        message = ""
        starts: Set[int] = set()
        try:
            completed = subprocess.run(
                self._command(project_dir, path, output, base_addr, bitness),
                capture_output=True,
                text=True,
                timeout=self.timeout + 120,
                env={**os.environ, "GHIDRA_INSTALL_DIR": self.install_dir},
            )
            if not os.path.isfile(output):
                status = "error"
                message = (completed.stderr or completed.stdout or "")[-800:]
            else:
                with open(output, encoding="utf-8") as output_file:
                    payload = json.load(output_file)
                starts = {
                    entry["addr"]
                    for entry in payload["functions"]
                    if entry["executable"] and not entry["external"] and entry["block"] != "EXTERNAL"
                }
        except subprocess.TimeoutExpired:
            status = "timeout"
            message = f"analyzeHeadless exceeded {self.timeout + 120}s"
        finally:
            shutil.rmtree(project_dir, ignore_errors=True)
        return starts, {
            "status": status,
            "seconds": time.time() - started,
            "ghidra_version": self.version,
            "message": message,
        }
