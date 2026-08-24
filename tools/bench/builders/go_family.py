"""Build the Go corpus: one binary per (program, platform, link mode) cell.

Ground truth is Go's own reading of the pclntab in the *unstripped* build, via
`go tool nm`; the corpus keeps the stripped twin. `-ldflags=-s -w` removes the
symbol table nm needs but leaves the pclntab and moves no address, so the two
describe the same code at the same addresses.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from bench.builders.truth import goFunctionStarts, writeTruth

#: cross-compilation targets. Chosen for what changes how a function start is
#: reached rather than for architecture coverage: container format, pointer
#: size, and the calling convention the runtime stubs are written in.
PLATFORMS = [
    ("linux", "amd64"),
    ("linux", "386"),
    ("linux", "arm64"),
    ("windows", "amd64"),
    ("windows", "386"),
    ("darwin", "amd64"),
    ("darwin", "arm64"),
]

MODES = [
    ("default", [], []),
    ("stripped", [], ["-s", "-w"]),
    ("pie", ["-buildmode=pie"], []),
]

GO_PROGRAMS: Dict[str, str] = {
    "hello": """package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

type record struct {
	name  string
	score int
}

type byScore []record

func (r byScore) Len() int           { return len(r) }
func (r byScore) Swap(i, j int)      { r[i], r[j] = r[j], r[i] }
func (r byScore) Less(i, j int) bool { return r[i].score < r[j].score }

func summarize(records []record) string {
	sort.Sort(byScore(records))
	parts := make([]string, 0, len(records))
	for _, item := range records {
		parts = append(parts, fmt.Sprintf("%s=%d", item.name, item.score))
	}
	return strings.Join(parts, ",")
}

func main() {
	records := []record{{"c", 3}, {"a", 1}, {"b", 2}}
	fmt.Fprintln(os.Stdout, summarize(records))
}
""",
    "netjson": """package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"time"
)

type payload struct {
	Name string    `json:"name"`
	When time.Time `json:"when"`
	Tags []string  `json:"tags"`
}

func handler(writer http.ResponseWriter, request *http.Request) {
	body := payload{Name: request.URL.Path, When: time.Unix(0, 0), Tags: []string{"a", "b"}}
	encoder := json.NewEncoder(writer)
	if err := encoder.Encode(body); err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
	}
}

func main() {
	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()
	matcher := regexp.MustCompile(`^\\{"name"`)
	response, err := http.Get(server.URL + "/probe")
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	defer response.Body.Close()
	var decoded map[string]any
	if err := json.NewDecoder(response.Body).Decode(&decoded); err != nil {
		fmt.Println("decode:", err)
		return
	}
	fmt.Println(matcher.String(), len(decoded))
}
""",
    "cryptozip": """package main

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
)

func sealed(plaintext []byte) ([]byte, error) {
	key := sha256.Sum256([]byte("benchmark-key"))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func packed(name string, body []byte) ([]byte, error) {
	buffer := new(bytes.Buffer)
	archive := zip.NewWriter(buffer)
	archive.RegisterCompressor(zip.Deflate, func(writer io.Writer) (io.WriteCloser, error) {
		return flate.NewWriter(writer, flate.BestCompression)
	})
	entry, err := archive.Create(name)
	if err != nil {
		return nil, err
	}
	if _, err := entry.Write(body); err != nil {
		return nil, err
	}
	if err := archive.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func main() {
	ciphertext, err := sealed([]byte("hello benchmark"))
	if err != nil {
		fmt.Println("seal:", err)
		return
	}
	blob, err := packed("payload.bin", ciphertext)
	if err != nil {
		fmt.Println("pack:", err)
		return
	}
	fmt.Println(len(blob))
}
""",
}

CGO_PROGRAM = """package main

/*
#include <stdio.h>
#include <string.h>

static int native_len(const char *value) {
	return (int)strlen(value);
}
*/
import "C"

import (
	"fmt"
	"unsafe"
)

func main() {
	text := C.CString("hello from cgo")
	defer C.free(unsafe.Pointer(text))
	fmt.Println(int(C.native_len(text)))
}
"""


@dataclass
class GoCell:
    program: str
    goos: str
    goarch: str
    mode: str
    cgo: bool = False
    extra: List[str] = field(default_factory=list)


def _writeModule(work_dir: str, program: str, body: str) -> str:
    module_dir = os.path.join(work_dir, program)
    os.makedirs(module_dir, exist_ok=True)
    with open(os.path.join(module_dir, "main.go"), "w", encoding="utf-8") as source:
        source.write(body)
    with open(os.path.join(module_dir, "go.mod"), "w", encoding="utf-8") as module_file:
        module_file.write(f"module bench/{program}\n\ngo 1.21\n")
    return module_dir


def buildCell(cell: GoCell, module_dir: str, work_dir: str, go_binary: str = "go") -> Dict[str, object]:
    name = f"{cell.program}_{cell.goos}-{cell.goarch}_{cell.mode}"
    unstripped = os.path.join(work_dir, name + ".unstripped")
    ldflags = []
    build_flags = []
    for mode_name, flags, link_flags in MODES:
        if mode_name == cell.mode:
            build_flags = list(flags)
            ldflags = list(link_flags)
    command = [go_binary, "build"] + build_flags
    if ldflags:
        command.append("-ldflags=" + " ".join(ldflags))
    command += ["-o", unstripped, "."]
    environment = {
        **os.environ,
        "GOOS": cell.goos,
        "GOARCH": cell.goarch,
        "CGO_ENABLED": "1" if cell.cgo else "0",
        "GOFLAGS": "-mod=mod",
        "GOCACHE": os.path.join(work_dir, "gocache"),
    }
    completed = subprocess.run(command, cwd=module_dir, capture_output=True, text=True, timeout=1800, env=environment)
    if completed.returncode != 0 or not os.path.isfile(unstripped):
        return {"status": "build_failed", "error": completed.stderr[-500:]}
    return {"status": "built", "name": name, "unstripped": unstripped}


def build(
    out_dir: str,
    work_dir: str,
    go_binary: str = "go",
    programs: Optional[List[str]] = None,
) -> Dict[str, object]:
    binary_dir = os.path.join(out_dir, "binary")
    truth_dir = os.path.join(out_dir, "truth")
    os.makedirs(work_dir, exist_ok=True)
    os.makedirs(binary_dir, exist_ok=True)
    cells: List[Dict[str, object]] = []
    selected = programs or sorted(GO_PROGRAMS)
    modules = {name: _writeModule(work_dir, name, GO_PROGRAMS[name]) for name in selected}
    host = subprocess.run([go_binary, "env", "GOOS", "GOARCH"], capture_output=True, text=True)
    host_goos, host_goarch = (host.stdout.split() + ["", ""])[:2]
    plan: List[GoCell] = []
    for program in selected:
        for goos, goarch in PLATFORMS:
            for mode, _, _ in MODES:
                # a PIE build needs a target-specific linker for some platforms;
                # keep it on the host triple where it is reliably available
                if mode == "pie" and (goos, goarch) != (host_goos, host_goarch):
                    continue
                plan.append(GoCell(program, goos, goarch, mode))
    modules["cgo"] = _writeModule(work_dir, "cgo", CGO_PROGRAM)
    for mode, _, _ in MODES:
        if mode == "pie":
            continue
        plan.append(GoCell("cgo", host_goos, host_goarch, mode, cgo=True))

    for cell in plan:
        record = {"program": cell.program, "goos": cell.goos, "goarch": cell.goarch, "mode": cell.mode, "cgo": cell.cgo}
        built = buildCell(cell, modules[cell.program], work_dir, go_binary)
        if built["status"] != "built":
            record.update(built)
            cells.append(record)
            continue
        name = str(built["name"])
        unstripped = str(built["unstripped"])
        try:
            truth = goFunctionStarts(unstripped, go_binary)
        except (RuntimeError, OSError, subprocess.TimeoutExpired) as failure:
            record.update({"status": "truth_failed", "error": str(failure)[:300]})
            cells.append(record)
            os.remove(unstripped)
            continue
        if not truth["starts"]:
            record.update({"status": "truth_empty"})
            cells.append(record)
            os.remove(unstripped)
            continue
        measured = os.path.join(binary_dir, name)
        # the stripped mode is the one whose symbol table is gone; the others
        # keep theirs, so their truth is trivially readable and they are kept
        # only as the reference points the stripped cells are compared against
        shutil.copyfile(unstripped, measured)
        writeTruth(
            truth_dir,
            name,
            list(truth["starts"]),
            {
                "plt": [],
                "bitness": 64 if cell.goarch in ("amd64", "arm64") else 32,
                "goos": cell.goos,
                "goarch": cell.goarch,
                "mode": cell.mode,
                "cgo": cell.cgo,
                "program": cell.program,
                "truth_source": truth["source"],
            },
        )
        record.update(
            {"status": "ok", "name": name, "truth_functions": len(truth["starts"]), "size": os.path.getsize(measured)}
        )
        cells.append(record)
        os.remove(unstripped)

    manifest = {
        "family": "go",
        "go_version": subprocess.run([go_binary, "version"], capture_output=True, text=True).stdout.strip(),
        "cells": cells,
        "ok": sum(1 for cell in cells if cell.get("status") == "ok"),
        "failed": sum(1 for cell in cells if cell.get("status") != "ok"),
    }
    with open(os.path.join(out_dir, "manifest.json"), "w", encoding="utf-8") as manifest_file:
        json.dump(manifest, manifest_file, indent=1, sort_keys=True)
    return manifest
