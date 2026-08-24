"""Source acquisition for the corpora this repository builds.

Nothing here is vendored: each entry names an upstream that is fetched on
demand, so a clean checkout carries the recipe and not the payload. Programs
were picked for buildability from a single command rather than for size — a
corpus that needs autotools per entry does not get re-run.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tarfile
import urllib.request
import zipfile
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class SourceProgram:
    key: str
    language: str
    #: git repository to shallow-clone, or an archive URL to download
    git: str = ""
    archive: str = ""
    revision: str = ""
    #: translation units to compile, relative to the unpacked source root
    sources: List[str] = field(default_factory=list)
    include_dirs: List[str] = field(default_factory=list)
    defines: List[str] = field(default_factory=list)
    #: extra flags a program needs regardless of optimization level
    extra_flags: List[str] = field(default_factory=list)
    #: shell commands run once in the source root, for headers a build system generates
    pre_build: List[str] = field(default_factory=list)
    #: subdirectory inside the archive, when it does not match `key`
    strip_prefix: str = ""


PROGRAMS: Dict[str, SourceProgram] = {
    "sqlite3": SourceProgram(
        key="sqlite3",
        language="c",
        archive="https://www.sqlite.org/2024/sqlite-amalgamation-3450100.zip",
        strip_prefix="sqlite-amalgamation-3450100",
        sources=["sqlite3.c", "shell.c"],
        defines=["SQLITE_THREADSAFE=0", "SQLITE_OMIT_LOAD_EXTENSION"],
    ),
    "lua": SourceProgram(
        key="lua",
        language="c",
        archive="https://www.lua.org/ftp/lua-5.4.6.tar.gz",
        strip_prefix="lua-5.4.6",
        sources=["src/*.c"],
        include_dirs=["src"],
        extra_flags=["-DMAKE_LIB=0"],
    ),
    "zlib": SourceProgram(
        key="zlib",
        language="c",
        git="https://github.com/madler/zlib",
        revision="v1.3.1",
        sources=["*.c", "test/minigzip.c"],
        include_dirs=["."],
    ),
    "xxhash": SourceProgram(
        key="xxhash",
        language="c",
        git="https://github.com/Cyan4973/xxHash",
        revision="v0.8.2",
        sources=["xxhash.c", "xxh_x86dispatch.c", "cli/*.c"],
        include_dirs=[".", "cli"],
        defines=["XXHSUM_DISPATCH=1"],
    ),
    "cjson": SourceProgram(
        key="cjson",
        language="c",
        git="https://github.com/DaveGamble/cJSON",
        revision="v1.7.18",
        sources=["cJSON.c", "cJSON_Utils.c", "test.c"],
        include_dirs=["."],
    ),
    "lz4": SourceProgram(
        key="lz4",
        language="c",
        git="https://github.com/lz4/lz4",
        revision="v1.9.4",
        sources=["lib/*.c", "programs/*.c"],
        include_dirs=["lib", "programs"],
    ),
    "brotli": SourceProgram(
        key="brotli",
        language="c",
        git="https://github.com/google/brotli",
        revision="v1.1.0",
        sources=["c/common/*.c", "c/dec/*.c", "c/enc/*.c", "c/tools/brotli.c"],
        include_dirs=["c/include"],
    ),
    "googletest": SourceProgram(
        key="googletest",
        language="cxx",
        git="https://github.com/google/googletest",
        revision="v1.14.0",
        sources=["googletest/src/gtest-all.cc", "googletest/src/gtest_main.cc"],
        include_dirs=["googletest/include", "googletest"],
    ),
    "tinyxml2": SourceProgram(
        key="tinyxml2",
        language="cxx",
        git="https://github.com/leethomason/tinyxml2",
        revision="10.0.0",
        sources=["tinyxml2.cpp", "xmltest.cpp"],
        include_dirs=["."],
    ),
    "miniz": SourceProgram(
        key="miniz",
        language="c",
        git="https://github.com/richgel999/miniz",
        revision="3.0.2",
        sources=["miniz.c", "miniz_tdef.c", "miniz_tinfl.c", "miniz_zip.c", "examples/example1.c"],
        include_dirs=["."],
        pre_build=["printf '#define MINIZ_EXPORT\\n' > miniz_export.h"],
    ),
}


def _download(url: str, destination: str) -> None:
    with urllib.request.urlopen(url, timeout=300) as response, open(destination, "wb") as output:
        shutil.copyfileobj(response, output)


def _unpack(archive_path: str, into: str) -> None:
    if archive_path.endswith(".zip"):
        with zipfile.ZipFile(archive_path) as archive:
            archive.extractall(into)
        return
    with tarfile.open(archive_path) as archive:
        archive.extractall(into)


def _runPreBuild(program: SourceProgram, root: str) -> None:
    for command in program.pre_build:
        subprocess.run(command, shell=True, cwd=root, capture_output=True, text=True, timeout=300)


def fetch(program: SourceProgram, cache_dir: str) -> Optional[str]:
    """Return the unpacked source root for `program`, fetching it if absent."""
    os.makedirs(cache_dir, exist_ok=True)
    target = os.path.join(cache_dir, program.key)
    if program.git:
        if os.path.isdir(os.path.join(target, ".git")):
            _runPreBuild(program, target)
            return target
        command = ["git", "clone", "--depth", "1", "--quiet"]
        if program.revision:
            command += ["--branch", program.revision]
        command += [program.git, target]
        completed = subprocess.run(command, capture_output=True, text=True, timeout=900)
        if completed.returncode != 0:
            shutil.rmtree(target, ignore_errors=True)
            return None
        _runPreBuild(program, target)
        return target
    if os.path.isdir(target):
        _runPreBuild(program, target)
        return target
    archive_name = os.path.join(cache_dir, os.path.basename(program.archive))
    if not os.path.isfile(archive_name):
        try:
            _download(program.archive, archive_name)
        except OSError:
            return None
    scratch = target + ".unpack"
    shutil.rmtree(scratch, ignore_errors=True)
    os.makedirs(scratch, exist_ok=True)
    try:
        _unpack(archive_name, scratch)
    except (OSError, tarfile.TarError, zipfile.BadZipFile):
        shutil.rmtree(scratch, ignore_errors=True)
        return None
    inner = os.path.join(scratch, program.strip_prefix) if program.strip_prefix else scratch
    if not os.path.isdir(inner):
        shutil.rmtree(scratch, ignore_errors=True)
        return None
    shutil.move(inner, target)
    shutil.rmtree(scratch, ignore_errors=True)
    _runPreBuild(program, target)
    return target
