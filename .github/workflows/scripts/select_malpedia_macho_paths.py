#!/usr/bin/env python
"""Select Malpedia sparse-checkout paths for macOS ``*_unpacked`` samples."""

import argparse
from pathlib import Path

MACOS_HINTS = (
    "osx",
    "macos",
    "macho",
    "darwin",
    "apple_macos",
    "apple macos",
    "mac os",
)
SKIP_PARTS = {
    ".git",
    "modules",
    "yara",
    "rules",
    "docs",
    "doc",
    "images",
    "resources",
}
METADATA_NAMES = {"meta.json", "metadata.json", "config.json", "README.md", "README.txt"}


def is_skipped(path):
    return any(part in SKIP_PARTS for part in Path(path).parts)


def has_macos_hint(path):
    lowered = path.lower()
    return any(hint in lowered for hint in MACOS_HINTS)


def is_metadata_path(path):
    name = Path(path).name
    return name in METADATA_NAMES or name.endswith((".json", ".yaml", ".yml"))


def selected_paths(paths):
    for path in paths:
        path = path.strip()
        if not path or is_skipped(path) or not has_macos_hint(path):
            continue
        name = Path(path).name
        if name.endswith("_unpacked") or is_metadata_path(path):
            yield path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths_file", type=Path)
    args = parser.parse_args()

    paths = args.paths_file.read_text(errors="ignore").splitlines()
    for path in sorted(set(selected_paths(paths))):
        print(path)


if __name__ == "__main__":
    main()
