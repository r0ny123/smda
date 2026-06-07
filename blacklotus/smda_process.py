#!/usr/bin/env python3
"""
smda_process.py
~~~~~~~~~~~~~~~
Disassemble all compiled BlackLotus binaries with SMDA and write .smda JSON
reports to ./smda_reports/.

Usage:
    python3 smda_process.py [--built-dir ./built] [--out-dir ./smda_reports]

The resulting .smda files are ready to be consumed by MCRIT's addReport() /
addBinarySample() API.
"""
import argparse
import json
import logging
import pathlib
import sys

# ---------------------------------------------------------------------------
# SMDA import (handles both installed package and local src/ layout)
# ---------------------------------------------------------------------------
try:
    from smda.Disassembler import Disassembler
    from smda.SmdaConfig import SmdaConfig
except ImportError:
    # Try adding the parent smda/src to the path
    _here = pathlib.Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(_here / "src"))
    from smda.Disassembler import Disassembler
    from smda.SmdaConfig import SmdaConfig

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("smda_process")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
FAMILY = "BlackLotus"

# Component metadata: filename -> (version_hint, is_64bit)
COMPONENT_META = {
    "Bot.exe":       ("1.0", True),
    "Bootkit.efi":   ("1.0", True),
    "Encryptor.exe": ("1.0", True),
}

def make_config(with_strings: bool = True) -> SmdaConfig:
    cfg = SmdaConfig()
    cfg.WITH_STRINGS        = with_strings
    cfg.CALCULATE_HASHING   = True   # PIC hash per function
    cfg.CALCULATE_SCC       = True
    cfg.CALCULATE_NESTING   = True
    cfg.STORE_BUFFER        = False  # do NOT embed the binary in the report
    cfg.LOG_LEVEL           = logging.WARNING
    return cfg


def process_binary(path: pathlib.Path, out_dir: pathlib.Path) -> bool:
    """Disassemble *path* with SMDA and write a .smda report to *out_dir*."""
    out_path = out_dir / (path.name + ".smda")
    if out_path.exists():
        log.info("Skip (already processed): %s", path.name)
        return True

    log.info("Processing: %s  (%d bytes)", path.name, path.stat().st_size)

    cfg = make_config()
    disasm = Disassembler(config=cfg)

    try:
        report = disasm.disassembleFile(str(path))
    except Exception as exc:
        log.warning("SMDA failed for %s: %s", path.name, exc)
        # Fall back to unmapped-buffer mode (handles unusual PE layouts)
        try:
            data = path.read_bytes()
            report = disasm.disassembleUnmappedBuffer(data)
        except Exception as exc2:
            log.error("Both disassembly modes failed for %s: %s", path.name, exc2)
            return False

    if report is None:
        log.error("No report produced for %s", path.name)
        return False

    # Annotate with family / component info
    meta = COMPONENT_META.get(path.name, ("1.0", True))
    report_dict = report.toDict()

    # Inject family metadata into the report so MCRIT can use it directly
    if "metadata" not in report_dict:
        report_dict["metadata"] = {}
    report_dict["metadata"]["family"]    = FAMILY
    report_dict["metadata"]["version"]   = meta[0]
    report_dict["metadata"]["component"] = path.stem   # "Bot", "Bootkit", etc.

    # Write .smda file
    out_path.write_text(json.dumps(report_dict, indent=2))

    n_funcs = len(report_dict.get("xcfg", {}))
    log.info(
        "  → %s  (%d functions, %d bytes)",
        out_path.name, n_funcs, path.stat().st_size,
    )
    return True


def main():
    ap = argparse.ArgumentParser(description="SMDA processor for BlackLotus binaries")
    ap.add_argument("--built-dir", default="built",
                    help="Directory containing compiled binaries (default: ./built)")
    ap.add_argument("--out-dir",   default="smda_reports",
                    help="Output directory for .smda reports (default: ./smda_reports)")
    ap.add_argument("--glob",      default="*",
                    help="Glob pattern to filter binaries (default: *)")
    args = ap.parse_args()

    here     = pathlib.Path(__file__).parent
    built    = (here / args.built_dir).resolve()
    out_dir  = (here / args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    if not built.exists():
        log.error("Built directory not found: %s", built)
        log.error("Run build_blacklotus.sh first.")
        sys.exit(1)

    # Process PE / EFI binaries
    extensions = {".exe", ".dll", ".sys", ".efi"}
    targets = [p for p in built.glob(args.glob)
               if p.is_file() and p.suffix.lower() in extensions]

    if not targets:
        log.warning("No PE/EFI binaries found in %s", built)
        sys.exit(0)

    log.info("Found %d binary file(s) to process", len(targets))
    ok = failed = 0
    for path in sorted(targets):
        if process_binary(path, out_dir):
            ok += 1
        else:
            failed += 1

    log.info("Done: %d succeeded, %d failed", ok, failed)
    log.info("SMDA reports in: %s", out_dir)
    if ok:
        log.info("Next step: python3 mcrit_upload.py --mcrit-host http://localhost:8000")


if __name__ == "__main__":
    main()
