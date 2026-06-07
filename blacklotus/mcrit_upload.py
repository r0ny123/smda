#!/usr/bin/env python3
"""
mcrit_upload.py
~~~~~~~~~~~~~~~
Upload BlackLotus SMDA reports to a running MCRIT instance.

For each .smda file in ./smda_reports/ the script:
  1. Loads the SMDA report JSON
  2. Calls McritClient.addReport() to index all functions
  3. Tags the sample with family="BlackLotus" and the component name

After upload, prints a summary table with sample IDs and function counts so
you can verify the database state.

Usage:
    python3 mcrit_upload.py [--mcrit-host http://localhost:8000]
                            [--smda-dir ./smda_reports]
                            [--dry-run]

MCRIT docs / source: https://github.com/danielplohmann/mcrit
"""
import argparse
import json
import logging
import pathlib
import sys
import time

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("mcrit_upload")

FAMILY = "BlackLotus"


# ---------------------------------------------------------------------------
# Import helpers
# ---------------------------------------------------------------------------

def import_smda_report(path: pathlib.Path):
    """Return an smda.common.SmdaReport from a .smda JSON file."""
    try:
        from smda.common.SmdaReport import SmdaReport
    except ImportError:
        _root = pathlib.Path(__file__).resolve().parent.parent
        sys.path.insert(0, str(_root / "src"))
        from smda.common.SmdaReport import SmdaReport

    data = json.loads(path.read_text())
    return SmdaReport(data)


def get_mcrit_client(host: str):
    """Return a connected McritClient instance."""
    try:
        from mcrit.client.McritClient import McritClient
    except ImportError:
        log.error(
            "mcrit package not found.  Install with:\n"
            "  pip install mcrit\n"
            "or clone https://github.com/danielplohmann/mcrit and install editable."
        )
        sys.exit(1)
    return McritClient(mcrit_server=host)


# ---------------------------------------------------------------------------
# Upload logic
# ---------------------------------------------------------------------------

def upload_report(client, smda_path: pathlib.Path, dry_run: bool) -> dict | None:
    """Upload a single SMDA report and return the resulting SampleEntry dict."""
    report = import_smda_report(smda_path)

    # Extract component from metadata injected by smda_process.py
    raw = json.loads(smda_path.read_text())
    component = raw.get("metadata", {}).get("component", smda_path.stem)
    version   = raw.get("metadata", {}).get("version", "1.0")

    n_funcs = len(raw.get("xcfg", {}))
    log.info("Uploading %-20s  %4d functions  family=%-12s component=%s",
             smda_path.name, n_funcs, FAMILY, component)

    if dry_run:
        log.info("  [dry-run] skipping actual upload")
        return {"sample_id": -1, "family": FAMILY, "component": component}

    try:
        sample_entry, job_id = client.addReport(report)
    except Exception as exc:
        log.error("  addReport failed: %s", exc)
        return None

    if sample_entry is None:
        log.warning("  No sample entry returned (duplicate?)")
        return None

    sample_id = getattr(sample_entry, "sample_id", None) or \
                (sample_entry.get("sample_id") if isinstance(sample_entry, dict) else None)

    # Tag the sample with family + component
    try:
        client.modifySample(
            sample_id,
            family_name=FAMILY,
            version=version,
            component=component,
        )
    except Exception as exc:
        log.warning("  modifySample failed (non-fatal): %s", exc)

    log.info("  → sample_id=%s  job_id=%s", sample_id, job_id)
    return {"sample_id": sample_id, "family": FAMILY, "component": component}


def wait_for_jobs(client, timeout: int = 120):
    """Poll MCRIT until all pending jobs finish (or timeout)."""
    deadline = time.time() + timeout
    log.info("Waiting for MCRIT to finish indexing (timeout %ds)…", timeout)
    while time.time() < deadline:
        try:
            stats = client.getStats()
            pending = (stats or {}).get("jobs", {}).get("num_pending", 0)
            if pending == 0:
                log.info("All jobs complete.")
                return
            log.info("  %d job(s) still pending…", pending)
        except Exception:
            pass
        time.sleep(3)
    log.warning("Timeout waiting for jobs – some functions may not be indexed yet.")


# ---------------------------------------------------------------------------
# Matching helper (post-upload verification)
# ---------------------------------------------------------------------------

def verify_sample(client, sample_id: int, component: str):
    """Query MCRIT to confirm the sample was indexed."""
    try:
        entry = client.getSampleById(sample_id)
        if entry:
            n = getattr(entry, "num_functions", "?")
            log.info("  Verified: sample_id=%d  %s functions  (%s/%s)",
                     sample_id, n, FAMILY, component)
    except Exception as exc:
        log.warning("  getSampleById failed: %s", exc)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Upload BlackLotus SMDA reports to MCRIT"
    )
    ap.add_argument("--mcrit-host", default="http://localhost:8000",
                    help="MCRIT server URL (default: http://localhost:8000)")
    ap.add_argument("--smda-dir", default="smda_reports",
                    help="Directory containing .smda files (default: ./smda_reports)")
    ap.add_argument("--dry-run", action="store_true",
                    help="Parse and validate reports but do not upload")
    ap.add_argument("--no-wait", action="store_true",
                    help="Do not wait for MCRIT jobs to finish after upload")
    args = ap.parse_args()

    here     = pathlib.Path(__file__).parent
    smda_dir = (here / args.smda_dir).resolve()

    if not smda_dir.exists():
        log.error("SMDA reports directory not found: %s", smda_dir)
        log.error("Run smda_process.py first.")
        sys.exit(1)

    reports = sorted(smda_dir.glob("*.smda"))
    if not reports:
        log.warning("No .smda files found in %s", smda_dir)
        sys.exit(0)

    log.info("Found %d SMDA report(s)", len(reports))

    if not args.dry_run:
        client = get_mcrit_client(args.mcrit_host)
        log.info("Connected to MCRIT at %s", args.mcrit_host)
    else:
        client = None
        log.info("Dry-run mode – no uploads will be made")

    results = []
    for rpt in reports:
        entry = upload_report(client, rpt, args.dry_run)
        if entry:
            results.append(entry)

    if not args.dry_run and not args.no_wait and results:
        wait_for_jobs(client)

    # Verification pass
    if not args.dry_run and results:
        log.info("")
        log.info("=== Upload Summary ===")
        for r in results:
            sid = r.get("sample_id")
            if sid and sid != -1:
                verify_sample(client, sid, r.get("component", ""))

    log.info("")
    log.info("Done.  %d/%d samples uploaded to %s",
             len(results), len(reports),
             args.mcrit_host if not args.dry_run else "(dry-run)")
    log.info("")
    log.info("To search for BlackLotus code reuse in a suspicious binary:")
    log.info("  from mcrit.client.McritClient import McritClient")
    log.info("  c = McritClient('%s')", args.mcrit_host)
    log.info("  job = c.requestMatchesForUnmappedBinary(open('suspect.exe','rb').read())")
    log.info("  # Poll c.getMatchJob(job.job_id) until done, then inspect matches")


if __name__ == "__main__":
    main()
