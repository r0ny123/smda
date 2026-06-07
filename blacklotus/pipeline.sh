#!/usr/bin/env bash
# ============================================================================
# pipeline.sh  –  end-to-end BlackLotus → MCRIT pipeline
#
# Steps:
#   1. Install required apt/pip packages
#   2. Compile BlackLotus (Bot.exe + Bootkit.efi)
#   3. Run SMDA on compiled binaries → .smda reports
#   4. Upload .smda reports to MCRIT
#
# Usage:
#   ./pipeline.sh [--mcrit-host http://localhost:8000] [--bl-path /path/to/BlackLotus] [--dry-run]
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MCRIT_HOST="http://localhost:8000"
BL_PATH="/home/user/BlackLotus"
DRY_RUN=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --mcrit-host) MCRIT_HOST="$2"; shift 2 ;;
        --bl-path)    BL_PATH="$2";    shift 2 ;;
        --dry-run)    DRY_RUN="--dry-run"; shift ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

echo "============================================================"
echo " BlackLotus → MCRIT Pipeline"
echo "============================================================"
echo " BlackLotus source : ${BL_PATH}"
echo " MCRIT host        : ${MCRIT_HOST}"
echo "============================================================"

# ---------------------------------------------------------------------------
# Step 0: Install prerequisites
# ---------------------------------------------------------------------------
echo ""
echo "[0] Installing prerequisites…"

# apt packages (non-interactive)
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    gcc-mingw-w64-x86-64-posix binutils-mingw-w64-x86-64 nasm gnu-efi \
    2>&1 | grep -E '(Setting up|already installed|error)' || true

# pip packages
pip3 install --quiet smda 2>/dev/null || true
# mcrit client – install from PyPI if available, else warn
pip3 install --quiet mcrit 2>/dev/null || \
    echo "[warn] mcrit pip package not found; clone https://github.com/danielplohmann/mcrit and pip install -e ."

# ---------------------------------------------------------------------------
# Step 1: Clone BlackLotus if needed
# ---------------------------------------------------------------------------
if [[ ! -d "${BL_PATH}/.git" ]]; then
    echo ""
    echo "[1] Cloning BlackLotus…"
    git clone https://github.com/ldpreload/BlackLotus "${BL_PATH}"
else
    echo "[1] BlackLotus already cloned at ${BL_PATH}"
fi

# ---------------------------------------------------------------------------
# Step 2: Compile
# ---------------------------------------------------------------------------
echo ""
echo "[2] Compiling BlackLotus…"
chmod +x "${SCRIPT_DIR}/build_blacklotus.sh"
BL_PATH="${BL_PATH}" "${SCRIPT_DIR}/build_blacklotus.sh"

# ---------------------------------------------------------------------------
# Step 3: SMDA processing
# ---------------------------------------------------------------------------
echo ""
echo "[3] Running SMDA on compiled binaries…"
cd "${SCRIPT_DIR}"
python3 smda_process.py --built-dir built --out-dir smda_reports

# ---------------------------------------------------------------------------
# Step 4: MCRIT upload
# ---------------------------------------------------------------------------
echo ""
echo "[4] Uploading to MCRIT at ${MCRIT_HOST}…"
python3 mcrit_upload.py \
    --mcrit-host "${MCRIT_HOST}" \
    --smda-dir smda_reports \
    ${DRY_RUN}

echo ""
echo "============================================================"
echo " Pipeline complete!"
echo " • Compiled binaries : ${SCRIPT_DIR}/built/"
echo " • SMDA reports      : ${SCRIPT_DIR}/smda_reports/"
echo " • MCRIT family      : BlackLotus"
echo "============================================================"
echo ""
echo " To detect BlackLotus code in an unknown binary:"
echo "   python3 - << 'EOF'"
echo "   from mcrit.client.McritClient import McritClient"
echo "   c = McritClient('${MCRIT_HOST}')"
echo "   job = c.requestMatchesForUnmappedBinary(open('suspect.exe','rb').read(),"
echo "             family='BlackLotus', minhash_threshold=0.5)"
echo "   print(job)"
echo "   EOF"
