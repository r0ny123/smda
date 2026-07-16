import hashlib
import importlib.util
import json
import struct
import sys
import uuid
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

MODULE_PATH = Path(__file__).parents[1] / ".github" / "workflows" / "scripts" / "collect_msvc_x64_targets.py"
SPEC = importlib.util.spec_from_file_location("collect_msvc_x64_targets", MODULE_PATH)
COLLECTOR = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = COLLECTOR
SPEC.loader.exec_module(COLLECTOR)


def make_pe(path, guid, age, pdb_name, machine=0x8664, optional_magic=0x20B, signature=b"RSDS"):
    data = bytearray(0x800)
    data[:2] = b"MZ"
    pe_offset = 0x80
    struct.pack_into("<I", data, 0x3C, pe_offset)
    data[pe_offset : pe_offset + 4] = b"PE\x00\x00"
    struct.pack_into("<H", data, pe_offset + 4, machine)
    struct.pack_into("<H", data, pe_offset + 6, 1)
    struct.pack_into("<H", data, pe_offset + 20, 0xF0)
    optional_offset = pe_offset + 24
    struct.pack_into("<H", data, optional_offset, optional_magic)
    struct.pack_into("<I", data, optional_offset + 60, 0x200)
    struct.pack_into("<II", data, optional_offset + 112 + 6 * 8, 0x1000, 28)
    section_offset = optional_offset + 0xF0
    struct.pack_into("<IIII", data, section_offset + 8, 0x200, 0x1000, 0x200, 0x200)
    pdb_bytes = pdb_name.encode() + b"\x00"
    struct.pack_into("<IIHHIIII", data, 0x200, 0, 0, 0, 0, 2, 24 + len(pdb_bytes), 0x1020, 0x220)
    data[0x220:0x224] = signature
    data[0x224:0x234] = guid.bytes_le
    struct.pack_into("<I", data, 0x234, age)
    data[0x238 : 0x238 + len(pdb_bytes)] = pdb_bytes
    path.write_bytes(data)


def pdb_summary(guid, age):
    return f"PDB Stream:\n  Age: {age}\n  Guid: {{{guid}}}\n"


def test_parse_pe_debug_identity_accepts_amd64_pe32_plus_rsds():
    with TemporaryDirectory() as directory:
        path = Path(directory) / "tool.exe"
        guid = uuid.UUID("12345678-1234-5678-9abc-def012345678")
        make_pe(path, guid, 4, r"C:\symbols\tool.pdb")

        identity = COLLECTOR.parse_pe_debug_identity(path)

    assert identity == COLLECTOR.PeDebugIdentity(str(guid), 4, "tool.pdb")


def test_parse_pe_debug_identity_rejects_invalid_platform_or_codeview():
    with TemporaryDirectory() as directory:
        root = Path(directory)
        guid = uuid.uuid4()
        make_pe(root / "x86.exe", guid, 1, "x86.pdb", machine=0x14C)
        make_pe(root / "pe32.exe", guid, 1, "pe32.pdb", optional_magic=0x10B)
        make_pe(root / "nb10.exe", guid, 1, "nb10.pdb", signature=b"NB10")
        (root / "not-pe.dll").write_bytes(b"not a PE")

        assert COLLECTOR.parse_pe_debug_identity(root / "x86.exe") is None
        assert COLLECTOR.parse_pe_debug_identity(root / "pe32.exe") is None
        assert COLLECTOR.parse_pe_debug_identity(root / "nb10.exe") is None
        assert COLLECTOR.parse_pe_debug_identity(root / "not-pe.dll") is None


def test_parse_pdb_identity_requires_guid_and_age():
    guid = "12345678-1234-5678-9abc-def012345678"

    assert COLLECTOR.parse_pdb_identity(pdb_summary(guid, 7)) == COLLECTOR.PdbIdentity(guid, 7)

    try:
        COLLECTOR.parse_pdb_identity("PDB Stream:\n  Age: 7\n")
    except ValueError:
        pass
    else:
        raise AssertionError("expected a missing GUID to be rejected")


def test_get_pdb_identity_uses_llvm_pdbutil_summary():
    guid = uuid.UUID("12345678-1234-5678-9abc-def012345678")
    with patch.object(
        COLLECTOR, "run", return_value=type("Result", (), {"stdout": pdb_summary(guid, 3)})()
    ) as mocked_run:
        identity = COLLECTOR.get_pdb_identity("llvm-pdbutil.exe", Path("sample.pdb"))

    assert identity == COLLECTOR.PdbIdentity(str(guid), 3)
    assert mocked_run.call_args.args[0] == ["llvm-pdbutil.exe", "dump", "--summary", "sample.pdb"]


def test_discover_candidates_rejects_missing_ambiguous_and_mismatched_pdbs():
    with TemporaryDirectory() as directory:
        root = Path(directory)
        guid = uuid.UUID("12345678-1234-5678-9abc-def012345678")
        make_pe(root / "valid.exe", guid, 1, "valid.pdb")
        make_pe(root / "missing.exe", guid, 1, "missing.pdb")
        make_pe(root / "ambiguous.exe", guid, 1, "ambiguous.pdb")
        make_pe(root / "mismatch.exe", guid, 1, "mismatch.pdb")
        (root / "valid.pdb").write_bytes(b"valid")
        (root / "mismatch.pdb").write_bytes(b"mismatch")
        (root / "one").mkdir()
        (root / "two").mkdir()
        (root / "one" / "ambiguous.pdb").write_bytes(b"one")
        (root / "two" / "ambiguous.pdb").write_bytes(b"two")

        def identity_for_path(_llvm_pdbutil, path):
            if path.name == "valid.pdb":
                return COLLECTOR.PdbIdentity(str(guid), 1)
            return COLLECTOR.PdbIdentity(str(guid), 2)

        with patch.object(COLLECTOR, "get_pdb_identity", side_effect=identity_for_path):
            candidates, pe_debug_candidate_count = COLLECTOR.discover_candidates(root, "llvm-pdbutil")

    assert pe_debug_candidate_count == 4
    assert [candidate.pe_path.name for candidate in candidates] == ["valid.exe"]


def test_write_artifact_deduplicates_pe_and_pdb_and_records_identity():
    with TemporaryDirectory() as directory:
        root = Path(directory)
        source_root = root / "source"
        source_root.mkdir()
        pe_one = source_root / "one.exe"
        pe_two = source_root / "two.exe"
        pdb_one = source_root / "one.pdb"
        pdb_two = source_root / "two.pdb"
        pe_one.write_bytes(b"same pe")
        pe_two.write_bytes(b"same pe")
        pdb_one.write_bytes(b"same pdb")
        pdb_two.write_bytes(b"same pdb")
        identity = COLLECTOR.PeDebugIdentity("12345678-1234-5678-9abc-def012345678", 1, "one.pdb")
        candidates = [
            COLLECTOR.Candidate(pe_one, pdb_one, identity, COLLECTOR.PdbIdentity(identity.guid, 1)),
            COLLECTOR.Candidate(pe_two, pdb_two, identity, COLLECTOR.PdbIdentity(identity.guid, 1)),
        ]

        summary = COLLECTOR.write_artifact(candidates, 2, source_root, root / "output", {"source": "test"})
        records = [json.loads(line) for line in (root / "output" / "manifest.jsonl").read_text().splitlines()]

        assert summary["status"] == "matched"
        assert summary["unique_binary_count"] == 1
        assert summary["unique_symbol_count"] == 1
        assert len(records) == 2
        assert records[0]["pe"]["sha256"] == hashlib.sha256(b"same pe").hexdigest()
        assert records[0]["pe"]["codeview"]["guid"] == identity.guid
        assert records[0]["pdb"]["guid"] == identity.guid


def test_write_artifact_marks_zero_matches_explicitly():
    with TemporaryDirectory() as directory:
        root = Path(directory)
        summary = COLLECTOR.write_artifact([], 3, root, root / "output", {"source": "test"})

        assert summary["status"] == "no_matches"
        assert (root / "output" / "manifest.jsonl").read_text() == ""


def test_write_error_artifact_is_auditable():
    with TemporaryDirectory() as directory:
        root = Path(directory)
        summary = COLLECTOR.write_error_artifact(root / "output", {"source": "test"}, ValueError("bad PDB"))

        assert summary["status"] == "error"
        assert "bad PDB" in summary["error"]
        assert (root / "output" / "toolchain.json").is_file()
