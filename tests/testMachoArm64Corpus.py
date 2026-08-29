import json
import logging
import os
import sys
import tempfile
import unittest

import lief

logging.disable(logging.CRITICAL)
lief.logging.disable()

REPOSITORY_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS_PATH = os.path.join(REPOSITORY_ROOT, "tools")
if TOOLS_PATH not in sys.path:
    sys.path.insert(0, TOOLS_PATH)

from bench.builders.macho_arm64 import (  # noqa: E402
    FIXTURE_ROOT,
    buildMachoArm64,
    decode,
    machoFunctionStarts,
    scoredRanges,
    symbolStubStarts,
)
from bench.metrics import scoreSample  # noqa: E402

FIXTURE_DIR = os.path.join(REPOSITORY_ROOT, FIXTURE_ROOT)
#: declares 147 function starts, small enough to parse in every test that needs one
A_FIXTURE = os.path.join(FIXTURE_DIR, "malpedia", "osx.frostyferret_ef27a525ec0b.xored")
#: carries the load command with nothing in it
AN_EMPTY_FIXTURE = os.path.join(FIXTURE_DIR, "objective-see", "Turtle_5f9cd91d8d1d.xored")


def _parse(path):
    with open(path, "rb") as fixture_file:
        return lief.MachO.parse(list(decode(fixture_file.read())))


class MachoTruthTest(unittest.TestCase):
    def testDeclaredStartsAreAbsoluteAndLandInText(self):
        binary = _parse(A_FIXTURE).at(0)
        starts = machoFunctionStarts(binary)
        text = [section for section in binary.sections if section.name == "__text"][0]
        self.assertGreater(len(starts), 100)
        self.assertTrue(all(start >= binary.imagebase for start in starts))
        # LC_FUNCTION_STARTS records file offsets from the image base; an address space
        # that disagreed with the disassembler's would score every function as a miss
        self.assertTrue(
            all(text.virtual_address <= start < text.virtual_address + text.size for start in starts),
            "a declared start fell outside __text",
        )

    def testStubsAreNotDeclaredFunctions(self):
        binary = _parse(A_FIXTURE).at(0)
        stubs = [section for section in binary.sections if section.name == "__stubs"]
        self.assertTrue(stubs, "fixture has no __stubs section to check the convention against")
        extent = (stubs[0].virtual_address, stubs[0].virtual_address + stubs[0].size)
        self.assertEqual([start for start in machoFunctionStarts(binary) if extent[0] <= start < extent[1]], [])

    def testAnImageDeclaringNothingYieldsNoTruthRatherThanAnEmptySet(self):
        # control: this fixture really does carry the load command, so the empty result
        # is the image declaring nothing and not the parser missing it
        binary = _parse(AN_EMPTY_FIXTURE).at(0)
        self.assertEqual(machoFunctionStarts(binary), [])


class MachoCorpusBuildTest(unittest.TestCase):
    def testEveryCellIsRecordedIncludingTheOneWithNoTruth(self):
        with tempfile.TemporaryDirectory() as out_dir:
            manifest = buildMachoArm64(out_dir, REPOSITORY_ROOT)
            names = sorted(os.listdir(os.path.join(out_dir, "binary")))
            truth_files = sorted(os.listdir(os.path.join(out_dir, "truth")))
            with open(os.path.join(out_dir, "truth", truth_files[0]), encoding="utf-8") as truth_file:
                first = json.load(truth_file)
        self.assertEqual(manifest["ok"], len(names))
        self.assertEqual(len(truth_files), len(names))
        self.assertEqual(manifest["ok"] + manifest["failed"], len(manifest["cells"]))
        skipped = [cell for cell in manifest["cells"] if cell["status"] != "ok"]
        self.assertEqual([cell["status"] for cell in skipped], ["declares_no_function_starts"])
        self.assertNotIn(skipped[0]["name"], names)
        self.assertEqual(first["source"], "LC_FUNCTION_STARTS plus declared symbol stubs")
        self.assertGreater(len(first["starts"]), 0)
        self.assertGreater(len(first["scored_ranges"]), 0)

    def testTheDecodedBinaryIsWrittenOutsideTheRepository(self):
        with tempfile.TemporaryDirectory() as out_dir:
            buildMachoArm64(out_dir, REPOSITORY_ROOT)
            written = os.path.join(out_dir, "binary", "osx.frostyferret_ef27a525ec0b")
            with open(written, "rb") as binary_file:
                head = binary_file.read(4)
        self.assertEqual(head, b"\xcf\xfa\xed\xfe")
        self.assertFalse(os.path.exists(os.path.join(FIXTURE_DIR, "malpedia", "osx.frostyferret_ef27a525ec0b")))


class ScoredRegionTest(unittest.TestCase):
    """The corpus scores where its oracles speak and says what it left out."""

    def setUp(self):
        self.binary = _parse(A_FIXTURE).at(0)
        self.sections = {section.name: section for section in self.binary.sections}

    def testDeclaredStubsAreDerivedFromTheSectionsOwnStride(self):
        stubs = self.sections["__stubs"]
        derived = symbolStubStarts(self.binary)
        # control: the stride comes from the image, not from a guess -- reserved2 on an
        # S_SYMBOL_STUBS section is the direct counterpart of an ELF section's entry size
        self.assertEqual(stubs.reserved2, 12)
        self.assertEqual(len(derived), stubs.size // stubs.reserved2)
        self.assertEqual(derived[0], stubs.virtual_address)
        self.assertEqual(derived[-1], stubs.virtual_address + stubs.size - stubs.reserved2)

    def testTheScoredRegionIsTextPlusDeclaredStubsAndNothingElse(self):
        ranges = scoredRanges(self.binary)
        text = self.sections["__text"]
        stubs = self.sections["__stubs"]
        self.assertEqual(
            ranges,
            sorted(
                [
                    (text.virtual_address, text.virtual_address + text.size),
                    (stubs.virtual_address, stubs.virtual_address + stubs.size),
                ]
            ),
        )
        # control: a section this image carries whose entries no oracle declares stays out
        helper = self.sections.get("__stub_helper")
        self.assertIsNotNone(helper, "fixture has no undeclared code section to check against")
        self.assertNotIn((helper.virtual_address, helper.virtual_address + helper.size), ranges)

    def testADetectionOutsideTheScoredRegionIsCountedRatherThanCharged(self):
        text = (0x1000, 0x2000)
        score = scoreSample("s", {0x1000, 0x1010}, {0x1000, 0x1010, 0x3000}, scored_ranges=[text])
        self.assertEqual((score.detected, score.true_positives, score.false_positives), (2, 2, 0))
        self.assertEqual(score.meta["outside_scored_region"], 1)
        # control: without the region the same detection is a false positive, so the
        # mechanism is doing the work and not the numbers happening to agree
        unscoped = scoreSample("s", {0x1000, 0x1010}, {0x1000, 0x1010, 0x3000})
        self.assertEqual(unscoped.false_positives, 1)
        self.assertNotIn("outside_scored_region", unscoped.meta)


if __name__ == "__main__":
    unittest.main()
