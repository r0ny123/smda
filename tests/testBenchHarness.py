import json
import logging
import os
import sys
import tempfile
import unittest

logging.disable(logging.CRITICAL)

TOOLS_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools")
if TOOLS_PATH not in sys.path:
    sys.path.insert(0, TOOLS_PATH)

from bench.corpora import (  # noqa: E402
    PAPER_OPT_LEVELS,
    bitnessFromName,
    filterSamples,
    loadByteweightTruth,
    loadFnmapTruth,
    parseBaseAddrFromName,
    parseOptLevel,
)
from bench.corpora import Sample  # noqa: E402
from bench.metrics import aggregate, scoreSample  # noqa: E402
from bench.report import renderRow, renderTable, writeResults  # noqa: E402


class BenchMetricsTest(unittest.TestCase):
    def testExactStartMatchDecidesEveryCount(self):
        score = scoreSample("s", {0x1000, 0x1010, 0x1020}, {0x1000, 0x1011, 0x1020})
        self.assertEqual(score.true_positives, 2)
        self.assertEqual(score.false_positives, 1)
        self.assertEqual(score.false_negatives, 1)
        self.assertAlmostEqual(score.ppv, 200.0 / 3)
        self.assertAlmostEqual(score.tpr, 200.0 / 3)
        self.assertAlmostEqual(score.f1, 200.0 / 3)

    def testEmptyDetectionScoresZeroRatherThanBeingAveragedAway(self):
        score = scoreSample("s", {0x1000}, set())
        self.assertEqual(score.ppv, 0.0)
        self.assertEqual(score.tpr, 0.0)
        self.assertEqual(score.f1, 0.0)

    def testEmptyTruthLeavesEveryRateUndefined(self):
        score = scoreSample("s", set(), {0x1000})
        self.assertEqual(score.ppv, 0.0)
        self.assertIsNone(score.tpr)
        self.assertIsNone(score.f1)

    def testTruthAndDetectionBothEmptyIsNotScoreable(self):
        score = scoreSample("s", set(), set())
        self.assertIsNone(score.ppv)
        self.assertIsNone(score.tpr)
        self.assertIsNone(score.f1)

    def testThreeAggregationsDivergeOnUnequalBinaries(self):
        scores = [
            scoreSample("big", set(range(100)), set(range(100))),
            scoreSample("small", {1, 2}, {1, 3}),
        ]
        aggregated = aggregate(scores)
        self.assertEqual(aggregated.n, 2)
        self.assertAlmostEqual(aggregated.macro_f1, 75.0)
        self.assertAlmostEqual(aggregated.geo_f1, (100.0 * 50.0) ** 0.5)
        self.assertAlmostEqual(aggregated.micro_tpr, 100.0 * 101 / 102)
        self.assertGreater(aggregated.macro_f1, aggregated.geo_f1)
        self.assertEqual(aggregated.total_fp, 1)
        self.assertEqual(aggregated.total_fn, 1)

    def testGeometricMeanCollapsesOnATotalFailure(self):
        scores = [
            scoreSample("good", {1, 2}, {1, 2}),
            scoreSample("dead", {5, 6}, {7}),
        ]
        aggregated = aggregate(scores)
        self.assertEqual(aggregated.geo_f1, 0.0)
        self.assertAlmostEqual(aggregated.macro_f1, 50.0)

    def testStdevNeedsTwoSamples(self):
        self.assertIsNone(aggregate([scoreSample("s", {1}, {1})]).stdev_f1)
        self.assertAlmostEqual(
            aggregate([scoreSample("a", {1}, {1}), scoreSample("b", {1}, {1})]).stdev_f1,
            0.0,
        )

    def testAggregateOfNothingReportsNothing(self):
        aggregated = aggregate([])
        self.assertEqual(aggregated.n, 0)
        self.assertIsNone(aggregated.macro_f1)
        self.assertIsNone(aggregated.geo_f1)
        self.assertIsNone(aggregated.micro_f1)


class BenchCorporaTest(unittest.TestCase):
    def testByteweightTruthFoldsThunksIntoFunctionStarts(self):
        with tempfile.TemporaryDirectory() as directory:
            function_path = os.path.join(directory, "fn")
            thunk_path = os.path.join(directory, "thunk")
            with open(function_path, "w", encoding="utf-8") as function_file:
                function_file.write("401000 401019\n401019 401028\n\n")
            with open(thunk_path, "w", encoding="utf-8") as thunk_file:
                thunk_file.write("40836c\n408372\n")
            starts = loadByteweightTruth(function_path, thunk_path)
        self.assertEqual(starts, {0x401000, 0x401019, 0x40836C, 0x408372})

    def testByteweightTruthToleratesAMissingThunkList(self):
        with tempfile.TemporaryDirectory() as directory:
            function_path = os.path.join(directory, "fn")
            with open(function_path, "w", encoding="utf-8") as function_file:
                function_file.write("401000 401019\n")
            self.assertEqual(loadByteweightTruth(function_path, None), {0x401000})
            self.assertEqual(
                loadByteweightTruth(function_path, os.path.join(directory, "absent")),
                {0x401000},
            )

    def testFnmapTruthTakesTheOwningFunctionColumn(self):
        with tempfile.TemporaryDirectory() as directory:
            fnmap_path = os.path.join(directory, "sample.fnmap")
            with open(fnmap_path, "w", encoding="utf-8") as fnmap_file:
                fnmap_file.write("0x2d1000;0x2d1000;mov\n0x2d1004;0x2d1000;push\n0x2d1010;0x2d1010;mov\nbroken\n")
            self.assertEqual(loadFnmapTruth(fnmap_path), {0x2D1000, 0x2D1010})

    def testBaseAddressComesFromTheNameSuffixOnly(self):
        self.assertEqual(parseBaseAddrFromName("x_dump7_0x00400000"), 0x400000)
        self.assertEqual(parseBaseAddrFromName("y_dump_0x140000000"), 0x140000000)
        self.assertIsNone(parseBaseAddrFromName("msvs_whatever_32_O1_7z"))

    def testOptimizationLevelComesFromTheNameInfix(self):
        self.assertEqual(parseOptLevel("msvs_whatever_32_O1_7z"), "O1")
        self.assertEqual(parseOptLevel("msvs_whatever_64_Ox_vim"), "Ox")
        self.assertIsNone(parseOptLevel("cerber_abcdef_dump_0x400000"))

    def testBitnessRuleDefaultsTo32AndHonoursBothMarkers(self):
        self.assertEqual(bitnessFromName("msvs_whatever_64_O1_7z"), 64)
        self.assertEqual(bitnessFromName("x64-trickbot_deadbeef_dump_0x140000000"), 64)
        self.assertEqual(bitnessFromName("msvs_whatever_32_O1_7z"), 32)
        self.assertEqual(bitnessFromName("cerber_abcdef_dump_0x400000"), 32)

    def testPaperFilterDropsOnlyTheExcludedOptimizationLevels(self):
        samples = [
            Sample(name=level, path="", truth=set(), meta={"opt": level}) for level in ("O1", "O2", "Od", "Ox", "Os")
        ]
        samples.append(Sample(name="dump", path="", truth=set(), meta={"opt": None}))
        kept = {sample.name for sample in filterSamples(samples, "paper")}
        self.assertEqual(kept, PAPER_OPT_LEVELS | {"dump"})
        self.assertEqual(len(filterSamples(samples, "all")), 6)

    def testUnknownFilterIsRejected(self):
        with self.assertRaises(ValueError):
            filterSamples([], "whatever")


class BenchReportTest(unittest.TestCase):
    def testRowNamesFilterAndSampleCount(self):
        aggregated = aggregate([scoreSample("a", {1, 2}, {1, 2})])
        row = renderRow("Some corpus", "smda", "paper", aggregated)
        self.assertIn("Some corpus", row)
        self.assertIn("paper", row)
        self.assertIn("100.000", row)
        self.assertIn("smda", row)

    def testTableHeaderNamesTheAggregationShown(self):
        self.assertIn("PPV/geo", renderTable([], "geometric"))
        self.assertIn("PPV/arith", renderTable([], "macro"))
        self.assertIn("PPV/micro", renderTable([], "micro"))

    def testMissingRateRendersAsADashRatherThanZero(self):
        aggregated = aggregate([scoreSample("a", set(), set())])
        self.assertIn("-", renderRow("c", "smda", "all", aggregated))
        self.assertNotIn("0.000", renderRow("c", "smda", "all", aggregated))

    def testWrittenResultCarriesEveryPerSampleCount(self):
        scores = [scoreSample("a", {1, 2}, {1, 3})]
        with tempfile.TemporaryDirectory() as directory:
            path = writeResults(
                directory,
                "corpus",
                "smda",
                "all",
                {"engine": "smda", "version": "x"},
                {"key": "corpus", "title": "Corpus", "n": 1},
                scores,
                aggregate(scores),
            )
            with open(path, encoding="utf-8") as result_file:
                payload = json.load(result_file)
        self.assertEqual(payload["filter"], "all")
        self.assertEqual(payload["samples"][0]["tp"], 1)
        self.assertEqual(payload["samples"][0]["fp"], 1)
        self.assertEqual(payload["samples"][0]["fn"], 1)
        self.assertEqual(payload["aggregate"]["n"], 1)


if __name__ == "__main__":
    unittest.main()
