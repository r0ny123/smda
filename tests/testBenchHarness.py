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
    KNOWN_TRUTH_DEFECTS,
    PAPER_OPT_LEVELS,
    Sample,  # noqa: E402
    bitnessFromName,
    filterSamples,
    knownTruthDefect,
    loadByteweightTruth,
    loadFnmapStartsAndInteriors,
    loadFnmapTruth,
    parseBaseAddrFromName,
    parseOptLevel,
)
from bench.metrics import aggregate, scoreSample  # noqa: E402
from bench.paper_table import cell, failedSamples  # noqa: E402
from bench.report import renderRow, renderTable, writeResults  # noqa: E402
from bench.run import parseArgs, smdaConfigFrom  # noqa: E402


class BenchBodySplitTest(unittest.TestCase):
    """A false positive inside a labelled function is an error on any reading; one outside
    every labelled address may be code the oracle never covered. Only a corpus labelling
    instructions can tell them apart, and the report has to say when it cannot."""

    def testASplitIsCountedOnlyWhenItLandsOnALabelledInterior(self):
        score = scoreSample(
            "s",
            truth={0x1000, 0x2000},
            detected={0x1000, 0x1008, 0x3000},
            truth_interiors={0x1004, 0x1008, 0x2004},
        )
        self.assertEqual(score.false_positives, 2)
        # 0x1008 is inside a labelled body; 0x3000 is where the oracle said nothing
        self.assertEqual(score.body_splits, 1)
        # the split stays inside the false positives rather than being discounted from them
        self.assertAlmostEqual(score.ppv, 100.0 / 3)

    def testACorpusThatCannotAnswerReportsNothingRatherThanZero(self):
        score = scoreSample("s", truth={0x1000}, detected={0x1000, 0x2000})
        self.assertIsNone(score.body_splits)
        self.assertEqual(score.false_positives, 1)
        summary = aggregate([score])
        self.assertIsNone(summary.total_body_splits)
        self.assertEqual(summary.body_split_samples, 0)
        # a dash, never a zero: zero would read as "no function was broken apart"
        self.assertEqual(renderRow("c", "smda", "all", summary).split()[-1], "-")
        answering = aggregate([scoreSample("s", {0x1000}, {0x1000, 0x1008}, truth_interiors={0x1008})])
        # control: the same column carries a number when the corpus can answer, so the
        # dash is the corpus speaking rather than the renderer never printing anything
        self.assertEqual(renderRow("c", "smda", "all", answering).split()[-1], "1")

    def testTheAggregateNamesHowManySamplesCouldAnswer(self):
        answering = scoreSample("a", {0x1000}, {0x1000, 0x1008}, truth_interiors={0x1008})
        silent = scoreSample("b", {0x2000}, {0x2000, 0x9000})
        summary = aggregate([answering, silent])
        self.assertEqual(summary.total_body_splits, 1)
        self.assertEqual(summary.body_split_samples, 1)
        self.assertIn("split", renderTable([]))

    def testTheScoreSurvivesASerializationRoundTrip(self):
        score = scoreSample("s", {0x1000}, {0x1000, 0x1008}, truth_interiors={0x1008})
        self.assertEqual(score.toDict()["body_splits"], 1)
        self.assertIsNone(scoreSample("s", {0x1000}, {0x1000}).toDict()["body_splits"])


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

    def testFnmapAlsoYieldsTheLabelledAddressesThatAreNotStarts(self):
        with tempfile.TemporaryDirectory() as directory:
            fnmap_path = os.path.join(directory, "sample.fnmap")
            with open(fnmap_path, "w", encoding="utf-8") as fnmap_file:
                fnmap_file.write("0x2d1000;0x2d1000;mov\n0x2d1004;0x2d1000;push\n0x2d1010;0x2d1010;mov\nbroken\n")
            starts, interiors = loadFnmapStartsAndInteriors(fnmap_path)
            self.assertEqual(starts, {0x2D1000, 0x2D1010})
            # 0x2d1004 is labelled and is not a start; the two starts are labelled as well
            # and must not appear here, or every recovered function would read as a split
            self.assertEqual(interiors, {0x2D1004})

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


class BenchIntegrityTest(unittest.TestCase):
    def testAKnownDefectMatchesItsDumpedVariantToo(self):
        stem = "msvs_whatever_32_Od_SfxSetup"
        self.assertIn(stem, KNOWN_TRUTH_DEFECTS)
        self.assertIsNotNone(knownTruthDefect(stem))
        self.assertIsNotNone(knownTruthDefect(stem + "_dump7_0x00400000"))

    def testAnUnaffectedSampleIsNotMatched(self):
        self.assertIsNone(knownTruthDefect("msvs_whatever_32_O1_SfxSetup"))
        self.assertIsNone(knownTruthDefect("cerber_abcdef_dump_0x400000"))

    def testEveryRecordedDefectStatesItsEvidence(self):
        for stem, reason in KNOWN_TRUTH_DEFECTS.items():
            self.assertTrue(reason.strip(), f"{stem} is excluded with no reason recorded")
            self.assertIn("0x", reason, f"{stem} is excluded without naming an address")

    def testRangesAreShiftedOntoTheAddressSpaceADumpWasLoadedAt(self):
        from bench.integrity import IntegrityFinding

        finding = IntegrityFinding(name="s", truth=100, outside=25, ranges=[(0x1000, 0x2000)])
        self.assertEqual(finding.share, 25.0)
        self.assertEqual(IntegrityFinding(name="s", truth=0, outside=0, ranges=[]).share, 0.0)


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


class PaperTableCellTest(unittest.TestCase):
    """A cell that averages an engine's failure has to say so."""

    @staticmethod
    def _sample(name, tpr, ppv, opt="O1", status="ok"):
        return {"name": name, "tpr": tpr, "ppv": ppv, "meta": {"opt": opt, "status": status}}

    def testASplitRowUsesTheGeometricMeanOfItsOwnOptimizationLevel(self):
        samples = [
            self._sample("a", 90.0, 80.0, opt="O1"),
            self._sample("b", 10.0, 20.0, opt="O1"),
            self._sample("c", 50.0, 50.0, opt="O2"),
        ]
        tpr, ppv, count, failed = cell(samples, "bao-x86", "O1")
        self.assertEqual(count, 2)
        self.assertEqual(failed, [])
        self.assertAlmostEqual(tpr, 0.3, places=6)
        self.assertAlmostEqual(ppv, 0.4, places=6)

    def testAnUnsplitRowUsesTheArithmeticMeanOfEveryBinary(self):
        samples = [self._sample("a", 90.0, 80.0, opt=""), self._sample("b", 10.0, 20.0, opt="")]
        tpr, ppv, count, failed = cell(samples, "malpedia", "-")
        self.assertEqual((count, failed), (2, []))
        self.assertAlmostEqual(tpr, 0.5, places=6)
        self.assertAlmostEqual(ppv, 0.5, places=6)

    def testACellNamesTheSamplesTheEngineDidNotComplete(self):
        samples = [
            self._sample("finished", 90.0, 90.0),
            self._sample("gave-up", 0.0, 0.0, status="timeout"),
        ]
        tpr, ppv, count, failed = cell(samples, "bao-x86", "O1")
        # control: the cell really did collapse, so the annotation is the only thing
        # separating "the engine scored zero" from "the engine did not answer"
        self.assertEqual((tpr, ppv), (0.0, 0.0))
        self.assertEqual(count, 2)
        self.assertEqual(failed, ["gave-up"])

    def testASampleWithNoRecordedStatusCountsAsIncomplete(self):
        self.assertEqual(failedSamples([{"name": "a", "meta": {}}]), ["a"])
        self.assertEqual(failedSamples([{"name": "a"}]), ["a"])
        self.assertEqual(failedSamples([{"name": "a", "meta": {"status": "ok"}}]), [])

    def testACellWithNoScoreableSampleIsNotReported(self):
        self.assertIsNone(cell([], "bao-x86", "O1"))
        self.assertIsNone(cell([self._sample("a", None, None)], "bao-x86", "O1"))


class BenchConfigOverrideTest(unittest.TestCase):
    """`--set` is how an off-by-default accuracy option gets measured without editing the library."""

    def testABooleanOverrideIsAppliedAndTheDefaultIsLeftAlone(self):
        from smda.SmdaConfig import SmdaConfig

        # control: the class default is what an un-overridden run gets, so the assertion below
        # is about the override rather than about the shipped value
        self.assertFalse(SmdaConfig.USE_LSDA_LANDING_PADS)
        self.assertFalse(smdaConfigFrom({}).USE_LSDA_LANDING_PADS)
        for spelling in ("1", "true", "yes", "on", "TRUE"):
            self.assertTrue(
                smdaConfigFrom({"config_overrides": {"USE_LSDA_LANDING_PADS": spelling}}).USE_LSDA_LANDING_PADS
            )
        for spelling in ("0", "false", "no", "off"):
            self.assertFalse(
                smdaConfigFrom({"config_overrides": {"USE_LSDA_LANDING_PADS": spelling}}).USE_LSDA_LANDING_PADS
            )

    def testAnIntegerOverrideAcceptsTheBaseItIsWrittenIn(self):
        self.assertEqual(
            smdaConfigFrom({"config_overrides": {"MAX_FUNCTION_CANDIDATES": "0x100"}}).MAX_FUNCTION_CANDIDATES, 256
        )
        self.assertEqual(
            smdaConfigFrom({"config_overrides": {"MAX_FUNCTION_CANDIDATES": "512"}}).MAX_FUNCTION_CANDIDATES, 512
        )

    def testAFloatOverrideStaysAFloat(self):
        overridden = smdaConfigFrom({"config_overrides": {"MEMORY_BUDGET_FRACTION": "0.25"}})
        self.assertEqual(overridden.MEMORY_BUDGET_FRACTION, 0.25)

    def testTheOverridesAreRecordedInTheEngineDescription(self):
        from bench.engines.smda_engine import SmdaEngine

        config = smdaConfigFrom({"config_overrides": {"USE_LSDA_LANDING_PADS": "1"}})
        self.assertEqual(SmdaEngine(config=config).describe()["config_overrides"], {"USE_LSDA_LANDING_PADS": True})
        # a run at stock settings must record nothing, or every result would claim an override
        self.assertEqual(SmdaEngine(config=smdaConfigFrom({})).describe()["config_overrides"], {})

    def testRepeatedSetFlagsAccumulate(self):
        args = parseArgs(["--set", "USE_LSDA_LANDING_PADS=1", "--set", "RESOLVE_TAILCALLS=1"])
        self.assertEqual(args.config_set, ["USE_LSDA_LANDING_PADS=1", "RESOLVE_TAILCALLS=1"])
        self.assertEqual(parseArgs([]).config_set, [])
