"""A callee that does not return must not merge its caller with the next function."""

import logging
import unittest
from pathlib import Path

import pytest

from smda.aarch64.definitions import FRAME_RECORD_WINDOW, opens_stack_frame
from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig

logging.disable(logging.CRITICAL)

CORPUS_DIR = Path(__file__).resolve().parent / "aarch64_macho_corpus"
#: without the boundary rule this image merges fifteen declared functions into two
FIXTURE = CORPUS_DIR / "malpedia" / "osx.frostyferret_ef27a525ec0b.xored"

SUB_SP_0X40 = 0xD10103FF  # sub sp, sp, #0x40
STP_FP_LR_AT_0X30 = 0xA9037BFD  # stp x29, x30, [sp, #0x30]
STP_CALLEE_SAVED = 0xA9024FF4  # stp x20, x19, [sp, #0x20]
SUB_X0_SP = 0xD10103E0  # sub x0, sp, #0x40
ADD_SP_0X40 = 0x910103FF  # add sp, sp, #0x40
STP_FP_LR_PREINDEX = 0xA9B87BFD  # stp x29, x30, [sp, #-0x80]!
NOP = 0xD503201F


def _decode(path):
    return bytes(byte ^ (index % 256) for index, byte in enumerate(path.read_bytes()))


class OpensStackFrameTest(unittest.TestCase):
    def testAllocationFollowedByTheFrameRecordIsAFrameOpening(self):
        self.assertTrue(opens_stack_frame([SUB_SP_0X40, STP_FP_LR_AT_0X30]))
        self.assertTrue(opens_stack_frame([SUB_SP_0X40, STP_CALLEE_SAVED, STP_FP_LR_AT_0X30]))

    def testAnAllocationOnItsOwnIsNot(self):
        # control: the allocation is the same word in both cases, so it is the frame
        # record and not the allocation that decides
        self.assertFalse(opens_stack_frame([SUB_SP_0X40]))
        self.assertFalse(opens_stack_frame([SUB_SP_0X40, NOP, NOP, NOP]))
        self.assertFalse(opens_stack_frame([SUB_SP_0X40, STP_CALLEE_SAVED, NOP, NOP]))

    def testTheFrameRecordHasToArriveInsideTheWindow(self):
        inside = [SUB_SP_0X40] + [NOP] * (FRAME_RECORD_WINDOW - 1) + [STP_FP_LR_AT_0X30]
        outside = [SUB_SP_0X40] + [NOP] * FRAME_RECORD_WINDOW + [STP_FP_LR_AT_0X30]
        self.assertTrue(opens_stack_frame(inside))
        self.assertFalse(opens_stack_frame(outside))

    def testOnlyAnAllocationOffTheStackPointerCounts(self):
        self.assertFalse(opens_stack_frame([SUB_X0_SP, STP_FP_LR_AT_0X30]))
        self.assertFalse(opens_stack_frame([ADD_SP_0X40, STP_FP_LR_AT_0X30]))

    def testThePreIndexedFrameStoreIsNotThisShape(self):
        # it allocates and stores at once, needs no preceding allocation, and is
        # already recognised on its own by is_function_prologue
        self.assertFalse(opens_stack_frame([STP_FP_LR_PREINDEX, STP_FP_LR_AT_0X30]))

    def testAShortOrEmptyWindowDoesNotMatch(self):
        self.assertFalse(opens_stack_frame([]))
        self.assertFalse(opens_stack_frame([None, STP_FP_LR_AT_0X30]))
        self.assertFalse(opens_stack_frame([SUB_SP_0X40, None, None, None]))


@pytest.mark.slow
class NoReturnCallBoundaryTest(unittest.TestCase):
    """Fifteen declared functions in one real image are reached only through this rule."""

    #: entries the image declares that follow a `bl` to a callee with no return
    MERGED_STARTS = (
        0x100008950,
        0x1000089A0,
        0x1000089F0,
        0x100008A40,
        0x100008B10,
        0x100008B60,
        0x100008BB0,
        0x100008C00,
        0x100008D00,
        0x100008D50,
        0x100008DA0,
        0x100008E04,
        0x100008E54,
        0x100008EB8,
        0x100008F08,
    )

    def testEveryEntryAfterANoReturnCallIsItsOwnFunction(self):
        config = SmdaConfig()
        config.TIMEOUT = 300
        report = Disassembler(config).disassembleUnmappedBuffer(_decode(FIXTURE))
        self.assertEqual(report.status, "ok")
        self.assertEqual(report.architecture, "aarch64")
        recovered = {function.offset for function in report.getFunctions()}
        self.assertEqual(sorted(set(self.MERGED_STARTS) - recovered), [])

    def testTheCallerBeforeThemIsStillOneFunction(self):
        # control: the rule cuts at the entry that follows the call, not at every call
        config = SmdaConfig()
        config.TIMEOUT = 300
        report = Disassembler(config).disassembleUnmappedBuffer(_decode(FIXTURE))
        recovered = {function.offset for function in report.getFunctions()}
        self.assertIn(0x100008900, recovered)
        self.assertNotIn(0x100008904, recovered)


if __name__ == "__main__":
    unittest.main()
