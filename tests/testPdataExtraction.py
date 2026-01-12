
import unittest
import struct
from smda.intel.FunctionCandidateManager import FunctionCandidateManager
from smda.DisassemblyResult import DisassemblyResult
from smda.SmdaConfig import SmdaConfig

class MockBinaryInfo:
    def __init__(self, bitness, base_addr, binary):
        self.bitness = bitness
        self.base_addr = base_addr
        self.binary = binary
        self.code_areas = []

    def getSections(self):
        # yields name, start, end
        # .pdata at 0x1000, size 36 (3 entries)
        yield ".pdata", self.base_addr + 0x1000, self.base_addr + 0x1000 + 36

class PdataExtractionTestSuite(unittest.TestCase):
    def test_pdata_candidates(self):
        config = SmdaConfig()
        fcm = FunctionCandidateManager(config)

        # Entry format: Start RVA, End RVA, Unwind RVA
        entries = [
            (0x2000, 0x2040, 0x3000),
            (0x2050, 0x2090, 0x3010),
            (0x2100, 0x2150, 0x3020)
        ]

        pdata_bytes = b""
        for start, end, unwind in entries:
            pdata_bytes += struct.pack("III", start, end, unwind)

        # Fill binary with zeros
        binary_size = 0x4000
        binary = bytearray(binary_size)

        # Place pdata at 0x1000
        binary[0x1000 : 0x1000 + len(pdata_bytes)] = pdata_bytes

        # Initialize Mock Disassembly and BinaryInfo
        disasm = DisassemblyResult()
        disasm.binary_info = MockBinaryInfo(64, 0x140000000, bytes(binary))

        # Mock code_areas in binary info so passesCodeFilter works
        # If code_areas is empty, it returns True (see FunctionCandidateManager.py)

        # We need to mock LanguageAnalyzer to avoid it running on empty/random binary and potentially crashing or taking time
        # But FunctionCandidateManager instantiates it inside init().
        # We can mock it by assigning to fcm.lang_analyzer *after* init? No init calls identify().
        # We can subclass FunctionCandidateManager and override init, or just mock disassembly.binary_info.binary to be safe for LanguageAnalyzer.
        # LanguageAnalyzer checks bytes.

        # Let's try running it. If LanguageAnalyzer crashes, we will see.

        fcm.init(disasm)

        candidates = fcm.candidates

        self.assertIn(0x140000000 + 0x2000, candidates)
        self.assertIn(0x140000000 + 0x2050, candidates)
        self.assertIn(0x140000000 + 0x2100, candidates)

if __name__ == '__main__':
    unittest.main()
