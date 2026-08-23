#!/usr/bin/python
"""Fingerprints the escaper output over a frozen instruction corpus.

The escaped representation of an instruction is what downstream consumers (e.g. MCRIT)
turn into function signatures, so a change to it silently invalidates every signature
computed by an older SMDA. These tests pin the output per architecture and per escaping
channel; when one of them fails, the escaper changed and the matching compatibility
marker has to move with it (see the failure message and AGENTS.md).
"""

import hashlib
import json
import logging
import os
import unittest

from smda.common.SmdaFunction import (
    AARCH64_PIC_HASH_ESCAPE_VERSION,
    CIL_PIC_HASH_ESCAPE_VERSION,
    DALVIK_PIC_HASH_ESCAPE_VERSION,
    INTEL_PIC_HASH_ESCAPE_VERSION,
    SmdaFunction,
)
from smda.common.SmdaInstruction import SmdaInstruction
from smda.common.SmdaReport import SmdaReport
from smda.intel.IntelInstructionEscaper import IntelInstructionEscaper
from smda.SmdaConfig import SmdaConfig

LOG = logging.getLogger(__name__)
logging.disable(logging.CRITICAL)

CORPUS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "escaper_fingerprint_corpus.json")

# sha256 over the respective escaper output for every instruction of the frozen corpus.
# "escaped_representation" (mnemonic group + escaped operands) is the channel that feeds
# downstream signature computation and is guarded by SmdaConfig.ESCAPER_DOWNWARD_COMPATIBILITY,
# "escaped_binary" is the pic_hash channel guarded by the per-architecture
# *_PIC_HASH_ESCAPE_VERSION constants in smda.common.SmdaFunction, and "opcode_only" is the
# opc_hash channel.
EXPECTED_FINGERPRINTS = {
    "aarch64_elf": {
        "escaped_binary": "8b3e569cc81fb17a706de606d01181fa8d32f6dc4958ba44a49a3433bdd8a035",
        "escaped_representation": "606beb12e20995e59a55ef65d4e5e6e046ac58427903134eb618e39685574133",
        "masked_operands": "f2965263b5e436508d2997780c6e0b135d5bcdee7aee40525a5a3ef414eeb709",
        "opcode_only": "74387475dc40bef813df7735a1804ce4fb6d2b91910b5256f0e8104df90c402e",
    },
    "cil_pe": {
        "escaped_binary": "073b9604877c1321848d6a0f91bd04dc7e7b5d7e2539ae7eb47d1cdccf7a8c18",
        "escaped_representation": "519610569b665853cbbd8379a46a6f4527a55df57e89ff6bb8de3cb326bcb85c",
        "masked_operands": "8c7ab63f49bf1441913e383b7748889e333f56238c286ee1bcdc34f72957fff4",
        "opcode_only": "037acc73127c78051ff9705e9524ae04d653f33493f59dc7c004920da47f5e64",
    },
    "dalvik_dex": {
        "escaped_binary": "720b4086591ddad91768232c0c0507413418d9516f32f6d9a20653577d99350c",
        "escaped_representation": "e4100c0cec63b40815916abb0bb0e7b8e362df0d532753f7655b82242cb1f805",
        "masked_operands": "37d149b61d331a028da601dd2e07b7257b5966cdaee0da1c75b8c48137e4d7fa",
        "opcode_only": "ba75be6ba0e8857e836f01ccbf49a1d780580eb6fea445a3db0484b543f637d9",
    },
    "intel_32_dump": {
        "escaped_binary": "411d078204d18143a68dae40e18266881986de702d6dd92f373572aeda1b0f65",
        "escaped_representation": "c8e3db5b7226465d3707f9abcd2b9ee45556ce2bc269b3544e03dad4fc2ef15a",
        "masked_operands": "c9b053d79d67e5479020b8a9eaa64ecb9e0b0a3f8806af439347036e404772c9",
        "opcode_only": "897fc97e09a1c476e224cd735503fbdfd1d6b6931cb5c08c6c85eb1a8462457a",
    },
    "intel_32_pe": {
        "escaped_binary": "463a60875691546dea2930c68726827295ac1f7950adf8d95b7562f36b94d547",
        "escaped_representation": "d2a803fee81f638379a3147c283655dd50628814f57f543653a65b1c99f6669f",
        "masked_operands": "45031d1b5ba132b69bbf97ef0d1cc8f20abc05db85a3ccc438fa472c21ac6513",
        "opcode_only": "9f9ce99d34f897b14c65c78a69134e785631303fbabf3f6c523896cfc1377907",
    },
    "intel_64_elf": {
        "escaped_binary": "0c0aab35db2b7770536782469ae2dc643abb9a2e37de246880ea79a423fcd829",
        "escaped_representation": "8f71f8d4c80f9f66c072daf7d6cf5f758eb70b5506e0480450929b37deb2d46e",
        "masked_operands": "a6a3bf72542b32514a140bbe45a8efdae1f4a3970117f928d5b350b50fae3cbe",
        "opcode_only": "cd9864e3e36f677d30b2654c1a2a97b77ff3252ce3bbe0b111ba6dbd672062d2",
    },
    "intel_edge_cases": {
        "escaped_representation": "8912217474e20bf8a7fce2b51da61e90dc11830fa3a881f1164a214a14030075",
        "masked_operands": "8b45b771aa68942da8305923eef7defb8e05ecadf1e1017d6633590ebe39b9d0",
    },
}

TEXT_CHANNELS = ("escaped_representation", "masked_operands")
BYTE_CHANNELS = ("opcode_only", "escaped_binary")

CHANNEL_MARKERS = {
    "escaped_representation": "SmdaConfig.ESCAPER_DOWNWARD_COMPATIBILITY",
    "masked_operands": "SmdaConfig.ESCAPER_DOWNWARD_COMPATIBILITY",
    "opcode_only": "SmdaConfig.ESCAPER_DOWNWARD_COMPATIBILITY",
    "escaped_binary": "the architecture's *_PIC_HASH_ESCAPE_VERSION in smda.common.SmdaFunction",
}


def _load_corpus():
    with open(CORPUS_PATH) as f_json:
        return json.load(f_json)


def _build_instructions(group):
    """Rehydrate the stored tuples into instructions bound to a report of the stored architecture.

    The Intel escaper re-decodes an instruction through capstone for pointer references, which
    needs the architecture and bitness of the report the instruction came from.
    """
    report = SmdaReport()
    report.architecture = group["architecture"]
    report.bitness = group["bitness"]
    report.base_addr = group["base_addr"]
    report.binary_size = group["binary_size"]
    smda_function = SmdaFunction(smda_report=report)
    smda_function.offset = group["instructions"][0][0]
    return [SmdaInstruction(entry, smda_function=smda_function) for entry in group["instructions"]]


def _escape_channels(group, instructions):
    escaper = SmdaFunction.getInstructionEscaper(group["architecture"])
    lower_addr = group["base_addr"]
    upper_addr = lower_addr + group["binary_size"]
    # a text-only group carries no instruction bytes, so only the channels derived from the
    # instruction text are available for it
    channels = {name: hashlib.sha256() for name in TEXT_CHANNELS}
    if not group["text_only"]:
        channels.update({name: hashlib.sha256() for name in BYTE_CHANNELS})
    for instruction in instructions:
        representation = f"{instruction.getMnemonicGroup(escaper)}|{instruction.getEscapedOperands(escaper)}"
        channels["escaped_representation"].update(representation.encode("utf-8"))
        channels["masked_operands"].update(instruction.getMaskedOperands(escaper).encode("utf-8"))
        if group["text_only"]:
            continue
        channels["opcode_only"].update(instruction.getEscapedToOpcodeOnly(escaper).encode("utf-8"))
        channels["escaped_binary"].update(
            instruction.getEscapedBinary(
                escaper,
                escape_intraprocedural_jumps=True,
                lower_addr=lower_addr,
                upper_addr=upper_addr,
            ).encode("utf-8")
        )
    return {name: digest.hexdigest() for name, digest in channels.items()}


class EscaperFingerprintTestSuite(unittest.TestCase):
    """Guard the escaper output against unnoticed drift."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.corpus = _load_corpus()

    def testEscaperFingerprintsAreStable(self):
        self.assertEqual(sorted(EXPECTED_FINGERPRINTS), sorted(self.corpus))
        for group_name in sorted(self.corpus):
            group = self.corpus[group_name]
            fingerprints = _escape_channels(group, _build_instructions(group))
            self.assertEqual(sorted(EXPECTED_FINGERPRINTS[group_name]), sorted(fingerprints))
            for channel, digest in sorted(fingerprints.items()):
                self.assertEqual(
                    EXPECTED_FINGERPRINTS[group_name][channel],
                    digest,
                    f"escaper output changed for '{group_name}' on the '{channel}' channel. If the change is "
                    f"intended, bump {CHANNEL_MARKERS[channel]} to the release that carries it and update the "
                    f"digest here - downstream signatures derived with an older SMDA are stale without that bump.",
                )

    def testCompatibilityMarkersDoNotOutrunTheVersion(self):
        def as_tuple(version):
            return tuple(int(part) for part in version.split("."))

        version = as_tuple(SmdaConfig.VERSION)
        self.assertLessEqual(as_tuple(SmdaConfig.ESCAPER_DOWNWARD_COMPATIBILITY), version)
        for pic_hash_version in (
            AARCH64_PIC_HASH_ESCAPE_VERSION,
            CIL_PIC_HASH_ESCAPE_VERSION,
            DALVIK_PIC_HASH_ESCAPE_VERSION,
            INTEL_PIC_HASH_ESCAPE_VERSION,
        ):
            self.assertLessEqual(tuple(pic_hash_version), version)

    def testSegmentQualifiedMemoryOperandsEscapeAsPointers(self):
        # the classification corrected in 4.4.5: the far-pointer test fired on any operand
        # containing a colon and overwrote the pointer classification
        cases = [
            (("push", "dword ptr fs:[0]"), "PTR"),
            (("mov", "rax, qword ptr gs:[0x60]"), "REG, PTR"),
            (("rep stosd", "dword ptr es:[edi], eax"), "PTR, REG"),
            (("rep movsd", "dword ptr es:[edi], dword ptr [esi]"), "PTR, PTR"),
            # a far pointer carries no memory operand and stays a constant
            (("jmp", "0xcd:0x12345678"), "CONST"),
        ]
        for (mnemonic, operands), expected in cases:
            instruction = SmdaInstruction((0, "90", mnemonic, operands))
            self.assertEqual(expected, IntelInstructionEscaper.escapeOperands(instruction))

    def testAvx512RegistersEscapeAsVectorRegisters(self):
        cases = [
            (("vpaddd", "zmm16, zmm17, zmm18"), "XREG, XREG, XREG"),
            (("vmovaps", "zmm0 {k3} {z}, zmm1"), "XREG, XREG"),
            (("kmovw", "k0, k1"), "XREG, XREG"),
            (("vaddps", "zmm1, zmm2, dword ptr [rax] {1to16}"), "XREG, XREG, PTR"),
        ]
        for (mnemonic, operands), expected in cases:
            instruction = SmdaInstruction((0, "90", mnemonic, operands))
            self.assertEqual(expected, IntelInstructionEscaper.escapeOperands(instruction))

    def testMnemonicsAreGroupedWithTheirFamily(self):
        cases = [("movsq", "M"), ("cmpsq", "C"), ("xgetbv", "P"), ("rorx", "A"), ("pushaw", "S"), ("popaw", "S")]
        for mnemonic, expected_group in cases:
            self.assertEqual(expected_group, IntelInstructionEscaper.escapeMnemonic(mnemonic))


if __name__ == "__main__":
    unittest.main()
