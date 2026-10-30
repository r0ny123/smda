"""AArch64 capstone constants under one set of names for capstone 5 and 6.

capstone 6 renames the arm64 modules and constants to aarch64 (CS_ARCH_ARM64 ->
CS_ARCH_AARCH64, capstone.arm64_const -> capstone.aarch64_const, ARM64_* -> AARCH64_*,
ARM64_CC_INVALID -> AArch64CC_Invalid) and splits some operand classes. Names that only
exist on one side resolve to -1 on the other, so comparisons against them never match.
"""

import importlib

import capstone

if hasattr(capstone, "CS_ARCH_AARCH64"):
    _const = importlib.import_module("capstone.aarch64_const")
    _PREFIX = "AARCH64_"
    CS_ARCH_AARCH64 = int(capstone.CS_ARCH_AARCH64)
    CC_INVALID = int(_const.AArch64CC_Invalid)
else:
    _const = importlib.import_module("capstone.arm64_const")
    _PREFIX = "ARM64_"
    CS_ARCH_AARCH64 = int(capstone.CS_ARCH_ARM64)
    CC_INVALID = int(_const.ARM64_CC_INVALID)


def _get(name: str) -> int:
    return int(getattr(_const, _PREFIX + name, -1))


def _classes(*names: str) -> frozenset[int]:
    return frozenset(value for value in map(_get, names) if value != -1)


OP_REG = _get("OP_REG")
OP_IMM = _get("OP_IMM")
OP_FP = _get("OP_FP")
OP_MEM = _get("OP_MEM")
OP_REG_MRS = _get("OP_REG_MRS")
OP_REG_MSR = _get("OP_REG_MSR")
OP_SVCR = _get("OP_SVCR")
OP_CIMM = _get("OP_CIMM")
# each set holds the capstone 5 class and the capstone 6 classes it was split into
OP_MEM_CLASSES = _classes("OP_MEM", "OP_MEM_REG", "OP_MEM_IMM")
OP_SYS_CLASSES = _classes("OP_SYS", "OP_AT", "OP_DC", "OP_IC", "OP_TLBI", "OP_SYSALIAS", "OP_SYSREG", "OP_SYSIMM")
OP_PREFETCH_CLASSES = _classes("OP_PREFETCH", "OP_PRFM", "OP_RPRFM", "OP_SVEPRFM")
OP_BARRIER_CLASSES = _classes("OP_BARRIER", "OP_DB", "OP_DBNXS", "OP_ISB", "OP_TSB")
OP_PSTATE_CLASSES = _classes("OP_PSTATE", "OP_PSTATEIMM0_1", "OP_PSTATEIMM0_15")

SFT_LSL = _get("SFT_LSL")
EXT_INVALID = _get("EXT_INVALID")
EXT_SXTB = _get("EXT_SXTB")
EXT_SXTH = _get("EXT_SXTH")
EXT_SXTW = _get("EXT_SXTW")
EXT_SXTX = _get("EXT_SXTX")
