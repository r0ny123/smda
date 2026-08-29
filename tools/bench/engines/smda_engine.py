"""SMDA engine adapter: binary in, recovered function starts out."""

from __future__ import annotations

import os
import time
from typing import Dict, Optional, Set, Tuple

import smda
from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig


class SmdaEngine:
    name = "smda"

    def __init__(self, config: Optional[SmdaConfig] = None, timeout: Optional[int] = None) -> None:
        self.config = config or SmdaConfig()
        if timeout is not None:
            self.config.TIMEOUT = timeout
        self.version = self.config.VERSION

    def describe(self) -> Dict[str, object]:
        # the module path is recorded because a second checkout on PYTHONPATH is
        # how another tree gets measured, and nothing else in the result proves
        # which one actually ran
        return {
            "engine": self.name,
            "version": self.version,
            "timeout": self.config.TIMEOUT,
            "module": os.path.dirname(os.path.abspath(smda.__file__)),
            "config_overrides": self.nonDefaultConfig(),
        }

    def nonDefaultConfig(self) -> Dict[str, object]:
        """Every SmdaConfig setting this run does not take from the class default.

        A result that does not say which settings produced it cannot be compared with another,
        and the settings worth measuring are exactly the ones that are off by default.
        """
        changed = {}
        for name in dir(SmdaConfig):
            if not name.isupper():
                continue
            default = getattr(SmdaConfig, name)
            if isinstance(default, (bool, int, float, str)) and getattr(self.config, name) != default:
                changed[name] = getattr(self.config, name)
        return changed

    def run(self, path: str, base_addr: Optional[int] = None, bitness: Optional[int] = None) -> Tuple[Set[int], Dict]:
        disassembler = Disassembler(config=self.config)
        started = time.time()
        if base_addr is None:
            report = disassembler.disassembleFile(path)
        else:
            with open(path, "rb") as binary_file:
                buffer = binary_file.read()
            report = disassembler.disassembleBuffer(buffer, base_addr, bitness=bitness)
        elapsed = time.time() - started
        starts = {function.offset for function in report.getFunctions()}
        info = {
            "status": report.status,
            "seconds": elapsed,
            "smda_version": report.smda_version,
            "message": report.message if report.status != "ok" else "",
        }
        return starts, info
