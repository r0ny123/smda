class DisassemblyStatistics:
    num_functions = None
    num_recursive_functions = None
    num_leaf_functions = None
    num_basic_blocks = None
    num_instructions = None
    num_api_calls = None
    num_function_calls = None
    num_failed_functions = None
    num_failed_instructions = None
    connected_function_count = None
    connected_instruction_count = None
    rooted_function_count = None
    rooted_instruction_count = None
    rooted_mode = None
    _fields = (
        "num_functions",
        "num_recursive_functions",
        "num_leaf_functions",
        "num_basic_blocks",
        "num_instructions",
        "num_api_calls",
        "num_function_calls",
        "num_failed_functions",
        "num_failed_instructions",
        "connected_function_count",
        "connected_instruction_count",
        "rooted_function_count",
        "rooted_instruction_count",
    )

    def __init__(self, disassembly_result=None):
        if disassembly_result is not None:
            self.num_functions = len(disassembly_result.functions)
            self.num_recursive_functions = len(disassembly_result.recursive_functions)
            self.num_leaf_functions = len(disassembly_result.leaf_functions)
            self.num_basic_blocks = self._countBlocks(disassembly_result)
            self.num_instructions = self._countInstructions(disassembly_result)
            self.num_api_calls = self._countApiCalls(disassembly_result)
            self.num_function_calls = self._countFunctionCalls(disassembly_result)
            self.num_failed_functions = len(disassembly_result.failed_analysis_addr)
            self.num_failed_instructions = len(disassembly_result.errors)
            metrics = getattr(disassembly_result, "report_policy_metrics", None) or {}
            self.connected_function_count = metrics.get("connected_function_count", self.num_functions)
            self.connected_instruction_count = metrics.get("connected_instruction_count", self.num_instructions)
            self.rooted_function_count = metrics.get("rooted_function_count", self.num_functions)
            self.rooted_instruction_count = metrics.get("rooted_instruction_count", self.num_instructions)
            self.rooted_mode = metrics.get("rooted_mode", "all-instructions")

    def _countBlocks(self, disassembly_result):
        num_blocks = 0
        for _, blocks in disassembly_result.functions.items():
            num_blocks += len(blocks)
        return num_blocks

    def _countApiCalls(self, disassembly_result):
        return len(disassembly_result.getAllApiRefs())

    def _countInstructions(self, disassembly_result):
        num_ins = 0
        for function_offset in sorted(disassembly_result.functions):
            for block in disassembly_result.functions[function_offset]:
                num_ins += len(block)
        return num_ins

    def _countFunctionCalls(self, disassembly_result):
        num_calls = 0
        for function_start in disassembly_result.functions:
            if function_start in disassembly_result.code_refs_to:
                num_calls += len(disassembly_result.code_refs_to[function_start])
        return num_calls

    @classmethod
    def fromDict(cls, statistics_dict):
        statistics = cls(None)
        statistics.num_functions = statistics_dict["num_functions"]
        statistics.num_recursive_functions = statistics_dict["num_recursive_functions"]
        statistics.num_leaf_functions = statistics_dict["num_leaf_functions"]
        statistics.num_basic_blocks = statistics_dict["num_basic_blocks"]
        statistics.num_instructions = statistics_dict["num_instructions"]
        statistics.num_api_calls = statistics_dict["num_api_calls"]
        statistics.num_function_calls = statistics_dict["num_function_calls"]
        statistics.num_failed_functions = statistics_dict["num_failed_functions"]
        statistics.num_failed_instructions = statistics_dict["num_failed_instructions"]
        statistics.connected_function_count = statistics_dict.get("connected_function_count", statistics.num_functions)
        statistics.connected_instruction_count = statistics_dict.get(
            "connected_instruction_count", statistics.num_instructions
        )
        statistics.rooted_function_count = statistics_dict.get("rooted_function_count", statistics.num_functions)
        statistics.rooted_instruction_count = statistics_dict.get(
            "rooted_instruction_count", statistics.num_instructions
        )
        statistics.rooted_mode = statistics_dict.get("rooted_mode", "all-instructions")
        return statistics

    def toDict(self):
        return {
            "num_functions": self.num_functions,
            "num_recursive_functions": self.num_recursive_functions,
            "num_leaf_functions": self.num_leaf_functions,
            "num_basic_blocks": self.num_basic_blocks,
            "num_instructions": self.num_instructions,
            "num_api_calls": self.num_api_calls,
            "num_function_calls": self.num_function_calls,
            "num_failed_functions": self.num_failed_functions,
            "num_failed_instructions": self.num_failed_instructions,
            "connected_function_count": self.connected_function_count,
            "connected_instruction_count": self.connected_instruction_count,
            "rooted_function_count": self.rooted_function_count,
            "rooted_instruction_count": self.rooted_instruction_count,
            "rooted_mode": self.rooted_mode,
        }

    def _merge_rooted_mode(self, other):
        left = self.rooted_mode or "all-instructions"
        right = other.rooted_mode or "all-instructions"
        if left == right:
            return left
        return "mixed"

    def __add__(self, other):
        if not isinstance(other, DisassemblyStatistics):
            raise ValueError("Needs another DisassemblyStatistics to perform addition of values")
        result = DisassemblyStatistics()
        for field in self._fields:
            setattr(result, field, (getattr(self, field) or 0) + (getattr(other, field) or 0))
        result.rooted_mode = self._merge_rooted_mode(other)
        return result

    def __iadd__(self, other):
        if not isinstance(other, DisassemblyStatistics):
            raise ValueError("Needs another DisassemblyStatistics to perform addition of values")
        for field in self._fields:
            setattr(self, field, (getattr(self, field) or 0) + (getattr(other, field) or 0))
        self.rooted_mode = self._merge_rooted_mode(other)
        return self
