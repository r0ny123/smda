"""Build the .NET corpus: managed CIL assemblies and their native counterparts.

Two different problems share this family. A framework-dependent or self-contained
build ships **CIL**, and its ground truth is the assembly's own metadata table of
method bodies. A **NativeAOT** or ReadyToRun build ships machine code, so it lands
in the x86/ARM64 path with .NET metadata sitting beside it — a candidate source
that a native disassembler may or may not be reading. They are kept as separate
cells because scoring them together would average two unrelated questions.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from typing import Dict, List, Optional

from bench.builders.truth import elfFunctionStarts, writeTruth

PROGRAM = """using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Bench
{
    public interface IWorker
    {
        int Step(int value);
        int Fold(IEnumerable<int> values);
        string Describe();
        Task<int> StepAsync(int value);
        bool TryParse(string text, out int parsed);
    }

    public readonly struct Pair<TFirst, TSecond> where TFirst : IComparable<TFirst>
    {
        public readonly TFirst First;
        public readonly TSecond Second;
        public Pair(TFirst first, TSecond second) { First = first; Second = second; }
        public override string ToString() => $"({First}, {Second})";
        public int CompareFirst(Pair<TFirst, TSecond> other) => First.CompareTo(other.First);
    }

    public sealed class BenchException : Exception
    {
        public BenchException(string message, int code) : base(message) => Code = code;
        public int Code { get; }
    }

    public sealed class Worker0 : IWorker
    {
        private readonly int seed;
        public Worker0(int seed) => this.seed = seed;
        public int Step(int value) => (value * 3) ^ seed;
        public int Fold(IEnumerable<int> values) => values.Aggregate(seed, (a, b) => Step(a) + b);
        public string Describe() => $"Worker0(seed={seed})";
        public async Task<int> StepAsync(int value)
        {
            await Task.Yield();
            return Step(value);
        }
        public bool TryParse(string text, out int parsed) => int.TryParse(text, out parsed);
    }
    public sealed class Worker1 : IWorker
    {
        private readonly int seed;
        public Worker1(int seed) => this.seed = seed;
        public int Step(int value) => (value * 4) ^ seed;
        public int Fold(IEnumerable<int> values) => values.Aggregate(seed, (a, b) => Step(a) + b);
        public string Describe() => $"Worker1(seed={seed})";
        public async Task<int> StepAsync(int value)
        {
            await Task.Yield();
            return Step(value);
        }
        public bool TryParse(string text, out int parsed) => int.TryParse(text, out parsed);
    }
    public sealed class Worker2 : IWorker
    {
        private readonly int seed;
        public Worker2(int seed) => this.seed = seed;
        public int Step(int value) => (value * 5) ^ seed;
        public int Fold(IEnumerable<int> values) => values.Aggregate(seed, (a, b) => Step(a) + b);
        public string Describe() => $"Worker2(seed={seed})";
        public async Task<int> StepAsync(int value)
        {
            await Task.Yield();
            return Step(value);
        }
        public bool TryParse(string text, out int parsed) => int.TryParse(text, out parsed);
    }
    public sealed class Worker3 : IWorker
    {
        private readonly int seed;
        public Worker3(int seed) => this.seed = seed;
        public int Step(int value) => (value * 6) ^ seed;
        public int Fold(IEnumerable<int> values) => values.Aggregate(seed, (a, b) => Step(a) + b);
        public string Describe() => $"Worker3(seed={seed})";
        public async Task<int> StepAsync(int value)
        {
            await Task.Yield();
            return Step(value);
        }
        public bool TryParse(string text, out int parsed) => int.TryParse(text, out parsed);
    }
    public sealed class Worker4 : IWorker
    {
        private readonly int seed;
        public Worker4(int seed) => this.seed = seed;
        public int Step(int value) => (value * 7) ^ seed;
        public int Fold(IEnumerable<int> values) => values.Aggregate(seed, (a, b) => Step(a) + b);
        public string Describe() => $"Worker4(seed={seed})";
        public async Task<int> StepAsync(int value)
        {
            await Task.Yield();
            return Step(value);
        }
        public bool TryParse(string text, out int parsed) => int.TryParse(text, out parsed);
    }
    public sealed class Worker5 : IWorker
    {
        private readonly int seed;
        public Worker5(int seed) => this.seed = seed;
        public int Step(int value) => (value * 8) ^ seed;
        public int Fold(IEnumerable<int> values) => values.Aggregate(seed, (a, b) => Step(a) + b);
        public string Describe() => $"Worker5(seed={seed})";
        public async Task<int> StepAsync(int value)
        {
            await Task.Yield();
            return Step(value);
        }
        public bool TryParse(string text, out int parsed) => int.TryParse(text, out parsed);
    }
    public sealed class Worker6 : IWorker
    {
        private readonly int seed;
        public Worker6(int seed) => this.seed = seed;
        public int Step(int value) => (value * 9) ^ seed;
        public int Fold(IEnumerable<int> values) => values.Aggregate(seed, (a, b) => Step(a) + b);
        public string Describe() => $"Worker6(seed={seed})";
        public async Task<int> StepAsync(int value)
        {
            await Task.Yield();
            return Step(value);
        }
        public bool TryParse(string text, out int parsed) => int.TryParse(text, out parsed);
    }
    public sealed class Worker7 : IWorker
    {
        private readonly int seed;
        public Worker7(int seed) => this.seed = seed;
        public int Step(int value) => (value * 10) ^ seed;
        public int Fold(IEnumerable<int> values) => values.Aggregate(seed, (a, b) => Step(a) + b);
        public string Describe() => $"Worker7(seed={seed})";
        public async Task<int> StepAsync(int value)
        {
            await Task.Yield();
            return Step(value);
        }
        public bool TryParse(string text, out int parsed) => int.TryParse(text, out parsed);
    }
    public sealed class Worker8 : IWorker
    {
        private readonly int seed;
        public Worker8(int seed) => this.seed = seed;
        public int Step(int value) => (value * 11) ^ seed;
        public int Fold(IEnumerable<int> values) => values.Aggregate(seed, (a, b) => Step(a) + b);
        public string Describe() => $"Worker8(seed={seed})";
        public async Task<int> StepAsync(int value)
        {
            await Task.Yield();
            return Step(value);
        }
        public bool TryParse(string text, out int parsed) => int.TryParse(text, out parsed);
    }
    public sealed class Worker9 : IWorker
    {
        private readonly int seed;
        public Worker9(int seed) => this.seed = seed;
        public int Step(int value) => (value * 12) ^ seed;
        public int Fold(IEnumerable<int> values) => values.Aggregate(seed, (a, b) => Step(a) + b);
        public string Describe() => $"Worker9(seed={seed})";
        public async Task<int> StepAsync(int value)
        {
            await Task.Yield();
            return Step(value);
        }
        public bool TryParse(string text, out int parsed) => int.TryParse(text, out parsed);
    }
    public sealed class Worker10 : IWorker
    {
        private readonly int seed;
        public Worker10(int seed) => this.seed = seed;
        public int Step(int value) => (value * 13) ^ seed;
        public int Fold(IEnumerable<int> values) => values.Aggregate(seed, (a, b) => Step(a) + b);
        public string Describe() => $"Worker10(seed={seed})";
        public async Task<int> StepAsync(int value)
        {
            await Task.Yield();
            return Step(value);
        }
        public bool TryParse(string text, out int parsed) => int.TryParse(text, out parsed);
    }
    public sealed class Worker11 : IWorker
    {
        private readonly int seed;
        public Worker11(int seed) => this.seed = seed;
        public int Step(int value) => (value * 14) ^ seed;
        public int Fold(IEnumerable<int> values) => values.Aggregate(seed, (a, b) => Step(a) + b);
        public string Describe() => $"Worker11(seed={seed})";
        public async Task<int> StepAsync(int value)
        {
            await Task.Yield();
            return Step(value);
        }
        public bool TryParse(string text, out int parsed) => int.TryParse(text, out parsed);
    }
    public sealed class Worker12 : IWorker
    {
        private readonly int seed;
        public Worker12(int seed) => this.seed = seed;
        public int Step(int value) => (value * 15) ^ seed;
        public int Fold(IEnumerable<int> values) => values.Aggregate(seed, (a, b) => Step(a) + b);
        public string Describe() => $"Worker12(seed={seed})";
        public async Task<int> StepAsync(int value)
        {
            await Task.Yield();
            return Step(value);
        }
        public bool TryParse(string text, out int parsed) => int.TryParse(text, out parsed);
    }
    public sealed class Worker13 : IWorker
    {
        private readonly int seed;
        public Worker13(int seed) => this.seed = seed;
        public int Step(int value) => (value * 16) ^ seed;
        public int Fold(IEnumerable<int> values) => values.Aggregate(seed, (a, b) => Step(a) + b);
        public string Describe() => $"Worker13(seed={seed})";
        public async Task<int> StepAsync(int value)
        {
            await Task.Yield();
            return Step(value);
        }
        public bool TryParse(string text, out int parsed) => int.TryParse(text, out parsed);
    }
    public sealed class Worker14 : IWorker
    {
        private readonly int seed;
        public Worker14(int seed) => this.seed = seed;
        public int Step(int value) => (value * 17) ^ seed;
        public int Fold(IEnumerable<int> values) => values.Aggregate(seed, (a, b) => Step(a) + b);
        public string Describe() => $"Worker14(seed={seed})";
        public async Task<int> StepAsync(int value)
        {
            await Task.Yield();
            return Step(value);
        }
        public bool TryParse(string text, out int parsed) => int.TryParse(text, out parsed);
    }
    public sealed class Worker15 : IWorker
    {
        private readonly int seed;
        public Worker15(int seed) => this.seed = seed;
        public int Step(int value) => (value * 18) ^ seed;
        public int Fold(IEnumerable<int> values) => values.Aggregate(seed, (a, b) => Step(a) + b);
        public string Describe() => $"Worker15(seed={seed})";
        public async Task<int> StepAsync(int value)
        {
            await Task.Yield();
            return Step(value);
        }
        public bool TryParse(string text, out int parsed) => int.TryParse(text, out parsed);
    }
    public sealed class Worker16 : IWorker
    {
        private readonly int seed;
        public Worker16(int seed) => this.seed = seed;
        public int Step(int value) => (value * 19) ^ seed;
        public int Fold(IEnumerable<int> values) => values.Aggregate(seed, (a, b) => Step(a) + b);
        public string Describe() => $"Worker16(seed={seed})";
        public async Task<int> StepAsync(int value)
        {
            await Task.Yield();
            return Step(value);
        }
        public bool TryParse(string text, out int parsed) => int.TryParse(text, out parsed);
    }
    public sealed class Worker17 : IWorker
    {
        private readonly int seed;
        public Worker17(int seed) => this.seed = seed;
        public int Step(int value) => (value * 20) ^ seed;
        public int Fold(IEnumerable<int> values) => values.Aggregate(seed, (a, b) => Step(a) + b);
        public string Describe() => $"Worker17(seed={seed})";
        public async Task<int> StepAsync(int value)
        {
            await Task.Yield();
            return Step(value);
        }
        public bool TryParse(string text, out int parsed) => int.TryParse(text, out parsed);
    }
    public sealed class Worker18 : IWorker
    {
        private readonly int seed;
        public Worker18(int seed) => this.seed = seed;
        public int Step(int value) => (value * 21) ^ seed;
        public int Fold(IEnumerable<int> values) => values.Aggregate(seed, (a, b) => Step(a) + b);
        public string Describe() => $"Worker18(seed={seed})";
        public async Task<int> StepAsync(int value)
        {
            await Task.Yield();
            return Step(value);
        }
        public bool TryParse(string text, out int parsed) => int.TryParse(text, out parsed);
    }
    public sealed class Worker19 : IWorker
    {
        private readonly int seed;
        public Worker19(int seed) => this.seed = seed;
        public int Step(int value) => (value * 22) ^ seed;
        public int Fold(IEnumerable<int> values) => values.Aggregate(seed, (a, b) => Step(a) + b);
        public string Describe() => $"Worker19(seed={seed})";
        public async Task<int> StepAsync(int value)
        {
            await Task.Yield();
            return Step(value);
        }
        public bool TryParse(string text, out int parsed) => int.TryParse(text, out parsed);
    }
    public sealed class Worker20 : IWorker
    {
        private readonly int seed;
        public Worker20(int seed) => this.seed = seed;
        public int Step(int value) => (value * 23) ^ seed;
        public int Fold(IEnumerable<int> values) => values.Aggregate(seed, (a, b) => Step(a) + b);
        public string Describe() => $"Worker20(seed={seed})";
        public async Task<int> StepAsync(int value)
        {
            await Task.Yield();
            return Step(value);
        }
        public bool TryParse(string text, out int parsed) => int.TryParse(text, out parsed);
    }
    public sealed class Worker21 : IWorker
    {
        private readonly int seed;
        public Worker21(int seed) => this.seed = seed;
        public int Step(int value) => (value * 24) ^ seed;
        public int Fold(IEnumerable<int> values) => values.Aggregate(seed, (a, b) => Step(a) + b);
        public string Describe() => $"Worker21(seed={seed})";
        public async Task<int> StepAsync(int value)
        {
            await Task.Yield();
            return Step(value);
        }
        public bool TryParse(string text, out int parsed) => int.TryParse(text, out parsed);
    }
    public sealed class Worker22 : IWorker
    {
        private readonly int seed;
        public Worker22(int seed) => this.seed = seed;
        public int Step(int value) => (value * 25) ^ seed;
        public int Fold(IEnumerable<int> values) => values.Aggregate(seed, (a, b) => Step(a) + b);
        public string Describe() => $"Worker22(seed={seed})";
        public async Task<int> StepAsync(int value)
        {
            await Task.Yield();
            return Step(value);
        }
        public bool TryParse(string text, out int parsed) => int.TryParse(text, out parsed);
    }
    public sealed class Worker23 : IWorker
    {
        private readonly int seed;
        public Worker23(int seed) => this.seed = seed;
        public int Step(int value) => (value * 26) ^ seed;
        public int Fold(IEnumerable<int> values) => values.Aggregate(seed, (a, b) => Step(a) + b);
        public string Describe() => $"Worker23(seed={seed})";
        public async Task<int> StepAsync(int value)
        {
            await Task.Yield();
            return Step(value);
        }
        public bool TryParse(string text, out int parsed) => int.TryParse(text, out parsed);
    }
    public sealed class Worker24 : IWorker
    {
        private readonly int seed;
        public Worker24(int seed) => this.seed = seed;
        public int Step(int value) => (value * 27) ^ seed;
        public int Fold(IEnumerable<int> values) => values.Aggregate(seed, (a, b) => Step(a) + b);
        public string Describe() => $"Worker24(seed={seed})";
        public async Task<int> StepAsync(int value)
        {
            await Task.Yield();
            return Step(value);
        }
        public bool TryParse(string text, out int parsed) => int.TryParse(text, out parsed);
    }
    public sealed class Worker25 : IWorker
    {
        private readonly int seed;
        public Worker25(int seed) => this.seed = seed;
        public int Step(int value) => (value * 28) ^ seed;
        public int Fold(IEnumerable<int> values) => values.Aggregate(seed, (a, b) => Step(a) + b);
        public string Describe() => $"Worker25(seed={seed})";
        public async Task<int> StepAsync(int value)
        {
            await Task.Yield();
            return Step(value);
        }
        public bool TryParse(string text, out int parsed) => int.TryParse(text, out parsed);
    }
    public sealed class Worker26 : IWorker
    {
        private readonly int seed;
        public Worker26(int seed) => this.seed = seed;
        public int Step(int value) => (value * 29) ^ seed;
        public int Fold(IEnumerable<int> values) => values.Aggregate(seed, (a, b) => Step(a) + b);
        public string Describe() => $"Worker26(seed={seed})";
        public async Task<int> StepAsync(int value)
        {
            await Task.Yield();
            return Step(value);
        }
        public bool TryParse(string text, out int parsed) => int.TryParse(text, out parsed);
    }
    public sealed class Worker27 : IWorker
    {
        private readonly int seed;
        public Worker27(int seed) => this.seed = seed;
        public int Step(int value) => (value * 30) ^ seed;
        public int Fold(IEnumerable<int> values) => values.Aggregate(seed, (a, b) => Step(a) + b);
        public string Describe() => $"Worker27(seed={seed})";
        public async Task<int> StepAsync(int value)
        {
            await Task.Yield();
            return Step(value);
        }
        public bool TryParse(string text, out int parsed) => int.TryParse(text, out parsed);
    }
    public sealed class Worker28 : IWorker
    {
        private readonly int seed;
        public Worker28(int seed) => this.seed = seed;
        public int Step(int value) => (value * 31) ^ seed;
        public int Fold(IEnumerable<int> values) => values.Aggregate(seed, (a, b) => Step(a) + b);
        public string Describe() => $"Worker28(seed={seed})";
        public async Task<int> StepAsync(int value)
        {
            await Task.Yield();
            return Step(value);
        }
        public bool TryParse(string text, out int parsed) => int.TryParse(text, out parsed);
    }
    public sealed class Worker29 : IWorker
    {
        private readonly int seed;
        public Worker29(int seed) => this.seed = seed;
        public int Step(int value) => (value * 32) ^ seed;
        public int Fold(IEnumerable<int> values) => values.Aggregate(seed, (a, b) => Step(a) + b);
        public string Describe() => $"Worker29(seed={seed})";
        public async Task<int> StepAsync(int value)
        {
            await Task.Yield();
            return Step(value);
        }
        public bool TryParse(string text, out int parsed) => int.TryParse(text, out parsed);
    }
    public sealed class Worker30 : IWorker
    {
        private readonly int seed;
        public Worker30(int seed) => this.seed = seed;
        public int Step(int value) => (value * 33) ^ seed;
        public int Fold(IEnumerable<int> values) => values.Aggregate(seed, (a, b) => Step(a) + b);
        public string Describe() => $"Worker30(seed={seed})";
        public async Task<int> StepAsync(int value)
        {
            await Task.Yield();
            return Step(value);
        }
        public bool TryParse(string text, out int parsed) => int.TryParse(text, out parsed);
    }
    public sealed class Worker31 : IWorker
    {
        private readonly int seed;
        public Worker31(int seed) => this.seed = seed;
        public int Step(int value) => (value * 34) ^ seed;
        public int Fold(IEnumerable<int> values) => values.Aggregate(seed, (a, b) => Step(a) + b);
        public string Describe() => $"Worker31(seed={seed})";
        public async Task<int> StepAsync(int value)
        {
            await Task.Yield();
            return Step(value);
        }
        public bool TryParse(string text, out int parsed) => int.TryParse(text, out parsed);
    }
    public sealed class Worker32 : IWorker
    {
        private readonly int seed;
        public Worker32(int seed) => this.seed = seed;
        public int Step(int value) => (value * 35) ^ seed;
        public int Fold(IEnumerable<int> values) => values.Aggregate(seed, (a, b) => Step(a) + b);
        public string Describe() => $"Worker32(seed={seed})";
        public async Task<int> StepAsync(int value)
        {
            await Task.Yield();
            return Step(value);
        }
        public bool TryParse(string text, out int parsed) => int.TryParse(text, out parsed);
    }
    public sealed class Worker33 : IWorker
    {
        private readonly int seed;
        public Worker33(int seed) => this.seed = seed;
        public int Step(int value) => (value * 36) ^ seed;
        public int Fold(IEnumerable<int> values) => values.Aggregate(seed, (a, b) => Step(a) + b);
        public string Describe() => $"Worker33(seed={seed})";
        public async Task<int> StepAsync(int value)
        {
            await Task.Yield();
            return Step(value);
        }
        public bool TryParse(string text, out int parsed) => int.TryParse(text, out parsed);
    }
    public sealed class Worker34 : IWorker
    {
        private readonly int seed;
        public Worker34(int seed) => this.seed = seed;
        public int Step(int value) => (value * 37) ^ seed;
        public int Fold(IEnumerable<int> values) => values.Aggregate(seed, (a, b) => Step(a) + b);
        public string Describe() => $"Worker34(seed={seed})";
        public async Task<int> StepAsync(int value)
        {
            await Task.Yield();
            return Step(value);
        }
        public bool TryParse(string text, out int parsed) => int.TryParse(text, out parsed);
    }
    public sealed class Worker35 : IWorker
    {
        private readonly int seed;
        public Worker35(int seed) => this.seed = seed;
        public int Step(int value) => (value * 38) ^ seed;
        public int Fold(IEnumerable<int> values) => values.Aggregate(seed, (a, b) => Step(a) + b);
        public string Describe() => $"Worker35(seed={seed})";
        public async Task<int> StepAsync(int value)
        {
            await Task.Yield();
            return Step(value);
        }
        public bool TryParse(string text, out int parsed) => int.TryParse(text, out parsed);
    }
    public sealed class Worker36 : IWorker
    {
        private readonly int seed;
        public Worker36(int seed) => this.seed = seed;
        public int Step(int value) => (value * 39) ^ seed;
        public int Fold(IEnumerable<int> values) => values.Aggregate(seed, (a, b) => Step(a) + b);
        public string Describe() => $"Worker36(seed={seed})";
        public async Task<int> StepAsync(int value)
        {
            await Task.Yield();
            return Step(value);
        }
        public bool TryParse(string text, out int parsed) => int.TryParse(text, out parsed);
    }
    public sealed class Worker37 : IWorker
    {
        private readonly int seed;
        public Worker37(int seed) => this.seed = seed;
        public int Step(int value) => (value * 40) ^ seed;
        public int Fold(IEnumerable<int> values) => values.Aggregate(seed, (a, b) => Step(a) + b);
        public string Describe() => $"Worker37(seed={seed})";
        public async Task<int> StepAsync(int value)
        {
            await Task.Yield();
            return Step(value);
        }
        public bool TryParse(string text, out int parsed) => int.TryParse(text, out parsed);
    }
    public sealed class Worker38 : IWorker
    {
        private readonly int seed;
        public Worker38(int seed) => this.seed = seed;
        public int Step(int value) => (value * 41) ^ seed;
        public int Fold(IEnumerable<int> values) => values.Aggregate(seed, (a, b) => Step(a) + b);
        public string Describe() => $"Worker38(seed={seed})";
        public async Task<int> StepAsync(int value)
        {
            await Task.Yield();
            return Step(value);
        }
        public bool TryParse(string text, out int parsed) => int.TryParse(text, out parsed);
    }
    public sealed class Worker39 : IWorker
    {
        private readonly int seed;
        public Worker39(int seed) => this.seed = seed;
        public int Step(int value) => (value * 42) ^ seed;
        public int Fold(IEnumerable<int> values) => values.Aggregate(seed, (a, b) => Step(a) + b);
        public string Describe() => $"Worker39(seed={seed})";
        public async Task<int> StepAsync(int value)
        {
            await Task.Yield();
            return Step(value);
        }
        public bool TryParse(string text, out int parsed) => int.TryParse(text, out parsed);
    }
    public sealed class Worker40 : IWorker
    {
        private readonly int seed;
        public Worker40(int seed) => this.seed = seed;
        public int Step(int value) => (value * 43) ^ seed;
        public int Fold(IEnumerable<int> values) => values.Aggregate(seed, (a, b) => Step(a) + b);
        public string Describe() => $"Worker40(seed={seed})";
        public async Task<int> StepAsync(int value)
        {
            await Task.Yield();
            return Step(value);
        }
        public bool TryParse(string text, out int parsed) => int.TryParse(text, out parsed);
    }
    public sealed class Worker41 : IWorker
    {
        private readonly int seed;
        public Worker41(int seed) => this.seed = seed;
        public int Step(int value) => (value * 44) ^ seed;
        public int Fold(IEnumerable<int> values) => values.Aggregate(seed, (a, b) => Step(a) + b);
        public string Describe() => $"Worker41(seed={seed})";
        public async Task<int> StepAsync(int value)
        {
            await Task.Yield();
            return Step(value);
        }
        public bool TryParse(string text, out int parsed) => int.TryParse(text, out parsed);
    }
    public sealed class Worker42 : IWorker
    {
        private readonly int seed;
        public Worker42(int seed) => this.seed = seed;
        public int Step(int value) => (value * 45) ^ seed;
        public int Fold(IEnumerable<int> values) => values.Aggregate(seed, (a, b) => Step(a) + b);
        public string Describe() => $"Worker42(seed={seed})";
        public async Task<int> StepAsync(int value)
        {
            await Task.Yield();
            return Step(value);
        }
        public bool TryParse(string text, out int parsed) => int.TryParse(text, out parsed);
    }
    public sealed class Worker43 : IWorker
    {
        private readonly int seed;
        public Worker43(int seed) => this.seed = seed;
        public int Step(int value) => (value * 46) ^ seed;
        public int Fold(IEnumerable<int> values) => values.Aggregate(seed, (a, b) => Step(a) + b);
        public string Describe() => $"Worker43(seed={seed})";
        public async Task<int> StepAsync(int value)
        {
            await Task.Yield();
            return Step(value);
        }
        public bool TryParse(string text, out int parsed) => int.TryParse(text, out parsed);
    }
    public sealed class Worker44 : IWorker
    {
        private readonly int seed;
        public Worker44(int seed) => this.seed = seed;
        public int Step(int value) => (value * 47) ^ seed;
        public int Fold(IEnumerable<int> values) => values.Aggregate(seed, (a, b) => Step(a) + b);
        public string Describe() => $"Worker44(seed={seed})";
        public async Task<int> StepAsync(int value)
        {
            await Task.Yield();
            return Step(value);
        }
        public bool TryParse(string text, out int parsed) => int.TryParse(text, out parsed);
    }
    public sealed class Worker45 : IWorker
    {
        private readonly int seed;
        public Worker45(int seed) => this.seed = seed;
        public int Step(int value) => (value * 48) ^ seed;
        public int Fold(IEnumerable<int> values) => values.Aggregate(seed, (a, b) => Step(a) + b);
        public string Describe() => $"Worker45(seed={seed})";
        public async Task<int> StepAsync(int value)
        {
            await Task.Yield();
            return Step(value);
        }
        public bool TryParse(string text, out int parsed) => int.TryParse(text, out parsed);
    }
    public sealed class Worker46 : IWorker
    {
        private readonly int seed;
        public Worker46(int seed) => this.seed = seed;
        public int Step(int value) => (value * 49) ^ seed;
        public int Fold(IEnumerable<int> values) => values.Aggregate(seed, (a, b) => Step(a) + b);
        public string Describe() => $"Worker46(seed={seed})";
        public async Task<int> StepAsync(int value)
        {
            await Task.Yield();
            return Step(value);
        }
        public bool TryParse(string text, out int parsed) => int.TryParse(text, out parsed);
    }
    public sealed class Worker47 : IWorker
    {
        private readonly int seed;
        public Worker47(int seed) => this.seed = seed;
        public int Step(int value) => (value * 50) ^ seed;
        public int Fold(IEnumerable<int> values) => values.Aggregate(seed, (a, b) => Step(a) + b);
        public string Describe() => $"Worker47(seed={seed})";
        public async Task<int> StepAsync(int value)
        {
            await Task.Yield();
            return Step(value);
        }
        public bool TryParse(string text, out int parsed) => int.TryParse(text, out parsed);
    }
    public sealed class Worker48 : IWorker
    {
        private readonly int seed;
        public Worker48(int seed) => this.seed = seed;
        public int Step(int value) => (value * 51) ^ seed;
        public int Fold(IEnumerable<int> values) => values.Aggregate(seed, (a, b) => Step(a) + b);
        public string Describe() => $"Worker48(seed={seed})";
        public async Task<int> StepAsync(int value)
        {
            await Task.Yield();
            return Step(value);
        }
        public bool TryParse(string text, out int parsed) => int.TryParse(text, out parsed);
    }
    public sealed class Worker49 : IWorker
    {
        private readonly int seed;
        public Worker49(int seed) => this.seed = seed;
        public int Step(int value) => (value * 52) ^ seed;
        public int Fold(IEnumerable<int> values) => values.Aggregate(seed, (a, b) => Step(a) + b);
        public string Describe() => $"Worker49(seed={seed})";
        public async Task<int> StepAsync(int value)
        {
            await Task.Yield();
            return Step(value);
        }
        public bool TryParse(string text, out int parsed) => int.TryParse(text, out parsed);
    }
    public sealed class Worker50 : IWorker
    {
        private readonly int seed;
        public Worker50(int seed) => this.seed = seed;
        public int Step(int value) => (value * 53) ^ seed;
        public int Fold(IEnumerable<int> values) => values.Aggregate(seed, (a, b) => Step(a) + b);
        public string Describe() => $"Worker50(seed={seed})";
        public async Task<int> StepAsync(int value)
        {
            await Task.Yield();
            return Step(value);
        }
        public bool TryParse(string text, out int parsed) => int.TryParse(text, out parsed);
    }
    public sealed class Worker51 : IWorker
    {
        private readonly int seed;
        public Worker51(int seed) => this.seed = seed;
        public int Step(int value) => (value * 54) ^ seed;
        public int Fold(IEnumerable<int> values) => values.Aggregate(seed, (a, b) => Step(a) + b);
        public string Describe() => $"Worker51(seed={seed})";
        public async Task<int> StepAsync(int value)
        {
            await Task.Yield();
            return Step(value);
        }
        public bool TryParse(string text, out int parsed) => int.TryParse(text, out parsed);
    }
    public sealed class Worker52 : IWorker
    {
        private readonly int seed;
        public Worker52(int seed) => this.seed = seed;
        public int Step(int value) => (value * 55) ^ seed;
        public int Fold(IEnumerable<int> values) => values.Aggregate(seed, (a, b) => Step(a) + b);
        public string Describe() => $"Worker52(seed={seed})";
        public async Task<int> StepAsync(int value)
        {
            await Task.Yield();
            return Step(value);
        }
        public bool TryParse(string text, out int parsed) => int.TryParse(text, out parsed);
    }
    public sealed class Worker53 : IWorker
    {
        private readonly int seed;
        public Worker53(int seed) => this.seed = seed;
        public int Step(int value) => (value * 56) ^ seed;
        public int Fold(IEnumerable<int> values) => values.Aggregate(seed, (a, b) => Step(a) + b);
        public string Describe() => $"Worker53(seed={seed})";
        public async Task<int> StepAsync(int value)
        {
            await Task.Yield();
            return Step(value);
        }
        public bool TryParse(string text, out int parsed) => int.TryParse(text, out parsed);
    }
    public sealed class Worker54 : IWorker
    {
        private readonly int seed;
        public Worker54(int seed) => this.seed = seed;
        public int Step(int value) => (value * 57) ^ seed;
        public int Fold(IEnumerable<int> values) => values.Aggregate(seed, (a, b) => Step(a) + b);
        public string Describe() => $"Worker54(seed={seed})";
        public async Task<int> StepAsync(int value)
        {
            await Task.Yield();
            return Step(value);
        }
        public bool TryParse(string text, out int parsed) => int.TryParse(text, out parsed);
    }
    public sealed class Worker55 : IWorker
    {
        private readonly int seed;
        public Worker55(int seed) => this.seed = seed;
        public int Step(int value) => (value * 58) ^ seed;
        public int Fold(IEnumerable<int> values) => values.Aggregate(seed, (a, b) => Step(a) + b);
        public string Describe() => $"Worker55(seed={seed})";
        public async Task<int> StepAsync(int value)
        {
            await Task.Yield();
            return Step(value);
        }
        public bool TryParse(string text, out int parsed) => int.TryParse(text, out parsed);
    }
    public sealed class Worker56 : IWorker
    {
        private readonly int seed;
        public Worker56(int seed) => this.seed = seed;
        public int Step(int value) => (value * 59) ^ seed;
        public int Fold(IEnumerable<int> values) => values.Aggregate(seed, (a, b) => Step(a) + b);
        public string Describe() => $"Worker56(seed={seed})";
        public async Task<int> StepAsync(int value)
        {
            await Task.Yield();
            return Step(value);
        }
        public bool TryParse(string text, out int parsed) => int.TryParse(text, out parsed);
    }
    public sealed class Worker57 : IWorker
    {
        private readonly int seed;
        public Worker57(int seed) => this.seed = seed;
        public int Step(int value) => (value * 60) ^ seed;
        public int Fold(IEnumerable<int> values) => values.Aggregate(seed, (a, b) => Step(a) + b);
        public string Describe() => $"Worker57(seed={seed})";
        public async Task<int> StepAsync(int value)
        {
            await Task.Yield();
            return Step(value);
        }
        public bool TryParse(string text, out int parsed) => int.TryParse(text, out parsed);
    }
    public sealed class Worker58 : IWorker
    {
        private readonly int seed;
        public Worker58(int seed) => this.seed = seed;
        public int Step(int value) => (value * 61) ^ seed;
        public int Fold(IEnumerable<int> values) => values.Aggregate(seed, (a, b) => Step(a) + b);
        public string Describe() => $"Worker58(seed={seed})";
        public async Task<int> StepAsync(int value)
        {
            await Task.Yield();
            return Step(value);
        }
        public bool TryParse(string text, out int parsed) => int.TryParse(text, out parsed);
    }
    public sealed class Worker59 : IWorker
    {
        private readonly int seed;
        public Worker59(int seed) => this.seed = seed;
        public int Step(int value) => (value * 62) ^ seed;
        public int Fold(IEnumerable<int> values) => values.Aggregate(seed, (a, b) => Step(a) + b);
        public string Describe() => $"Worker59(seed={seed})";
        public async Task<int> StepAsync(int value)
        {
            await Task.Yield();
            return Step(value);
        }
        public bool TryParse(string text, out int parsed) => int.TryParse(text, out parsed);
    }

    public static class Pipeline
    {
        public static IEnumerable<T> Sorted<T>(IEnumerable<T> source) where T : IComparable<T>
        {
            var buffer = source.ToList();
            buffer.Sort();
            return buffer;
        }

        public static string Join(IEnumerable<string> parts)
        {
            var builder = new StringBuilder();
            foreach (var part in parts)
            {
                builder.Append(part).Append(';');
            }
            return builder.ToString();
        }

        public static int Guarded(Func<int> body, int fallback)
        {
            try
            {
                return body();
            }
            catch (BenchException failure)
            {
                return failure.Code;
            }
            catch (Exception)
            {
                return fallback;
            }
            finally
            {
                GC.KeepAlive(body);
            }
        }
    }

    public static class Program
    {
        private static IEnumerable<IWorker> Workers()
        {
            yield return new Worker0(0 * 31);
            yield return new Worker1(1 * 31);
            yield return new Worker2(2 * 31);
            yield return new Worker3(3 * 31);
            yield return new Worker4(4 * 31);
            yield return new Worker5(5 * 31);
            yield return new Worker6(6 * 31);
            yield return new Worker7(7 * 31);
            yield return new Worker8(8 * 31);
            yield return new Worker9(9 * 31);
            yield return new Worker10(10 * 31);
            yield return new Worker11(11 * 31);
            yield return new Worker12(12 * 31);
            yield return new Worker13(13 * 31);
            yield return new Worker14(14 * 31);
            yield return new Worker15(15 * 31);
            yield return new Worker16(16 * 31);
            yield return new Worker17(17 * 31);
            yield return new Worker18(18 * 31);
            yield return new Worker19(19 * 31);
            yield return new Worker20(20 * 31);
            yield return new Worker21(21 * 31);
            yield return new Worker22(22 * 31);
            yield return new Worker23(23 * 31);
            yield return new Worker24(24 * 31);
            yield return new Worker25(25 * 31);
            yield return new Worker26(26 * 31);
            yield return new Worker27(27 * 31);
            yield return new Worker28(28 * 31);
            yield return new Worker29(29 * 31);
            yield return new Worker30(30 * 31);
            yield return new Worker31(31 * 31);
            yield return new Worker32(32 * 31);
            yield return new Worker33(33 * 31);
            yield return new Worker34(34 * 31);
            yield return new Worker35(35 * 31);
            yield return new Worker36(36 * 31);
            yield return new Worker37(37 * 31);
            yield return new Worker38(38 * 31);
            yield return new Worker39(39 * 31);
            yield return new Worker40(40 * 31);
            yield return new Worker41(41 * 31);
            yield return new Worker42(42 * 31);
            yield return new Worker43(43 * 31);
            yield return new Worker44(44 * 31);
            yield return new Worker45(45 * 31);
            yield return new Worker46(46 * 31);
            yield return new Worker47(47 * 31);
            yield return new Worker48(48 * 31);
            yield return new Worker49(49 * 31);
            yield return new Worker50(50 * 31);
            yield return new Worker51(51 * 31);
            yield return new Worker52(52 * 31);
            yield return new Worker53(53 * 31);
            yield return new Worker54(54 * 31);
            yield return new Worker55(55 * 31);
            yield return new Worker56(56 * 31);
            yield return new Worker57(57 * 31);
            yield return new Worker58(58 * 31);
            yield return new Worker59(59 * 31);
        }

        public static int Main(string[] args)
        {
            var workers = Workers().ToList();
            var values = Enumerable.Range(1, 32).ToList();
            var folded = workers.Select(worker => worker.Fold(values)).ToArray();
            var described = Pipeline.Sorted(workers.Select(worker => worker.Describe()));
            var joined = Pipeline.Join(described);
            var guarded = Pipeline.Guarded(() => throw new BenchException("expected", 7), -1);
            var pair = new Pair<int, string>(folded.Length, joined.Length.ToString());
            var waited = workers[0].StepAsync(args.Length).GetAwaiter().GetResult();
            Console.WriteLine($"{folded.Sum()} {guarded} {pair} {waited}");
            return 0;
        }
    }
}
"""

PROJECT = """<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net8.0</TargetFramework>
    <Nullable>disable</Nullable>
    <ImplicitUsings>disable</ImplicitUsings>
    <AssemblyName>bench</AssemblyName>
    <RootNamespace>Bench</RootNamespace>
    <InvariantGlobalization>true</InvariantGlobalization>
    <SatelliteResourceLanguages>en</SatelliteResourceLanguages>
  </PropertyGroup>
</Project>
"""

#: (label, publish arguments, which artifact to score)
MODES = [
    ("framework-dependent", ["-c", "Release"], "cil"),
    ("self-contained", ["-c", "Release", "-r", "linux-x64", "--self-contained", "true"], "cil"),
    (
        "readytorun",
        ["-c", "Release", "-r", "linux-x64", "--self-contained", "true", "-p:PublishReadyToRun=true"],
        "cil",
    ),
    (
        "single-file",
        ["-c", "Release", "-r", "linux-x64", "--self-contained", "true", "-p:PublishSingleFile=true"],
        "cil",
    ),
    ("nativeaot", ["-c", "Release", "-r", "linux-x64", "-p:PublishAot=true"], "native"),
]


def cilMethodStarts(path: str) -> Dict[str, object]:
    """Method-body starts from an assembly's metadata, in the CIL backend's own space.

    A managed method's address is a **file offset**, not a virtual address: the CIL
    backend walks method bodies by offset, so the truth has to be stated the same
    way or the two describe different things. An abstract, extern or
    runtime-implemented method has RVA 0, no body in the file, and is not a
    function anything could detect.
    """
    import dnfile

    assembly = dnfile.dnPE(path)
    if assembly.net is None:
        raise RuntimeError(f"not a managed assembly: {path}")
    table = assembly.net.mdtables.MethodDef
    if table is None:
        raise RuntimeError(f"assembly has no MethodDef table: {path}")
    starts = set()
    declared = 0
    for row in table.rows:
        if not row.Rva:
            continue
        declared += 1
        starts.add(assembly.get_offset_from_rva(row.Rva))
    return {
        "starts": sorted(starts),
        "plt": [],
        "bitness": 32,
        "declared_bodies": declared,
        "address_space": "file_offset",
        "source": "dnfile MethodDef.Rva mapped to file offset",
    }


def _writeProject(work_dir: str) -> str:
    project_dir = os.path.join(work_dir, "bench")
    os.makedirs(project_dir, exist_ok=True)
    with open(os.path.join(project_dir, "Program.cs"), "w", encoding="utf-8") as source:
        source.write(PROGRAM)
    with open(os.path.join(project_dir, "bench.csproj"), "w", encoding="utf-8") as project:
        project.write(PROJECT)
    return project_dir


def _findArtifact(publish_dir: str, kind: str) -> Optional[str]:
    if kind == "native":
        candidate = os.path.join(publish_dir, "bench")
        return candidate if os.path.isfile(candidate) else None
    candidate = os.path.join(publish_dir, "bench.dll")
    return candidate if os.path.isfile(candidate) else None


def _truthArtifact(artifact: str, kind: str) -> str:
    """Where the symbols live, which is not always where the code does.

    A NativeAOT publish emits the stripped image beside a `.dbg` companion holding
    the symbol table. Measuring the image against its own (absent) symbols would
    report an empty corpus; measuring it against the companion is the same code.
    """
    companion = artifact + ".dbg"
    if kind == "native" and os.path.isfile(companion):
        return companion
    return artifact


def build(out_dir: str, work_dir: str, dotnet_root: str = "") -> Dict[str, object]:
    binary_dir = os.path.join(out_dir, "binary")
    truth_dir = os.path.join(out_dir, "truth")
    os.makedirs(work_dir, exist_ok=True)
    os.makedirs(binary_dir, exist_ok=True)
    dotnet = os.path.join(dotnet_root, "dotnet") if dotnet_root else shutil.which("dotnet")
    cells: List[Dict[str, object]] = []
    if not dotnet or not os.path.isfile(dotnet):
        manifest = {"family": "dotnet", "cells": [{"status": "sdk_unavailable"}], "ok": 0, "failed": 1}
        with open(os.path.join(out_dir, "manifest.json"), "w", encoding="utf-8") as manifest_file:
            json.dump(manifest, manifest_file, indent=1, sort_keys=True)
        return manifest
    project_dir = _writeProject(work_dir)
    environment = {
        **os.environ,
        "DOTNET_CLI_TELEMETRY_OPTOUT": "1",
        "DOTNET_NOLOGO": "1",
        "DOTNET_ROOT": dotnet_root or os.path.dirname(dotnet),
    }
    for label, arguments, kind in MODES:
        publish_dir = os.path.join(work_dir, "publish", label)
        shutil.rmtree(publish_dir, ignore_errors=True)
        command = [dotnet, "publish", *arguments, "-o", publish_dir]
        completed = subprocess.run(
            command, cwd=project_dir, capture_output=True, text=True, timeout=2400, env=environment
        )
        record = {"mode": label, "kind": kind}
        if completed.returncode != 0:
            record.update({"status": "publish_failed", "error": (completed.stdout + completed.stderr)[-600:]})
            cells.append(record)
            continue
        artifact = _findArtifact(publish_dir, kind)
        if artifact is None:
            reason = "no managed assembly on disk"
            if label == "single-file":
                reason = "the assembly is embedded in the apphost bundle, which nothing here unpacks"
            record.update({"status": "artifact_missing", "publish_dir": publish_dir, "reason": reason})
            cells.append(record)
            continue
        name = f"bench_{label}"
        truth_source_path = _truthArtifact(artifact, kind)
        try:
            truth = cilMethodStarts(artifact) if kind == "cil" else elfFunctionStarts(truth_source_path)
        except (RuntimeError, OSError, ImportError) as failure:
            record.update({"status": "truth_failed", "error": str(failure)[:300]})
            cells.append(record)
            continue
        if not truth["starts"]:
            record.update({"status": "truth_empty"})
            cells.append(record)
            continue
        measured = os.path.join(binary_dir, name)
        shutil.copyfile(artifact, measured)
        if kind == "native":
            subprocess.run(["strip", measured], capture_output=True, text=True)
        writeTruth(
            truth_dir,
            name,
            list(truth["starts"]),
            {
                "plt": truth.get("plt", []),
                "bitness": truth.get("bitness", 64),
                "kind": kind,
                "mode": label,
                "address_space": truth.get("address_space", "virtual"),
                "truth_source": truth["source"],
                "truth_from": os.path.basename(truth_source_path),
            },
        )
        record.update(
            {"status": "ok", "name": name, "truth_functions": len(truth["starts"]), "size": os.path.getsize(measured)}
        )
        cells.append(record)
    manifest = {
        "family": "dotnet",
        "sdk_version": subprocess.run(
            [dotnet, "--version"], capture_output=True, text=True, env=environment
        ).stdout.strip(),
        "cells": cells,
        "ok": sum(1 for cell in cells if cell.get("status") == "ok"),
        "failed": sum(1 for cell in cells if cell.get("status") != "ok"),
    }
    with open(os.path.join(out_dir, "manifest.json"), "w", encoding="utf-8") as manifest_file:
        json.dump(manifest, manifest_file, indent=1, sort_keys=True)
    return manifest
