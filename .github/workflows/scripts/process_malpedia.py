import argparse
import json
import logging
import os
import re
import struct
import sys
import traceback
from multiprocessing import Pool, cpu_count

import tqdm

from smda.Disassembler import Disassembler

dump_file_pattern = re.compile("dump7?_0x[0-9a-fA-F]{8,16}")
unpacked_file_pattern = re.compile("_unpacked(_x64)?$")

logger = logging.getLogger("smda-multithreaded")


def get_word(buffer, start):
    return _get_binary_data(buffer, start, 2)


def get_dword(buffer, start):
    return _get_binary_data(buffer, start, 4)


def _get_binary_data(buffer, start, length):
    if length not in _unsigned_unpack_formats:
        raise RuntimeError("Unsupported data length")

    return struct.unpack(_unsigned_unpack_formats[length], buffer[start : start + length])[0]


_unsigned_unpack_formats = {2: "H", 4: "I", 8: "Q"}


def get_pe_offset(content):
    if len(content) >= 0x40:
        pe_offset = get_word(content, 0x3C)
        return pe_offset
    raise RuntimeError("Buffer too small to extract PE offset (< 0x40)")


def check_bitness(content):
    bitness = None
    pe_offset = get_pe_offset(content)
    if pe_offset and len(content) >= pe_offset + 6:
        bitness = get_word(content, pe_offset + 4)
        bitness_map = {0x14C: 32, 0x8664: 64}
        bitness = bitness_map.get(bitness, 0)
    return bitness


class NativeCodeIdentifier:
    family_override = []

    def _identifyDotnet(self, content):
        if not check_bitness(content):
            return False
        pe_offset = get_pe_offset(content)
        file_characteristics_offset = pe_offset + 0x18
        file_characteristics = get_word(content, file_characteristics_offset)
        field_offset = 0
        if file_characteristics == 0x10B:
            field_offset = 0xE8
        elif file_characteristics == 0x20B:
            field_offset = 0xF8
        image_dir_com_descriptor_offset = pe_offset + field_offset
        # only .NET binaries will feature a COM descriptor table in the data directory
        com_descriptor_offset = get_dword(content, image_dir_com_descriptor_offset)
        return bool(field_offset > 0 and len(content) - 8 > com_descriptor_offset > 0)

    def _identifyPython(self, content):
        return bool(re.search(rb"python(2|3)\d*\.dll", content))

    def isNativeCode(self, filepath):
        for family in self.family_override:
            if family in filepath:
                return True
        content = ""
        with open(filepath, "rb") as fin:
            content = fin.read()
        # Keep Delphi and Go in the benchmark scope; exclude formats handled by
        # other SMDA backends or wrappers.
        is_dotnet = self._identifyDotnet(content)
        is_python = self._identifyPython(content)
        return not (is_dotnet or is_python)


def parseBaseAddrFromArgs(filename):
    baddr_match = re.search(re.compile("0x(?P<base_addr>[0-9a-fA-F]{8,16})"), filename)
    if baddr_match:
        return int(baddr_match.group("base_addr"), 16)
    return 0


def getBitnessFromFilename(filename):
    baddr_match = re.search(re.compile("0x(?P<base_addr>[0-9a-fA-F]{8,16})"), filename)
    if baddr_match:
        return 32 if len(baddr_match.group("base_addr")) == 8 else 64
    return 0


def readFileContent(file_path):
    file_content = b""
    with open(file_path, "rb") as fin:
        file_content = fin.read()
    return file_content


def getAllReportFilenames(output_path):
    report_filenames = set()
    if not os.path.exists(output_path):
        return report_filenames
    for _root, _subdir, files in os.walk(output_path):
        for filename in files:
            report_filenames.add(filename)
    return report_filenames


def getFamilyName(input_path):
    family_name = ""
    abs_path = os.path.abspath(input_path)
    for folder in abs_path.split("/")[::-1]:
        if folder == "malpedia":
            break
        family_name = folder
    return family_name


def getSampleVersion(input_path, family):
    sample_version = ""
    abs_path = os.path.dirname(os.path.abspath(input_path))
    for folder in abs_path.split("/")[::-1]:
        if folder == family or folder == "modules":
            break
        sample_version = folder
    return sample_version


def getMalpediaFilePath(input_path):
    egg = "malpedia/"
    abs_path = os.path.abspath(input_path)
    pos = abs_path.index(egg)
    malpedia_filepath = abs_path[pos + len(egg) :]
    return malpedia_filepath


def getBenchmarkMode(filepath, filename):
    if "elf." in filepath and ("x86" in filepath or "x64" in filepath) and re.search(unpacked_file_pattern, filename):
        return "file"
    if "win." in filepath and re.search(unpacked_file_pattern, filename):
        return "file"
    if re.search(dump_file_pattern, filename):
        return "dump"
    return None


def buildTargetQueue(malpedia_path):
    input_queue = []
    skipped = {
        "non_native": 0,
        "module": 0,
        "unsupported": 0,
        "native_errors": 0,
    }
    identifier = NativeCodeIdentifier()

    for root, _subdir, files in sorted(os.walk(malpedia_path)):
        if ".git" in root:
            continue
        for filename in sorted(files):
            if not (re.search(unpacked_file_pattern, filename) or re.search(dump_file_pattern, filename)):
                continue

            filepath = root + os.sep + filename
            try:
                if not identifier.isNativeCode(filepath):
                    skipped["non_native"] += 1
                    continue
            except Exception:
                skipped["native_errors"] += 1
                print("RunTimeError, we skip!")
                print("smda: " + str(filename))
                traceback.print_exc()
                continue

            malpedia_relative_path = getMalpediaFilePath(filepath)
            in_family_path = os.sep.join(malpedia_relative_path.split(os.sep)[1:])
            if in_family_path.startswith("module"):
                skipped["module"] += 1
                continue

            input_mode = getBenchmarkMode(filepath, filename)
            if not input_mode:
                skipped["unsupported"] += 1
                continue

            family = getFamilyName(filepath)
            input_queue.append(
                {
                    "base_addr": parseBaseAddrFromArgs(filename),
                    "bitness": getBitnessFromFilename(filename),
                    "family": family,
                    "filename": filename,
                    "filepath": filepath,
                    "input_mode": input_mode,
                    "malpedia_relative_path": malpedia_relative_path,
                    # Family-relative stem keeps reports unique across family folders that reuse
                    # the same dump/sample basename (e.g. dump_0x00400000).
                    "report_stem": os.path.relpath(filepath, malpedia_path).replace(os.sep, "_"),
                    "version": getSampleVersion(filepath, family),
                }
            )

    return input_queue, skipped


def resolveWorkerCount():
    explicit_workers = os.environ.get("SMDA_BENCH_WORKERS")
    if explicit_workers:
        try:
            workers = int(explicit_workers)
        except ValueError as exc:
            raise RuntimeError("SMDA_BENCH_WORKERS must be an integer") from exc
    elif os.environ.get("SMDA_BENCH_LOW_NOISE") == "1":
        workers = 1
    else:
        workers = cpu_count() or 1
    return max(1, min(workers, 8))


def work(input_element):
    # Resume + output are keyed on the family-relative stem (not the bare basename) so
    # same-named samples in different family folders do not collide / overwrite each other.
    REPORT_STEM = input_element["report_stem"]
    if REPORT_STEM + ".smda" in input_element["finished_reports"]:
        print("Skipping file {}".format(input_element["filepath"]))
        return "skipped"
    REPORT = None
    INPUT_FILEPATH = input_element["filepath"]
    INPUT_FILENAME = input_element["filename"]
    try:
        disassembler = Disassembler()
        if input_element["input_mode"] == "file":
            print(f"Analyzing file: {INPUT_FILEPATH}")
            try:
                REPORT = disassembler.disassembleFile(INPUT_FILEPATH)
            except AttributeError:
                logger.error("AttributeError for: " + str(INPUT_FILENAME))
        elif input_element["input_mode"] == "dump":
            print(f"Analyzing file: {INPUT_FILEPATH}")
            BUFFER = readFileContent(INPUT_FILEPATH)
            BASE_ADDR = input_element["base_addr"]
            BITNESS = input_element["bitness"]
            try:
                REPORT = disassembler.disassembleBuffer(BUFFER, BASE_ADDR, BITNESS)
            except AttributeError:
                logger.error("AttributeError for: " + str(INPUT_FILENAME))
        if REPORT:
            REPORT.family = input_element["family"]
            REPORT.version = input_element["version"]
            REPORT.filename = os.path.basename(input_element["malpedia_relative_path"])
            output_dir = input_element.get("output_dir", "finished-reports")
            with open(output_dir + os.sep + REPORT_STEM + ".smda", "w") as fout:
                json.dump(REPORT.toDict(), fout, indent=1, sort_keys=True)
                logger.info("Wrote " + output_dir + "/" + REPORT_STEM + ".smda")
            return "written"
    except Exception:
        print("RunTimeError, we skip!")
        print("smda: " + str(INPUT_FILENAME))
        traceback.print_exc()
        return "error"
    return "ignored"


def parseArgs(argv=None):
    parser = argparse.ArgumentParser(description="Run SMDA over selected Malpedia benchmark samples")
    parser.add_argument("malpedia_root", help="Path to extracted malpedia root")
    parser.add_argument("output_dir", nargs="?", default="finished-reports", help="Output folder or run-folder prefix")
    parser.add_argument(
        "--runs",
        type=int,
        default=None,
        help="Number of repeated run folders to write as <output_dir>_N. Omit for legacy single-folder mode.",
    )
    return parser.parse_args(argv)


def buildOutputDirs(output_dir, runs):
    if runs is None:
        return [output_dir]
    if runs < 1:
        raise RuntimeError("--runs must be greater than zero")
    return [f"{output_dir}_{i}" for i in range(runs)]


def runOneOutput(input_queue, output_dir, workers):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    finished_reports = getAllReportFilenames(output_dir)
    run_queue = []
    for input_element in input_queue:
        run_element = dict(input_element)
        run_element["finished_reports"] = finished_reports
        run_element["output_dir"] = output_dir
        run_queue.append(run_element)

    counts = {}
    if workers == 1:
        for result in tqdm.tqdm(map(work, run_queue), total=len(run_queue)):
            counts[result] = counts.get(result, 0) + 1
    else:
        with Pool(workers) as pool:
            for result in tqdm.tqdm(pool.imap_unordered(work, run_queue), total=len(run_queue)):
                counts[result] = counts.get(result, 0) + 1
    print(
        "Run summary for {}: written={}, skipped={}, ignored={}, errors={}".format(
            output_dir,
            counts.get("written", 0),
            counts.get("skipped", 0),
            counts.get("ignored", 0),
            counts.get("error", 0),
        )
    )


if __name__ == "__main__":
    logging.basicConfig(
        filename="/tmp/smda.log",
        filemode="a",
        format="[%(asctime)s:%(msecs)d] %(name)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        level=logging.INFO,
    )

    formatter = logging.Formatter(
        "%(process)d - %(processName)s - %(threadName)s - %(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    # Add logger to stdout
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.INFO)
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    args = parseArgs()
    workers = resolveWorkerCount()
    output_dirs = buildOutputDirs(args.output_dir, args.runs)
    input_queue, skipped = buildTargetQueue(args.malpedia_root)
    print(
        "Malpedia benchmark queue: targets={}, skipped={}, workers={}, output_dirs={}".format(
            len(input_queue),
            sum(skipped.values()),
            workers,
            ", ".join(output_dirs),
        )
    )
    print("Skipped by reason: " + ", ".join(f"{key}={value}" for key, value in sorted(skipped.items())))
    for output_dir in output_dirs:
        runOneOutput(input_queue, output_dir, workers)
    print("DONE, shutting down")
