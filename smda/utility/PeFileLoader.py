import logging
import struct

import lief

lief.logging.disable()

LOG = logging.getLogger(__name__)


class PeFileLoader:
    BITNESS_MAP = {0x14C: 32, 0x8664: 64}

    @staticmethod
    def isCompatible(data):
        return data[:2] == b"MZ"

    @staticmethod
    def mapBinary(binary):
        # lief is awesome and does all the heavy lifting.
        pe = lief.parse(binary)
        if pe is None:
            return b""
        # get maximum size of mapped sections to define size of the mapped_binary
        max_offset = 0
        for section in pe.sections:
            max_offset = max(max_offset, section.virtual_address + section.virtual_size)
        # support up to 100MB for now.
        if max_offset > 100 * 1024 * 1024:
            return b""
        # create mapped binary
        mapped_binary = bytearray(max_offset)
        # copy PE header
        if pe.optional_header.sizeof_headers > 0:
            mapped_binary[:pe.optional_header.sizeof_headers] = binary[:pe.optional_header.sizeof_headers]
        # copy sections
        for section in pe.sections:
            mapped_from = section.virtual_address
            mapped_to = section.virtual_address + len(section.content)
            mapped_binary[mapped_from:mapped_to] = section.content
            LOG.debug(
                "Mapping %s: raw 0x%x (0x%x bytes) -> virtual 0x%x (0x%x bytes)",
                section.name,
                section.offset,
                section.size,
                section.virtual_address,
                section.virtual_size,
            )
        LOG.debug(
            "Mapped binary of size %d bytes (%d sections) to memory view of size %d bytes",
            len(binary),
            len(pe.sections),
            len(mapped_binary),
        )
        return bytes(mapped_binary)

    @staticmethod
    def getBitness(binary):
        bitness_id = 0
        pe_offset = PeFileLoader.getPeOffset(binary)
        if pe_offset and len(binary) >= pe_offset + 0x6:
            bitness_id = struct.unpack("H", binary[pe_offset + 0x4 : pe_offset + 0x6])[0]
        return PeFileLoader.BITNESS_MAP.get(bitness_id, 0)

    @staticmethod
    def getBaseAddress(binary):
        base_addr = 0
        pe_offset = PeFileLoader.getPeOffset(binary)
        if pe_offset and len(binary) >= pe_offset + 0x38:
            if PeFileLoader.getBitness(binary) == 32:
                base_addr = struct.unpack("I", binary[pe_offset + 0x34 : pe_offset + 0x38])[0]
            elif PeFileLoader.getBitness(binary) == 64:
                base_addr = struct.unpack("Q", binary[pe_offset + 0x30 : pe_offset + 0x38])[0]
        if base_addr:
            LOG.debug(
                "Changing base address from 0 to: 0x%x for inference of reference counts (based on PE header)",
                base_addr,
            )
        return base_addr

    @staticmethod
    def getPeOffset(binary):
        if len(binary) >= 0x40:
            pe_offset = struct.unpack("H", binary[0x3C : 0x3C + 2])[0]
            return pe_offset
        return 0

    @staticmethod
    def getOEP(binary):
        oep_rva = 0
        if PeFileLoader.checkPe(binary):
            pe_offset = PeFileLoader.getPeOffset(binary)
            if pe_offset and len(binary) >= pe_offset + 0x2C:
                oep_rva = struct.unpack("I", binary[pe_offset + 0x28 : pe_offset + 0x2C])[0]
        return oep_rva

    @staticmethod
    def getArchitecture(binary):
        architecture = "intel"
        pefile = lief.parse(binary)
        if pefile:
            for d in pefile.data_directories:
                if d.type == lief.PE.DataDirectory.TYPES.CLR_RUNTIME_HEADER and d.size > 0:
                    architecture = "cil"
        return architecture

    @staticmethod
    def checkPe(binary):
        pe_offset = PeFileLoader.getPeOffset(binary)
        if pe_offset and len(binary) >= pe_offset + 6:
            bitness = struct.unpack("H", binary[pe_offset + 4 : pe_offset + 4 + 2])[0]
            return bitness in PeFileLoader.BITNESS_MAP
        return False

    @staticmethod
    def getCodeAreas(binary):
        pefile = lief.parse(binary)
        code_areas = []
        base_address = PeFileLoader.getBaseAddress(binary)
        if pefile and pefile.sections:
            for section in pefile.sections:
                # MEM_EXECUTE
                if section.characteristics & 0x20000000:
                    section_start = base_address + section.virtual_address
                    section_size = section.virtual_size
                    if section_size % 0x1000 != 0:
                        section_size += 0x1000 - (section_size % 0x1000)
                    section_end = section_start + section_size
                    code_areas.append([section_start, section_end])
        return PeFileLoader.mergeCodeAreas(code_areas)

    @staticmethod
    def mergeCodeAreas(code_areas):
        merged_code_areas = sorted(code_areas)
        result = []
        index = 0
        while index < len(merged_code_areas) - 1:
            this_area = merged_code_areas[index]
            next_area = merged_code_areas[index + 1]
            if this_area[1] != next_area[0]:
                result.append(this_area)
                index += 1
            else:
                merged_code_areas = (
                    merged_code_areas[:index] + [[this_area[0], next_area[1]]] + merged_code_areas[index + 2 :]
                )
        return merged_code_areas
