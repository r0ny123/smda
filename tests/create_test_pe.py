import lief

pe = lief.PE.Binary(lief.PE.PE_TYPE.PE32)

section_text = lief.PE.Section(".text")
section_text.content = [0x90] * 0x1000 # nop
section_text.virtual_address = 0x1000
section_text.virtual_size = 0x1000

section_data = lief.PE.Section(".data")
section_data.content = [0x41] * 0x1000 # 'A'
section_data.virtual_address = 0x2000
section_data.virtual_size = 0x1000

# This will cause the old mapBinary to fail, as it doesn't handle this correctly.
section_data.sizeof_raw_data = 0x2000

pe.add_section(section_text)
pe.add_section(section_data)

builder = lief.PE.Builder(pe)
builder.build()
builder.write("tests/test_pe.exe")
