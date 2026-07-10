import lief, capstone
b = lief.parse('/home/z/.macify/bin/bash')
for sec in b.sections:
    if sec.name == '__text':
        text_sec = sec; break
data = bytes(text_sec.content)
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
target = 0x20c8
start = max(0, target - 80)
end = min(len(data), target + 20)
for ins in md.disasm(data[start:end], text_sec.virtual_address + start):
    m = ' <-- EXIT' if ins.address == 0x100005074 else ''
    print('0x%x: %s %s%s' % (ins.address, ins.mnemonic, ins.op_str, m))
