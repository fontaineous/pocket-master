#!/usr/bin/env python3
"""Disassemble the Cortex-M host firmware (segment c): flash part (base 0x4000) or the RAM image built by c_unpack.py.
usage: c_disasm.py flash <c.bin> [start end]   |   c_disasm.py ram <ram_20000000.bin> [start end]
Literal-pool loads are resolved; `bl` targets are annotated when they are function starts seen elsewhere in the dump."""
import re, struct, sys
from capstone import *
mode, path = sys.argv[1:3]
img = open(path, 'rb').read()
base, off0 = (0x4000, 0) if mode == 'flash' else (0x20000000, 0)
lo = int(sys.argv[3], 16) if len(sys.argv) > 3 else (0x4400 if mode == 'flash' else 0x20000000)
hi = int(sys.argv[4], 16) if len(sys.argv) > 4 else (base + len(img) if mode == 'flash' else 0x2000218c)
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS); md.skipdata = True
def word(a):
    o = a - base
    return struct.unpack_from('<I', img, o)[0] if 0 <= o < len(img) - 3 else None
for i in md.disasm(img[lo - base:hi - base], lo):
    t = f'{i.mnemonic} {i.op_str}'; ex = ''
    m = re.match(r'ldr\w*\s+\w+, \[pc, #(0x[0-9a-f]+|\d+)\]', t)
    if m:
        w = word(((i.address + 4) & ~3) + int(m.group(1), 0)); ex = f'    ; =0x{w:x}' if w is not None else ''
    if i.mnemonic == 'push' and 'lr' in i.op_str: print()
    print(f'{i.address:08x}: {i.mnemonic:8s} {i.op_str}{ex}')
