#!/usr/bin/env python3
"""Disassemble an overlay module extracted by g_modules.py.
Resolves pc-relative literal loads (decoding likely float constants) and marks entry points.
(payload = blob[w0 : w0+w1] is mapped at the slot base, as the host loader does)
usage: mod_disasm.py <module.bin> <slot_base_hex> [--from OFFSET] [--to OFFSET]"""
import re, struct, sys
from capstone import *
path, base = sys.argv[1], int(sys.argv[2], 16)
raw = open(path, 'rb').read()
_hs, _pl = struct.unpack_from('<2I', raw, 0)
b = raw[_hs:_hs + _pl]          # the loader copies only the payload to the slot base (header and data block are not part of it)
lo = int(sys.argv[sys.argv.index('--from') + 1], 16) if '--from' in sys.argv else 0
hi = int(sys.argv[sys.argv.index('--to') + 1], 16) if '--to' in sys.argv else len(b)
hs, pl, tot, w3, e1, e2 = struct.unpack_from('<6I', raw, 0)
print(f'; header: hdr={hs:#x} payload={pl:#x} total={tot:#x} w3={w3:#x} entry1={e1:#x} entry2={e2:#x} base={base:#x}')
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS); md.skipdata = True
def fl(w):
    f = struct.unpack('<f', struct.pack('<I', w))[0]
    return f' ({f:.7g})' if w and f == f and 1e-9 < abs(f) < 1e9 and (w >> 23) & 0xff not in (0,) else ''
ents = {e1 & ~1: 'ENTRY1', e2 & ~1: 'ENTRY2'}
for i in md.disasm(b[lo:hi], base + lo):
    if i.address in ents: print(f'\n<{ents[i.address]}>:')
    elif i.mnemonic == 'push' and 'lr' in i.op_str: print()
    t = f'{i.mnemonic} {i.op_str}'; ex = ''
    m = re.match(r'(ldr\w*|vldr)\s+\w+, \[pc, #(0x[0-9a-f]+|\d+)\]', t)
    if m:
        a = ((i.address + 4) & ~3) + int(m.group(2), 0); o = a - base
        if 0 <= o <= len(b) - 4:
            w = struct.unpack_from('<I', b, o)[0]; ex = f'   ; [{a:#x}] = {w:#x}{fl(w)}'
    print(f'{i.address:08x}: {i.mnemonic:8s} {i.op_str}{ex}')
