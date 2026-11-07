#!/usr/bin/env python3
"""Disassemble a range of the stock NDS32 image with jal/j targets replaced by symbol names.
usage: annotate.py <objdump> <b.bin> <symbols.csv> <start_runtime_hex> <end_runtime_hex>
(runtime = file offset + 0x10000; csv columns: runtime_addr,size,names)"""
import re, subprocess, sys
objdump, binf, symf, lo, hi = sys.argv[1:6]; lo = int(lo, 16); hi = int(hi, 16)
sym = {}
for l in list(open(symf))[1:]:
    p = l.rstrip('\n').split(',', 2); sym[int(p[0], 16)] = p[2]
out = subprocess.run([objdump, '-D', '-b', 'binary', '-m', 'nds32', binf, f'--start-address={lo-0x10000:#x}', f'--stop-address={hi-0x10000:#x}'],
                     capture_output=True, text=True).stdout
for l in out.splitlines():
    m = re.match(r'\s*([0-9a-f]+):\t((?:[0-9a-f]{2} )+)\s*\t?(.*)', l)
    if not m: continue
    a = int(m.group(1), 16) + 0x10000
    if a in sym: print(f'\n<{sym[a]}>:')
    t = m.group(3)
    mj = re.match(r'(jal|j)\t0x([0-9a-f]+)$', t)
    if mj:
        tg = int(mj.group(2), 16) + 0x10000
        t = f'{mj.group(1)}\t0x{tg:x}' + (f'  ; {sym[tg]}' if tg in sym else '')
    print(f'{a:6x}:  {t}')
