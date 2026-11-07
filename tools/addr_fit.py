#!/usr/bin/env python3
"""Compare the firmware's peripheral/RAM addresses with a candidate MCU's CMSIS device header(s).
Parses '#define NAME_BASE (EXPR)' macros (resolving earlier macros), then reports for each firmware address the exact base match
(if any) and the nearest base below. Use it to quickly eliminate candidates from public vendor SDKs.
usage: addr_fit.py <device_header.h> [more headers...]"""
import re, sys
firm = {  # addresses recovered from the Cortex-M host (docs/FINDINGS.md sections 16, 17, 19)
 'periph 0x40005000': 0x40005000, 'periph 0x4000B000 (+n*0x1000 instances)': 0x4000b000, 'periph 0x4000C000': 0x4000c000,
 'periph 0x4000E000': 0x4000e000, 'periph 0x40011000': 0x40011000, 'periph 0x40020000 (+0x100,+0x120)': 0x40020000,
 'periph 0x40030000 (+0x100..0x160)': 0x40030000, 'periph 0x40050000 (cmd block, +0x30/+0x34)': 0x40050000,
 'RAM 0x10000000 (128 KB)': 0x10000000, 'RAM 0x28000000 (32 KB)': 0x28000000, 'ext RAM 0x29000000': 0x29000000, 'SRAM 0x20000000': 0x20000000}
consts = {}
for path in sys.argv[1:]:
    txt = open(path, errors='ignore').read()
    for m in re.finditer(r'#define\s+(\w+)\s+\(?\s*(?:\(\s*\w+\s*\))?\s*([^\n/]*?)\s*\)?\s*(?:/[*/].*)?$', txt, re.M):
        name, expr = m.group(1), m.group(2)
        e = re.sub(r'\b0[xX]([0-9a-fA-F]+)[uUlL]*', r'0x\1', expr).replace('UL', '').replace('U', '')
        try:
            v = eval(e, {}, dict(consts))
            if isinstance(v, int) and v >= 0x1000: consts[name] = v
        except Exception: pass
bases = sorted((v, n) for n, v in consts.items() if n.endswith(('_BASE', '_BASE_ADDR', '_ADDR')) or 'BASE' in n)
print(f'{len(bases)} base macros parsed')
for label, a in firm.items():
    ex = [n for v, n in bases if v == a]; below = [(v, n) for v, n in bases if v <= a]
    nb = below[-1] if below else None
    print(f'{label:46s} exact: {", ".join(ex[:3]) or "-":34s} nearest below: {(nb[1]+" +%#x" % (a-nb[0])) if nb else "-"}')
