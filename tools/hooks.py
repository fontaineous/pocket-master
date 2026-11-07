#!/usr/bin/env python3
"""List call-site hooks a CFW installs into the stock NDS32 application (segment b).

Disassembles both 'b' segments with nds32be-elf-objdump, walks the stock-code range
instruction-by-instruction by address and reports every j/jal whose target changed.

usage: hooks.py <nds32be-elf-objdump> <stock_b.bin> <cfw_b.bin> [load_offset=0x10000]
"""
import re, subprocess, sys

def dis(objdump, path):
    out = subprocess.run([objdump, '-D', '-b', 'binary', '-m', 'nds32', '-EB', path],
                         capture_output=True, text=True, check=True).stdout
    ins = {}
    for l in out.splitlines():
        m = re.match(r'\s*([0-9a-f]+):\t((?:[0-9a-f]{2} )+)\s*\t?(.*)', l)
        if m:
            ins[int(m.group(1), 16)] = m.group(3).strip()
    return ins

def main():
    objdump, stock, cfw = sys.argv[1:4]
    base = int(sys.argv[4], 0) if len(sys.argv) > 4 else 0x10000
    a, b = dis(objdump, stock), dis(objdump, cfw)
    stock_len = len(open(stock, 'rb').read())
    rows = []
    for addr in sorted(a):
        if addr >= stock_len:
            break
        ia, ib = a[addr], b.get(addr)
        ma = re.match(r'(jal|j)\t0x([0-9a-f]+)$', ia)
        mb = re.match(r'(jal|j)\t0x([0-9a-f]+)$', ib or '')
        if ma and mb and ma.group(2) != mb.group(2):
            rows.append((addr, ma.group(1), int(ma.group(2), 16), int(mb.group(2), 16)))
    print(f'| site (file off) | runtime addr | op | stock target | new target (file off) | into appended blob |')
    print('|---|---|---|---|---|---|')
    for addr, op, old, new in rows:
        print(f'| 0x{addr:x} | 0x{addr+base:x} | {op} | 0x{old:x} | 0x{new:x} | {"yes" if new >= stock_len else "no"} |')
    print(f'\n{len(rows)} retargeted branches; stock code length 0x{stock_len:x}')

main()
