#!/usr/bin/env python3
"""Inventory of peripheral accesses in the Cortex-M host code (flash image at 0x4000 and the RAM-resident code).
Tracks constants loaded into registers (pc-relative literals, movw/movt, mov.w) and records every load/store whose effective
address (base + displacement) falls in peripheral/system space. Output: per 4 KB page, the register offsets used with r/w counts and
the functions (nearest preceding push {..lr}) that touch it.
usage: periph_scan.py <c.bin> <ram_20000000.bin>   (markdown to stdout)"""
import re, struct, sys, collections
from capstone import *
c_img = open(sys.argv[1], 'rb').read(); ram_img = open(sys.argv[2], 'rb').read()
RANGES = [(0x40000000, 0x60000000), (0xE0000000, 0xE0100000), (0x10000000, 0x10000100)]
def inper(a): return any(lo <= a < hi for lo, hi in RANGES[:2])
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS); md.skipdata = True
wvals = collections.defaultdict(list)   # effective address -> [(constant value written, function)]
acc = collections.defaultdict(lambda: collections.defaultdict(lambda: [0, 0, set()]))   # page -> off -> [reads, writes, funcs]
def scan(img, base, lo, hi, label):
    regs = {}; func = lo
    def lit(addr):
        o = addr - base
        return struct.unpack_from('<I', img, o)[0] if 0 <= o <= len(img) - 4 else None
    for i in md.disasm(img[lo - base:hi - base], lo):
        mn, ops = i.mnemonic, i.op_str
        if mn.startswith('push') and 'lr' in ops: func = i.address; regs.clear()
        if mn in ('bl', 'blx', 'bx') or (mn == 'pop' and 'pc' in ops): regs.clear(); continue
        m = re.match(r'ldr(?:\.w)?\s+(\w+), \[pc, #(-?(?:0x)?[0-9a-f]+)\]', f'{mn} {ops}')
        if m:
            v = lit(((i.address + 4) & ~3) + int(m.group(2), 0)); regs[m.group(1)] = v; continue
        m = re.match(r'movw\s+(\w+), #(0x[0-9a-f]+|\d+)', f'{mn} {ops}')
        if m: regs[m.group(1)] = int(m.group(2), 0); continue
        m = re.match(r'movt\s+(\w+), #(0x[0-9a-f]+|\d+)', f'{mn} {ops}')
        if m:
            r = m.group(1); regs[r] = ((int(m.group(2), 0) << 16) | (regs.get(r) or 0)) & 0xffffffff if regs.get(r) is not None else None; continue
        m = re.match(r'mov(?:\.w)?\s+(\w+), #(0x[0-9a-f]+|\d+)', f'{mn} {ops}')
        if m: regs[m.group(1)] = int(m.group(2), 0) & 0xffffffff; continue
        m = re.match(r'(ldr|str)(b|h|sb|sh)?(?:\.w)?\s+(\w+), \[(\w+)(?:, #(-?(?:0x)?[0-9a-f]+))?\]', f'{mn} {ops}')
        if m:
            kind, sz, rt, rb, off = m.groups(); base_v = regs.get(rb)
            if base_v is not None and inper(base_v + int(off or '0', 0)):
                ea = (base_v + int(off or '0', 0)) & 0xffffffff
                e = acc[ea & ~0xfff][ea & 0xfff]; e[0 if kind == 'ldr' else 1] += 1; e[2].add(func)
                if kind == 'str' and regs.get(rt) is not None and (sz or '') == '': wvals[ea].append((regs[rt] & 0xffffffff, func))
            if kind == 'ldr' and rt != rb: regs.pop(rt, None)
            continue
        m = re.match(r'(?:v?ldr|vstr)\S*\s+', f'{mn} {ops}')
        if m: continue
        dest = re.match(r'(\w+),', ops)
        if dest and not mn.startswith(('cmp', 'tst', 'str', 'b', 'cb', 'it', 'push', 'vstr', 'teq', 'cmn')): regs.pop(dest.group(1), None)
scan(c_img, 0x4000, 0x4400, 0x4000 + len(c_img), 'flash')
scan(ram_img, 0x20000000, 0x20000190, 0x20002188, 'ram')
names = {0xE0001000: 'DWT', 0xE000E000: 'NVIC/SysTick/SCS', 0xE000ED00: 'SCB'}
print('| page | register offsets (r=reads w=writes) | functions |\n|---|---|---|')
for page in sorted(acc):
    offs = ', '.join(f'+{o:#x}({e[0]}r/{e[1]}w)' for o, e in sorted(acc[page].items()))
    fs = sorted({f for e in acc[page].values() for f in e[2]})
    print(f'| `{page:#010x}` | {offs} | {" ".join(hex(f) for f in fs[:8])}{" ..." if len(fs) > 8 else ""} |')

print('\n### Constant values written (word stores whose value is a compile-time constant)\n')
print('| register | value(s) written | function |\n|---|---|---|')
for ea in sorted(wvals):
    vs = collections.OrderedDict()
    for v, f in wvals[ea]: vs.setdefault(v, set()).add(f)
    print(f'| `{ea:#010x}` | ' + ', '.join(f'`{v:#x}`' for v in vs) + ' | ' + ' '.join(hex(f) for f in sorted({f for s in vs.values() for f in s})[:4]) + ' |')
