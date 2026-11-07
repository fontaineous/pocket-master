#!/usr/bin/env python3
"""Survey which named SDK driver init/config functions the stock application calls, with constant arguments.
usage: periph.py <objdump> <b.bin> <symbols.csv> <regex of function names>  (markdown to stdout)"""
import re, subprocess, sys, collections
objdump, binf, symf, rx = sys.argv[1:5]
rx = re.compile(rx)
names = {}
for l in list(open(symf))[1:]:
    p = l.rstrip('\n').split(',', 2); names[int(p[0], 16)] = p[2]
dis = subprocess.run([objdump, '-D', '-b', 'binary', '-m', 'nds32', binf, '--stop-address=0xd0000'], capture_output=True, text=True).stdout
ins = []
for l in dis.splitlines():
    m = re.match(r'\s*([0-9a-f]+):\t(?:[0-9a-f]{2} )+\s*\t?(.*)', l)
    if m: ins.append((int(m.group(1), 16) + 0x10000, m.group(2).strip()))
def const(reg, k):
    hi = None
    for j in range(k - 1, max(k - 12, 0), -1):
        t = ins[j][1]
        m = re.match(r'(movi55|movi|movpi45)\s+%s, #(-?(?:0x)?[0-9a-f]+)' % re.escape(reg), t)
        if m: return int(m.group(2), 0) if 'x' in m.group(2) else int(m.group(2))
        m = re.match(r'ori\s+%s, %s, #(0x[0-9a-f]+|\d+)' % (re.escape(reg), re.escape(reg)), t)
        if m: hi = int(m.group(1), 0); continue
        m = re.match(r'sethi\s+%s, #(0x[0-9a-f]+|\d+)' % re.escape(reg), t)
        if m: return (int(m.group(1), 0) << 12) | (hi or 0)
        if re.match(r'(jal|jral5?|ret5|j|jr5?)\b', t): return None
    return None
res = collections.defaultdict(list)
for k, (a, t) in enumerate(ins):
    m = re.match(r'jal\t0x([0-9a-f]+)$', t)
    if not m: continue
    tg = int(m.group(1), 16) + 0x10000
    nm = names.get(tg)
    if not nm or not any(rx.search(n) for n in nm.split('|')): continue
    if len(nm.split('|')) > 3: continue
    args = [const('$r%d' % i, k) for i in range(3)]
    res[nm].append((a, args))
fmt = lambda v: '?' if v is None else (hex(v) if abs(v) > 9 else str(v))
print('| function | call site (runtime) | r0 | r1 | r2 |\n|---|---|---|---|---|')
for nm in sorted(res):
    for a, args in res[nm][:6]:
        print(f'| {nm} | 0x{a:x} | {fmt(args[0])} | {fmt(args[1])} | {fmt(args[2])} |')
    if len(res[nm]) > 6: print(f'| {nm} | ... +{len(res[nm])-6} more | | | |')
