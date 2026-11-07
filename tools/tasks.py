#!/usr/bin/env python3
"""List FreeRTOS tasks created by the stock firmware.
xTaskCreate is found by behaviour (call sites whose r1 is a C string, r2 a stack depth, r4 a small priority), then every
call site is decoded: entry point (r0), name (r1), stack words (r2), priority (r4).
usage: tasks.py <objdump> <b.bin> <symbols.csv>   (markdown to stdout; symbols.csv optional names for entry points)"""
import re, subprocess, sys, collections
objdump, binf = sys.argv[1:3]
names = {}
if len(sys.argv) > 3:
    for l in list(open(sys.argv[3]))[1:]:
        p = l.rstrip('\n').split(',', 2); names[int(p[0], 16)] = p[2]
B = open(binf, 'rb').read()
dis = subprocess.run([objdump, '-D', '-b', 'binary', '-m', 'nds32', binf, '--stop-address=0xd0000'], capture_output=True, text=True).stdout
ins = []
for l in dis.splitlines():
    m = re.match(r'\s*([0-9a-f]+):\t(?:[0-9a-f]{2} )+\s*\t?(.*)', l)
    if m: ins.append((int(m.group(1), 16) + 0x10000, m.group(2).strip()))
def const(reg, k, span=16):
    hi = None
    for j in range(k - 1, max(k - span, 0), -1):
        t = ins[j][1]
        m = re.match(r'(movi55|movi|movpi45)\s+%s, #(-?(?:0x)?[0-9a-f]+)' % re.escape(reg), t)
        if m: return int(m.group(2), 0) if 'x' in m.group(2) else int(m.group(2))
        m = re.match(r'ori\s+%s, %s, #(0x[0-9a-f]+|\d+)' % (re.escape(reg), re.escape(reg)), t)
        if m: hi = int(m.group(1), 0); continue
        m = re.match(r'sethi\s+%s, #(0x[0-9a-f]+|\d+)' % re.escape(reg), t)
        if m: return (int(m.group(1), 0) << 12) | (hi or 0)
        if re.match(r'(jal|jral5?|ret5|j|jr5?)\b', t): return None
    return None
def cstr(v):
    if v is None: return None
    o = v - 0x10000
    if not 0 <= o < len(B): return None
    e = B.find(b'\0', o, o + 40); s = B[o:e] if e > o else b''
    return s.decode() if len(s) >= 3 and all(32 <= c < 127 for c in s) else None
sites = collections.defaultdict(list)
for k, (a, t) in enumerate(ins):
    m = re.match(r'jal\s+0x([0-9a-f]+)$', t)
    if not m: continue
    tg = int(m.group(1), 16) + 0x10000
    nm, r2, r4, r0 = cstr(const('$r1', k)), const('$r2', k), const('$r4', k), const('$r0', k)
    if nm and r2 and 64 <= r2 <= 16384 and r4 is not None and 0 <= r4 <= 12:
        sites[tg].append((a, r0, nm, r2, r4))
tg, l = max(sites.items(), key=lambda x: len(x[1]))
print(f'xTaskCreate = 0x{tg:x} ({len(l)} call sites)\n')
print('| created at | entry | name | stack (words) | priority |\n|---|---|---|---|---|')
for a, r0, nm, r2, r4 in sorted(l):
    print(f'| 0x{a:x} | {hex(r0) if r0 else "?"}{" "+names[r0] if r0 in names else ""} | {nm} | {r2} | {r4} |')
