#!/usr/bin/env python3
"""Recover the stock firmware's GPIO alternate-function assignments.

Parses the per-pin mode tables from the SDK's gpio.h comments (GPIOAn / GPIOBn, 'GpioMode' lists), then finds every
call to GPIO_PortAModeSet / GPIO_PortBModeSet in the stock image and recovers the (pin mask, mode) constants
by scanning backwards for the instructions that load $r0/$r1.
usage: pinmap.py <objdump> <b.bin> <gpio.h> <symbols.csv>   (writes markdown to stdout)
"""
import re, subprocess, sys, collections
objdump, binf, gpioh, symf = sys.argv[1:5]
text = open(gpioh, 'rb').read().decode('latin1')
table = {}   # ('A',24) -> {mode: name}
for m in re.finditer(r'GPIO([AB])(\d+)\s*=\s*\(1\s*<<\s*\d+\)\s*,\s*/\*\*\s*GpioMode(.*?)\*/', text, re.S):
    port, n, body = m.group(1), int(m.group(2)), m.group(3)
    d = {}
    for line in body.splitlines():
        mm = re.match(r'\s*([01]+)\s*:\s*(\S.*?)\s*$', line)
        if mm: d[int(mm.group(1), 2)] = mm.group(2)
    table[(port, n)] = d
sym = {}
for l in list(open(symf))[1:]:
    p = l.rstrip('\n').split(',', 2); sym[p[2].split('|')[0]] = int(p[0], 16)
fa, fb = sym.get('GPIO_PortAModeSet'), sym.get('GPIO_PortBModeSet')
dis = subprocess.run([objdump, '-D', '-b', 'binary', '-m', 'nds32', binf, '--stop-address=0xd0000'], capture_output=True, text=True).stdout
ins = []
for l in dis.splitlines():
    m = re.match(r'\s*([0-9a-f]+):\t(?:[0-9a-f]{2} )+\s*\t?(.*)', l)
    if m: ins.append((int(m.group(1), 16) + 0x10000, m.group(2).strip()))
def const_for(reg, k):
    """value loaded into reg before instruction index k (scan back <= 14 insns), or None."""
    hi = None
    for j in range(k - 1, max(k - 15, 0), -1):
        a, t = ins[j]
        m = re.match(r'(movi55|movi|movpi45)\s+%s, #(-?(?:0x)?[0-9a-f]+)' % re.escape(reg), t)
        if m: return int(m.group(2), 0) if m.group(2).lstrip('-').startswith('0x') else int(m.group(2))
        m = re.match(r'ori\s+%s, %s, #(0x[0-9a-f]+|\d+)' % (re.escape(reg), re.escape(reg)), t)
        if m: hi = ('ori', int(m.group(1), 0)); continue
        m = re.match(r'sethi\s+%s, #(0x[0-9a-f]+|\d+)' % re.escape(reg), t)
        if m:
            v = int(m.group(1), 0) << 12
            return v | (hi[1] if hi else 0)
        if re.match(r'(jal|jral5?|ret5|j|jr5?)\b', t) : return None   # crossed a call/jump
        if re.match(r'[a-z0-9.]+\s+%s,' % re.escape(reg), t) and not t.startswith(('sw','sh','sb','bn','be','sl')): return None
    return None
rows = []
for k, (a, t) in enumerate(ins):
    m = re.match(r'jal\t0x([0-9a-f]+)$', t)
    if not m: continue
    tg = int(m.group(1), 16) + 0x10000
    if tg not in (fa, fb): continue
    port = 'A' if tg == fa else 'B'
    pin, mode = const_for('$r0', k), const_for('$r1', k)
    rows.append((port, pin, mode, a))
by = collections.defaultdict(list)
unk = 0
for port, pin, mode, a in rows:
    if pin is None or mode is None or pin <= 0 or pin & (pin - 1): unk += 1; continue
    by[(port, pin.bit_length() - 1)].append((mode, a))
print('| pin | mode | function (from gpio.h) | call sites |\n|---|---|---|---|')
for (port, n) in sorted(by):
    seen = collections.OrderedDict()
    for mode, a in by[(port, n)]: seen.setdefault(mode, []).append(a)
    for mode, sites in seen.items():
        fn = table.get((port, n), {}).get(mode, 'gpio default' if mode == 0 else '?')
        print(f'| {port}{n} | {mode} | {fn} | {" ".join(hex(s) for s in sites[:4])}{" ..." if len(sites)>4 else ""} |')
print(f'\n{len(rows)} call sites; {len(rows)-unk} resolved to a constant single pin; {unk} unresolved (pin/mode not a compile-time constant here).')
