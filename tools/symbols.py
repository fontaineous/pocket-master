#!/usr/bin/env python3
"""Recover a first-pass symbol table from the stock NDS32 application (segment b).

 - function starts  = targets of jal (call graph roots), restricted to the code area
 - string refs      = sethi/ori pairs whose value - LOAD_BASE points at a printable C string
 - each string ref is attributed to the enclosing function (greatest known start <= site)
Output CSV: runtime_addr,calls_in,size_hint,strings(| separated)

usage: symbols.py <nds32be-elf-objdump> <b_segment.bin> [out.csv]
Runtime address = file offset + 0x10000 (proved: 699 vs 17 string-pointer hits).
"""
import re, subprocess, sys, collections
LOAD_BASE = 0x10000
CODE_END = 0x100000      # data/assets start about here (see docs/FINDINGS.md)

def main():
    objdump, path = sys.argv[1:3]
    out = sys.argv[3] if len(sys.argv) > 3 else None
    B = open(path, 'rb').read()
    txt = subprocess.run([objdump, '-D', '-b', 'binary', '-m', 'nds32', '-EB', path],
                         capture_output=True, text=True, check=True).stdout
    ins = []
    for l in txt.splitlines():
        m = re.match(r'\s*([0-9a-f]+):\t(?:[0-9a-f]{2} )+\s*\t?(.*)', l)
        if m and int(m.group(1), 16) < CODE_END:
            ins.append((int(m.group(1), 16), m.group(2).strip()))
    calls = collections.Counter()
    for a, t in ins:
        m = re.match(r'jal\t0x([0-9a-f]+)$', t)
        if m and int(m.group(1), 16) < CODE_END:
            calls[int(m.group(1), 16)] += 1
    starts = sorted(calls)
    def cstr(off):
        if off < 0 or off >= len(B): return None
        e = B.find(b'\0', off, off + 160)
        s = B[off:e] if e > off else b''
        return s.decode() if len(s) >= 4 and all(32 <= c < 127 or c in (9, 10) for c in s) else None
    import bisect
    funcs = collections.defaultdict(list)
    for k, (a, t) in enumerate(ins):
        m1 = re.match(r'sethi\t(\$\w+), #(0x[0-9a-f]+)', t)
        if not m1: continue
        for j in range(k + 1, min(k + 8, len(ins))):
            m2 = re.match(r'ori\t(\$\w+), (\$\w+), #(0x[0-9a-f]+)', ins[j][1])
            if m2 and m2.group(1) == m2.group(2) == m1.group(1):
                v = (int(m1.group(2), 16) << 12) | int(m2.group(3), 16)
                s = cstr(v - LOAD_BASE)
                if s:
                    i = bisect.bisect_right(starts, a) - 1
                    if i >= 0: funcs[starts[i]].append(s.strip().replace(',', ';'))
                break
    rows = []
    for f in sorted(funcs):
        nxt = starts[bisect.bisect_right(starts, f)] if bisect.bisect_right(starts, f) < len(starts) else f
        rows.append((f + LOAD_BASE, calls[f], nxt - f, '|'.join(dict.fromkeys(funcs[f]))))
    print(f'{len(starts)} call-target functions, {len(rows)} reference strings', file=sys.stderr)
    w = open(out, 'w') if out else sys.stdout
    w.write('runtime_addr,calls_in,size_hint,strings\n')
    for r in rows: w.write(f'0x{r[0]:x},{r[1]},{r[2]},{r[3]}\n')
main()
