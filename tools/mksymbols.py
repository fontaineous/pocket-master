#!/usr/bin/env python3
"""Merge sigmatch CSV output(s) into one symbol table: addr -> name(s).
Several reference functions with identical bodies map to one address; their names are joined with '|'.
usage: mksymbols.py out.csv sig1.csv [sig2.csv ...]"""
import csv, sys, collections
names = collections.defaultdict(set)
for path in sys.argv[2:]:
    for line in open(path):
        if line.startswith(('#', 'runtime')): continue
        addrs, size, name, n = line.rstrip('\n').split(',')[:4]
        for a in addrs.split(';'):
            names[int(a, 16)].add((name, int(size)))
with open(sys.argv[1], 'w') as f:
    f.write('runtime_addr,size,names\n')
    for a in sorted(names):
        ns = sorted(names[a]); f.write(f'0x{a:x},{max(s for _, s in ns)},{"|".join(n for n, _ in ns)}\n')
print(len(names), 'addresses named', file=sys.stderr)
