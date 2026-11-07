#!/usr/bin/env python3
"""Make a Pocket Master firmware with a longer looper (EXPERIMENTAL, NOT TESTED ON HARDWARE).

Changes two 32-bit constants in the Cortex-M4 image (segment c):
  flash 0x8fd8  loop capacity in int16 samples      (stock 0x6bac0 = 441,024 -> 20 s at the stock 22.05 kHz mono mode)
  flash 0xe3c8  zero-init size of the 0x29000000 array in the scatter-load table (stock 0xd7580 = 2 x capacity)
Segment c is stored in the container at address 0x4000 (file offset = flash address - 0x4000). The CRC-16 of the segment is recomputed
by htfw.py. The unknown header word at offset 4 is copied unchanged from the input image (see tools/htfw.py); whether the updater
checks it is not known.

WARNING: the memory behind 0x29000000 must be at least 2 x capacity bytes; its real size is unknown. Take a flash backup first.
usage: patch_looper.py <in.bin> <out.bin> --seconds 120      (22.05 kHz mono mode, stock quality)
       patch_looper.py <in.bin> <out.bin> --samples 2646000"""
import argparse, os, struct, subprocess, sys, tempfile, json
HERE = os.path.dirname(os.path.abspath(__file__)); HTFW = os.path.join(HERE, 'htfw.py')
CAP_ADDR, ZI_ADDR, BASE, STOCK_CAP = 0x8fd8, 0xe3c8, 0x4000, 0x6bac0
ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
ap.add_argument('inp'); ap.add_argument('out')
g = ap.add_mutually_exclusive_group(required=True)
g.add_argument('--seconds', type=float, help='loop length at 22.05 kHz (the stock recording mode)')
g.add_argument('--samples', type=int, help='capacity in int16 samples')
a = ap.parse_args()
cap = a.samples if a.samples else int(round(a.seconds * 22050))
hdr4 = struct.unpack_from('<I', open(a.inp, 'rb').read(), 4)[0]
with tempfile.TemporaryDirectory() as t:
    subprocess.run([sys.executable, HTFW, 'unpack', a.inp, t], check=True, capture_output=True)
    meta = json.load(open(os.path.join(t, 'meta.json')))
    cf = os.path.join(t, next(s['file'] for s in meta['segments'] if s['type'] == 'c'))
    c = bytearray(open(cf, 'rb').read())
    old_cap = struct.unpack_from('<I', c, CAP_ADDR - BASE)[0]; old_zi = struct.unpack_from('<I', c, ZI_ADDR - BASE)[0]
    if old_cap != STOCK_CAP or old_zi != 2 * STOCK_CAP:
        sys.exit(f'unexpected constants in this image (cap {old_cap:#x}, zi {old_zi:#x}); refusing to patch')
    struct.pack_into('<I', c, CAP_ADDR - BASE, cap); struct.pack_into('<I', c, ZI_ADDR - BASE, 2 * cap)
    open(cf, 'wb').write(c)
    subprocess.run([sys.executable, HTFW, 'pack', '--hdr4', hex(hdr4), t, a.out], check=True)
print(f'capacity {old_cap} -> {cap} samples ({cap/22050:.1f} s at 22.05 kHz, {cap/44100:.1f} s at 44.1 kHz); RAM needed at 0x29000000: {2*cap/1e6:.2f} MB')
print('written', a.out)
