#!/usr/bin/env python3
"""Drive the firmware's real looper block function (flash 0x8b8c) through record -> play in the emulator, with the loop capacity
constant (flash 0x8fd8) optionally patched, and report loop length, wrap-around and time readout.
usage: looper_sim.py <c.bin> <g.bin> <ram_20000000.bin> [capacity_samples]   (default: stock 0x6bac0)"""
import sys, struct, math, time
sys.path.insert(0, __import__('os').path.dirname(__file__))
from emu_host import HostMachine
c, g, r = [open(p, 'rb').read() for p in sys.argv[1:4]]
cap = int(sys.argv[4], 0) if len(sys.argv) > 4 else 0x6bac0
c = bytearray(c); struct.pack_into('<I', c, 0x8fd8 - 0x4000, cap); c = bytes(c)
S = 0x20004850
hm = HostMachine(c, g, r)
need = (cap * 2 + 0xfff) & ~0xfff        # emu.py maps the first 1 MB of 0x29000000 already
if need > 0x100000: hm.uc.mem_map(0x29100000, need - 0x100000)
hm.call(0x8f7e, [S]); print('after init: cap', hm.read32(S + 0x2c), 'base', hex(hm.read32(S + 0x28)))
hm.uc.mem_write(S + 4, bytes([1, 1])); hm.uc.mem_write(S + 8, bytes([1, 1]))   # +4/+5 requested and +8/+9 active must match, else 0x8fec clears the loop each block      # mode 1 = 22.05 kHz mono (stock behaviour per the owner: 20 s)
hm.write32(S + 0x34, 0)
hm.uc.mem_write(S + 0, bytes([0x10]))                                   # request: start recording
blk, out = 0x20008000, 0x20009000
hm.writef(blk, [0.3 * math.sin(2 * math.pi * 440 * (i // 2) / 44100) for i in range(128)])
t0 = time.time(); last = None; n = 0
def st(): return hm.uc.mem_read(S + 1, 1)[0]
while n < 200000:
    hm.call(0x8b8c, [blk, out, 64, 1], max_insns=3_000_000); n += 1
    s = st()
    if s != last: print(f'block {n}: state -> {s} pos={hm.read32(S+0x34)} len={hm.read32(S+0x30)}'); last = s
    if s == 3: break
print(f'record phase: {n} blocks = {n*64/44100:.2f} s, loop length {hm.read32(S+0x30)} samples, pos {hm.read32(S+0x34)}, err={hm.error}')
ms = hm.call(0x9810, []); print('0x9810 elapsed(ms?) =', ms, ' 0x9840 =', hm.call(0x9840, []))
wraps = 0; prev = hm.read32(S + 0x34)
for k in range(n + 5):
    hm.call(0x8b8c, [blk, out, 64, 1], max_insns=3_000_000); p = hm.read32(S + 0x34)
    if p < prev: wraps += 1; print(f'play: wrapped at block {k}: pos {prev} -> {p}'); break
    prev = p
print(f'play wrap ok={wraps==1} state={st()} elapsed {time.time()-t0:.1f}s')
