#!/usr/bin/env python3
"""Run the firmware's looper record function (flash 0x9324: float stereo block -> int16 loop buffer at 0x29000000) in the emulator
for loop mode byte state+8 = 1 and 2 and report how far the write position (state+0x34, in int16 samples) advances per 64-frame
block.  State struct is at 0x20004850; capacity constant state+0x2c = 0x6bac0.  usage: looper_probe.py <c.bin> <g.bin> <ram_20000000.bin>"""
import sys, struct, math
sys.path.insert(0, __import__('os').path.dirname(__file__))
from emu_host import HostMachine
c, g, r = [open(p, 'rb').read() for p in sys.argv[1:4]]
S = 0x20004850
for D in (1, 2):
    hm = HostMachine(c, g, r)
    try: hm.uc.mem_map(0x29000000, 0xe0000)
    except Exception: pass
    hm.uc.mem_write(S + 0x28, struct.pack('<II', 0x29000000, 0x6bac0))
    hm.uc.mem_write(S + 8, bytes([D]))
    hm.uc.mem_write(S + 0x18, struct.pack('<ff', 0.0, 1.0)); hm.uc.mem_write(S + 0x20, struct.pack('<f', 1.0))
    blk = 0x20008000
    hm.writef(blk, [0.5 * math.sin(2 * math.pi * 1000 * (i // 2) / 44100) for i in range(128)])
    hm.write32(S + 0x34, 0)
    for k in range(3):
        hm.call(0x9324, [blk, 0x20009000, 64], max_insns=2_000_000)
        print(f'mode byte={D}: after block {k+1} pos={hm.read32(S+0x34)} err={hm.error}')
    print('  capacity 0x6bac0 =', 0x6bac0, 'int16 samples; blocks to fill =', 0x6bac0 // max(1, hm.read32(S+0x34) // 3))
