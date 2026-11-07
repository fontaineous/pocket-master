#!/usr/bin/env python3
"""Emulate the Keil scatter loader of HTFW segment 'c' (Cortex-M, linked at 0x4000) and dump the RAM image it builds.

Runs __main (0x44e0) up to the C-runtime entry (0x45c4) with unicorn, so ARM's own decompressor routines do the work.
Outputs: <out>/ram_20000000.bin (RAM after scatter load), <out>/regions.txt (region table as executed)
usage: c_unpack.py <c_segment.bin> <outdir>
"""
import struct, sys, os
from unicorn import *
from unicorn.arm_const import *
BASE = 0x4000; MAIN = 0x44e0; RT_ENTRY = 0x45c4
seg, out = sys.argv[1:3]
img = open(seg, 'rb').read(); os.makedirs(out, exist_ok=True)
uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
uc.mem_map(0, 0x100000)                       # flash/ROM view incl. 0x4000.. image (low addresses)
uc.mem_write(BASE, img)
uc.mem_map(0x20000000, 0x100000)              # SRAM
uc.mem_map(0xE0000000, 0x100000)              # system control space (plain memory)
uc.mem_map(0x10000000, 0x100000)              # secondary RAM seen in the region table (zero-init at 0x1001f400)
uc.mem_map(0x29000000, 0x100000 * 1)          # large zero-init region at 0x29000000 (size 0xd7580)
sp = struct.unpack_from('<I', img, 0x400)[0]
uc.reg_write(UC_ARM_REG_SP, sp)
log = []
def hook_code(u, addr, size, ud):
    if addr == 0x44fe + 0 - 0:  pass
uc.hook_add(UC_HOOK_CODE, hook_code)
try:
    uc.emu_start(MAIN | 1, RT_ENTRY, timeout=60_000_000, count=5_000_000)
except UcError as e:
    print('emulation stopped:', e, 'pc=%#x' % uc.reg_read(UC_ARM_REG_PC)); 
pc = uc.reg_read(UC_ARM_REG_PC)
print('stopped at pc=%#x (target %#x)' % (pc, RT_ENTRY))
ram = uc.mem_read(0x20000000, 0x20000)
open(os.path.join(out, 'ram_10000000.bin'), 'wb').write(bytes(uc.mem_read(0x1001f000, 0x1000)))
open(os.path.join(out, 'ram_20000000.bin'), 'wb').write(bytes(ram))
# region table as the loader sees it
tab_base = 0x4514
w0, w1 = struct.unpack_from('<II', img, tab_base - BASE)
sl, fp = tab_base + w0, tab_base + w1
with open(os.path.join(out, 'regions.txt'), 'w') as f:
    f.write('table %#x..%#x\n' % (sl, fp))
    a = sl
    while a < fp:
        r0, r1, r2, r3 = struct.unpack_from('<IIII', img, a - BASE)
        handler = (sl - 1 - r3) & 0xffffffff if r3 & 1 == 0 else r3
        f.write('src=%#x dst=%#x size=%#x handler=%#x (raw %#x)\n' % (r0, r1, r2, handler, r3)); a += 16
print(open(os.path.join(out, 'regions.txt')).read())
