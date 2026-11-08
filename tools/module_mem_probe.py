#!/usr/bin/env python3
"""Which external-memory addresses does each DSP module touch?  Loads every (slot, index) through the real loader, runs a few 64-frame
blocks and records the lowest/highest address read or written in the 0x29000000.. window (SDRAM) and the 0x28000000 data windows.
usage: module_mem_probe.py <c.bin> <g.bin> <ram.bin> [slot ...]"""
import sys
import numpy as np
sys.path.insert(0, __import__('os').path.dirname(__file__))
from emu_host import HostMachine
from unicorn import UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
c, g, r = [open(p, 'rb').read() for p in sys.argv[1:4]]
slots = [int(x) for x in sys.argv[4:]] or list(range(9))
hm = HostMachine(c, g, r)
lo = {}; hi = {}
def rec(kind):
    def f(uc, access, addr, size, value, ud):
        k = (kind, 'sdram' if 0x29000000 <= addr < 0x2a000000 else 'win' if 0x28000000 <= addr < 0x29000000 else ('w10' if kind == 'w' and 0x10000000 <= addr < 0x10100000 else ('w20' if kind == 'w' and 0x20000000 <= addr < 0x20100000 else None)))
        if k[1] is None: return
        lo[k[1]] = min(lo.get(k[1], addr), addr); hi[k[1]] = max(hi.get(k[1], addr), addr + size)
    return f
hm.uc.hook_add(UC_HOOK_MEM_READ, rec('r')); hm.uc.hook_add(UC_HOOK_MEM_WRITE, rec('w'))
print('| slot | idx | window span | sdram span | written in 0x1000xxxx | written in 0x2000xxxx |'); print('|---|---|---|---|---|---|')
for slot in slots:
    for idx in range(len(hm.groups[slot])):
        lo.clear(); hi.clear()
        try:
            hm.load_module(slot, idx); hm.set_params(slot, [50.0] * 8)
            hm.call_entry(slot, 1, [hm.params_addr(slot), 0, 0, 0])
            sig = np.zeros(128, dtype=np.float32); sig[0::2] = 0.3; sig[1::2] = 0.3
            for _ in range(6): hm.process(slot, sig.tolist())
            w = f"{lo['win']:#x}-{hi['win']:#x}" if 'win' in lo else '-'
            s = f"{lo['sdram']:#x}-{hi['sdram']:#x} ({hi['sdram']-lo['sdram']})" if 'sdram' in lo else '-'
            f10 = f"{lo['w10']:#x}-{hi['w10']:#x} ({hi['w10']-lo['w10']})" if 'w10' in lo else '-'
            f20 = f"{lo['w20']:#x}-{hi['w20']:#x} ({hi['w20']-lo['w20']})" if 'w20' in lo else '-'
            print(f'| {slot} | {idx} | {w} | {s} | {f10} | {f20} |', flush=True)
        except Exception as ex:
            print(f'| {slot} | {idx} | ERROR {ex} | |', flush=True)
