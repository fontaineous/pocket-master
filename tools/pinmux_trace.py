#!/usr/bin/env python3
"""Run the firmware's clock/PLL setup (flash 0x5d48) and pin-mux setup (0x5db8) in the emulator and print the final register
values and the decoded 4-bit function fields.  usage: pinmux_trace.py <c.bin> <g.bin> <ram_20000000.bin>"""
import sys, collections
sys.path.insert(0, __import__('os').path.dirname(__file__))
from emu_host import HostMachine
from unicorn import UC_HOOK_MEM_WRITE
c, g, r = [open(p, 'rb').read() for p in sys.argv[1:4]]
hm = HostMachine(c, g, r)
log = []
hm.uc.hook_add(UC_HOOK_MEM_WRITE, lambda u, a, ad, sz, v, ud: log.append((ad, v & 0xffffffff)) if 0x40000000 <= ad < 0x40100000 else None)
def run(title, addr):
    log.clear(); ret = hm.call(addr, [], max_insns=200000)
    print(f'## {title} err={hm.error} writes={len(log)}'); last = collections.OrderedDict()
    for a, v in log: last[a] = v
    for a, v in last.items(): print(f'  {a:#010x} = {v:#010x}')
    return last
run('clock/PLL setup 0x5d48', 0x5d48)
st = run('pin-mux setup 0x5db8', 0x5db8)
print('\n4-bit function fields (value per pin index, only non-zero):')
for a, v in st.items():
    if a in (0x40011018, 0x4001101c, 0x40011024, 0x40011028, 0x4001105c, 0x40011058, 0x40011054):
        print(f'  {a:#x}: ' + ' '.join(f'p{i}={(v >> 4*i) & 0xf:x}' for i in range(8) if (v >> 4*i) & 0xf))
