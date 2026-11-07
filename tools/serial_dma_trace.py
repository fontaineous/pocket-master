#!/usr/bin/env python3
"""Run the firmware's own SerialDma_Init (flash 0x9900) and SerialDma_Start (0x99e8) in the emulator and decode every
peripheral register write: DMA channel descriptors (0x40020100+0x20n), request IDs (0x40020224/228), DMA enable, and the serial
instance registers (0x4000B000+n*0x1000).  usage: serial_dma_trace.py <c.bin> <g.bin> <ram_20000000.bin>"""
import sys, struct
sys.path.insert(0, __import__('os').path.dirname(__file__))
from emu_host import HostMachine
from unicorn import UC_HOOK_MEM_WRITE
c, g, r = [open(p, 'rb').read() for p in sys.argv[1:4]]
hm = HostMachine(c, g, r)
log = []
def hw(u, access, address, size, value, ud):
    if 0x40000000 <= address < 0x40100000 or 0xe000e000 <= address < 0xe000f000: log.append((address, size, value & 0xffffffff))
def name(a):
    if 0x40020100 <= a < 0x40020200:
        ch, off = divmod(a - 0x40020100, 0x20)
        return f'DMA.ch{ch}+{off:#x} (' + {0: 'ctrl', 4: 'cfg', 8: 'src', 0xc: 'dst', 0x10: '?', 0x14: 'count'}.get(off, '?') + ')'
    if 0x40020000 <= a < 0x40020100: return f'DMA+{a-0x40020000:#x} (' + {0x20: 'busy', 0x24: 'enable', 0x28: 'sync'}.get(a - 0x40020000, '?') + ')'
    if 0x40020200 <= a < 0x40020300: return f'DMA+{a-0x40020000:#x} (req-id)'
    if 0x4000b000 <= a < 0x4000e000:
        n, off = divmod(a - 0x4000b000, 0x1000); return f'SER{n}+{off:#x}'
    return f'{a:#x}'
def run(title, addr, args):
    log.clear(); h = hm.uc.hook_add(UC_HOOK_MEM_WRITE, hw)
    ret = hm.call(addr, args); hm.uc.hook_del(h)
    print(f'## {title}  ret={ret:#x} err={hm.error}')
    for a, s, v in log: print(f'  {name(a):28s} <= {v:#010x}')
# cfg struct as built by the board init at 0x5bb0: {rx buffer, tx buffer, length}
CFG = 0x20007000
for i, v in enumerate((0x200023bc, 0x200027bc, 0x200)): hm.write32(CFG + 4 * i, v)
run('SerialDma_Init(n=1, {rx=0x200023bc, tx=0x200027bc, len=0x200})', 0x9900, [1, CFG])
run('SerialDma_Start(n=1, rx=0x1001fc00, tx=0x1001fe00, len=0x200)', 0x99e8, [1, 0x1001fc00, 0x1001fe00, 0x200])
