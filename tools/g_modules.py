#!/usr/bin/env python3
"""Parse HTFW segment 'g': an index of effect-algorithm overlay modules for the Cortex-M co-processor.

Layout (little-endian words):
  0x00 u32 0x1463 (id/version?)   0x04 u32 file size   0x08 u32 data start (0x1d0)   0x0c u32 0xffffffff   0x10 u32 0xb0001ff   0x14 u32 0x40
  0x14..0x3c  11 pointers to group records  [count][count module offsets]   (group sizes 1,15,8,22,1,3,17,9,10,1,2)
  each offset points at a module: header (0x24 or 0x28 bytes)
     w0 header size, w1 payload size, w2 total size, w3 secondary size/offset,
     w4 Thumb entry #1 (0x1000xxxx|1), w5 Thumb entry #2, then Thumb code with absolute (0x1000xxxx) addresses.
  The module is linked to run at <slot base> (entry point & ~0xfff in practice); modules of one group share a slot.
usage: g_modules.py <g_segment.bin> [outdir]
"""
import struct, sys, os
d = open(sys.argv[1], 'rb').read()
out = sys.argv[2] if len(sys.argv) > 2 else None
w = struct.unpack_from('<%dI' % (struct.unpack_from('<I', d, 8)[0] // 4), d, 0)
# words 5..15: pointers (byte offsets inside the index) to the 11 group records [count][count module offsets]
ptrs = [x for x in w[5:16]]
groups = []
for p in ptrs:
    n = w[p // 4]; groups.append(list(w[p // 4 + 1: p // 4 + 1 + n]))
bounds = sorted({o for g in groups for o in g} | {len(d)})
print('groups:', [len(g) for g in groups])
print(f'{"grp":>3} {"idx":>3} {"offset":>8} {"size":>6} {"hdr":>4} {"payload":>7} {"w3":>6} {"entry1":>10} {"entry2":>10}  slot?')
for gi, g in enumerate(groups):
    for k, o in enumerate(g):
        nxt = min(b for b in bounds if b > o); blk = d[o:nxt]
        if len(blk) < 24:
            print(f'{gi:>3} {k:>3} {o:#08x} {len(blk):>6}  raw (stub)'); 
            if out:
                os.makedirs(out, exist_ok=True); open(os.path.join(out, f'g{gi:02d}_{k:02d}_{o:06x}.bin'), 'wb').write(blk)
            continue
        hs, pl, tot, w3, e1, e2 = struct.unpack_from('<6I', blk, 0)
        raw = hs != 0x24 and hs != 0x28
        slot = 0
        if not raw:
            # modules hold a pointer to base+payload (their own data area): infer the load base from it
            cnt = {}
            for q in range(0, len(blk) - 3, 4):
                v = struct.unpack_from('<I', blk, q)[0]
                if 0x10000000 <= v < 0x10020000 and ((v - pl) & 0xff) == 0: cnt[v - pl] = cnt.get(v - pl, 0) + 1
            slot = max(cnt, key=cnt.get) if cnt else 0
        print(f'{gi:>3} {k:>3} {o:#08x} {len(blk):>6} {hs if not raw else "raw":>4} {pl:>7} {w3:>#6x} {e1:#010x} {e2:#010x}  {slot:#x}')
        if out:
            os.makedirs(out, exist_ok=True)
            open(os.path.join(out, f'g{gi:02d}_{k:02d}_{o:06x}.bin'), 'wb').write(blk)
