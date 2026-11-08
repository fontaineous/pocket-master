#!/usr/bin/env python3
"""Run every probe of tools/module_catalog.py over all overlay modules and write one JSON (docs/dsp_module_catalog.json).
Adds: amplitude/frequency modulation test, per-module RAM state beyond the payload, data-window write ranges (groups 2-5),
parameter indices read by ENTRY1/ENTRY2, resident-library references, delay character, reverb decay, FX probes, group 9 (clone).
usage: module_catalog_full.py <c.bin> <g.bin> <ram_20000000.bin> <out.json>"""
import sys, json, struct, re, math
import numpy as np
sys.path.insert(0, __import__('os').path.dirname(__file__))
import module_catalog as mc
from module_catalog import HostMachine, blocks, BLK, FS
from unicorn import UC_HOOK_MEM_WRITE
from capstone import *

def modtest(hm, slot, idx, params, f0=1000.0, secs=4.0):
    n = BLK * int(secs * FS / BLK); t = np.arange(n) / FS; s = (0.2 * np.sin(2 * np.pi * f0 * t)).astype(np.float32)
    y = blocks(hm, slot, s, params, idx)[BLK * 100:]
    if np.max(np.abs(y)) < 1e-6: return dict(silent=True)
    w = 220; env = np.sqrt(np.convolve(y ** 2, np.ones(w) / w, 'valid'))[::w]; am = float((env.max() - env.min()) / (env.max() + env.min() + 1e-12))
    zc = np.where((y[:-1] < 0) & (y[1:] >= 0))[0]; fi = FS / np.diff(zc); fm = float(np.std(fi)) if len(fi) > 5 else 0.0
    sp = np.abs(np.fft.rfft(y * np.hanning(len(y)))) ** 2; f = np.fft.rfftfreq(len(y), 1 / FS); k = int(np.argmax(sp)); fp = float(f[k])
    side = float(1 - sp[(f > fp - 10) & (f < fp + 10)].sum() / sp[f > 20].sum())
    return dict(am=round(am, 3), fm_hz=round(fm, 1), f_peak=round(fp, 1), sideband=round(side, 3))

def scan(hm, g, slot, idx, md):
    off = hm.groups[slot][idx]; blob = g[off:hm._end_of(off)]; hs, pl, tot, w3, e1, e2 = struct.unpack_from('<6I', blob, 0)
    base = hm.read32(hm.desc(slot)); code = blob[hs:hs + pl]
    def params_used(entry, reg):
        o = (entry & ~1) - base; seen = set(); k = 0
        for i in md.disasm(code[o:o + 240], entry & ~1):
            m = re.match(rf'vldr\s+\w+, \[{reg}(?:, #(0x[0-9a-f]+|\d+))?\]', f'{i.mnemonic} {i.op_str}')
            if m: seen.add(int(m.group(1), 0) // 4 if m.group(1) else 0)
            k += 1
            if k > 70: break
        return sorted(seen)
    lib = 0; lastw = {}
    for i in md.disasm(code, base):
        m = re.match(r'mov[wt]\s+(\w+), #(0x[0-9a-f]+|\d+)', f'{i.mnemonic} {i.op_str}')
        if m:
            rr, v = m.group(1), int(m.group(2), 0)
            if i.mnemonic == 'movw': lastw[rr] = v
            elif v == 0x1001 and lastw.get(rr) in (0x8800, 0x8804): lib += 1
    lib += sum(1 for w in struct.unpack_from('<%dI' % (len(code) // 4), code, 0) if w in (0x10018800, 0x10018804))
    chg, chw = state_extent(hm, slot, idx, g)
    state = (max(chg) + 1 - (base + pl)) if chg else 0
    win = [hex(min(chw)), hex(max(chw) + 1)] if chw else None
    return dict(lib_refs=lib, state_bytes=state, data_window=win, window_bytes_changed=len(chw), params_entry1=params_used(e1, 'r0'), params_entry2=params_used(e2, 'r2'))

def state_extent(hm, slot, idx, g, blocks_n=24):
    """RAM touched by a module (no write hooks: they break multi-register stores in this unicorn build).
    Slot RAM beyond the payload (slots 0-7) is pre-filled with 0xA5 after loading; data windows (0x28000000) are compared by snapshot.
    Returns (changed offsets in slot RAM beyond payload, changed offsets in the data windows)."""
    hm.load_module(slot, idx); hm.set_params(slot, [50] * 8)
    off = hm.groups[slot][idx]; blob = g[off:hm._end_of(off)]; pl = struct.unpack_from('<I', blob, 4)[0]
    base = hm.read32(hm.desc(slot)); end = base + pl; top = 0x10018400 if slot < 8 else end
    if top > end: hm.uc.mem_write(end, b'\xa5' * (top - end))
    win0 = bytes(hm.uc.mem_read(0x28000000, 0x8000))
    hm.call_entry(slot, 1, [hm.params_addr(slot), 0, 0, 0]); rng = np.random.default_rng(7)
    for b in range(blocks_n): hm.process(slot, (0.1 * rng.standard_normal(128)).astype(np.float32).tolist())
    after = bytes(hm.uc.mem_read(end, top - end)) if top > end else b''
    chg = [end + i for i, v in enumerate(after) if v != 0xa5]
    win1 = bytes(hm.uc.mem_read(0x28000000, 0x8000)); chw = [0x28000000 + i for i in range(0x8000) if win0[i] != win1[i]]
    return chg, chw


if __name__ == '__main__':
    c, g, r = [open(p, 'rb').read() for p in sys.argv[1:4]]; out = sys.argv[4]
    hm = HostMachine(c, g, r); md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS); md.skipdata = True
    res = {}
    for slot in range(0, 9):
        for idx in range(len(hm.groups[slot])):
            off = hm.groups[slot][idx]; blob = g[off:hm._end_of(off)]; hs, pl, tot, w3, e1, e2 = struct.unpack_from('<6I', blob, 0)
            rec = dict(group=slot, idx=idx, blob=len(blob), header=hs, payload=pl, data_block=w3, entry1=hex(e1), entry2=hex(e2), slot_base=hex(hm.read32(hm.desc(slot))))
            hm2 = HostMachine(c, g, r)          # fresh machine: the data windows keep earlier writes, so measure them first
            rec.update(scan(hm2, g, slot, idx, md))
            c1, cb_, cmax = mc.cost(hm, slot, idx, [50] * 8); rec.update(cost_entry1=c1, cost_block=cb_, cost_max=cmax)
            rec['behave'] = mc.behave(hm, slot, idx, [50] * 8)
            if slot in (0, 1, 6):
                rec['fx'] = mc.fx_probe(hm, slot, idx); rec['mod'] = {pv: modtest(hm, slot, idx, [pv] * 8) for pv in (50, 100, 0)}
            if slot == 7:
                rec['delay_burst'] = {t: mc.delay_probe(hm, idx, t) for t in (5, 100, 1000)}; rec['delay_char'] = mc.delay_character(hm, idx)
            if slot == 8:
                rec['reverb'] = {k: mc.reverb_decay(hm, idx, [100] + [v] * 7) for k, v in (('p0', 0), ('p50', 50), ('p100', 100))}
            res[f'{slot}.{idx}'] = rec; print(slot, idx, flush=True)
    # group 9 (clone engine): loaded through the real loader as slot 9
    off = hm.groups[9][0]; blob = g[off:hm._end_of(off)]; hs, pl, tot, w3, e1, e2 = struct.unpack_from('<6I', blob, 0)
    hm.load_module(9, 0); hm.set_params(9, [50] * 8); hm.call_entry(9, 1, [hm.params_addr(9), 0, 0, 0], count_insns=True); c1 = hm.icount
    a = hm.arg_block; hm.writef(hm.buf, [0.1] * 128); hm.write32(a, hm.buf); hm.write32(a + 4, 0); hm.write32(a + 8, 64); hm.write32(a + 0xc, hm.params_addr(9)); hm.write32(a + 0x10, 1); hm.write32(a + 0x14, 0)
    hm.call_entry(9, 2, [hm.buf, 64, hm.params_addr(9), 0], stack_args=[a + 0x10, a + 0x14, a + 0x18], count_insns=True)
    res['9.0'] = dict(group=9, idx=0, blob=len(blob), header=hs, payload=pl, data_block=w3, entry1=hex(e1), entry2=hex(e2), slot_base=hex(hm.read32(hm.desc(9))), cost_entry1=c1, cost_block=hm.icount, output_equals_input=bool(abs(hm.readf(hm.buf, 1)[0] - 0.1) < 1e-6))
    json.dump(res, open(out, 'w'), indent=1, default=str)
