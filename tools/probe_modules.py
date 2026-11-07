#!/usr/bin/env python3
"""Behavioural probe of every effect module, run inside the firmware's own loader + the module code (emulated).

For each (slot, index): load via the real loader, set parameters, run 64-frame stereo float blocks and measure
  - impulse response: energy, delay of the peak, samples until 99% of energy, number of echo peaks
  - 1 kHz sine gain at three input levels (linearity => drive/compression/clipping) and bypass-ness
  - crude frequency response from the impulse response (low / mid / high band gain)
usage: probe_modules.py <c.bin> <g.bin> <ram.bin> [slot ...]   (markdown table to stdout)
"""
import sys, math
import numpy as np
sys.path.insert(0, __import__('os').path.dirname(__file__))
from emu_host import HostMachine
FS = 44100.0; BLK = 64
def run(hm, slot, signal, params, entry1=True):
    hm.load_module(slot, hm._cur_idx)
    hm.set_params(slot, params)
    if entry1: hm.call_entry(slot, 1, [hm.params_addr(slot), 0, 0, 0])
    out = []
    n = len(signal) // BLK
    for b in range(n):
        blk = signal[b * BLK:(b + 1) * BLK]
        inter = np.empty(BLK * 2, dtype=np.float32); inter[0::2] = blk; inter[1::2] = blk   # same signal on L and R
        o = np.array(hm.process(slot, inter.tolist()), dtype=np.float32)
        if hm.error is not None: raise RuntimeError(f'{hm.error} pc={hm.pc:#x}')
        out.append(o[0::2])
    return np.concatenate(out)
def metrics(hm, slot, params):
    imp = np.zeros(BLK * 120, dtype=np.float32); imp[0] = 1.0
    ir = run(hm, slot, imp, params)
    e = float(np.sum(ir ** 2)); pk = int(np.argmax(np.abs(ir))); amp = float(np.max(np.abs(ir)))
    cum = np.cumsum(ir ** 2) / (e + 1e-30); t99 = int(np.searchsorted(cum, 0.99)) if e > 0 else 0
    peaks = int(np.sum((np.abs(ir[1:-1]) > 0.1 * amp) & (np.abs(ir[1:-1]) >= np.abs(ir[:-2])) & (np.abs(ir[1:-1]) >= np.abs(ir[2:])))) if amp > 0 else 0
    gains = []
    for a in (0.05, 0.3, 0.9):
        t = np.arange(BLK * 60) / FS; s = (a * np.sin(2 * np.pi * 1000 * t)).astype(np.float32)
        y = run(hm, slot, s, params)
        gains.append(float(np.sqrt(np.mean(y[BLK * 30:] ** 2)) / (a / math.sqrt(2) + 1e-30)))
    spec = np.abs(np.fft.rfft(ir[:4096], 4096)); f = np.fft.rfftfreq(4096, 1 / FS)
    band = lambda lo, hi: float(np.mean(spec[(f >= lo) & (f < hi)])) if amp > 0 else 0.0
    return dict(energy=e, peak_at=pk, peak=amp, t99=t99, echoes=peaks, g_lo=gains[0], g_mid=gains[1], g_hi=gains[2],
                lf=band(50, 300), mf=band(300, 3000), hf=band(3000, 15000))
if __name__ == '__main__':
    c, g, r = [open(p, 'rb').read() for p in sys.argv[1:4]]
    slots = [int(x) for x in sys.argv[4:]] or list(range(0, 9))
    hm = HostMachine(c, g, r)
    print('| slot | idx | size | params | energy | peak@ | peak | t99 | echoes | gain .05/.3/.9 | LF | MF | HF |'); print('|' + '---|' * 13)
    for slot in slots:
        for idx in range(len(hm.groups[slot])):
            hm._cur_idx = idx
            for label, params in (('50', [50.0] * 8),):
                try:
                    m = metrics(hm, slot, params)
                    sz = hm._end_of(hm.groups[slot][idx]) - hm.groups[slot][idx]
                    print(f"| {slot} | {idx} | {sz} | {label} | {m['energy']:.3g} | {m['peak_at']} | {m['peak']:.3g} | {m['t99']} | {m['echoes']} | {m['g_lo']:.2f}/{m['g_mid']:.2f}/{m['g_hi']:.2f} | {m['lf']:.3g} | {m['mf']:.3g} | {m['hf']:.3g} |", flush=True)
                except Exception as ex:
                    print(f'| {slot} | {idx} | | {label} | ERROR {ex} | | | | | | | | |', flush=True)
