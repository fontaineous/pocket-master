#!/usr/bin/env python3
"""Parameter sensitivity sweep for every effect module (emulated).
For each (slot, index, param i): run with p_i in VALUES (other params = BASE) and classify what changes:
  level   : 1 kHz gain at a mid input level
  drive   : nonlinearity (gain at 0.9 / gain at 0.05)
  tone    : high/low-frequency balance of the impulse response
  time    : impulse peak position or 99%-energy time
  none    : output unchanged
usage: sweep_params.py <c.bin> <g.bin> <ram.bin> [slot ...]  (markdown to stdout)"""
import sys, math
import numpy as np
sys.path.insert(0, __import__('os').path.dirname(__file__))
from emu_host import HostMachine
from probe_modules import run, BLK, FS
VALUES = [0.0, 1.0, 25.0, 50.0, 100.0]; BASE = 50.0
def measure(hm, slot, params):
    imp = np.zeros(BLK * 60, dtype=np.float32); imp[0] = 1.0
    ir = run(hm, slot, imp, params)
    e = float(np.sum(ir ** 2)); amp = float(np.max(np.abs(ir)))
    cum = np.cumsum(ir ** 2) / (e + 1e-30); t99 = int(np.searchsorted(cum, 0.99)) if e > 0 else 0
    g = []
    for a in (0.05, 0.9):
        t = np.arange(BLK * 40) / FS; s = (a * np.sin(2 * np.pi * 1000 * t)).astype(np.float32)
        y = run(hm, slot, s, params); g.append(float(np.sqrt(np.mean(y[BLK * 20:] ** 2)) / (a / math.sqrt(2) + 1e-30)))
    spec = np.abs(np.fft.rfft(ir[:2048], 2048)); f = np.fft.rfftfreq(2048, 1 / FS)
    lf = float(np.mean(spec[(f >= 50) & (f < 400)])); hf = float(np.mean(spec[(f >= 3000) & (f < 15000)]))
    return dict(g_lo=g[0], g_hi=g[1], nl=g[1] / (g[0] + 1e-30), tone=(hf + 1e-9) / (lf + 1e-9), peak=int(np.argmax(np.abs(ir))), t99=t99, e=e)
def classify(ms):
    def spread(key):
        v = np.array([m[key] for m in ms], dtype=float); lo, hi = v.min(), v.max()
        return (hi - lo) / (abs(hi) + abs(lo) + 1e-9)
    tags = []
    if spread('g_lo') > 0.15: tags.append('level')
    if spread('nl') > 0.15: tags.append('drive')
    if spread('tone') > 0.15: tags.append('tone')
    if len({m['peak'] for m in ms}) > 1 or spread('t99') > 0.3: tags.append('time')
    return tags or ['none']
if __name__ == '__main__':
    c, g, r = [open(p, 'rb').read() for p in sys.argv[1:4]]
    slots = [int(x) for x in sys.argv[4:]] or list(range(0, 9))
    hm = HostMachine(c, g, r)
    print('| slot | idx | active params (p0..p7: effect) |'); print('|---|---|---|')
    for slot in slots:
        for idx in range(len(hm.groups[slot])):
            hm._cur_idx = idx; cells = []
            for i in range(8):
                try:
                    ms = []
                    for v in VALUES:
                        p = [BASE] * 8; p[i] = v; ms.append(measure(hm, slot, p))
                    tg = classify(ms)
                    if tg != ['none']: cells.append(f'p{i}: {"+".join(tg)}')
                except Exception as ex: cells.append(f'p{i}: ERR')
            print(f'| {slot} | {idx} | {"; ".join(cells) if cells else "none (all params inert at base 50)"} |', flush=True)
