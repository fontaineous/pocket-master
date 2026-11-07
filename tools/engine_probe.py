#!/usr/bin/env python3
"""Run audio through the firmware's own block engine (emulated): mono int32 input at IO+8 -> 64-frame blocks -> packed 16-bit stereo output at 0x200027bc.
  from engine_probe import Engine
  e = Engine(c, g, ram); e.configure(selection={slot: idx}, params={slot: [..8 floats..]}, enabled=[slots])
  y = e.run(x)            # x: float32 mono samples in [-1, 1]; returns (L, R) float arrays
"""
import sys, struct, math
import numpy as np
sys.path.insert(0, __import__('os').path.dirname(__file__))
from emu_host import HostMachine
IO = 0x200029bc; OUT = 0x200027bc; STATE = 0x20002af4
SCALE_IN = float(1 << 28)           # int32 full-scale used by the engine's float conversion (empirical: 1.0 -> 2^28)
class Engine:
    def __init__(self, c, g, ram):
        self.hm = HostMachine(c, g, ram); self.blocks = 0
    def configure(self, selection=None, params=None, enabled=None, nslots=9):
        hm = self.hm; hm.init_chain(selection, params, nslots)
        mask = sum(1 << s for s in (enabled if enabled is not None else range(nslots)))
        hm.write32(STATE + 0x188, mask)
    def run(self, x, warm=120):
        hm = self.hm; x = np.asarray(x, dtype=np.float64); out = []
        n = (len(x) // 64) * 64
        for b in range(warm + n // 64):
            blk = x[(b - warm) * 64:(b - warm + 1) * 64] if b >= warm else np.zeros(64)
            hm.uc.mem_write(IO + 8, struct.pack('<64i', *[int(max(-2**31, min(2**31 - 1, v * SCALE_IN))) for v in blk]))
            hm.uc.mem_write(IO + 0x12d, bytes([1]))
            hm.run_engine()
            if hm.error: raise RuntimeError(f'engine fault {hm.error} pc={hm.pc:#x} block {b}')
            if b >= warm:
                o = np.frombuffer(bytes(hm.uc.mem_read(OUT, 256)), dtype='<i2').astype(np.float64) / 32768.0
                out.append(o)
        o = np.concatenate(out) if out else np.zeros(0)
        return o[0::2], o[1::2]
if __name__ == '__main__':
    c, g, r = [open(p, 'rb').read() for p in sys.argv[1:4]]
    FS = 44100.0
    t = np.arange(64 * 40) / FS
    for label, enabled in (('all slots', None), ('no modules', [])):
        e = Engine(c, g, r); e.configure(enabled=enabled)
        res = []
        for a in (0.01, 0.05, 0.2, 0.5):
            x = a * np.sin(2 * np.pi * 1000 * t)
            L, R = e.run(x, warm=0 if res else 120)
            y = L[64 * 20:]; res.append((a, float(np.sqrt(np.mean(y ** 2)) / (a / math.sqrt(2) + 1e-30))))
        print(label, 'gain(level):', [(a, round(g_, 3)) for a, g_ in res])
