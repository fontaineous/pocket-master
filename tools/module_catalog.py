#!/usr/bin/env python3
"""Catalog of the overlay modules of segment g (Cortex-M co-processor): static header data, CPU cost and measured behaviour.

For every (group, index) the REAL firmware loader (emulated) loads the module, ENTRY1 sets parameters, ENTRY2 processes 64-frame
stereo float blocks.  Measured per module:
  - sizes (header / payload / data block), entry points, slot base
  - instructions per 64-frame block (ENTRY2 only, warmed with noise) and for ENTRY1
  - impulse response metrics (peak, energy, t99, echoes), 1 kHz gain at three levels (linearity), dominant output frequency for a 440 Hz sine
  - delay modules (group 7): first echo / maximum delay / feedback behaviour with p0=mix, p1=time(ms), p2=feedback
  - reverb modules (group 8): decay time (-60 dB) from an impulse
usage: module_catalog.py <c.bin> <g.bin> <ram_20000000.bin> [json_out]
"""
import sys, json, math, struct
import numpy as np
sys.path.insert(0, __import__('os').path.dirname(__file__))
from emu_host import HostMachine
FS, BLK = 44100.0, 64

def blocks(hm, slot, sig, params, warm_idx):
    hm.load_module(slot, warm_idx); hm.set_params(slot, params)
    hm.call_entry(slot, 1, [hm.params_addr(slot), 0, 0, 0])
    out = []
    for b in range(len(sig) // BLK):
        x = sig[b * BLK:(b + 1) * BLK]; inter = np.empty(BLK * 2, np.float32); inter[0::2] = x; inter[1::2] = x
        o = np.array(hm.process(slot, inter.tolist()), np.float32)
        if hm.error is not None: raise RuntimeError(f'{hm.error} pc={hm.pc:#x}')
        out.append(o[0::2])
    return np.concatenate(out)

def cost(hm, slot, idx, params):
    hm.load_module(slot, idx); hm.set_params(slot, params)
    hm.call_entry(slot, 1, [hm.params_addr(slot), 0, 0, 0], count_insns=True); c1 = hm.icount
    rng = np.random.default_rng(1); costs = []
    for b in range(6):
        blk = (0.1 * rng.standard_normal(BLK * 2)).astype(np.float32)
        hm.writef(hm.buf, blk.tolist()); a = hm.arg_block
        hm.write32(a, hm.buf); hm.write32(a + 4, 0); hm.write32(a + 8, BLK); hm.write32(a + 0xc, hm.params_addr(slot)); hm.write32(a + 0x10, 1); hm.write32(a + 0x14, 0)
        hm.call_entry(slot, 2, [hm.buf, BLK, hm.params_addr(slot), 0], stack_args=[a + 0x10, a + 0x14, a + 0x18], count_insns=True); costs.append(hm.icount)
    return c1, int(np.median(costs[2:])), max(costs)

def dom_freq(y, f0=None):
    y = y[len(y) // 2:]
    if np.max(np.abs(y)) < 1e-6: return None
    s = np.abs(np.fft.rfft(y * np.hanning(len(y)))); f = np.fft.rfftfreq(len(y), 1 / FS)
    return float(f[int(np.argmax(s))])

def behave(hm, slot, idx, params):
    imp = np.zeros(BLK * 80, np.float32); imp[0] = 1.0
    ir = blocks(hm, slot, imp, params, idx)
    e = float(np.sum(ir ** 2)); amp = float(np.max(np.abs(ir))) if e > 0 else 0.0
    cum = np.cumsum(ir ** 2) / (e + 1e-30); t99 = int(np.searchsorted(cum, 0.99)) if e > 0 else 0
    gains = []
    for a in (0.03, 0.3, 0.9):
        t = np.arange(BLK * 50) / FS; s = (a * np.sin(2 * np.pi * 1000 * t)).astype(np.float32)
        y = blocks(hm, slot, s, params, idx); gains.append(float(np.sqrt(np.mean(y[BLK * 25:] ** 2)) / (a / math.sqrt(2))))
    t = np.arange(BLK * 80) / FS; s = (0.3 * np.sin(2 * np.pi * 440 * t)).astype(np.float32)
    y = blocks(hm, slot, s, params, idx)
    return dict(imp_energy=e, imp_peak=amp, imp_t99=t99, gain_03=gains[0], gain_3=gains[1], gain_9=gains[2], f_440=dom_freq(y), out_rms_440=float(np.sqrt(np.mean(y[BLK*40:]**2))))

def delay_probe(hm, idx, tms, mix=100, fb=50):
    """Tone burst (10 ms, 1 kHz) through the delay with mix=100 (dry removed): returns echo envelope peaks as
    (position in samples @44.1k, amplitude relative to the first echo).  The module runs at 22.05 kHz internally, so an impulse
    is smeared to nothing; a burst is needed."""
    n = BLK * int(math.ceil((tms * 3.2 + 150) * 44.1 / BLK)); x = np.zeros(n, np.float32)
    x[:441] = 0.5 * np.sin(2 * np.pi * 1000 * np.arange(441) / FS)
    y = blocks(hm, 7, x, [mix, tms, fb, 50, 50, 50, 50, 50], idx)
    env = np.convolve(np.abs(y), np.ones(60) / 60, 'same'); pk = float(np.max(env))
    if pk < 1e-4: return [], []
    # local maxima above 20 % of the largest, at least 200 samples apart
    cand = [i for i in range(1, n - 1) if env[i] >= 0.2 * pk and env[i] >= env[i - 1] and env[i] > env[i + 1]]
    sel = []
    for i in cand:
        if not sel or i - sel[-1] > 200: sel.append(i)
    sel = sel[:4]
    return [int(i) for i in sel], [round(float(env[i] / env[sel[0]]), 2) for i in sel]

def reverb_probe(hm, idx, decay):
    imp = np.zeros(BLK * 700, np.float32); imp[0] = 0.5
    y = blocks(hm, 8, imp, [100, decay, 50, 50, 50, 50, 50, 50], idx)
    en = np.convolve(y ** 2, np.ones(441) / 441, 'same'); pk = float(np.max(en))
    if pk <= 0: return None
    db = 10 * np.log10(en / pk + 1e-30); below = np.where(db < -60)[0]; below = below[below > int(np.argmax(en))]
    return float(below[0] / FS) if len(below) else float(len(y) / FS)

if __name__ == '__main__':
    c, g, r = [open(p, 'rb').read() for p in sys.argv[1:4]]
    out = sys.argv[4] if len(sys.argv) > 4 else None
    hm = HostMachine(c, g, r); res = []
    for slot in range(0, 9):
        for idx in range(len(hm.groups[slot])):
            hm.load_module(slot, idx)
            rec = dict(group=slot, idx=idx)
            off = hm.groups[slot][idx]; blob = g[off:hm._end_of(off)]
            hs, pl, tot, w3, e1, e2 = struct.unpack_from('<6I', blob, 0)
            rec.update(blob=len(blob), header=hs, payload=pl, data=w3, entry1=e1, entry2=e2, slot_base=hm.read32(hm.desc(slot)))
            try:
                c1, c2, cmax = cost(hm, slot, idx, [50] * 8); rec.update(cost_entry1=c1, cost_block=c2, cost_max=cmax)
                rec['behave'] = behave(hm, slot, idx, [50] * 8)
                if slot == 7:
                    rec['delay'] = dict(t100=delay_probe(hm, idx, 100), t1000=delay_probe(hm, idx, 1000), t5=delay_probe(hm, idx, 5))
                if slot == 8:
                    rec['rt60'] = dict(d0=reverb_probe(hm, idx, 0), d50=reverb_probe(hm, idx, 50), d100=reverb_probe(hm, idx, 100))
            except Exception as ex:
                rec['error'] = str(ex)
            res.append(rec); print(json.dumps(rec, default=str), flush=True)
    if out: json.dump(res, open(out, 'w'), indent=1, default=str)


# ---------------------------------------------------------------------------------------------------------------------------
# Extra probes used for the catalog write-up (FX modules, delay character, reverb decay)
BANDS = [(80, 160), (250, 500), (800, 1600), (2500, 5000), (6000, 10000), (12000, 18000)]
def band_levels(x, y):
    n = 8192; w = np.hanning(n); fx = np.zeros(n // 2 + 1); fy = np.zeros(n // 2 + 1)
    for k in range(0, len(x) - n, n // 2):
        fx += np.abs(np.fft.rfft(x[k:k + n] * w)) ** 2; fy += np.abs(np.fft.rfft(y[k:k + n] * w)) ** 2
    f = np.fft.rfftfreq(n, 1 / FS)
    return [round(10 * math.log10((fy[(f >= lo) & (f < hi)].sum() + 1e-30) / (fx[(f >= lo) & (f < hi)].sum() + 1e-30)), 1) for lo, hi in BANDS]

def fx_probe(hm, slot, idx, params=None):
    params = params or [50] * 8
    rng = np.random.default_rng(3); x = (0.05 * rng.standard_normal(BLK * 700)).astype(np.float32)
    y = blocks(hm, slot, x, params, idx); lv = band_levels(x[BLK * 100:], y[BLK * 100:])
    # time variation (modulation): std over time of the 1-3 kHz level in 50 ms frames, in dB
    n = 2205; fr = [10 * math.log10(np.sum(y[k:k + n] ** 2) / (np.sum(x[k:k + n] ** 2) + 1e-30) + 1e-30) for k in range(BLK * 100, len(y) - n, n)]
    modidx = float(np.std(fr))
    # pitch: 440 Hz tone, long FFT
    t = np.arange(BLK * 400) / FS; s = (0.2 * np.sin(2 * np.pi * 440 * t)).astype(np.float32)
    ys = blocks(hm, slot, s, params, idx)[BLK * 100:]
    sp = np.abs(np.fft.rfft(ys * np.hanning(len(ys)))); f = np.fft.rfftfreq(len(ys), 1 / FS)
    top = float(f[int(np.argmax(sp))]); thd = None
    if sp.max() > 0:
        k0 = int(np.argmax(sp)); h = [sp[min(len(sp) - 1, k0 * m)] for m in (2, 3)]; thd = round(float(np.sqrt(h[0] ** 2 + h[1] ** 2) / sp[k0]), 3)
    # level dependence and dynamics: step 0.02 -> 0.5 -> 0.02 (1 kHz)
    st = np.concatenate([0.02 * np.sin(2 * np.pi * 1000 * np.arange(BLK * 120) / FS), 0.5 * np.sin(2 * np.pi * 1000 * np.arange(BLK * 120) / FS), 0.02 * np.sin(2 * np.pi * 1000 * np.arange(BLK * 200) / FS)]).astype(np.float32)
    ysd = blocks(hm, slot, st, params, idx); e = lambda a, b: float(np.sqrt(np.mean(ysd[a * BLK:b * BLK] ** 2)))
    g = lambda a, b, ref: e(a, b) / ref
    gl, gm, gh = g(100, 120, 0.02 / math.sqrt(2)), g(220, 240, 0.5 / math.sqrt(2)), g(430, 440, 0.02 / math.sqrt(2))
    return dict(bands_db=lv, modulation_db=round(modidx, 2), f_out_440=round(top, 1), harm=thd, gain_quiet=round(gl, 2), gain_loud=round(gm, 2), gain_after=round(gh, 2))

def delay_character(hm, idx, t=100):
    """continuous 1 kHz sine through the delay (mix 100, fb 0): output frequency wobble (Hz std), 2nd/3rd harmonic ratio at 0.9, HF tilt of noise"""
    n = BLK * 900; tt = np.arange(n) / FS; s = (0.4 * np.sin(2 * np.pi * 1000 * tt)).astype(np.float32)
    y = blocks(hm, 7, s, [100, t, 0, 50, 50, 50, 50, 50], idx)[BLK * 300:]
    an = np.angle(np.fft.fft(y)[:0].sum()) if False else None
    # instantaneous frequency by zero crossings
    zc = np.where((y[:-1] < 0) & (y[1:] >= 0))[0]; per = np.diff(zc) if len(zc) > 4 else np.array([])
    fi = FS / per if len(per) else np.array([0.0]); wob = float(np.std(fi))
    s9 = (0.9 * np.sin(2 * np.pi * 1000 * tt)).astype(np.float32)
    y9 = blocks(hm, 7, s9, [100, t, 0, 50, 50, 50, 50, 50], idx)[BLK * 300:]
    sp = np.abs(np.fft.rfft(y9 * np.hanning(len(y9)))); f = np.fft.rfftfreq(len(y9), 1 / FS); k0 = int(np.argmax(sp))
    h = float(np.sqrt(sp[min(len(sp)-1, 2*k0)] ** 2 + sp[min(len(sp)-1, 3*k0)] ** 2) / sp[k0])
    rng = np.random.default_rng(5); xn = (0.1 * rng.standard_normal(BLK * 500)).astype(np.float32)
    yn = blocks(hm, 7, xn, [100, t, 0, 50, 50, 50, 50, 50], idx); lv = band_levels(xn[BLK * 200:], yn[BLK * 200:])
    # feedback repeats: how the 2nd repeat's spectrum differs from the 1st (darkening)
    return dict(wobble_hz=round(wob, 1), harm9=round(h, 3), bands_db=lv)

def reverb_decay(hm, idx, params):
    """noise burst (50 ms) with mix=100: time for the envelope to fall 30 dB below its maximum (T30), and the level at 100/300 ms"""
    rng = np.random.default_rng(2); n = BLK * 1400; x = np.zeros(n, np.float32); x[:2205] = (0.3 * rng.standard_normal(2205)).astype(np.float32)
    y = blocks(hm, 8, x, params, idx)
    env = np.sqrt(np.convolve(y ** 2, np.ones(882) / 882, 'same')); pk = float(env.max())
    if pk <= 1e-6: return None
    after = np.arange(len(env)) > int(np.argmax(env)); db = 20 * np.log10(env / pk + 1e-12)
    below = np.where((db < -30) & after)[0]
    return dict(t30_s=round(float(below[0] / FS - int(np.argmax(env)) / FS), 2) if len(below) else None, peak=round(pk, 3),
                db_at_300ms=round(float(db[int(np.argmax(env)) + 13230]), 1) if int(np.argmax(env)) + 13230 < len(db) else None)
