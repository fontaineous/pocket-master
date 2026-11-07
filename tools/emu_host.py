#!/usr/bin/env python3
"""Host-in-the-loop emulation of the Cortex-M firmware's module system (unicorn).

 - flash: segment c at 0x4000, segment g at 0x13000
 - RAM  : image produced by c_unpack.py at 0x20000000 (descriptor table, veneers, RW data)
 - 0x28000000 (32 KB data windows), 0x29000000 (external RAM), 0x10000000 (module slots + resident library at 0x10018800)
ModuleLib_Install is reimplemented here (it needs the firmware's malloc); LoadModule (0x4ee4) is the *real* firmware code.

  hm = HostMachine(c_bin, g_bin, ram_image)
  hm.load_module(slot, index)           # real loader copies payload + data block
  hm.set_params(slot, [p0..p7])
  out = hm.process(slot, in_block)      # 64 frames stereo float -> list of floats
"""
import struct, sys
sys.path.insert(0, __import__('os').path.dirname(__file__))
from emu import Machine, LIB_BASE
G_BASE = 0x13000
LOADMOD, GROUPCOUNT = 0x4ee4, 0x4ec4
IDX_PTR, LOADED_TBL = 0x20002350, 0x2000382c
STATE = 0x20002af4
DESC_LIST = 0x200022f4
HEAP = 0x20040000                 # scratch area used for the reconstructed index
class HostMachine(Machine):
    def __init__(self, c_img, g_img, ram_img):
        super().__init__(c_img)
        self.g = g_img
        self.uc.mem_map(0x28000000, 0x10000)
        for base in (0x40000000, 0x40100000, 0x40200000, 0x40300000, 0x40400000, 0x40500000, 0x40600000, 0x40700000):
            self.uc.mem_map(base, 0x100000)       # peripheral space as plain memory (reads return 0)
        self.uc.mem_write(G_BASE, g_img)
        self.uc.mem_write(0x20000000, ram_img[:0x4800])
        self.install_lib()
        # resident library (group 10) loaded raw at 0x10018800
        grp = self.groups[10]; self.libblob = g_img[grp[0]: self._end_of(grp[0])]
        self.install_resident_lib()
        self.arg_block = 0x20050000; self.buf = 0x20051000
    def _end_of(self, off):
        offs = sorted({o for g in self.groups for o in g} | {len(self.g)})
        return min(o for o in offs if o > off)
    def install_lib(self):
        g = self.g; n = g[0x13]
        self.groups = []
        w = lambda o: struct.unpack_from('<I', g, o)[0]
        a = HEAP
        self.write32(IDX_PTR, a); self.uc.mem_write(a, g[:0x14 + 4 * n]); a += 0x14 + 4 * n
        for k in range(n):
            rec = w(0x14 + 4 * k); cnt = w(rec)
            offs = [w(rec + 4 + 4 * i) for i in range(cnt)]; self.groups.append(offs)
            self.write32(a, cnt)
            for i, o in enumerate(offs): self.write32(a + 4 + 4 * i, G_BASE + o)
            self.write32(HEAP + 0x14 + 4 * k, a)                    # group pointer inside the index object
            a += 4 + 4 * cnt
        for i in range(11): self.write32(LOADED_TBL + 4 * i, 0)
    def install_resident_lib(self):
        """(Re)load the resident library (group 10, copied raw incl. its export table) and zero its BSS up to 0x1001f400.
        The real loader clears whole slot ranges (slot 8 covers 0x10018400-0x1001f400), so this must follow every slot load."""
        self.uc.mem_write(LIB_BASE, bytes(0x1001f400 - LIB_BASE))
        self.uc.mem_write(LIB_BASE, self.libblob)
    def desc(self, slot): return self.read32(DESC_LIST + 8 * slot)
    def load_module(self, slot, index):
        r = self.call(LOADMOD, [slot, index, self.desc(slot)])
        if self.error: raise RuntimeError(f'LoadModule slot {slot}: {self.error} pc={self.pc:#x}')
        if slot != 10: self.install_resident_lib()
        return r
    def module_ptr(self, slot): return self.read32(LOADED_TBL + 4 * slot)
    def params_addr(self, slot): return STATE + 0x1a0 + 0x20 * slot      # effective (mirror) parameters: what GetParams(slot) returns
    def set_params(self, slot, vals):
        v = list(vals) + [0.0] * (8 - len(vals))
        self.writef(STATE + 0x30 + 0x20 * slot, v); self.writef(self.params_addr(slot), v)   # host keeps both copies
    def call_entry(self, slot, which, args, **kw):
        mod = self.module_ptr(slot); ent = self.read32(mod + (0x10 if which == 1 else 0x14))
        return self.call(ent & ~1, args, **kw)
    def process(self, slot, block, enable=1, extra=0):
        n = len(block) // 2
        self.writef(self.buf, block)
        a = self.arg_block
        self.write32(a + 0, self.buf); self.write32(a + 4, 0); self.write32(a + 8, n)
        self.write32(a + 0xc, self.params_addr(slot)); self.write32(a + 0x10, enable); self.write32(a + 0x14, extra)
        # entry2(r0=args[0], r1=n, r2=params, r3=args[4], stack: &args[0x10], &args[0x14], &args[0x18])
        r = self.call_entry(slot, 2, [self.buf, n, self.params_addr(slot), 0], stack_args=[a + 0x10, a + 0x14, a + 0x18])
        return self.readf(self.buf, len(block))

    # ---- whole-engine helpers -------------------------------------------------------------------------
    IO = 0x200029bc
    INL, INR, OUTL, OUTR = 0x20060000, 0x20061000, 0x20062000, 0x20063000
    def init_chain(self, selection=None, params=None, nslots=9):
        """Load one module per slot (selection: dict slot->index, default 0), set params (dict slot->[8 floats]) and call each ENTRY1
        the way the host does, then configure the engine context so the full chain runs."""
        selection = selection or {}; params = params or {}
        for s in range(nslots):
            self.load_module(s, selection.get(s, 0))
        for s in range(nslots):
            self.set_params(s, params.get(s, [50.0] * 8))
            self.call_entry(s, 1, [self.params_addr(s), 0, 0, 0])
        io = self.IO
        self.write32(io + 0, self.INL); self.write32(io + 4, self.INR); self.write32(io + 0x108, self.OUTL); self.write32(io + 0x10c, self.OUTR)
        for off, v in ((0x12c, 0), (0x12d, 1), (0x12e, 0), (0x12f, 1)): self.uc.mem_write(io + off, bytes([v]))
        self.uc.mem_write(STATE + 0x30c, bytes([0])); self.uc.mem_write(STATE + 0x170, bytes([1])); self.uc.mem_write(STATE + 0x185, bytes([nslots]))
        self.write32(STATE + 0x188, (1 << nslots) - 1); self.uc.mem_write(STATE + 0x18c, bytes(range(nslots)))
    def run_engine(self, max_insns=5_000_000):
        r = self.call(0x200009a1, [], max_insns=max_insns)
        return r
