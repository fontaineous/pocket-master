#!/usr/bin/env python3
"""Emulation harness for the Cortex-M host's overlay modules and the resident DSP library (unicorn).

Memory map used (as seen by the firmware): 0x10000000..0x1001ffff RAM (slots + resident library at 0x10018800),
0x20000000.. SRAM, 0x29000000.. large pool, 0x00000000.. image (flash).  Cortex-M4 CPU model with the FPU enabled.

  from emu import Machine
  m = Machine(); m.load_lib(g10_bytes); m.load_module(slot_base, module_bytes)
  r0 = m.call(entry_addr, [args], trace_writes=(lo, hi))
"""
import struct
from unicorn import *
from unicorn.arm_const import *
SENTINEL = 0x0000fff0          # return address; execution stops here
LIB_BASE = 0x10018800

class Machine:
    def __init__(self, c_image=None):
        self.uc = uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
        try: uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_M4)
        except Exception: pass
        uc.mem_map(0x00000000, 0x00200000)
        uc.mem_map(0x10000000, 0x00020000)
        uc.mem_map(0x20000000, 0x00100000)
        uc.mem_map(0x29000000, 0x00100000)
        uc.mem_map(0xE0000000, 0x00100000)
        if c_image is not None: uc.mem_write(0x4000, c_image)
        self.stack_top = 0x200ff000
        self.writes = []
        self.icount = 0
        self._enable_fpu()
    def _enable_fpu(self):
        uc = self.uc
        try:
            uc.reg_write(UC_ARM_REG_C1_C0_2, uc.reg_read(UC_ARM_REG_C1_C0_2) | (0xf << 20))
            uc.reg_write(UC_ARM_REG_FPEXC, 0x40000000)
        except Exception as e:
            print('FPU enable warning:', e)
    def load_lib(self, blob): self.uc.mem_write(LIB_BASE, blob)
    def load_module(self, base, blob): self.uc.mem_write(base, blob)
    def read32(self, a): return struct.unpack('<I', bytes(self.uc.mem_read(a, 4)))[0]
    def readf(self, a, n=1): return list(struct.unpack('<%df' % n, bytes(self.uc.mem_read(a, 4 * n))))
    def write32(self, a, v): self.uc.mem_write(a, struct.pack('<I', v & 0xffffffff))
    def writef(self, a, vals): self.uc.mem_write(a, struct.pack('<%df' % len(vals), *vals))
    def call(self, addr, args=(), max_insns=20_000_000, trace_writes=None, sp=None, stack_args=()):
        uc = self.uc
        regs = [UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3]
        for r, v in zip(regs, args): uc.reg_write(r, v & 0xffffffff)
        sp = sp or self.stack_top
        for k, v in enumerate(reversed(stack_args)):
            sp -= 4; uc.mem_write(sp, struct.pack('<I', v & 0xffffffff))
        uc.reg_write(UC_ARM_REG_SP, sp)
        uc.reg_write(UC_ARM_REG_LR, SENTINEL | 1)
        self.writes = []; self.icount = 0
        hooks = []
        if trace_writes:
            lo, hi = trace_writes
            def hw(u, access, address, size, value, ud):
                if lo <= address < hi: self.writes.append((address, size))
            hooks.append(uc.hook_add(UC_HOOK_MEM_WRITE, hw))
        def hc(u, address, size, ud): self.icount += 1
        hooks.append(uc.hook_add(UC_HOOK_CODE, hc))
        try:
            uc.emu_start(addr | 1, SENTINEL, count=max_insns)
            err = None
        except UcError as e:
            err = e
        for h in hooks: uc.hook_del(h)
        self.error = err
        self.pc = uc.reg_read(UC_ARM_REG_PC)
        return uc.reg_read(UC_ARM_REG_R0)
