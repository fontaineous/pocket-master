# Pocket Master firmware: reverse-engineering notes

Images analysed (all `HTFW` containers, product "Pocket Master", base version V1.3.3):

| file | size | role |
|---|---|---|
| `Pocket Master Firmware V1.3.3.bin` | 2,056,820 | stock base |
| `PocketMaster_CFW0.5_base1.3.3.bin` | 2,091,468 | custom FW 0.5 |
| `PocketMaster_CFW0.9.4_base1.3.3.bin` | 2,121,656 | custom FW 0.9.4 |

Everything below was measured from these files. Items marked **(inferred)** are not proven; **(unknown)** are open.

## 1. Container format (`tools/htfw.py`)

See the docstring in `tools/htfw.py` for the byte layout. Summary: 0x88-byte header, five segments.
Each segment has a **CRC-16/MODBUS of its data, stored big-endian** (verified on all 15 segments of
the three images). `htfw.py unpack` then `pack` reproduces all three images **byte-exactly**.

| type | load addr | stock size | content |
|---|---|---|---|
| `b` | 0x000000 | 0x15bb60 | **NDS32 big-endian application** (the DSP/UI firmware; this is the one the CFWs patch) |
| `c` | 0x200000 | 0x00c63c | Thumb (Cortex-M) image: ARM C library strings ("SIGABRT", "Out of heap memory"), "User IR" handling |
| `g` | 0x240000 | 0x049050 | float tables (IR / model data) |
| `f` | 0x280000 | 0x008000 | cab/IR name table + settings (`a5 5a` magic) |
| `e` | 0x190000 | 0x03d000 | factory presets ("Sweet OD", "Chill CLN", ...) |

**(unknown)** The u32 at header offset 4 (0x1ac24 / 0x15818 / 0x1132a). It is not a sum, xor or CRC of
the whole file, payload, header or any single segment (about 1200 combinations tried). `pack` copies
it from the unpacked header, which is fine for experiments but a real build may need it recomputed.
It is also unknown whether the device's updater checks it.

## 2. Architecture of segment `b`: Andes NDS32, big-endian

- Reset/vector table at offset 0: 41 four-byte `j` instructions (`48 00 xx xx`); reset handler at 0x1d28 is
  textbook crt0 (`sethi/ori $gp`, `mfsr $msc_cfg`, `mtusr $itb`, enable FPU via `$fucpr`, `fmtcsr`, set `$sp`, `jal` C init and main).
- 16-bit instructions have bit 7 of the first byte set (the NDS32 rule). A linear walk stays in sync across thousands of instructions.
- Disassemble with a real toolchain: `tools/build-binutils.sh` builds `nds32be-elf-{as,ld,objdump,objcopy}` from Ubuntu's `binutils-source` 2.42
  (GNU upstream still ships the NDS32 port in 2.42). Capstone has no NDS32 support.
- **Runtime address = file offset + 0x10000 (inferred, strong evidence).** The CFW trampolines call absolute
  addresses `0x16bd3e, 0x16be0a, ...`; each minus 0x10000 lands on a `push25` prologue (`fc xx ..`) in the appended
  blob (9 of 12 on the nose, the rest look like leaf functions). So the app runs from 0x10000, probably behind a 64 KB
  bootloader that is not part of the HTFW file. A linker script must use `. = 0x10000 + file_offset`.
  Relative `j/jal` are position independent, which is why they never revealed this.

## 3. How the CFWs inject code

Both CFWs use the same recipe on segment `b` (`tools/hooks.py` lists the sites; tables in `docs/hooks_cfw*.md`):

1. **Append a blob at the end of the stock code**, starting at stock length 0x15bb60 (CFW0.5 adds 0x8758 bytes, CFW0.9.4 adds 0xc3f0).
   The blob begins with a table of **register-saving trampolines**, then the new C-compiled functions, then strings/data
   (UI style names "Amber CRT", "Tube Amp", "Synthwave", "Stage Hi-Contrast", "Game Boy", "DRY DI", "DI|WET", "USB REC", `-CFW0.5` ...).
   A trampoline (reproduced **byte-identically** from source in `examples/trampoline0.S`):
   ```
   addi10.sp #-4 ; smw.adm $r0,[$sp],$p1,#0x2     ; save r0..r27 + lp
   sethi $r15,#hi ; ori $r15,$r15,#lo ; jral $lp,$r15   ; call the C hook (absolute address, +0x10000 base)
   lmw.bim $r0,[$sp],$p1,#0x2 ; addi10.sp #4 ; ret5 $lp
   ```
2. **Call-site retargeting.** In the stock code, 24-bit `jal`/`j` targets are rewritten in place so existing call sites enter a trampoline
   (e.g. `0x3a9cc: jal 0x40be8` becomes `jal 0x15bb60`). **23 sites in CFW0.5; 66 in CFW0.9.4; all 23 of CFW0.5's sites are also in 0.9.4.**
   Only the 3 low bytes change, which is why the diffs show up as 3-byte regions.
3. **Function-entry detours.** The first instruction of a stock function is overwritten with `j <blob>`:
   `0xc4b0` and `0xda7c` (both CFWs; stock instruction was `smw.adm` prologue), plus `0x3c0dc` in 0.9.4. The displaced instruction must be re-executed in the blob (not yet traced).
4. **Immediate/constant patches** in stock code, e.g. `14 e7` to `19 e7` at several compares (20 to 25). It matches segment `f`: the count byte 0x14 to 0x19 and
   "User IR 1..6" entries written into the formerly 0xFF-filled tail of the cab table. So CFW0.5 raises the number of user IR slots.
5. **Asset replacement:** the `0x100000–0x120000` region of `b` (animated GIFs with Photoshop XMP, plus tables) is largely rewritten (~108 KB of differing bytes in both CFWs).
   Everything else in `b` between 0x20000 and 0x100000 is untouched. Total stock-code changes are a few hundred bytes.
6. Segments `c`, `f`, `e`, `g` are also changed in CFW0.9.4 (larger `c` and `g`); not analysed yet.

Caveat: `hooks.py` only compares `j/jal` at identical addresses, and detour/immediate classification above 0x100000 is meaningless
because that area is data, not code.

## 4. What "compile from source" can honestly mean here

There is no source for the stock firmware, and full decompilation of 1.4 MB of NDS32 is not realistic. The CFWs themselves were
clearly built the way described above, so the practical goal is the same method with real sources:

1. C/asm sources for new features, compiled for NDS32 (big-endian, FPU), linked at `0x10000 + <append offset>` against a **symbol file of stock-firmware function/data addresses** (to be recovered by reversing the hook targets).
2. A build script that appends the linked blob to stock segment `b`, applies the call-site/entry/immediate patches, recomputes CRC-16/MODBUS and repacks with `htfw.py`.

## 5. Open items / next steps

- A **C compiler** for NDS32: not installed. Ubuntu 24.04 ships `gcc-13-source` (GCC 13 still contains the `nds32` backend); building `nds32be-elf-gcc` is a roughly 30–60 minute job. Assembly already works.
- Recover the **hook targets' semantics** (what `0x40be8`, `0x3ffdc`, `0x4180c` ... are in stock), and symbolise the stock firmware.
- Decode the u32 at header offset 4.
- Analyse segment `c` (Thumb, separate Cortex-M MCU?) and the `c/g/f/e` changes in CFW0.9.4.
- **Nothing has been flashed or tested on a device.** Anything produced from this needs a recovery path (bootloader/DFU) before it goes near hardware; a bad CRC or a bad hook can brick the unit.
