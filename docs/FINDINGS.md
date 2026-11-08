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
- **Runtime address = file offset + 0x10000 (proved).** Also confirmed independently: 699 `sethi/ori` pairs in stock code resolve to printable C strings at +0x10000, against 17 at +0.
  Original evidence: The CFW trampolines call absolute
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

## 6. Vendor SDK identification and symbol recovery (added after the first pass)

The NDS32 image prints this boot banner, so the SoC firmware is built on the **MVsilicon B1 SDK**
("Mountain View Silicon Technology Co.,Ltd.", `SDK Version: %d.%d.%d`). Other strings: `*BP10-LYM`,
`../bt_audio_app_src/main.c`, `AudioCoreService`, `BtLib Version`, `Audio Decoder Version`, `Fatfs presearch acc Lib Version`.
The SDK itself is not publicly downloadable (see session notes: vendor/distributor access only).

Structure inferred from assert/source strings:
- **SDK part:** started from the SDK's `bt_audio_app` example (`bt_audio_app_src/main.c`); prebuilt libraries for the Bluetooth stack, decoders and FatFS.
- **Manufacturer part:** `../UserSources/Components/WinManager/WinManager.c` (UI window/message manager, `WinMessageListRegister`
  at runtime 0x16358, `WinGlobalMessageListRegister` at 0x163ac). Effect handling near 0x57754 ("Get Audio Effect Parameter From FLASH").
- The SoC also shows an SPI-slave audio task ("SPIS Audio task"), so another processor may exchange audio with it. Chip identity of the other IC(s) is unconfirmed.

`tools/symbols.py` produces `docs/symbols_stock_v1.3.3.csv`: 4,512 call-target functions found, 198 that reference strings
(runtime address, call count, size hint, strings). This is a starting point for naming, not a finished symbol table; function
boundaries come from `jal` targets only, so functions only reached via pointer tables are missed.

Corrections to earlier statements: the "SIGABRT"/ARM-libc Cortex-M segment `c` has essentially no peripheral register accesses (movw/movt-checked), so
it is compute-style code loaded into RAM; whether it runs on an i.MX RT or another core is still unknown.

## 7. Public SDK source found: leadercxn/bp1048_sdk_v0.1.12

<https://github.com/leadercxn/bp1048_sdk_v0.1.12> (public; MVsilicon `MVsB1_BT_Audio_SDK_v0.1.12`, release dated 2021-02-08, Chinese/GBK comments).
It contains: full C sources of `BT_Audio_APP` (`bt_audio_app_src/`: main.c, services/, apps/, display/, device/, startup/, ...),
`MVsB1_Base_SDK` (drivers, middleware sources, ~40 examples), the linker script/scatter file (`nds32-ae210p.ld/.sag`) and **prebuilt libraries**
(`libBtStack*.a`, `libAudioDecoderLibrary.a`, `libAudioEffectLibrary.a`, `libDriver.a`, `libfatfs.a`, `libFlashFS.a`, `libreverb_p.a`, `libopus*.a`, ...).
License: no LICENSE file in the repo; MVsilicon copyright headers say all rights reserved. Check licensing before redistributing anything derived from it (this repo does not copy any of it).

Matches with our stock image:
- Boot banner ("MVsilicon B1 SDK ... SDK Version: %d.%d.%d"), `Audio Decoder Version`, `BtLib Version`, `Fatfs presearch acc Lib Version`, `bt em size`, `AudioCoreService`, `[BT_OFFSET]` are all in the SDK sources (`main.c`, `services/`).
- `__nds32__mtsr(0x10000, NDS32_SR_IVB)` in `startup/init-default.c` and `Remap_InitTcm(FLASH_ADDR+0x10000, ...)` in `main.c` explain the +0x10000 runtime base.
- The flash-boot header the SDK describes at offset 0xB8 matches structured bytes at the start of segment b.
- Toolchain per the SDK projects: `nds32le-elf-mculib-v3s` (GCC), `-O3`, `-mext-dsp`, chip config `nds32-ae210p`.

NOT in the SDK (so manufacturer additions): `WinManager`/`UserSources`, `dspVer`/`bootVer`, `SPIS Audio task`, `BP10-LYM`, the effect/UI code.

**Endianness correction.** Data in the image is little-endian (44 vs 1 string-pointer hits), matching the SDK's `nds32le` target. NDS32 instruction bytes
appear in the same order in BE and LE builds, which is why `nds32be-elf-objdump` still decodes the code. Build and link with `nds32le-elf`.

### Evidence for a second processor
- `0x28358` (a 6 KB UI function) shows `V0.0.02`, `B0.0.02`, `V0.0.01`, `dspVer= %s`, `bootVer= %s`, `Light:%d`, `NR Calibrate Value`: looks like an info screen showing versions of other components.
- `0x542a4` (`AudioResInit`) creates the **SPI-slave audio task** (`SPIS Audio task` at `0x51f90`); `Uart DMA Rx` at `0x157c8`.
- Segment `c` is 50 KB of Thumb code with no peripheral register accesses (compute-style, RAM-resident) starting with a `V132` tag, and segment `g` is ~300 KB of float tables.
Together that fits a separate DSP/MCU doing the heavy audio/IR processing, with the BP1048-class SoC handling Bluetooth/USB/UI. Not yet proved: which chip runs `c`, and how it is loaded.

## 8. Toolchain built; SDK example compiled (Example_GPIO)

An `nds32le-elf` toolchain (binutils 2.42, GCC 13.3 C-only, newlib 4.4) now builds `Example_GPIO` from the public SDK sources
(`build/sdk-example/Makefile`, recipe in `tools/build-toolchain.sh`). It links the **prebuilt vendor `libDriver.a`** against our own objects and produces a `.bin`.

Compatibility problems found and fixed (each one would hit anyone using a modern GCC with this SDK):
1. **ABI.** SDK objects are `ABI2 FP+` with a single-precision FPU (32 SP/16 DP regs). Needs `-mabi=2fp+ -mext-fpu-sp -mconfig-fpu=2`, and libgcc + newlib rebuilt with the same flags, else `ABI version of object files mismatched`.
2. **Assembler spelling skew.** GCC 13 passes `-mabi=v2fp+`; binutils 2.42 gas only accepts `v2fpp`. One-line alias patch in `tools/binutils-nds32-abi-alias.patch`.
3. **`-fcommon`.** The SDK headers define variables without `extern`; GCC 10+ defaults to `-fno-common` and reports duplicate definitions.
4. **libc.** The SDK targets Andes "mculib" (hooks `putchar`/`nds_write`), not newlib; `build/sdk-example/syscalls.c` bridges `_write`/`_sbrk`/etc.
5. Andes-only flags upstream GCC rejects: `-mext-zol` (zero-overhead loops); `-ldsp`/`-mvh` not used.

Check against the SDK's own committed build of the same example (`examples/Example_GPIO/Debug/`):
- Same vector-table shape (`48 00 xx xx` jump table), as in the stock firmware.
- `GPIO_RegOneBitSet` from the prebuilt `libDriver.a` has **identical instructions** in both builds.
- Ours is bigger: text 40,520 vs 34,044 bytes, data 2,152 vs 1,016 (different compiler, newlib instead of mculib; code generation will differ from Andes's GCC).

Not done / not proven: nothing here was run on hardware; the example's `.bin` has not been wrapped into the HTFW format or compared against how the stock image is laid out
(flash-boot header at 0xB8, `.sag` memory map, +0x10000 IVB); the Andes `-mext-zol` and DSP library (`-ldsp`) are unavailable, so DSP-heavy SDK libs may need care.

## 9. Stock image map (segment `b`, offsets are file offsets; runtime = +0x10000)

Measured with per-block entropy, disassembly validity (`*unknown*` rate) and call/return density over `tools`' NDS32 disassembly.

| file offset | size | what | evidence |
|---|---|---|---|
| `0x000000–0x0000A4` | 164 B | vector table: 41 `j` instructions, reset handler `0x1d28` | disassembly |
| `0x0000A4–0x000100` | | **flash-boot header** emitted by the SDK's `.stub_section` (see below) | SDK `init-default.c` |
| `0x000100–~0x0CF000` | ~830 KB | **code** (4,512 `jal` entry points, highest `0xcef30`; <1.3% undecodable, 8–17% call/ret) | |
| `~0x0CF000–0x100000` | ~200 KB | sparse tables/data (70–80% zero bytes, entropy 1–2, ~1% calls) | |
| `0x100000–0x130000` | 192 KB | **UI assets**: GIF89a at `0x1054bc` (Photoshop XMP), high-entropy payload in `0x110000–0x120000`; this is the block both CFWs rewrite (~108 KB differs) | signatures, diffs |
| `0x130000–0x15AEC0` | ~172 KB | **read-only data**: strings and constant tables (498 string refs in `0x130000`, 89 in `0x150000`), includes the effect-mode table at `0x132748` (blank in stock) | string xrefs |
| `0x15AEC0–0x15BB60` | 3,232 B | **`.data` load image** (copied to RAM `0x20003900` at boot); last bytes of stock `b` | `__c_init` decode, section 10 |
| `0x15bb60–` | | **CFW appended blob** (code placed after the data tail; flash is execute-in-place so this works) | diffs |

Flash-boot header (SDK writes it in `startup/init-default.c`; stock values in the right column):

| offset | SDK source | stock | meaning |
|---|---|---|---|
| `0xB0` | `0x100000` | `0x178000` | constant-data boundary (`CONST_DATA_ADDR`-style) |
| `0xB4` | `0x1D0000` | `0x1F0000` | user data address (matches `USER_DATA_ADDR 0x1F0000` in the SDK's `flash_config.h`) |
| `0xB8–0xBB` | `01 00 00 01` | `b1 00 00 01` | chip B1X, version bytes |
| `0xBC` | `FFFFFFFF` (code CRC) | `01 00 00 00` | code CRC placeholder, edited after build |
| `0xC0` | `0xB0BEBDC9` | `0xB0BEBDC9` | magic (exact match) |
| `0xC4` | `0x706` | `0x706` | 32 kHz crystal capacitance calibration (exact match) |
| `0xD4` | `0x03444846` | `FFFFFFFF` | |

The three fields that differ show a post-build packaging step edits this block; which tool, and how `0xBC` is computed, is **unknown**.
`0xB0` is the most useful number for modding: the code image must stay below the constant-data boundary at flash `0x178000` if that value is an absolute flash address
(**inferred**; whether `b`'s file offset 0 corresponds to flash 0 or 0x10000 is not settled). Stock `b` ends at `0x15bb60`; CFW0.9.4 ends at `0x167f50`; that leaves about 70 KB below `0x178000` for additions.

Other facts established:
- The stack-protection bound `0x20003000` and `ivb = 0x10000` in stock equal the SDK source values, so startup code is unmodified SDK code.
- On-chip RAM starts at `0x20000000`; the SDK's `.sag` puts RW data at `0x20003900`-`0x20004000`.
- Effect handling (`FUNC_ID_EFFECT_MODE`, runtime `0x57754`) scans a table of 16-byte records at runtime `0x142748` for an id byte (`0xFF` terminates); in stock the table is empty and the string "No Audio effect File load!!!!" covers that case, so effects presumably come from a separately loaded effect file.

## 10. Data tail, RAM map and how the CFWs obtain RAM

**Boot data copy** (`__c_init`, file `0x526ac`, runtime `0x626ac`; `$gp = 0x2000FA40`):
- `.data`: RAM `0x20003900–0x200045A0` (**3,232 B**), loaded from runtime `0x16AEC0` = file `0x15AEC0`, which is exactly the last 3,232 bytes of stock segment `b`.
- `.bss`: `0x200045A0–0x2001BB88` (**~95 KB**), zeroed with `memset` up to `_end = 0x2001BB88`.
- (An earlier note in this session had `.data` as 4,768 B; that was an arithmetic slip, corrected here.)

**RAM facts (SDK sources):** on-chip SRAM starts at `0x20000000`; the SDK's MPU table uses `0x50000 - BB_EM_SIZE` bytes; `remap.h` has `SRAM_END_ADDR 0x20048000`.
The **FreeRTOS heap is `[&_end, SRAM end)`** (`prvInitialiseHeap()` in `rtos_api.c`), so anything placed at or above `_end` in stock is heap and will be overwritten.

**CFW technique for RAM (both CFW0.5 and CFW0.9.4, identical):**
1. Patch the two `$gp`-relative loads of `_end` (file `0x526cc`: end of the `.bss` memset; `0x58c62`: heap start) from `0x2001BB88` to `0x2001BF88`:
   **+0x400 bytes (1 KB) of zero-initialised RAM reserved at `0x2001BB88–0x2001BF88`**, heap pushed up by the same amount.
2. New variables live in that block (blob references `0x2001bb90`, `0x2001bb94`, `0x2001bbcc`, `0x2001bbf0`, `0x2001bc38`).
3. Ten stock `addi.gp` loads (file `0x8b68`...`0x8faa`) of a stock global at `0x2000c9a8`/`0x2000c9b0` are redirected to `0x2001bc88`/`0x2001bc90` in the new block.
   Plausibly the enlarged user-IR table (20 to 25 slots) moved there; the identity of the stock global is **not** established.
4. No change to the `.data` copy: the blob has no initialised RAM data, so all mutable state starts at zero.

**Modding consequence:** to add code with state, (a) append code after `0x15bb60` (stay under the `0xB0` boundary, see section 9), and (b) either reuse the 1 KB trick (change the two `_end` loads; a larger value works the same way, at the cost of heap) or add a real `.data` image, which would also mean patching the `__c_init` copy size/source.

## 11. SPI-slave link decoded; function naming by signature (autonomous pass)

**Method.** `tools/sigmatch.py` takes Andes-built *linked* reference ELFs, masks address-dependent instruction fields (j/jal, sethi/ori, `$gp`-relative) and
finds each function in the stock image by byte pattern. Two references: the SDK's own committed `Example_GPIO.adx`, and a whole-archive link of the 18 libraries the
application links (`Driver sra cec sbcenc VocalCut mp3enc AudioEffectLibrary resampler AudioDecoderLibrary BtStack FlashFS Lrc fatfs RTC cvsd_plc BlueAEC xmauth opus`)
built with our toolchain. Result: **1,300 addresses named** (`docs/symbols_libs_v1.3.3.csv`; `tools/mksymbols.py`; `tools/annotate.py` prints disassembly with names).
Ambiguous identical-body functions are listed with all candidate names (e.g. the SPIS/I2C flag-clear one-liners), never guessed.
Limits: only functions whose compiled bytes equal the reference match (library code only; the manufacturer's code is not in any reference), and our linker printed
BFD relaxation assertions on unresolved symbols while building the reference, so some library functions will have been missed.

**SPI slave (`SPIS Audio task`, runtime 0x51f90) is an audio link, not flash:**
- Setup at runtime `0x51d20` calls, in order: `DMA_ChannelAllocTableSet`, `SPIS_IoConfig(1)`, `SPIS_Init(0)`, `DMA_ChannelDisable(0/1)`, `SPIS_DMA_Init(rx,0x200,tx,0x200)`, `SPIS_BlockDMA_Init`, `SPIS_RxDmaModeSet(1)`, then enables the two DMA channels (ids from a config struct).
- Per the SDK header and example: **port 1 = A20 MOSI, A21 CLK, A22 MISO, A23 CS**; mode 0 = CPOL0/CPHA0; **512-byte DMA blocks**. The chip is the SPI **slave**, so another device is the master and clocks the data.
- Context object (0x50 bytes, `0x51ee0`): 16-entry queue of 2-byte messages; **44,100** stored as the rate; RX and TX ring buffers (SDK circular buffers) of configurable size; accessors convert bytes to frames with `>>2`, i.e. **16-bit stereo, 4 bytes/frame**.
- Task body (`0x51ce8`): waits on its queue; on message type 2 (DMA block done) it posts message `0xE02` to the application queue passed at creation. It is an event bridge; the audio is moved by DMA plus ring buffers.
Conclusion: the BP1048-class chip exchanges **stereo PCM at 44.1 kHz with another processor over SPI (it is the slave)**. This fits a separate DSP/MCU doing the heavy audio processing. Which chip the master is remains unknown; probing A20–A23 (BP1048 pins per its datasheet) would show it.

## 12. Tasks, UART link and pin configuration (autonomous pass, continued)

**Bug note.** Several early scans missed 16-bit instructions (`movi55 $r4, #2` prints with a space, 32-bit forms with a tab); fixed in `tools/pinmap.py`, `tools/periph.py`, `tools/tasks.py`.

**FreeRTOS tasks** (`tools/tasks.py`; `xTaskCreate` found by behaviour at runtime `0x681e4`, 16 call sites; table in `docs/tasks_stock_v1.3.3.md`):

| task | entry | stack (words) | prio | origin |
|---|---|---|---|---|
| Uart DMA Rx | 0x15598 | 256 | 2 | manufacturer |
| GUI_MAIN_TASK (3 creation sites) | 0x2c46c / 0x2c4b0 / 0x2c414 | 2560 | 1 | manufacturer (GUI library) |
| DRUM Audio task | 0x51334 | 512 | 3 | manufacturer |
| Flash Task | 0x51aa8 | 1024 | 1 | manufacturer |
| User Msg Task | 0x51c8c | 256 | 2 | manufacturer |
| SPIS Audio task | 0x51ce8 | 1024 | 2 | manufacturer |
| MainApp, BtStack, AudioCoreService, DecoderService, DeviceService, BtAudioPlay, WaitingPlay | | | 3-5 | SDK (`bt_audio_app`) |
So this chip runs **the display GUI, a drum machine, Bluetooth/USB audio and UI messaging**; the SPI-slave audio link (section 11) connects it to a second processor.

**UART0 link** (runtime `0x51008` setup, task `0x15598`): pins **A0 = UART0 RX (mode 2), A1 = UART0 TX (mode 12)**, **460,800 baud, 8N1**, DMA circular receive (peripheral id 5) with a 512-byte buffer, TX by DMA block (id 12).
The receive task cuts the stream into packets: 12 slots of 0x204 bytes (4-byte header + up to 508 payload bytes).
The image also contains the SDK's tuning-protocol builders: a dense cluster of `0xA5`,`0x5A` frame-header stores between runtime `0x58708` and `0x5a704`
(SDK `audio/communication.c`: frames `A5 5A | cmd | len | payload | 16`, effect parameters from `gCtrlVars`). Not proven: whether UART0 carries that protocol to a PC tool or to the other processor.

**Pin configuration** (`tools/pinmap.py`, `docs/pinmap_stock_v1.3.3.md`): direct `GPIO_PortAModeSet/PortBModeSet` calls are few (13); the app mostly selects pins through peripheral init calls such as `SPIS_IoConfig(1)` (A20-A23).
Direct calls found: A0 uart0_rxd_0, A1 uart0_txd_0, B2/B3 mode 5 = FM2R/FM2L (analog line inputs); A7, A9, A16, A17, A22, A24, B2, B3, B5 set to mode 0 (plain GPIO).

## 13. Flash layout vs the BP1048 variants: evidence that c, g, f belong to another device

SDK `app_config.h` lists the chip variants: BP1048A2/B2 = 48-pin, 288 MHz, **16 Mbit (2 MB)** flash; BP1048P2 = 320 MHz, 16 Mbit; BP1048P4 = 320 MHz, **32 Mbit (4 MB)**. The SDK's `flash_config.h` for the 2 MB parts puts
`CODE_ADDR 0`, `CONST_DATA_ADDR 0x198000`, `AUDIO_EFFECT_ADDR 0x1C8000`, `FLASHFS_ADDR 0x1D0000`, `USER_DATA_ADDR 0x1F0000` (P4 parts add 0x200000).

Stock values: flash-boot header user-data `0xB4 = 0x1F0000`, constant-data boundary `0xB0 = 0x178000`, the Flash Task manages a region at `0x1D0000` in 4 KB sectors. All consistent with a **2 MB** BP1048 flash.
HTFW segment destinations: `b` at 0, `e` at `0x190000..0x1CD000` fit inside that 2 MB (and below `FLASHFS 0x1D0000`).
`c` at `0x200000`, `g` at `0x240000`, `f` at `0x280000` do not: they are **above 2 MB**.
**Inference (not proven):** `b` and `e` are the BP1048's own code and effect data; `c` (Thumb code, no peripheral accesses), `g` (float tables) and `f` (cab/IR name table, settings) are addressed in the **second processor's flash/address space** and presumably forwarded to it by the BP1048-side updater over the SPI/UART links.
Alternative explanations still open: a BP1048P4 (4 MB) used with its own non-default layout, or an external SPI flash. The stock `0xB4 = 0x1F0000` argues against a P4 layout (which would use `0x3F0000`).
The effect handling visible on the BP1048 side (DRUM Audio task, drum/aux effects from the SDK's effect library, empty effect table) is consistent with it *not* doing the amp/IR modelling.

## 14. Fingerprint of segment `c`'s core, and a caveat on the version strings

Linear sweep of `c` (Thumb-2, from its vector table at `+0x400`, 17,753 valid instructions):
- **Single-precision VFP only:** 1,138 `f32` operations, **0** `f64`.
- DSP-extension / saturating / SIMD-style instructions: 108; hardware divide (`sdiv`/`udiv`): 51; IT blocks: 490.
- System-control literals: `VTOR`, `CCR`, `CPACR` (FPU enable); **no** cache-maintenance registers (`ICIALLU`, `DCC*`) or cache ID registers.
- Built with ARM's C library (`SIGRTMEM`, `Heap memory corrupted`), i.e. Keil/ARMCC-style.
This is most consistent with a **Cortex-M4F** (FPv4-SP, DSP extension, no caches). It is weaker evidence for an i.MX RT (Cortex-M7 with caches, and double-precision FPU on most parts). Not conclusive: a cache-less use of an M7 cannot be excluded, and the image touches no peripherals itself.

Caveat on earlier note: the `V0.0.02`, `B0.0.02`, `V0.0.01` strings are adjacent rodata literals (runtime `0xe106c`-`0xe1154`) used by the UI info code (`0x271f6`, `0x28eb8`-`0x28ed0`), i.e. likely constants,
so they do **not** by themselves show that the BP1048 queries another device's version. `dspVer= %s` / `bootVer= %s` (runtime `0xe1111`, `0xe1129`) are log formats and are not referenced by `sethi/ori` pairs.

## Open questions after this pass
1. How (or whether) segments `c`/`g`/`f` are delivered to the other processor: the BP1048 side shows a 460,800-baud UART0 (A0/A1) with a packet receiver and a 44.1 kHz stereo SPI-slave audio link (A20-A23), but no code was found that streams flash contents to a peer.
2. Which chip is the SPI master / `c` runner (Cortex-M4F-like evidence only).
3. The post-build edit of the flash-boot header (`0xB8`, `0xBC`, `0xD4`) and the HTFW header word at offset 4.
4. The SPI-flash read/write/erase functions were not matched by signature; the SDK functions exist but their stock bytes differ from the reference builds.

## 15. Milestone: the SDK's full application builds and links (BT_Audio_APP)

`build/bt-audio-app/build.sh <SDK> <toolchain prefix> <out>` compiles **142/142** sources (application, FreeRTOS, drivers, middleware, USB host/udisk), links them with the 18 prebuilt vendor libraries
and the application's own linker script, and produces `bt_audio_app.elf/.bin`: **text 1,498,956, data 3,056, bss 53,720; `.bin` 1,502,032 bytes** (stock segment `b`: 1,424,224).
**Link rc=0, no unresolved symbols**, with one deliberate placeholder (below).

Modern-GCC incompatibilities found and handled (each would break anyone rebuilding this SDK):
1. `-fcommon` (header-defined variables).
2. **`-fgnu89-inline`**: `inline void f(void){...}` without `static`/`extern` produced no external symbol under C99 semantics (undefined `StartModeExit`, `EndModeExit`, `SleepMainAppTask`, ...).
3. `-D1088` in the project file is not a valid macro name for modern GCC; dropped.
4. Case-sensitivity: the SDK was written on Windows (`freertos.h` vs `FreeRTOS.h`, `EOSDEF.h` vs `EOSDEF.H`, ...); symlink shim include directory.
5. `os_cpu_a.S` line 102: `movi $r0,#0xfff8fff8` is rejected by gas 2.42; use `li`.
6. ABI `2fp+` + FPU flags; libgcc/newlib rebuilt with them; assembler `v2fp+` alias patch (section 8).
7. **`nds32_sin_q15`, `nds32_sin_q31`, `nds32_cos_q31`, `nds32_sqrt_q31` come from Andes's proprietary `libdsp` (`-ldsp`), which is not in the SDK.** The build supplies **slow placeholder implementations** (`dsp_stubs.c`, generated by `build.sh`); replace before relying on those audio paths.
8. The default `app_config.h` enables features (USB host/udisk) whose sources the original `.cproject` excluded; the manufacturer's actual configuration is unknown.

Comparison with stock (structural, not byte-level):
| | SDK build (ours) | stock `b` |
|---|---|---|
| vector table | 41 x `j` jump table | same |
| header `0xB4` user data | `0x1F0000` | `0x1F0000` (same) |
| header `0xB0` const-data boundary | `0x198000` | `0x178000` |
| header `0xB8` / `0xBC` / `0xD4` | `01 00 00 01` / `FFFFFFFF` / `03444846` | `b1 00 00 01` / `01 00 00 00` / `FFFFFFFF` (edited after build) |
| magic `0xC0`, crystal cal `0xC4` | `B0BEBDC9`, `0x706` | identical |
| `_start` | `0x10000` | `0x10000` (file offset 0) |
| `.data` | 3,056 B | 3,232 B |
| banner strings (`MVsilicon B1 SDK`, `BtLib Version`, ...) | present | present |
Interpretation: the stock image is this SDK application (plus manufacturer code and a different configuration/linker script) built by the same flash-boot flow.
This image is **not** flash-ready or device-compatible: it is the SDK's reference app, lacks the manufacturer's code, has not been wrapped in the HTFW format, and has not been tested on hardware.

## 16. Segment `c` and `g` decoded: a Cortex-M host firmware plus overlay effect modules

(The i.MX RT assumption is dropped: nothing in the data supports it. The processor is "a Cortex-M4-class MCU of unknown vendor".)

### 16.1 Segment `c` (50,748 B) is a Keil/ARMCC image linked at **0x4000**
- Header (file `0x0-0x400`): `FF*8`, ASCII **`V132`** at +8, `0x4400` at +0xC (the vector-table address); rest zero.
- Vector table at file `0x400` = address `0x4400`; SP `0x20006ae8`; reset `0x4d91`; most IRQs use the default `b .` handler `0x45f7`; real IRQ handlers at `0x9a91`, `0x9c41`, `0x9c55`, `0x9c69`, `0x9c7d` (20-byte stubs); NMI/HardFault etc. point into **RAM** (`0x20000999`, `0x200008ad`, ...).
- The link base was found from the default-handler and ISR-stub spacing (`b .` candidates scored by stub similarity); it is consistent with the reset code (`ldr.w sp`, call `0x9aa1`, jump `0x44e1`).
- `0x9aa0` = CMSIS-style init: sets VTOR (`0xE000ED08`) to `0x4400`, writes AIRCR with key `0x05FA`, loops over all NVIC priority registers.
- `0x44e0` = Keil `__main` + `__scatterload` with ARM's compressed-data handlers. `tools/c_unpack.py` runs it in an emulator (unicorn) and dumps the RAM image.
- Scatter-load regions: `0x20000000` size `0x218c` copied from file `0xA3D0` (RAM-resident code: the IRQ vector veneers `movw/movt ip; bx ip` target here); `0x2000218c` size `0x230` decompressed;
  zero-init: `0x1001f400` (0xc00), `0x200023bc` (0x472c, ends exactly at the initial SP), and **`0x29000000` size `0xd7580` (~881 KB)**, a very large zeroed buffer in a non-SRAM window (external memory? unproven).
- Constants in flash/RAM code: peripheral pages `0x40005000`, `0x4000b000`, `0x4000c000`, `0x4000e000`, `0x40011000` (+8/+0xC), `0x40020000`, `0x40030000`, `0x40050000`; **`0xE0001000` (DWT, cycle counter)**; a **~128 KB RAM at `0x10000000`** (variables up to `0x10007cdc`, stack-like areas near `0x1001f400-0x1001fe00`).
  (Many other `0x4xxxxxxx` hits are float constants such as `0x40a00000` = 5.0f and were excluded.)

### 16.2 Segment `g` (299,088 B) is a library of **overlay code modules** for that MCU (`tools/g_modules.py`)
- Index: `0x1463`, file size, data start `0x1d0`, `0xffffffff`, `0x0b0001ff`, then 11 pointers (`0x40 0x48 0x88 0xac 0x108 0x110 0x120 0x168 0x190 0x1bc 0x1c4`) to group records `[count][offsets]`.
  **11 groups with 1, 15, 8, 22, 1, 3, 17, 9, 10, 1 and 2 modules (88 blobs).**
- Module header: `w0` header size (`0x24`/`0x28`), `w1` payload size, `w2` total size, `w3` secondary size/offset, `w4`/`w5` Thumb entry points (`0x1000xxxx|1`), then Thumb code using absolute `0x1000xxxx` addresses.
  A module holds a pointer to `base + payload` (its own data area), which gives its load base.
- **Slots in the MCU's `0x10000000` RAM** (modules of one group are alternatives for one slot): `0x10000000` (g0), `0x10001000` (g1), `0x10002800` (g2), `0x10003800` (g3 and g9), `0x10006400` (g4), `0x10007c00` (g5), `0x10009000` (g6), `0x1000c000` (g7), `0x10018400` (g8).
  Group 5 holds three identical blobs. Group 10 holds a raw code blob (`push {r4,lr}` ...) plus a 20-byte stub.
- The host `c` references fixed addresses inside the slots (`0x100037b4`, `0x10003d58/5c`, `0x100074dc`, `0x10007cdc/ce0`), i.e. it reads/writes module state or parameters in place.
Interpretation (inferred): the signal chain is built from slots; selecting an effect/amp/cab means copying that module from `g` (in flash) into its slot and calling its entry points. The HTFW's 20 to 25 IR/cab slots (`f`) and presets (`e`) select among these.

## 17. The Cortex-M host and its DSP modules: how the pieces fit

### 17.1 Host RAM image (`tools/c_unpack.py`, `tools/c_disasm.py`)
- RAM `0x20000000..0x218c` (copied by the scatter loader): first **40 ten-byte veneers** (`movw ip,#lo; movt ip,#hi; bx ip`) at `0x20000000 + 10*n`, each jumping to a flash function (`0x4a91`, `0x89cd`, `0x9a6d`, `0x69b1`, ...): a fixed-address entry table.
  No module calls these veneers directly (they are ~256 MB away from `0x1000xxxx`, out of `bl` range), so module-to-host calls must go through function pointers.
- Real RAM code starts at `0x20000190`. It holds: the ISR bodies the vector stubs tail-call (`0x20000191`, `0x200019a9`, `0x20001b69`, `0x20001e09`, ...), and routines that program a controller at **`0x40050000`**
  (4-word command writes to `+0x0..+0xC`, source/length at `+0x30`/`+0x34`, timeout-polling helper `0x2000077c`) and use windows at **`0x28000000`/`0x28008000`**.
  These look like a flash or memory-controller driver running from RAM (necessary when reprogramming the memory you execute from). **Inferred, not proven.**
- IRQ5/6 and IRQ7/8 stubs test two callback slots at `0x200047c0`/`0x200047c4` and tail-call RAM handlers; SysTick increments a counter at `0x20002344`.
- `0xE0001000` (DWT) is used at `0x20001f90` and `0x20001fa8`: cycle counting, i.e. DSP load measurement.

### 17.2 Module library (segment `g`) facts
- 88 modules, **single-precision float code only** (no `f64` instructions in any module); a few have DSP-extension SIMD instructions.
- **Group 6 (17 modules, slot `0x10009000`) is group 1 (15 modules, slot `0x10001000`) relinked at another address**: matched pairs differ in only 0.7-3.2% of bytes (absolute addresses); group 6 adds three modules of its own, and one group-1 module (5,088 B) has no same-size partner.
  So there are **two parallel effect slots sharing one effect library**. Group 5 is three same-size, same-instruction-count variants (not byte-identical).
- Groups 3 and 9 share slot `0x10003800` (22 + 1 alternatives, up to 12 KB each; two of them make 273 and 179 calls, so they lean on helper routines). Group 8 is ten ~250-byte stubs at `0x10018400`. Group 10 is a resident ~8 KB library (490 VFP ops) with entry points `0x10018dfd` and `0x10019435`.
- Constants: **44100** is the only sample-rate constant (host and 12 modules); no 48000. `1/32768` and `32768` (int16 to float and back), `1/sqrt(2)` x33, `2*pi` x6, `pi`, `pi/2`.
  This matches the **0xAC44 (44,100)** stored by the BP1048's SPI-audio context: both chips run at 44.1 kHz with 16-bit samples.

### 17.3 Whole-system picture (evidence level in brackets)
```
 USB / Bluetooth / UI / display / drum machine / flash UI settings      <- BP1048-class SoC, NDS32 (segments b, e) [proved]
        |  SPI (SoC is slave: A20 MOSI, A21 CLK, A22 MISO, A23 CS), 16-bit stereo, 44.1 kHz, 512-B DMA blocks   [proved on SoC side]
        |  UART0 A0/A1 460,800 8N1, framed packets (control/tuning protocol?)                                   [proved on SoC side; peer unknown]
        v
 Cortex-M (FPU, 128 KB RAM at 0x10000000, 881 KB zeroed buffer at 0x29000000, DWT profiling)  <- segment c host (Keil, linked at 0x4000)   [proved: image; chip identity unknown]
        loads overlay modules from segment g into 9 RAM slots, converts int16 <-> float32, runs the float DSP chain                           [inferred from structure]
```
### 17.4 Memory-map fingerprint to identify the Cortex-M part from datasheets
SRAM: `0x20000000` (at least `0x6ae8` up to the initial SP) and about **128 KB at `0x10000000`**; a **0x29000000** window with >= 881 KB used as zeroed buffers; **0x28000000/0x28008000** used by RAM routines;
peripheral pages `0x40005000`, `0x4000B000`, `0x4000C000`, `0x4000E000`, `0x40011000` (regs `+8`,`+0xC`), `0x40020000`, `0x40030000`, `0x40050000` (command-style block); Keil toolchain; VTOR relocated to `0x4400` (image at `0x4000`); FPv4-SP + DSP extension; DWT present.

## 18. Candidate identity of the Cortex-M part: Levetop LT32U03 (UNVERIFIED)

Suggested by the project owner (who has seen the board); the owner reports that the SDK is not available. Web search (secondary sources, product listings and a brochure summary; the datasheet PDFs themselves could not be fetched because the LCSC hosts are blocked from this session):
- Levetop LT32U03A / B / C: Cortex-M4 with single-precision FPU, up to 150 MHz, **508 KB flash, 256 KB SRAM, 8 KB cache**, 3 SPI, 3 UART, I2C, PWM, 12-bit ADC, DAC, USB, AES/DES; packages QFN-48, **QFN-68**, LQFP-100 (LT32U03A is listed as QFN-48, LT32U03C as LQFP-100; B is presumably the QFN-68 part but that was not confirmed).

Consistency with the firmware evidence (what fits, what does not, what is unknown):
- Fits: Cortex-M4F class core with FPU and DSP extension; DWT use; image size (c 50 KB plus g 299 KB plus others) fits in 508 KB of internal flash; about 128 KB of RAM at `0x10000000` plus RAM at `0x20000000` is plausible within 256 KB total.
- Needs checking: **the 881 KB zero-initialised region at `0x29000000` exceeds both 256 KB SRAM and 508 KB flash**, so it would have to be external memory (does this part have an external memory interface? the summary lists none) or my reading of that region-table entry is wrong.
  The `0x28000000` window and the `0x40050000` command-style block (flash/cache controller?) also need the vendor's memory map.
- Implication if confirmed: `c`/`g`/`f` HTFW destinations (`0x200000`, `0x240000`, `0x280000`) are above the part's flash size, so they are update-package addresses rather than the MCU's own flash addresses.
- No SDK or Keil device pack is known; the image was built with Keil/ARMCC, so a vendor Keil pack may exist (unchecked).

To verify: provide the LT32U03 datasheet / reference manual (a PDF in this repo or the three LCSC hosts allowed in the session network settings), then compare its memory map and peripheral base addresses with section 17.4.

## 19. Module loader, module ABI and the M4's flash map (reverse engineered from the host)

### 19.1 Flash map of the Cortex-M part (addresses in its own flash space)
| address | content | evidence |
|---|---|---|
| `0x0000-0x3fff` | not in the update (bootloader?) | image linked at `0x4000` |
| `0x4000-0x1063c` | segment `c` (host firmware) | link base |
| **`0x13000`** | **segment `g`** (module library) | `AppInit` (`0x9edc`) calls `ModuleLib_Install(0x13000)` |
| `0x65000` size `0x8000`, sector `0x1000` | storage region (32 KB; same size as segment `f`) | `AppInit` region setup (`bl 0x83a4`) |
| `0x6d000` size `0xa000` | storage region (40 KB) | `AppInit` (`bl 0x6f5c`) |
| `0x77000` size `0x8000`, sector `0x1000` | storage region (32 KB), **ends at `0x7f000` = 520,192 B = 508 KB** | `AppInit` |
So the HTFW destinations of `c`/`g`/`f` (`0x200000`, `0x240000`, `0x280000`) are package partition addresses, not these addresses. The 508 KB flash size matches the Levetop LT32U03 (section 18); the 192/96/64 MHz clock table (`0x2000235c`) does not match its 150 MHz brochure figure.

### 19.2 RAM map seen from the host
`0x10000000-0x1001f3ff` module slots + resident library; `0x1001f400-0x1001ffff` stacks; `0x20000000` host SRAM (RAM code, data, BSS to the initial SP `0x20006ae8`); **`0x28000000-0x28007fff` 32 KB data windows for the slots** (carved sequentially, ends at `0x28008000`);
**`0x29000000` external RAM** (a self-test at `0x6c44` writes/reads 200-byte blocks there and counts mismatches; the 881 KB zero-init region is variables placed in it).
Central application state block: **`0x20002af4`** (+`0x171+slot` selected index, +`0x185` slot count, +`0x196+slot` copy of selection, +`0x2e0-0x2e4` flags/pointers, +`0x2f8/0x2fc` floats).

### 19.3 Slot descriptor table (RW data at `0x200021a4`, pointer list at `0x200022f4`)
Two 16-byte descriptors per slot. First: `{code base (0x1000xxxx), code size, data window (0x2800xxxx), data size}`; second: `{end of slot (= base + size), 0, 0, 0}` (runtime fields).
Slots: 0 `0x10000000` (0x1000); 1 `0x10001000` (0x1800); 2 `0x10002800` (0x1000, data `0x28004000` size 0x1400); 3 `0x10003800` (0x2c00, data `0x28005400` size 0x1800); 4 `0x10006400` (0x1800, data `0x28006c00` size 0xc00); 5 `0x10007c00` (0x1400, data `0x28007800` size 0x800); `0x10009000` (0x3000); `0x1000c000` (0xc400); `0x10018400` (0x7000); `0x10018800` (0x6c00 = resident library).

### 19.4 Library installer and module loader
- **`0x4e18` ModuleLib_Install(g)**: zero the 11-entry loaded-module table (`0x2000382c`); require group count (`g[0x13]`) <= 11; malloc (`0x4634`) an index object stored at `*0x20002350`, copying the `g` header; for each group allocate `4+4*count` bytes, store the count and the **absolute module pointers `g + offset`**.
- **`0x4ec4` GroupCount(slot)**, **`0x4f60` SlotCount()**.
- **`0x4ee4` LoadModule(slot, index, desc)**: clamp index to the group count (else 0); take the module pointer; clear and copy **payload to the slot base** (`src = module + w0`, length `w1`, so the header is *not* copied); if the descriptor's data size is non-zero, clear the data window and copy **`w3` bytes found at `module + w2`** (the initialised-data block) into it; remember the module pointer in `loaded[slot]` (`0x2000382c + 4*slot`).
  Blob layout, verified on all 87 modules: `blob = header (w0) + code payload (w1) + data block (w3)`, `w2 = w0 + w1`. Module state starts right after the payload (`base + w1`).
- **`0x4f6c` module call (set params)**: `loaded[slot][+0x10]` (header `w4`, "entry1") with `r0 = args[0]`. **`0x4f90` module call (process)**: `loaded[slot][+0x14]` (`w5`, "entry2") with `r0 = args[0], r1 = u16 args[8], r2 = args[0xc], r3 = args[4]` and three stack arguments `&args[0x10]`, `&args[0x14]`, `&args[0x18]`.
- Modules reach the resident library (loaded at `0x10018800`) through two function pointers at `0x10018800` and `0x10018804` (`bx r2` / `blx r4`). Library export A (offset `0x5fc`) builds its working structures in the library's own RAM (it never touches the 881 KB pool); B is at `0xc34`.
Correction: earlier notes treated the module header as part of the loaded image; it is not, and entry offsets are relative to `base + (entry - base)` as linked (payload starts at the slot base).

## 20. Emulation harness and behavioural results (tools/emu.py, emu_host.py, probe_modules.py, sweep_params.py)

**What exists.** `emu_host.HostMachine` (unicorn, Cortex-M4 model with FPU) maps the host flash (`c` at `0x4000`, `g` at `0x13000`), the RAM image from `c_unpack.py`, the slot RAM (`0x10000000`), the 32 KB data windows (`0x28000000`), the external RAM (`0x29000000`) and peripheral space as plain memory.
It runs the **real firmware `LoadModule` (`0x4ee4`)** (only `ModuleLib_Install` is reimplemented, because it needs the firmware's heap), then calls each module's `ENTRY1` (set parameters) and `ENTRY2` (process) exactly as the host dispatchers do.
The resident library is reinstalled after every slot load because the real loader clears the slot-8 range that contains it. All 87 modules load and run without faults.

**Corrections found while building it:** parameters are read from `state + 0x1a0 + 0x20*slot` (8 floats; the host also keeps a copy at `+0x30`); the module header is not loaded; `GetEnable(slot)` is bit `slot` of `state+0x188`; chain order bytes are at `state+0x18c`.

**Module probe** (`docs/module_probe_params50.md`) and **parameter sweep** (`docs/module_param_sweep.md`), parameters all 50 or varied one at a time over {0,1,25,50,100} (ranges are a guess; the real knob scale is unknown):
- **Slot 1 (15 modules) and slot 6 (17 modules, the same library relinked plus 3 extra):** these are the true audio effects. Each has between 1 and 6 parameters that change the signal. Behaviour classes seen: saturating modules whose gain falls with level (e.g. slot 1 idx 0/1: output pinned near a fixed RMS, i.e. drive/limiter), linear modules with tails (EQ-, filter- or modulation-like), a comb/echo-like one (idx 10: peak at 44 samples, 20 echo peaks), and a high-frequency-dominant one (idx 14).
- **Slot 7 (9 modules):** one active parameter (`p0`), near-unity linear behaviour with a `level`/`time` dependence.
- **Slot 8 (10 small modules, ~250 B):** near-unity gain with very long low-energy tails, 0-3 parameters: shelving/EQ-like.
- **Slots 0, 2, 3, 4, 5 (1+8+22+1+3 modules):** `ENTRY2` is exact pass-through and no parameter has any effect on the audio. For slot 3 the process entry only latches scaled parameters into a data window (`0x28001108`) and sets a flag, so these modules appear to **supply parameters/coefficient tables to engine code that runs elsewhere** (the host's RAM engine reads module state at fixed addresses such as `0x10003d5c`). Their large payloads are probably the model data.
Classification here is behavioural and heuristic (level/drive/tone/time); it does not name the effects.

## 21. The block audio engine in RAM (`0x200009a1`): what is known

- One call processes a **64-frame block**; the engine measures itself with SysTick (`0x9a6c`). Scaling: **input int32 samples are left-aligned (`1.0` = 2^31)**; with that scaling the direct path is exactly unity gain; output is **16-bit stereo, 256 bytes at `0x200027bc`** (`0x200028bc` receives a copy).
- Context struct `IO = 0x200029bc`: mono input `int32[64]` at `IO+8` (alternate mode: pointers at `IO+0/+4`, output pointers at `IO+0x108/+0x10c`); aux/second source arrays at `0x200025bc` (L) and `0x200026bc` (R); gains smoothed per block (step 0.01 for `IO+0x110/+0x124`; 1/128 of the error per block for `IO+0x114` toward `IO+0x128`); flags `IO+0x12c/0x12d/0x12e/0x12f`.
  `IO+0x12d` must be 1 for the module chain to run, and the engine **clears `IO+0x12d`/`0x12e` at the end of each block** (re-arm before every call).
- Mode selectors read from the state block: `state[0x30c]` (input mode), `state[0x170]` (variant 1-3), `state[1]` (second source), `state[0x185]` (slot count), `state[0x188]` (enable bits).
- Constants in the prologue: `1/128`, `0.01`, `2.1`, `1/64`, input scale about `1.02e-9` (about 2^-30), output scale about `9.8e8` (about 2^30), `0.1`, `10.01`.
- Chain: for each position the order table gives a slot id; slot 9 is skipped; **slot 2 runs a sub-sequence (slots 2, 9, 5 in one mode, four consecutive slots in another)**; after the chain, a post-stage (`0x20001eca`) and the float to int conversion.
- Emulated whole-engine runs complete without faults (all nine slots are dispatched each block, output buffer written), but **with every context combination tried the module chain was fed silence while the input went to the output through the direct path**, so the engine twin does not yet reproduce the effect chain's audio.
  Open: which flag or handshake routes the input through the chain (candidates: `IO+0x118/0x11c/0x120` gains, `IO+0x12e`, `state[0x2e0-0x2e4]`, the setters at flash `0x5b36` and `0xfd94`).

## 22. Candidate check: Nuvoton NuMicro M480 (NOT a good fit)

Candidate proposed by the project owner (Cortex-M4F with DSP extension, up to 192 MHz, 256/512 KB flash, 96/160 KB SRAM). Checked against the public BSP header (`OpenNuvoton/M480BSP`, `M480.h`), with `tools/addr_fit.py`.
For: **192 MHz HCLK and 96 MHz PCLK** match the firmware's clock table (`192000000, 96000000, 64000000` at `0x2000235c`); Cortex-M4F with DSP extension; 512 KB flash vs the firmware's flash regions ending at `0x7f000`.
Against (stronger):
- **Memory map.** M480 has SRAM only at `0x20000000` (max 160 KB total). The firmware uses at least 128 KB of RAM at `0x10000000`, a 32 KB window at `0x28000000` and external RAM at `0x29000000`; none of these exist in the M480 map.
- **Peripheral page usage.** The firmware computes `0x4000B000 + n*0x1000` and programs `+0x0/+0x4/+0x8/+0xC` of each page: repeated instances of one peripheral type. In the M480 map those pages are EMAC (`0x4000B000`), FMC (`0x4000C000`), SDH0, SDH1 (`0x4000E000`), i.e. different peripherals.
  The `0x4000C000` page is written as `reg[+4] |= 0x1000` followed by a PendSV trigger, not as an ISP flash command; `0x40050000` is TIMER0 on M480 but behaves as a descriptor/command block here; `0x40005000`, `0x40011000`, `0x40020000` match no M480 peripheral.
- No access to the SYS/CLK pages (`0x40000000`, `0x40000200`) that M480 firmware normally touches.
Conclusion: the 192/96 MHz clock plan is a useful constraint, but the memory and peripheral map do not match the M480. Use `tools/addr_fit.py` with other vendors' CMSIS headers to test further candidates.

## 23. Candidate check: Artery AT32F4xx (incl. AT32F455) and a partial peripheral map (NOT a fit)

Headers of the Artery families (`ArteryTek/*_Firmware_Library`, `libraries/cmsis/cm4/device_support/at32*.h`: F435/437, F45x, F402/405, F403/403A/407, F413, F415, F423, A423, F425, F422/426, F490) were run through `tools/addr_fit.py`.
- Every family gives the same 3 generic hits (`0x40005000` USART5/UART5, `0x40011000` USART1, `0x40020000` GPIOA), i.e. the usual STM32-style addresses; these say little. The firmware does touch `0x40011008` and `0x4001100c`, which fits an STM32-style USART (BAUDR at +8, CTRL1 at +0xC), but that layout is common.
- **None** provides RAM at `0x10000000` (the `0x10000000` string in the headers is `PERIPH_BASE + 0x10000000`, the AHB2 region), a window at `0x28000000` or external RAM at `0x29000000`; the Artery SDRAM/XMC windows are elsewhere.
- The AT32F455 (F45x header) is no better than the other families.

**Partial peripheral map recovered from the firmware itself** (host flash `0x9900-0x9a60`): three **serial-interface instances** at `0x4000B000 + n*0x1000` (n = 0..2; the firmware rejects n >= 3), each with TX and RX DMA.
- Per instance: two DMA descriptor structures in RAM (pointers at `0x20002380` and `0x20002384`; words `+0` control, `+4`, `+8`/`+0xC` peripheral and buffer addresses, `+0x14` length), the instance's request IDs `0x20+2n` and `0x21+2n` written to **`0x40020224` / `0x40020228`**, further setup at `0x40020000 + 0x24/0x28`, then NVIC priority/enable.
- Instance registers used: `+4` (config word, bit 4 = enable, bit 12 = another enable), `+8` (data/divider), `+0x10`.
- `0x40020000` therefore behaves as a **linked-descriptor DMA controller with a request-select register file**, with channel-style blocks at `+0x100`, `+0x120`, ... (0x20 apart; seen at `0x40020100/0x40020120`, `0x40030100..0x40030160` for a second controller).
This DMA style is not the STM32/AT32 one (per-channel CCR/CNDTR/CPAR/CMAR with a DMAMUX or fixed request map).
Status of the identity question: still unknown. Constraints so far: Cortex-M4F + DSP extension, 192 MHz / 96 MHz / 64 MHz clock plan, about 508 KB flash (regions end `0x7f000`), RAM windows `0x10000000` (128 KB), `0x20000000`, `0x28000000` (32 KB), external RAM `0x29000000` (>= 881 KB used), the peripheral map above.

## 24. DMA fingerprint and candidate status (what we know, what is ruled out)

**Page-address matching is not a discriminator.** 4 KB-aligned base addresses coincide across many unrelated chips (STM32-style USART/GPIO pages, M480 EMAC/FMC/SDH1, Artery USART5/USART1/GPIOA, Stellaris/nRF52 pages in code searches). Any ranking by pages alone is noise.

**Distinctive fingerprint: the DMA controller at `0x40020000`** (code at host flash `0x9900-0x9a60`), register map as the firmware uses it:
| offset | use in the firmware | matches (Faraday FTDMAC020 layout) |
|---|---|---|
| `+0x20` | bit n read before reconfiguring channel n | CH_BUSY |
| `+0x24` | written 1 once to enable the controller | main CSR |
| `+0x28` | written `0xff` | SYNC |
| `+0x100 + 0x20*n` | channel n blocks (seen `0x40020100`, `0x40020120`) | channel CSR/CFG/SRC/DST/LLP/SIZE |
| descriptor words (RAM) | `+0` control, `+4` config, `+8` source, `+0xC` destination, `+0x14` size | linked-list descriptor |
| `+0x224`, `+0x228` | request IDs `0x20+2n` and `0x21+2n` for serial instance n | vendor request-select extension (not in FTDMAC020) |
A second controller at `0x40030000` has the same channel stride (`+0x100..0x160`). The BP1048's own DMA (NDS32 side, base `0x4000D000`, channels at `+0x20*n`, enable mask at `+0x100`) is a different layout, so the two chips do not share this DMA.
This DMA style is not the STM32/AT32, GD32 or M480 style. Faraday IP appears in some SoCs, but the one Cortex-M4F hit found by code search, Kneron KL520, was **rejected by the project owner** (and uses a different address style).

**Ruled out / not a fit:** Nuvoton M480, Artery AT32F4xx incl. AT32F455 (section 22, 23), Kneron KL520. **Unverified lead:** Levetop LT32U03 (508 KB flash matches; 150 MHz brochure figure vs the firmware's 192 MHz plan does not).
**Constraints to match any candidate:** Cortex-M4F + DSP extension; clock plan 192/96/64 MHz; ~508 KB flash; RAM windows `0x10000000` (128 KB), `0x20000000`, `0x28000000` (32 KB), external RAM at `0x29000000` (a pool descriptor stores it as a plain pointer, so its controller is configured elsewhere, probably by the bootloader); three DMA-capable serial instances at `0x4000B000 + n*0x1000`; the DMA map above.

## 25. Artery AT32F4xx tested by behaviour (contradicted by the firmware's own register use)

Requested focus: Artery. Their headers (AT32F435_437, F45x) have an STM32-F4-style map: UART5/USART5 `0x40005000`, I2C1-3 `0x40005400-0x40005c00`, USART1 `0x40011000`, USART6 `0x40011400`, GPIOA-H `0x40020000-0x40021c00` (0x400 apart), CRC `0x40023000`, CRM `0x40023800`, FLASH_REG `0x40023c00`, (F435/437) EDMA `0x40026000`, DMA1 `0x40026400`, DMA2 `0x40026600` (F45x: DMA1 `0x40026000`, DMA2 `0x40026400`). **Nothing at `0x4000B000-0x4000F000`, `0x40030000` or `0x40050000`.**
What the firmware does at the pages that "coincide":
- **`0x40011000`** (Artery: USART1; STM32 USART registers are STS/DT/BAUDR/CTRL1.. at +0..+0x1c): the firmware writes `0x55555555` to `+0x30`, `+0x34` and `+0x6c`, and read-modify-writes `+0x24` setting several 3-bit fields to `4` (`bic 0x70000000/orr 0x40000000`, then the same at bits 24, 16, 20...). That is a **GPIO-style block with alternate-function fields**, not a USART.
- **`0x40020000`** (Artery: GPIOA, 0x3c bytes of registers): the firmware uses `+0x20` (busy bit read), `+0x24`, `+0x28`, `+0x100`, `+0x120`, `+0x224`, `+0x228`: far beyond a GPIO block; it is the DMA-style controller of section 24.
- **`0x4000B000 + n*0x1000`**, **`0x40030000`**, **`0x40050000`**: no Artery peripheral exists there.
So on an Artery part the firmware would be programming the wrong peripherals at those addresses. Unless the chip is Artery and this segment is not that chip's firmware, the Artery families do not fit. What would change this: an Artery part number read from the board, or an Artery family whose header has a GPIO bank at `0x40011000` and a DMA with `+0x20/+0x24/+0x28` at `0x40020000`.

## 26. Candidate comparison on the owner's criteria (Chinese vendor, QFN-68 package, ~192 MHz)

Secondary sources only (distributor listings, press summaries); datasheets for LT32U03 could not be fetched.
| candidate | QFN-68 package | ~192 MHz | flash | RAM needed (>= ~188 KB: 128 KB @0x10000000 + >= 28 KB @0x20000000 + 32 KB @0x28000000) | register behaviour |
|---|---|---|---|---|---|
| Artery AT32F435/437 | not found (QFN48; LQFP48/64/100/144) | 288 MHz max, 192 MHz possible as a setting | up to MB-class | fits (up to 512 KB) | contradicted (section 25) |
| Nuvoton M480 | not found (QFN is 33-pin; otherwise LQFP) | 192 MHz exact | 256/512 KB | 160 KB total: too small | contradicted (section 22) |
| Levetop LT32U03 | listed (QFN 48/68, LQFP100) | 150 MHz per brochure | 508 KB (matches the firmware's flash end 0x7f000) | 256 KB: fits | unverified |
Notes: Nuvoton is a Taiwanese company. The firmware's 192/96/64 MHz table is not proven to be the CPU clock. To resolve: obtain the LT32U03 datasheet/reference manual and compare its DMA and GPIO register layouts with sections 24 and 25.

## 27. Artery AT32F455/456 facts (192 MHz parts) and the jlcsearch attempt

- jlcsearch.tscircuit.com was requested as a parts-search tool (QFN-68, Cortex-M4/M4F, ~192 MHz, general purpose). It is **not reachable from this session** (shell: HTTP CONNECT 403; web-fetch agent: DNS failure), i.e. outside the allowed network domains; no results were obtained or invented.
- Web search leads: **Artery AT32F455 / AT32F456: Cortex-M4F at 192 MHz, 512 KB flash, 144 KB SRAM (AT32F456 page: 128+16 KB), QSPI and an SDRAM-capable external memory controller; AT32F456 packages LQFP100/LQFP144**; AT32M412/M416 (motor line) are also listed at 192 MHz / 512 KB. Packages of F455 not confirmed. Other 68-pin QFN Cortex-M4 hits were non-Chinese (Infineon CY8C6xxx, Maxim MAX32626).
- AT32F455 GCC linker scripts (`libraries/cmsis/cm4/device_support/startup/gcc/linker/AT32F455xE_FLASH.ld`): flash `0x08000000` 512 KB; **RAM `0x20000000`, 144 KB** (`_estack = 0x20024000`); comment about external memory banks when SDRAM is used. No RAM at `0x10000000` or `0x28000000`.
- Fit with the firmware: frequency (192 MHz exact), flash (regions end `0x7f000`, 4 KB under 512 KB) and external SDRAM support fit; **total internal RAM 144 KB is less than the firmware's use (128 KB at `0x10000000` + >= 28 KB at `0x20000000` + 32 KB at `0x28000000`)**, the peripheral/DMA register behaviour contradicts (sections 24, 25), and a QFN-68 package is unconfirmed.
- To resolve: allow jlcsearch.tscircuit.com (Network access > Allowed domains), or provide the AT32F455/456 reference manual memory map and package list.

## 28. Peripheral inventory of the Cortex-M host (tools/periph_scan.py, docs/m4_peripheral_accesses.md)

Static scan of flash code and the RAM-resident code (constants loaded via literals/movw-movt, then `[base,#off]` loads/stores). Roles are inferred from usage, not from a datasheet.
| page | observed use | confidence |
|---|---|---|
| `0xE0001000` DWT | CYCCNT (`+4`) read: CPU-load measurement | certain (Cortex-M standard) |
| `0xE000E000` SCS | NVIC set-enable/priority (`+0x104`, `+0x420`), ICSR (PendSV trigger), VTOR (`0x4400`), AIRCR, CPACR, DHCSR | certain |
| `0x4000E000` | init block written by `AppInit` (`+0xC = 0x1fc3f`, six writes to `+0x14`, `+0x1c..+0x30`, `+0x54..+0x5c`); also used by `0x5cec`, `0x87e0` | unknown role; looks like system/clock/reset control (single instance, written once at startup) |
| `0x40011000` | `+0x30`, `+0x34`, `+0x6c` = `0x55555555`; `+0x24` 3-bit fields set to 4; `+0x18` and `+0x54` read-modify-write: pin/alternate-function configuration | GPIO/pin-mux-like (not a USART) |
| `0x40020000` | `+0x20` busy bit, `+0x24` enable, `+0x28` sync (`0xff`), `+0x224/+0x228` request IDs, halfword accesses at `+0x136/+0x152`, channel blocks `+0x100+0x20n` | DMA controller (Faraday FTDMAC020-like layout, section 24) |
| `0x40030000` | `+0x28` written once (`0x8a04`); channel blocks `+0x100..+0x160` seen in the RAM table | second DMA-like controller |
| `0x4000B000 + n*0x1000` (n = 0..2) | instance registers `+4` (config, bit 4 enable, bit 12), `+8`, `+0x10`; TX/RX DMA programmed with the instance base as the peripheral address (data register at `+0`) | three serial interfaces with DMA (audio or SPI/I2S class) |
| `0x4000C000` | `+4 |= 0x1000` then PendSV (`0x5a14`) | likely instance n=1 above or a separate enable bit |
| `0x40050000` | command block: `+0..+0xC` written (4-word command, 6x), `+0x10`, `+0x18` polled (status, 8 reads), `+0x24`, `+0x30` (address) and `+0x34` (length, constant `0x400`) written 8x, `+0x4c = 0x10000`, `+0x04 = 0x7fffc`, `+0x100`; used by RAM-resident routines (`0x200001e4`, `0x2000032c`, `0x20000604`) | flash/serial-memory controller with a command interface (inferred) |
| `0x50000000` | `+0`, `+4`, `+8` written once by `0x87e0` | unknown |
| `0x402e0000`, `0x407e0000` | false positives: the "function" `0xdba8` is a data table decoded as code | ignore |
**Audio:** there is no dedicated I2S, ADC or DAC register block among these. Audio reaches the host through the three DMA-driven serial instances (mono input `int32` buffer at `IO+8`, aux L/R arrays at `0x200025bc`/`0x200026bc`) and leaves as 16-bit stereo at `0x200027bc`; the converters are on the other side of those links (the BP1048-class chip, whose own audio ADC/DAC addresses are visible in its SDK, e.g. DMA at `0x4000D000`).

## 29. Test against the AT32F455/456/457 Reference Manual (owner-supplied, Ver 2.00)

The manual itself was uploaded by the owner and is not copied into the repo.
Table 2-3 (peripheral boundaries) compared with the addresses the M4 image uses:

| Firmware address use | AT32F455 at that address | Verdict |
|---|---|---|
| 0x40020000 DMA-like block (+0x20 busy, +0x24 enable, +0x28 sync, channels at +0x100+0x20n) | GPIO port A (0x40020000-03FF); DMA1/DMA2 are at 0x40026000/0x40026400 with an STS/CLR/CxCTRL layout | no match |
| 0x40030000 second controller | Reserved (CRC is 0x40023000) | no match |
| 0x4000B000 + n*0x1000 (3 DMA serial instances) | Reserved (APB1 0x40008000-0x4000FFFF) | no match |
| 0x4000E000 init block | Reserved | no match |
| 0x40011000 pinmux-like block | USART1 (at 0x40011000) | address collision only; firmware writes 0x55555555 to +0x30/+0x34/+0x6c, which does not fit USART |
| 0x40050000 command/status block | Reserved (OTG_FS1 is 0x50000000) | no match |
| 0x50000000 | OTG_FS1 | address collision only; unverified |
| 0x10000000 128 KB code/data window, 0x28000000, 0x29000000 | Not an AT32 SRAM region (SRAM 0x20000000-0x2023FFFF; 0x10000000 falls inside the QSPI multi-map range 0x09000000-0x18FFFFFF) | no match |

The AT32 uses DMA1/DMA2 plus a DMAMUX, I2SF and CRM. The firmware has no
access to the CRM at 0x40023800 or to the AT32 DMA bases.

Conclusion: the image does not run on an AT32F455. The few collisions, USART1
at 0x40011000 and OTG_FS1 at 0x50000000, are page coincidences and the register
usage disagrees with them. Together with the M480 result in section 26 this
leaves the host M4 as an undocumented or custom-peripheral part.
Cross-checking this against the 0x4000B000 serial instances would still be
the next useful comparison.

## 30. Serial instances and DMA descriptors (tools/serial_dma_trace.py)

The generic driver (`SerialDma_Init` flash 0x9900, `SerialDma_Start` 0x99e8, both with n < 3 else fault at 0x47ce) was run
unmodified in the emulator and every peripheral write was logged.

**Only instance 1 (0x4000C000) is ever used.** Instances 0 (0x4000B000) and 2 (0x4000D000) are never initialised. Both the
Init caller (board init 0x5b9c-0x5bbc: `Init(1, {rx=0x200023bc, tx=0x200027bc, len=0x200})`) and the Start caller (block
callback 0x5a14-0x5aa0: `Start(1, rx=0x1001fc00, tx=0x1001fe00, len=0x200)`) pass n = 1. This is the 512-byte full-duplex
audio link to the BP1048 SPIS port (section 17): the 512 B block size and the full-duplex DMA pair are the same ones seen from
the NDS32 side.

DMA controller (0x40020000), as the driver programs it:

| offset | meaning | evidence |
|---|---|---|
| +0x20 | status, bit1 = a channel is busy (Start returns early if set) | read at 0x9a06 |
| +0x24 | global enable (1) | |
| +0x28 | sync/mask, 0xff | |
| +0x100 + 0x20*ch | channel registers: +0 control, +4 config, +8 source, +0xc destination, +0x14 count (+0x10 never written) | writes in Init/Start |
| +0x220 + 4*k | request-ID registers, k = 1 -> 0x224, k = 2 -> 0x228 | Init |

Serial instance n uses request IDs 0x20+2n (TX) and 0x21+2n (RX); for n = 1: 0x22 on `ch1` (memory -> serial) and 0x23 on `ch0`
(serial -> memory). `ch0` is wired to 0x228 and `ch1` to 0x224.

Channel control words (constants at flash 0xA5A0):

| channel | direction | ctrl | cfg (+4) |
|---|---|---|---|
| ch0 | serial -> memory | 0x800200C1 | 0x000014D7 |
| ch1 | memory -> serial | 0x80020091 | 0x0000324F |

The two ctrl words differ only in bit6 (set for RX) and bit4 (set for TX). Since ch0 has the serial data register as source and
the buffer as destination, bit4 and bit6 look like source-increment and destination-increment. Bit0 is enable. Bits 7, 17 and 31
are common to both. The remaining cfg bits are not decoded.

Serial registers (constants at flash 0xA5B0 = {0x000CC110, 0x000003EA, 0, 0x40005000}):

| offset | use |
|---|---|
| +0x04 | mode word 0x000CC110 (bits 4, 8, 14, 15, 18, 19). Bit4 is the enable (Init ORs it in). Bit12 (0x1000) is cleared by Start and set by the block callback before it calls Start, so it behaves like a hold/re-arm bit. |
| +0x08 | transfer length in bytes (0x200). Start writes the same length to the DMA count. |
| +0x10 | 0x3EA (1002); meaning unknown (timing or divider). |

The block callback (0x5a14) deinterleaves 16-bit samples from the received buffer into two int32 arrays (sample << 16) and the
difference (A-B)>>1 into the working struct. This was read from the disassembly, not run on real audio.

Reproduce: `python3 tools/serial_dma_trace.py c.bin g.bin ram_20000000.bin`.

Still open: the cfg word bit fields; what 0x3EA configures; whether 0x40005000 (4th word of the serial table; USART5 on the
AT32 map, which is only an address coincidence) is a clock or pin block; and the UART path to the BP1048, which is probably the 0x40011000 block.

## 31. BLE roles and connection limit (NDS32 side, segment b)

Addresses below are file offsets in segment b (runtime = file + 0x10000). Strings are at runtime 0xdf0ac-0xdf2f0.

**What the stock firmware has**
- A manufacturer BLE module ("V1.0.01" string, runtime 0xdf068) with a **central role**: scan, a scan-result list (8 entries x 0x28 bytes = 0x140 bytes, cleared by the memset at file 0x4b52, entries added at 0x4d18 with the check `count < 8`), "Open Scan for Connect", "Time Out Close Scan/Connect", "Set Connect 2:%d", a GATT-client receive handler ("Receive data type:%02x size:%d, conHandle valHandle") and a "Has been connected" guard.
- A **peripheral role** (GATT server, advertising) with the standard BLE-MIDI service UUID 03B80E5A-EDE8-4B33-A751-6CE34EC4C700 in the data at file 0xcf308 (plus the "Pocket Master BLE" name).
- Role switches `close_role(r)` at 0x4acc ("Close Ble Role %d") and `open_role(r)` at 0x4b00 ("open Ble Role %d"). Both end up in `BleRoleSet(role, enable)` at file 0x8f696 (a library routine), where role 0 is the scan/central side, 1 the peripheral and 2 a second variant. App role 3 is mapped to 0 and also does a `ListMemInit` call (0x91d82).

**Evidence that roles are exclusive in the stock policy**
- The state machine at 0x52a8-0x5430 always calls `close_role(3)` before `open_role(1)` or `open_role(2)` and clears its connection counters, and `open_role(3)` is preceded by closing the others. State bytes (gp-relative) track the current mode, a target-address word and timeouts (0x542c: 0x2ee1 / 0xfa1 tick limits per mode).
- The SDK's own `BLE_APP_CONTEXT` has one `ble_device_role` (CENTRAL_DEVICE or PERIPHERAL_DEVICE) per `InitBleStack`, one GATT server profile and a single `BleConnectFlag`. There is no connection-count parameter in the public SDK header `ble_api.h`.

**What is not known**
- Whether the closed BLE library itself can hold two LE links, or an LE link next to A2DP (A2DP is classic BR/EDR and is independent of the LE role in principle, but the stock firmware may close central when audio is active: `0x421bc` returns a global byte, gp-41536, that gates the role change at 0x53dc; what sets it is not yet identified).
- Whether notifications received in central mode are parsed as BLE-MIDI. The handler is the "Receive data type" function; its consumer was not followed.

## 32. Test against the LT32U03 datasheet (LT32U03_DS_V11_ENG.pdf, owner-supplied, on `main`)

Chapter 3 (memory map), chapter 23 (DMAC) and the clock tree (section 4) compared with the Cortex-M host evidence:

| Firmware | LT32U03 | Verdict |
|---|---|---|
| SRAM at 0x20000000 (stack 0x20006ae8, copied code/data) | SRAM0-3 at 0x20000000-0x20037FFF, TCM at 0x1FFF8000 | fits |
| 508 KB flash (storage regions end 0x7f000) | 512 KB EFLASH at 0x08000000, aliased at 0x0 | fits (508 KB is the vendor's quoted figure) |
| 0x10000000 used as a 128 KB RAM window (ZI at 0x1001f400, module slots) | 0x10000000-0x10FFFFFF is the SPIM1 memory-mapped window (16 MB), and 0x60000000 is a second SPIM1 window | interesting: could be external SPI PSRAM or flash mapped there; not proved |
| 0x28000000 and 0x29000000 | not in the map | no match |
| 0x40020000 DMA-like block (busy +0x20, enable +0x24, sync +0x28, channels +0x100+0x20n) | ADC at 0x40020000; DMACs are at 0x40046000/0x40047000, EDMAC at 0x4000A000/0x40039000 | no match |
| DMAC layout | Synopsys DesignWare style: channel stride 0x58, CFG at +0x40, interrupt status banks from +0x2C0, CHEN at +0x3A0 | differs from the firmware's controller |
| 0x4000B000+n*0x1000 serial instances, 0x4000C000, 0x4000E000, 0x40030000, 0x40050000 | reserved / LD (0x40030000) / reserved | no match (SPI1-3 are at 0x40010000-0x40012000, SCI1-3 elsewhere) |
| 0x40011000 pinmux-like block | SPI2 | register use disagrees |
| 192/96/64 MHz clock table | CORE_CLK max 120 MHz, internal oscillator 120 MHz (marketing text says 150 MHz) | no match |

Conclusion: LT32U03 matches RAM base and flash size but not any peripheral base, the DMA controller layout or the clock rates,
so it is not the host M4 (unless the peripheral maps differ between silicon revisions, which the datasheet does not suggest).
Together with sections 26, 27, 29 and the PSoC 6 check, the host is not one of the candidates tried so far.
The 0x10000000 observation is worth following up: it gives a concrete way for a RAM window at 0x10000000 to exist on a
Levetop-style part, but it is not enough on its own.

## 33. Behavioural decode of the clock, pin-mux and flash-command blocks (tools/pinmux_trace.py)

**Corrections to section 28 (scanner false positives).** `0x402e006c`, `0x407e0078` (function 0xdba8) and `0x50000000` (function 0x87e0) are not
peripheral accesses: 0xdba8 is a constant table that the linear sweep decoded as code, and 0x87e0 is DSP code whose literals
were misread. Ignore those rows (and the "unlock key" idea built on them). The 0x4000C000 +0x4 entry is the serial block of
section 30. The first part of 0x5cec is a struct clear, not a pin-mux function.

**0x4000E000: clock / PLL controller** (function 0x5d48, run unmodified in the emulator):
- +0x14: write-enable guard (1 while writing, 0 afterwards)
- +0x54 / +0x58 / +0x5C: three PLL configuration words, 0x03000F00 / 0x0B400000 / 0x03002222 (table at flash 0xA574). They are only rewritten if they differ from what is already there.
- Sequence: clear bits [1:0] of +0x20 (select the bypass clock), write the three words, set bit0 of +0x54, wait about 0xC6 loop iterations (~600 cycles), clear bit0, wait again, then set bit1 of +0x20 (switch to the PLL).
- +0x0C = 0x1FC3F (function 0x9edc): peripheral clock-enable mask, bits 0-5 and 10-16.
- Other +0x1C..+0x30 writes are in the clock tree setup (not yet decoded).

**0x40011000: chip-wide pin controller** (function 0x5DB8):
- 4-bit alternate-function field per pin, 8 pins per register: +0x18 (pins 0-7) = 0x33333333, +0x1C (8-15) = 0x22222222, +0x20 = 0x00000020, +0x24 (24-31) = 0x44440000.
- A second bank at +0x58 = 0x22200011 and +0x54 area = 0x00222222.
- +0x30, +0x34, +0x6C = 0x55555555: 2-bit fields set to 01 for 16 pins each (48 pins), probably pull or drive setting.
- This fits a package with about 50 GPIO.

**0x40050000: SPI-NOR style flash command engine** (RAM-resident code, executes from RAM because it erases/programs):
- Registers: +0x00..+0x0C command words, +0x24 status (bit0 = done; helper at RAM 0x2000077C waits with a timeout), +0x30 address/window (written with `0x20000000 | addr`), +0x34 length (0x400 = 1 KB chunk).
- The command tables at RAM 0x200020C8 use the standard SPI-NOR opcodes: erase 0x20 (4 KB), 0x52 (32 KB), 0xD8 (64 KB), 0x60 (chip erase, size field 0x80000 = 512 KB); and 0x05 (read status), 0x06 (write enable), 0x66 (reset enable), 0x02 / 0x32 / 0x42 (page program variants).
- Reading: the 508 KB "flash" is NOR behind this engine, not a classic on-chip flash array: 512 KB chip-erase size minus the 4 KB at the end.

Consequence for chip identification: this is a Cortex-M4 whose program memory is a 512 KB SPI-NOR style device driven by a command controller
at 0x40050000, with PLL words at 0x4000E054-5C and an AF-per-pin controller at 0x40011018-0x40011024. These are three unusual register layouts to search for in
vendor documentation (an SPI-NOR flash in package or on die). The DMA controller layout (section 30) remains the other.

## 34. Looper: end-to-end simulation and an experimental longer-loop patch (tools/looper_sim.py, tools/patch_looper.py)

Details of the buffer layout are in `docs/looper_notes.md`. New here:

- **The stock limit is 20 s** (confirmed by the owner: the pedal records in mode 1 = 22.05 kHz mono).
- **Mode fields.** The block function 0x8b8c calls the state machine 0x8fec each block. That machine compares the half-word at state+4
  (requested: mode byte, second byte) with the half-word at state+8 (active). If they differ it sets the "clear loop" bit and erases the loop
  every block. Anything driving the looper must keep +4/+5 equal to +8/+9. Which code writes them was not found (the init routine writes only +4=1, +5=0; they probably come from the other chip).
  The block function also drops the audio (zero output) unless the byte at +9 equals its fourth argument.
- **Record ends** when `length - pos <= mode*frames` (length starts at the capacity constant). The state machine then sets the end bit and
  moves to play; play wraps to 0 at the loop length.
- **Simulation** (`looper_sim.py`, real code, mode 1): stock capacity 441,024 -> 13,779 blocks = **20.00 s**, loop length 440,896, play wraps correctly.
  With capacity 2,646,000 -> 82,685 blocks = **120.00 s**, loop length 2,645,888, play wraps correctly. No 16-bit or other overflow.
- **UI side.** The main chip formats the loop time with "%d.%ds" (seconds and tenths: function around runtime 0x1118c); there is no
  fixed-width minute field, so 120.0 s is a longer text but not a different format. Label width was not checked.
- **Patch tool.** `patch_looper.py in.bin out.bin --seconds 120` rewrites the capacity (flash 0x8fd8) and the matching zero-init size
  (flash 0xe3c8, 2x capacity), recomputes the segment CRC and repacks with htfw.py. On CFW 0.9.4 exactly 8 bytes differ (2 CRC bytes, 3 + 3
  constant bytes). **Not tested on hardware.** Open risks: (1) the size of the memory at 0x29000000 is unknown (120 s needs 5.29 MB);
  (2) the header word at offset 4 is copied unchanged and it is not known whether the updater checks it (its value differs between the three
  images but is not a plain sum or CRC of anything tried); (3) the loop zero-fill at start-up takes longer.

## 35. Board observations from the owner (not derived from the firmware)

- The external RAM is a **Winbond W9864G6KH**: 64 Mbit (8 MB, 4M x 16) SDRAM, 166 MHz, 54-pin TSOP-II. Found under another part.
  A 16-bit SDRAM needs about 38 signal pins (A0-A11, BA0-1, DQ0-15, CLK, CKE, CS, RAS, CAS, WE, LDQM, UDQM), so it cannot hang off the
  BP1048 (28 GPIO, no external memory bus). It is attached to the other processor, which therefore has a parallel SDRAM controller.
  Open question: the package count of that chip (a 68-pin QFN would be unusual for a 16-bit SDRAM bus); to be confirmed by counting pins and
  tracing the SDRAM clock/CS to the chip.
- The loop buffer (0x29000000, 882,048 bytes today) therefore lives in an 8 MB device. A 120 s loop at 22.05 kHz mono is 5.29 MB. How the
  rest of the 8 MB is used (heap, delay and reverb buffers, module data) and where the SDRAM is mapped is not known.
- The 5-pin 0.1" header (pin 1 GND, pin 5 3.3 V, pins 2-4 pulled up through about 15 kohm) was traced by the owner to the second processor.
  An SWD attempt with an ST-LINK (Nucleo, CN2 jumpers removed) did not connect with pin pairs from pins 2-4 and no reset line. A first
  attempt with the jumpers left in connected to the Nucleo's own STM32F303 (device ID 0x446) and tells nothing about the pedal.
- The SOIC-8 part near the BP1048 is probably a battery controller, not a SPI NOR. No NOR flash was found. The CFW manual's advice to dump
  the flash with a CH341A and SOP-8 clip is therefore not understood and may not apply to this board.

## 36. Memory budget of the second processor (boot trace and module probe)

Run unmodified in the emulator (`reset 0x4d91`, then the scatter-load and C runtime): the three zero-fills are 0x1001f400 (0xc00), 0x200023bc (0x472c) and
**0x29000000 (0xd7580)**; the decompressor fills 0x2000218c (0x230). The C runtime then builds a heap descriptor at 0x20004ae8 with
**one 0xff0-byte block at 0x20004af8**, and the heap-extension routines (0x4b00, 0x4b28) contain `nop.w` where an OS call would be,
so the heap is not grown: it is about 4 KB of on-chip SRAM, used by the module loader for its small index structures (the mallocs
seen during ModuleLib_Install are 8-0x5c bytes).

Module slots (descriptor table at RAM 0x200021a4): payload slots inside 0x10000000-0x1001f400 (sizes 0x1000-0xc400) and data
windows at 0x28004000-0x28008000 (0x400-0x1800 bytes each; slots 6-8 have none). `tools/module_mem_probe.py` loads every module through the real loader and runs six
blocks: **no module touches 0x29000000**, slots 2-5 use the 0x28000000 windows (spans of 14-24 KB) and slots 1 and 6-8 touch neither. Only
three code sites in segment c hold the literal 0x29000000 (0x8fd4, 0x90c8, 0xe3c4), all in the looper init/scatter code.

Consequence: as far as the code examined shows, **the SDRAM is used only by the looper (882 KB of the 8 MB)**. Not explained: where the
delay and reverb buffers live (not in the SDRAM and not in the windows in this probe; probably in on-chip SRAM beyond 0x20006ae8, whose size is unknown).
Caveats: the probe uses default parameters and six blocks, so lazily allocated state may not show; the emulator maps 1 MB at 0x20000000, so an access beyond the real SRAM would not fault there.

## 37. Search for the loader that programs the second processor (negative result so far)

Looked for any code on either chip that transfers segments c/g/f to the second processor:

- **BP1048 application (segment b).** Found no routine that streams an image out. Its only visible link to the other chip is the SPI audio port and the UART0
  tuning-protocol receiver. The factory-test screen (code at file 0x18e40, strings at runtime 0xe1100-0xe1150) prints `dspVer`, `mcuVer`, `bootVer`, `HwVer`
  and `uid`; these come from constant strings and a settings struct (`0x418b4` copies a version string from a structure whose first half-word must be 0x5AFF), not from a query to the other chip that I could trace.
  The code at file 0xa2040-0xa2290 that compares against 0x65/0x66/0x67 is a Bluetooth state machine, not a segment-type dispatcher.
- **Second processor (segment c).** Its flash driver (erase 0x8488, page program 0x84c8, reached through veneers 0x4dbc / 0x4dd0 into RAM routines at 0x200001e4 and 0x2000032c) is only called from the storage code at 0x7332-0x7e2a
  (user IR / Clone / name regions, which the CFW rewrites). Nothing found that writes the code and DSP regions (0x4000-0x64fff).
- **Interpretation.** The update of segments c/g/f (the CFW replaces c and g) must be done by something that is not in the update file: the **bootloader on the BP1048 or on the second
  processor**, which the CFW manual says is not part of the update. The loader protocol is therefore not recoverable from the package.
- **Experiments that would reveal it without a flash dump:** watch the header's reset line and the BP1048's UART/SPI pins with a scope or logic analyser while Sonicake Manager flashes a firmware (a reset pulse followed by traffic on a UART or SPI line would show how the other chip is entered and what protocol it speaks).
  The segment c header (0x400 bytes: 8 x 0xFF, "V132", 0x4400, zeros) is also a format fingerprint for the second chip's bootloader.
