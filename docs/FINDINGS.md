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
