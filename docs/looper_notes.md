# Looper: where the audio lives and what limits its length

Status key: **[verified]** = read from the disassembly and/or reproduced in the emulator (`tools/looper_probe.py`);
**[inferred]** = consistent with the evidence but not proved.

## Result in one paragraph
The loop buffer belongs to the **Cortex-M4 image (segment c)**, not to the NDS32 chip. It is a single array of **441,024 int16
samples (882,048 bytes) at 0x29000000**. The record path has two modes. In one mode the signal is decimated 2:1 (22.05 kHz, mono) and
the buffer holds **20.0 s**; in the other it is 44.1 kHz mono and the buffer holds **10.0 s**. The length limit is one 32-bit constant
(0x6bac0) plus the size of the zero-initialised region the loader reserves for the array. Nothing else in the M4 image uses the
0x29000000 region.

## Loop state struct (RAM 0x20004850) [verified from code]
| offset | meaning | evidence |
|---|---|---|
| +0x00 | command bit mask (bit0/1/3/4/5 pending requests) | 0x9310 sets `1 << n`; state machines at 0x8fec / 0x90d0 / 0x9228 test the bits |
| +0x01 | state 0-5 (3 = play, 4 = record, 5 = overdub/mix) | dispatch in 0x8b8c: 3 -> 0x8be4, 4 -> 0x9324, 5 -> 0x950c |
| +0x08 | mode byte: 1 or 2 (1 = decimated 22.05 kHz, 2 = 44.1 kHz) | emulation below; time formulas at 0x9810 / 0x9840 |
| +0x14 / +0x15 | two level settings, default 0x32 (50) | init at 0x8f98-0x8f9c, setters 0x9894 / 0x9888 |
| +0x18 / +0x1c / +0x20 / +0x24 | float gain ramps | record loop at 0x9324, play loop at 0x8c80 |
| +0x28 | buffer base = **0x29000000** | init at 0x8fb4 (literal at flash 0x8fd4), reset at 0x906c (literal 0x90c8) |
| +0x2c | capacity in int16 samples = **0x6bac0 = 441,024** | init at 0x8fb8 (literal at flash 0x8fd8) |
| +0x30 | length of the recorded loop (starts at 0x6bac0) | 0x8fba |
| +0x34 | current position in int16 samples | record: `base + pos*2`, advanced at 0x94f2-0x94f6 |

## Capacity arithmetic [verified]
* 0x6bac0 = 441,024 samples x 2 bytes = 882,048 bytes = 0xD7580, which is exactly the zero-initialised region in the scatter-load
  table (`dst=0x29000000 size=0xd7580`, table entry at flash 0xe3c4 / 0xe3c8). The array fills the whole region.
* Time readout functions (0x9810 elapsed, 0x9840 position/remaining) compute `ms = ((pos*2) >> (mode-1)) * 0.0226757` where
  0.0226757 = 1/44.1 (ms per sample at 44.1 kHz). So one stored sample is 2 time-samples in mode 1 and 1 in mode 2.
* Emulation (`tools/looper_probe.py`, real record function 0x9324, 64-frame stereo float blocks):
  * mode byte 1: position advances **32** per block -> 13,782 blocks x 64 / 44,100 = **20.0 s**
  * mode byte 2: position advances **64** per block -> 6,891 blocks = **10.0 s**
* Mode 1 reads only the left channel (stride 8 bytes), runs it through a filter/decimator at 0x85a4 (64 taps, `movs r2,#0x40`)
  and keeps every other sample. Mode 2 stores one sample per frame at 44.1 kHz (details of which channel it keeps are [inferred];
  the code stores both L and R of each frame to a temporary and copies only the first half of that temporary).
* The "about 20 s" limit is therefore the mode-1 case. I did **not** find what writes the mode byte at +0x08 (not in the init
  routine, not set through a literal-pool base anywhere in flash/RAM code; probably set by a command from the other chip or a
  settings copy). If mode 2 is the one the product normally uses, the real limit is 10 s.

## What to change for a longer loop [inferred, not tested on hardware]
1. Capacity constant: 32-bit word at flash 0x8fd8 (file offset 0x4fd8 in segment c); value 0x6bac0.
2. ZI size in the scatter-load table: word at flash 0xe3c8 (0xd7580); it must equal 2 x capacity or the extra memory is not zeroed.
   (Table entry layout: src=0x10638, dst=0x29000000 at 0xe3c4, size at 0xe3c8, handler 0x4594 = zero-fill.)
3. Physical memory at 0x29000000+size must exist. **The size of the memory behind 0x29000000 is unknown** (it may be the external
   RAM chip, on-chip SRAM, or something else; the address map of this M4 is not identified). Required sizes:
   * 2 min, 22.05 kHz mono mode: 2,646,000 samples = 5.29 MB
   * 2 min, 44.1 kHz mono mode: 5,292,000 samples = 10.58 MB
4. Position/length fields are 32-bit and the time readout is int32, so no arithmetic limit is hit below 2^31 samples.
5. Not checked: any clamp in the NDS32 firmware's looper UI (it draws "Empty / Recording / Playing / Overdub", "REC VOL", "Play VOL";
   strings at runtime 0xe1600-0xe1740) and whether loop time is displayed in a fixed-width field.

## NDS32 side
* Looper UI strings: `Stop, Drum VOL, Drum BPM, REC VOL, Play VOL, Empty, Recording, Playing, Overdub, Pre, Post, Level, ...`
  near runtime 0xe1600; also `FX REC`, `BT REC`. These are GUI labels; I found no loop buffer or SDRAM address on the NDS32 side.
* The `SDRAM SUCCESS` / `SDRAM\nFAIL:%lu` strings at runtime 0xe119c sit among factory-test strings (`Please Test Audio`,
  `Test Finish\nPlease Quit`). I did not find the code that uses them (the linear disassembly there is data), so which chip
  the SDRAM test targets is **not established**.

## Custom firmwares
* CFW0.5 and CFW0.9.4 both **modify segment c** (1,216 and 1,339 changed bytes; CFW0.9.4 also grows c to 61,424 bytes and changes g).
  Many one-byte changes are `0x05 -> 0x0a` (e.g. flash 0x5266, 0x52f2, 0x53a4, 0x562a, 0x578e, 0x5838, 0x6600, 0x837a-0x846a:
  a limit of 5 raised to 10, probably a slot/chain count) plus rewritten functions at 0x53ae, 0x56a4-0x5727, 0x7340-0x73fb,
  0x7830-0x7ad7, 0x7be0-0x7c97 and constants at 0xa0b0, 0xa52c, 0xe434-0xe4af.
* **None of these changes fall in the looper code (0x8f7c-0x9500) or touch the 0x6bac0 / 0x29000000 / 0xd7580 constants.** The
  looper is stock in both custom firmwares.
* Separate finding for the parent notes: the earlier assumption that the custom firmwares only patch the NDS32 segment is wrong; they
  also patch the M4 image.
