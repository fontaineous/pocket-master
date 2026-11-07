# SWD probing of the second processor (UNTESTED)

Wiring (Nucleo ST-LINK/V2-1, jumpers on CN2 removed so it talks to the outside, CN4 SWD connector):

| Nucleo CN4 | Pedal header |
|---|---|
| 3 GND | pin 1 (ground) |
| 1 VDD_TARGET | pin 5 (3.3 V; this pin only senses the voltage, do not power the pedal from it) |
| 2 SWCLK, 4 SWDIO | two of pins 2-4 (try both orders) |
| 5 NRST | the third of pins 2-4 (leave unconnected for the first attempt) |

Power the pedal from its own USB. Series resistors of 100-330 ohm on SWCLK/SWDIO are optional but a good idea.

First read-only commands (OpenOCD telnet or `-c`):

```
dap info                 # prints the ARM debug IDs and the ROM table (names the part's vendor/designer code)
mdw 0xE000ED00           # CPUID (a Cortex-M4 r0p1 reads 0x410FC241)
mdw 0xE0042000 4         # many vendors put a device ID here; may fault if not implemented
```
Then, only with the CPU halted (`halt`; a reset or power cycle restores the pedal):

```
mdw 0x29000000 4         # does the 0x29000000 window read back
mww 0x29000000 0x12345678 ; mdw 0x29000000 1     # RAM write test (this is the loop buffer, nothing else lives there)
mdw 0x4000e054 3         # PLL words, expect 0x03000f00 0x0b400000 0x03002222
mdw 0x40020000 8         # DMA-like block
```
Size probe: write a distinct word at 0x29000000 + 2^n for n = 16..26 and read back 0x29000000 after each write; an alias (the first word changes) shows the end of the memory.
Do not run `flash write_*`, `flash erase_*`, `stm32* unlock` or any mass-erase command.
