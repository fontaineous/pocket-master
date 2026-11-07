| pin | mode | function (from gpio.h) | call sites |
|---|---|---|---|
| A0 | 2 | uart0_rxd_0(i) | 0x51014 |
| A1 | 12 | uart0_txd_0(o) | 0x5101c |
| A7 | 0 | gpio default register value | 0x508a0 |
| A9 | 0 | gpio default register value | 0x508ac |
| A16 | 0 | gpio default register value | 0x508b6 |
| A17 | 0 | gpio default register value | 0x50814 |
| A22 | 0 | gpio default register value | 0x50832 |
| A24 | 0 | gpio default register value | 0x50950 |
| B2 | 0 | gpio default register value | 0x50a36 |
| B2 | 5 | FM2R | 0x5ecce |
| B3 | 0 | gpio default register value | 0x509f6 |
| B3 | 5 | FM2L | 0x5ecfc |
| B5 | 0 | gpio default register value | 0x509aa |

13 call sites; 13 resolved to a constant single pin; 0 unresolved (pin/mode not a compile-time constant here).
