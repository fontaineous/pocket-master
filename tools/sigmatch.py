#!/usr/bin/env python3
"""Name stock-firmware functions by matching functions of an Andes-built reference ELF.

For every function symbol in the reference ELF (nds32le, linked), mask the address-dependent
fields of each instruction (j/jal targets, sethi/ori immediates, $gp-relative offsets), turn it into a
byte regex and search the stock NDS32 code. Unique matches become symbols.

usage: sigmatch.py <nds32le-elf-nm> <nds32le-elf-objdump> <reference.elf> <stock_b.bin> [min_bytes=16]
Output: CSV  runtime_addr,size,name,matches   (runtime = file offset + 0x10000)
"""
import re, subprocess, sys

def functions(nm, objdump, elf):
    out = subprocess.run([nm, '-S', '--defined-only', elf], capture_output=True, text=True, check=True).stdout
    funcs = []
    for l in out.splitlines():
        p = l.split()
        if len(p) == 4 and p[2] in 'TtWw':
            funcs.append((int(p[0], 16), int(p[1], 16), p[3]))
    # image bytes via objcopy-style: read sections with objdump -s would be slow; use objcopy binary of the ELF
    return funcs

def mask_insns(code):
    """Return (bytes, mask) where mask[i]=1 means the byte is address-dependent."""
    mask = bytearray(len(code)); i = 0
    while i < len(code):
        b0 = code[i]
        if b0 & 0x80:                       # 16-bit instruction
            i += 2; continue
        if i + 4 > len(code): break
        op = b0 >> 1                        # 6-bit opcode field in bits 30:25
        if b0 in (0x48, 0x49):              # j / jal : 24-bit displacement
            mask[i+1:i+4] = b'\x01\x01\x01'
        elif op == 0x23:                    # sethi : 20-bit immediate
            mask[i+1] |= 1; mask[i+2] = 1; mask[i+3] = 1
        elif op == 0x2c:                    # ori (often completes a sethi pair)
            mask[i+2] = 1; mask[i+3] = 1
        elif op in (0x1e, 0x1f):            # $gp-relative load/store/addi.gp (imm17/18)
            mask[i+1] |= 1; mask[i+2] = 1; mask[i+3] = 1
        i += 4
    return mask

def main():
    nm, objdump, elf, stock = sys.argv[1:5]
    minb = int(sys.argv[5]) if len(sys.argv) > 5 else 16
    B = open(stock, 'rb').read()
    # dump the reference ELF's loadable bytes to a flat binary at its link addresses
    flat = elf + '.flat.tmp'
    subprocess.run([objdump.replace('objdump', 'objcopy'), '-O', 'binary', elf, flat], check=True)
    img = open(flat, 'rb').read()
    funcs = functions(nm, objdump, elf)
    print('runtime_addr,size,name,matches')
    seen = 0
    for addr, size, name in sorted(funcs):
        if size < minb or addr + size > len(img): continue
        code = img[addr:addr + size]
        m = mask_insns(code)
        # longest run of unmasked bytes is used as a fast anchor, then the full masked pattern is verified
        best = (0, 0); run = 0
        for k in range(len(code) + 1):
            if k < len(code) and not m[k]: run += 1
            else:
                if run > best[0]: best = (run, k - run)
                run = 0
        if best[0] < 6: continue
        a0, alen = best[1], best[0]
        anchor = code[a0:a0 + alen]
        pat = re.compile(b''.join(b'.' if m[k] else re.escape(bytes([code[k]])) for k in range(len(code))), re.DOTALL)
        hits = []; pos = B.find(anchor, 0, 0x100000)
        while pos != -1:
            start = pos - a0
            if start >= 0 and start % 2 == 0 and pat.fullmatch(B, start, start + len(code)): hits.append(start)
            pos = B.find(anchor, pos + 1, 0x100000)
        if hits:
            seen += 1
            print(f'{";".join(hex(h + 0x10000) for h in hits)},{size},{name},{len(hits)}')
    print(f'# {seen} reference functions matched', file=sys.stderr)
main()
