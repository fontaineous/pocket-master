#!/usr/bin/env python3
"""Hotone Pocket Master 'HTFW' firmware container: unpack / pack / info.

Layout (all little-endian):
  0x00  "HTFW"
  0x04  u32  UNKNOWN (not a plain sum/xor/CRC of anything tried; copied from a donor image)
  0x08  u32  total file size
  0x0c  char[16] product name ("Pocket Master")
  0x1c  4 bytes  'V',1,3,3  (base firmware version)
  0x20  u32  0x50000 (constant in all samples)
  0x24  u32  payload length (= file size - 0x88)
  0x38  5 x 16-byte segment entries:
          +0  crc16 (CRC-16/MODBUS of the segment data, stored BIG-endian)  [2 bytes]
          +2  0x00
          +3  segment type char: c g f b e
          +4  u32 destination address (flash offset)
          +8  u32 offset of data inside payload
          +12 u32 size
  0x88  payload (segments back to back)
Segments: b = NDS32 (big-endian) application, c = Cortex-M/Thumb image,
          g = float tables (IR/model data), f = cab/IR name table + settings, e = presets.
"""
import argparse, json, os, struct, sys

HDR = 0x88
NSEG = 5

def crc16_modbus(data, crc=0xFFFF):
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc

def parse(path):
    d = open(path, 'rb').read()
    if d[:4] != b'HTFW':
        sys.exit(f'{path}: not an HTFW image')
    hdr = bytearray(d[:HDR])
    segs = []
    for i in range(NSEG):
        e = d[0x38 + 16 * i: 0x48 + 16 * i]
        crc_be, flag, typ = e[0:2], e[2], chr(e[3])
        addr, off, size = struct.unpack_from('<III', e, 4)
        data = d[HDR + off: HDR + off + size]
        segs.append(dict(type=typ, flag=flag, addr=addr, off=off, size=size,
                         crc=int.from_bytes(crc_be, 'big'), data=data))
    return d, hdr, segs

def info(path):
    d, hdr, segs = parse(path)
    print(f'{path}: {len(d)} bytes, unknown hdr[4]=0x{struct.unpack_from("<I", d, 4)[0]:x}')
    for s in segs:
        c = crc16_modbus(s['data'])
        print(f"  {s['type']} addr=0x{s['addr']:06x} off=0x{s['off']:06x} size=0x{s['size']:06x} "
              f"crc=0x{s['crc']:04x} calc=0x{c:04x} {'OK' if c == s['crc'] else 'BAD'}")

def unpack(path, outdir):
    d, hdr, segs = parse(path)
    os.makedirs(outdir, exist_ok=True)
    meta = dict(header=hdr.hex(), segments=[])
    for s in segs:
        fn = f"{s['type']}_{s['addr']:08x}.bin"
        open(os.path.join(outdir, fn), 'wb').write(s['data'])
        meta['segments'].append(dict(type=s['type'], flag=s['flag'], addr=s['addr'], file=fn))
    json.dump(meta, open(os.path.join(outdir, 'meta.json'), 'w'), indent=1)

def pack(indir, out, hdr4=None):
    meta = json.load(open(os.path.join(indir, 'meta.json')))
    hdr = bytearray.fromhex(meta['header'])
    payload = bytearray()
    for i, s in enumerate(meta['segments']):
        data = open(os.path.join(indir, s['file']), 'rb').read()
        crc = crc16_modbus(data)
        ent = (crc.to_bytes(2, 'big') + bytes([s['flag'], ord(s['type'])]) +
               struct.pack('<III', s['addr'], len(payload), len(data)))
        hdr[0x38 + 16 * i: 0x48 + 16 * i] = ent
        payload += data
    struct.pack_into('<I', hdr, 8, HDR + len(payload))
    struct.pack_into('<I', hdr, 0x24, len(payload))
    if hdr4 is not None:
        struct.pack_into('<I', hdr, 4, hdr4)
    open(out, 'wb').write(bytes(hdr) + bytes(payload))

if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sp = ap.add_subparsers(dest='cmd', required=True)
    a = sp.add_parser('info'); a.add_argument('image')
    a = sp.add_parser('unpack'); a.add_argument('image'); a.add_argument('outdir')
    a = sp.add_parser('pack'); a.add_argument('indir'); a.add_argument('out')
    a.add_argument('--hdr4', type=lambda x: int(x, 0), help='value for the unknown u32 at 0x04 (default: keep unpacked value)')
    r = ap.parse_args()
    if r.cmd == 'info': info(r.image)
    elif r.cmd == 'unpack': unpack(r.image, r.outdir)
    else: pack(r.indir, r.out, r.hdr4)
