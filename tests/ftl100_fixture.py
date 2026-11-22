"""Independent FAT12 image and M-Systems FTL100 NOR fixture writer."""
import struct


def fat12():
    raw = bytearray(128 * 512)
    raw[:3] = b'\xeb\x3c\x90'
    raw[3:11] = b'MSDOS5.0'
    struct.pack_into('<HBHBHHBHHHII', raw, 11, 512, 1, 1, 2, 16, 128, 0xf8, 1, 1, 1, 0, 0)
    raw[36:39] = b'\x80\x00\x29'
    struct.pack_into('<I', raw, 39, 0x12345678)
    raw[43:54] = b'FTL100 TEST'
    raw[54:62] = b'FAT12   '
    raw[510:512] = b'\x55\xaa'
    fat = bytearray(512)
    fat[:3] = b'\xf8\xff\xff'
    def entry(cluster, value):
        off = cluster * 3 // 2
        word = struct.unpack_from('<H', fat, off)[0]
        word = (word & 0x000f) | (value << 4) if cluster & 1 else (word & 0xf000) | value
        struct.pack_into('<H', fat, off, word)
    entry(2, 4)
    entry(4, 3)
    entry(3, 0xfff)
    entry(5, 0xfff)
    raw[512:1024] = fat
    raw[1024:1536] = fat
    payload = bytes((i * 37 + 11) & 255 for i in range(1300))
    root = 3 * 512
    raw[root:root+11] = b'HELLO   BIN'
    raw[root+11] = 0x20
    struct.pack_into('<H', raw, root+26, 2)
    struct.pack_into('<I', raw, root+28, len(payload))
    raw[root+32:root+43] = b'EMPTY   TXT'
    raw[root+43] = 0x20
    struct.pack_into('<H', raw, root+58, 5)
    for k, cluster in enumerate((2, 4, 3)):
        at = (4 + cluster - 2) * 512
        data = payload[k*512:(k+1)*512]
        raw[at:at+len(data)] = data
    # Visible marker in logically unallocated FAT space.
    raw[20*512:20*512+16] = b'FTL-FREE-MARKER!'
    return bytes(raw), payload


def encode(logical, absolute=True, prefix=0):
    erase = 65536
    per_unit = 120
    data_units = (len(logical)//512 + per_unit-1)//per_unit
    total = data_units + 1
    first = 5
    raw = bytearray(b'\xff' * (prefix + total*erase))
    for unit in range(total):
        base = prefix + unit*erase
        h = bytearray(68)
        h[:5] = b'\x13\x03CIS'
        h[8:14] = b'FTL100'
        h[15] = 1
        struct.pack_into('<I', h, 16, 10 + unit)
        lun = 0xffff if unit == data_units else unit + (first if absolute else 0)
        struct.pack_into('<H', h, 20, lun)
        h[22:24] = bytes((9, 16))
        struct.pack_into('<HHI', h, 24, first, total, len(logical))
        struct.pack_into('<I', h, 48, 512)
        raw[base:base+68] = h
        if unit == data_units:
            continue
        for j in range(per_unit):
            sector = unit*per_unit + j
            if sector >= len(logical)//512:
                break
            slot = j + 2
            struct.pack_into('<I', raw, base+512+slot*4, (sector << 9) | 0x40)
            raw[base+slot*512:base+(slot+1)*512] = logical[sector*512:(sector+1)*512]
    return bytes(raw)
