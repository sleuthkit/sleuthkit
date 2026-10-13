"""Independent writer for the observed Reliance Nitro 2.7.1 NAND profile."""
import struct


def logical():
    data = bytearray(32*4096)
    data[64:68] = b'MAST'
    struct.pack_into('<II', data, 72, 4096, 32)
    struct.pack_into('<II', data, 104, 1, 2)
    for block, transaction in ((1, 3), (2, 9)):
        at = block*4096
        data[at:at+4] = b'META'
        struct.pack_into('<I', data, at+8, transaction)
        struct.pack_into('<II', data, at+16, 3, 6)
    for block, magic, children in ((3, b'IDIR', [4, 5]), (6, b'IALC', [7])):
        at = block*4096
        data[at:at+4] = magic
        struct.pack_into('<I', data, at+16, len(children))
        for k, child in enumerate(children):
            struct.pack_into('<I', data, at+0xab0+k*4, child)
    longname = 'a_very_long_reliance_filename.bin'
    rows = [(2, 10, 'sub'), (2, 11, longname), (10, 12, 'deep.txt'),
            (10, 15, 'nested'), (15, 16, 'empty.dat'), (2, 17, 'zero.txt')]
    for block, entries in ((4, rows[:2]), (5, rows[2:])):
        at = block*4096
        data[at:at+4] = b'LDIR'
        records = []
        for parent, oid, name in entries:
            encoded = name.encode()
            for fragment, pos in enumerate(range(0, len(encoded), 16), 1):
                key = struct.pack('>I', parent << 2) + oid.to_bytes(3, 'big') + bytes([fragment])
                slot = encoded[pos:pos+16].ljust(16, b'\0') + struct.pack('<I', oid)
                records.append((key, slot))
        struct.pack_into('<I', data, at+16, len(records))
        for k, (key, slot) in enumerate(records):
            data[at+24+k*8:at+32+k*8] = key
            data[at+0x4a0+k*20:at+0x4a0+(k+1)*20] = slot
    payload = bytes((k*31+7)&255 for k in range(9000))
    deep = b'Reliance nested payload\n'
    data[8*4096:9*4096] = payload[:4096]
    data[14*4096:14*4096+len(payload)-4096] = payload[4096:]
    data[20*4096:20*4096+len(deep)] = deep
    allocations = []
    def record(oid, cls, index, value):
        allocations.append((struct.pack('>II', (oid << 2) | cls, index), struct.pack('<Q', value)))
    record(11, 0, 0, (1 << 32) | 8)
    record(11, 0, 1, (2 << 32) | 14)
    record(12, 0, 0, (1 << 32) | 20)
    for oid, size in ((11, len(payload)), (12, len(deep)), (16, 0), (17, 0)):
        record(oid, 1, 2, size << 16)
        for index in (3, 4, 5):
            record(oid, 1, index, 1710000000123 + index)
    allocations.sort(key=lambda kv: kv[0])
    at = 7*4096
    data[at:at+4] = b'LALC'
    struct.pack_into('<I', data, at+16, len(allocations))
    for k, (key, value) in enumerate(allocations):
        data[at+24+k*8:at+32+k*8] = key
        data[at+0x808+k*8:at+0x810+k*8] = value
    return bytes(data), {longname: payload, 'sub/deep.txt': deep, 'sub/nested/empty.dat': b'', 'zero.txt': b''}


def raw(logical, serial=0x12345678):
    out = bytearray(b'\xff' * (4320*128*2))
    def putpage(page, main, allocation):
        at = page*4320
        struct.pack_into('<H', out, at+2, allocation)
        for k in range(8):
            out[at+10+k*538:at+10+k*538+512] = main[k*512:(k+1)*512]
    for unit in range(2):
        header = bytearray(4096)
        header[:11] = b'\xcc\xddDL_FS4.00'
        struct.pack_into('<IIIIII', header, 16, unit*32*4096, unit+5, serial, 10+unit, 2, 0)
        struct.pack_into('<HHHHHHH', header, 40, 0, 4096, 2, 0, 128, 32, 127)
        struct.pack_into('<H', header, 54, sum(header[:54]) & 65535)
        putpage(unit*128, header, 0xffff)
        for k in range(32):
            lp = unit*32+k
            main = logical[lp*4096:(lp+1)*4096].ljust(4096, b'\xff')
            putpage(unit*128+k+1, main, 0x4000 | k)
    return bytes(out)
