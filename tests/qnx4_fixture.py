"""Synthetic QNX4 fixtures; disk layout checked against Linux QNX4 headers.
Extends the independently spelled layout used by abrignoni/qnxprobe selftest.
No confirmed real-world QNX4 image is claimed by these tests.
"""
import struct


def inode(name, size, extents, xblk=0, mode=0o100640, uid=123, gid=456, links=1):
    b = bytearray(64)
    b[:16] = name.encode()[:16].ljust(16, b'\0')
    struct.pack_into('<I', b, 16, size)
    if extents:
        struct.pack_into('<II', b, 20, extents[0][0] + 1, extents[0][1])
    struct.pack_into('<I', b, 28, xblk + 1 if xblk else 0)
    struct.pack_into('<IIII', b, 32, 1600000000, 1700000001, 1700000002, 1700000003)
    struct.pack_into('<HHHHH', b, 48, len(extents), mode, uid, gid, links)
    b[63] = 0x21 if mode & 0o170000 == 0o040000 else 1
    return b


def link(name, node):
    b = bytearray(64)
    b[:48] = name.encode().ljust(48, b'\0')
    struct.pack_into('<I', b, 48, node // 8 + 1)
    b[52] = node % 8
    b[63] = 8
    return b


def make_fixture():
    blocks = 8192
    raw = bytearray(blocks * 512)
    used = {0, 1}
    expected = {}
    nodes = {}
    root_slot = 0

    def put(start, data, count=1):
        assert len(data) <= count * 512
        raw[start*512:start*512+len(data)] = data
        used.update(range(start, start+count))

    def put_inode(node, entry):
        raw[node*64:node*64+64] = entry
        used.add(node//8)

    def xblock(block, extents, nxt=0, prev=0):
        b = bytearray(512)
        struct.pack_into('<II', b, 0, nxt + 1 if nxt else 0, prev + 1 if prev else 0)
        b[8] = len(extents)
        struct.pack_into('<I', b, 12, sum(n for _, n in extents))
        for k, (start, count) in enumerate(extents):
            struct.pack_into('<II', b, 16 + k*8, start+1, count)
        b[496:503] = b'IamXblk'
        put(block, b)

    def root_entry(entry):
        nonlocal root_slot
        node = 2*8 + root_slot
        put_inode(node, entry)
        root_slot += 1
        return node

    def file(name, data, spans, xblk=0, mode=0o100640):
        node = root_entry(inode(name, len(data), spans, xblk, mode))
        remaining = data
        for start, count in spans:
            put(start, remaining[:count*512], count)
            remaining = remaining[count*512:]
        assert not remaining
        expected[name] = data
        nodes[name] = node
        return node

    # Root and bitmap use different storage paths; .bitmap is fragmented.
    put_inode(8, inode('/', 8*512, [(2, 8)], mode=0o040755))
    used.update(range(2, 10))
    put_inode(9, inode('', 2*512, [(11, 2)], mode=0o100444))
    put(11, b'IamTHE.inodeFILE', 2)
    root_entry(inode('.bitmap', blocks//8, [(10, 1), (40, 1)], 41, 0o100444))
    xblock(41, [(40, 1)])
    bitmap_node = 16
    file('short.txt', b'QNX4 native regression\n', [(50, 1)])
    file('empty.bin', b'', [])
    file('full16chars_name', b'exactly sixteen-byte name\n', [(51, 1)])
    long_name = 'a_very_long_qnx4_name_with_inode_reference.bin'
    assert len(long_name) <= 48
    long_data = b'linked inode payload\n' * 41
    long_node = 11*8 + 1
    put_inode(long_node, inode('long-inode', len(long_data), [(52, 2)], links=2))
    root_entry(link(long_name, long_node))
    root_entry(link('second_long_hardlink_name.bin', long_node))
    put(52, long_data, 2)
    for name in (long_name, 'second_long_hardlink_name.bin'):
        expected[name] = long_data
        nodes[name] = long_node
    # Exactly 48 bytes with no terminating NUL, as allowed by QNX4.
    name48 = 'n'*44 + '.bin'
    node48 = 12*8
    put_inode(node48, inode('name48-inode', 7, [(54, 1)]))
    root_entry(link(name48, node48))
    put(54, b'name48\n')
    expected[name48] = b'name48\n'
    nodes[name48] = node48
    # Multi-block directory plus a nested directory and symlink.
    sub_node = root_entry(inode('subdir', 512, [(20, 1)], mode=0o040750))
    sub_data = b'nested content\n'
    put_inode(20*8, inode('deep.txt', len(sub_data), [(55, 1)]))
    put(55, sub_data)
    expected['subdir/deep.txt'] = sub_data
    nodes['subdir/deep.txt'] = 20*8
    file('symlink', b'subdir/deep.txt', [(56, 1)], mode=0o120777)
    # Short final directory block: data after i_size must not become entries.
    put_inode(20*8+1, inode('tiny-dir', 64, [(21, 1)], mode=0o040755))
    put_inode(21*8, inode('tiny.txt', 4, [(57, 1)]))
    put(57, b'tiny')
    expected['subdir/tiny-dir/tiny.txt'] = b'tiny'
    nodes['subdir/tiny-dir/tiny.txt'] = 21*8
    put_inode(21*8+1, inode('beyond-size', 4, [(58, 1)]))
    put(58, b'hide')
    # Three extents, including extents longer than one block.
    multi = bytes((k*31+7)&255 for k in range(3400))
    file('multi.bin', multi, [(100, 3), (110, 2), (120, 2)], 200)
    xblock(200, [(110, 2), (120, 2)])
    # 63 extents force two IamXblk blocks (60 + 2 after inline extent).
    spans = [(300+k*2, 1) for k in range(63)]
    chained = bytes((k*17+3)&255 for k in range(63*512-19))
    file('chain63.bin', chained, spans, 500)
    xblock(500, spans[1:61], 501)
    xblock(501, spans[61:], prev=500)
    # Enough ordinary files to span several root-directory blocks.
    for k in range(20):
        file(f'f{k:02}.bin', bytes([k])* (k*17+1), [(600+k, 1)])
    marker = b'QNX4-FREE-MARKER'
    raw[700*512:700*512+len(marker)] = marker
    # Mark metadata storage, including both fragmented bitmap blocks.
    used.update((10, 40, 41))
    bitmap = bytearray(blocks//8)
    for block in used:
        bitmap[block//8] |= 1 << (block%8)
    put(10, bitmap[:512])
    put(40, bitmap[512:])
    # Boot signature alone must not change filesystem auto detection.
    raw[510:512] = b'\x55\xaa'
    return bytes(raw), expected, nodes, used, bitmap_node
