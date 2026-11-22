"""Independent synthetic classic Microware OS-9 RBF layout/payload writer."""
import struct


def u24(n):
    return bytes((n >> 16, (n >> 8) & 255, n & 255))


def text(name, width):
    b = bytearray(name.encode('ascii'))
    if b:
        b[-1] |= 128
    return bytes(b).ljust(width, b'\0')


def fixture(bs, cluster, relocated=False):
    total = 1024
    raw = bytearray(total*bs)
    mapbytes = (total+cluster*8-1)//(cluster*8)
    maplsn = 900 if relocated else 1
    raw[:3] = u24(total)
    struct.pack_into('>HH', raw, 4, mapbytes, cluster)
    raw[8:11] = u24(4)
    raw[31:63] = text('Microware OS9 Test', 32)
    if relocated:
        raw[96:100] = b'Cruz'
        struct.pack_into('>I', raw, 100, maplsn)
        struct.pack_into('>H', raw, 104, bs)
    used = {0, 4, *range(maplsn, maplsn+(mapbytes+bs-1)//bs)}
    cursor = 32
    expected, nodes = {}, {}

    def allocate(n=1):
        nonlocal cursor
        start = cursor
        cursor += n+2  # small gaps make allocation-bit order observable
        used.update(range(start, start+n))
        return start

    def write(start, data):
        raw[start*bs:start*bs+len(data)] = data

    def descriptor(lsn, data, spans, attr=0x0b, links=1):
        b = bytearray(bs)
        b[0] = attr
        struct.pack_into('>H', b, 1, 0x1234)
        b[3:8] = bytes((126,10,12,19,55))
        b[8] = links
        struct.pack_into('>I', b, 9, len(data))
        b[13:16] = bytes((124,1,2))
        for k, (start, count) in enumerate(spans):
            b[16+k*5:19+k*5] = u24(start)
            struct.pack_into('>H', b, 19+k*5, count)
        write(lsn,b)
        pos = 0
        for start,count in spans:
            write(start,data[pos:pos+count*bs])
            pos += count*bs
        assert pos >= len(data)

    def regular(name, data, fragmented=False):
        fd = allocate()
        if fragmented:
            spans = [(allocate(2),2),(allocate(1),1),(allocate(3),3)]
        else:
            count = (len(data)+bs-1)//bs
            spans = [(allocate(count), count)] if count else []
        descriptor(fd,data,spans)
        expected[name] = data
        nodes[name] = fd
        return fd

    root_entries = []
    def entry(name, fd):
        return text(name,29)+u24(fd)

    root_entries.extend((entry('.',4),entry('..',4)))
    for k in range(18):
        name = f'f{k:02}.bin'
        data = bytes((i*17+k)&255 for i in range(k*11+1))
        root_entries.append(entry(name,regular(name,data)))
    name29 = 'n'*25+'.bin'
    root_entries.append(entry(name29,regular(name29,b'exactly 29 characters\n')))
    root_entries.append(entry('empty',regular('empty',b'')))
    fragmented = bytes((i*31+7)&255 for i in range(6*bs-19))
    root_entries.append(entry('fragmented.bin',regular('fragmented.bin',fragmented,True)))
    aliasfd = nodes['f00.bin']
    raw[aliasfd*bs+8] = 2
    root_entries.append(entry('hardlink',aliasfd))
    expected['hardlink'] = expected['f00.bin']
    nodes['hardlink'] = aliasfd
    subfd = allocate()
    deepfd = regular('sub/deep.txt',b'nested OS-9 payload\n')
    subdata = entry('.',subfd)+entry('..',4)+entry('deep.txt',deepfd)
    count = (len(subdata)+bs-1)//bs
    descriptor(subfd,subdata,[(allocate(count),count)],0x89)
    root_entries.append(entry('sub',subfd))
    # Deleted directory slot: first byte erased; previous name/FD must not leak.
    deleted = bytearray(entry('deleted',800));deleted[0]=0
    root_entries.append(bytes(deleted))
    rootdata = b''.join(root_entries)
    count = (len(rootdata)+bs-1)//bs
    descriptor(4,rootdata,[(allocate(count),count)],0x89)
    marker = b'OS9-FREE-MARKER'
    write(800,marker)
    bits = bytearray(mapbytes)
    for sector in used:
        c = sector//cluster
        bits[c//8] |= 128 >> (c%8)
    write(maplsn,bits)
    occupied = {n for n in range(total) if bits[(n//cluster)//8] & (128 >> ((n//cluster)%8))}
    return bytes(raw),expected,nodes,occupied
