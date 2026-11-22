#!/usr/bin/env python3
"""Native TSK QNX4 regressions with synthetic fixtures and qnxprobe oracle."""
import argparse
import hashlib
import importlib.util
import io
import pathlib
import re
import struct
import subprocess
import tempfile
from qnx4_fixture import make_fixture


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--tools', type=pathlib.Path, required=True)
    ap.add_argument('--reference', type=pathlib.Path, required=True)
    opt = ap.parse_args()
    spec = importlib.util.spec_from_file_location('reference_qnxprobe', opt.reference/'qnxprobe.py')
    reference = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reference)
    tools = {name: opt.tools/name for name in ('fls', 'icat', 'fsstat', 'blkls', 'ils', 'istat')}

    vs_dir = opt.tools if any((opt.tools / p).exists() for p in ('mmls', 'mmls.exe')) else opt.tools.parent/'vstools'
    tools['mmls'] = vs_dir/'mmls'

    def run(name, *args):
        return subprocess.check_output([str(tools[name]), *map(str, args)])

    def refused(name, *args):
        result = subprocess.run([str(tools[name]), *map(str, args)], capture_output=True)
        assert result.returncode > 0, (name, args, result.returncode)

    raw, expected, nodes, used, bitmap_node = make_fixture()
    walker = reference.Qnx4Walker(io.BytesIO(raw), 0)
    assert reference.identify_qnx4(io.BytesIO(raw), 0, len(raw))[0] == 'qnx4'
    with tempfile.TemporaryDirectory() as tmp:
        tmp = pathlib.Path(tmp)
        image = tmp/'qnx4.img'
        image.write_bytes(raw)
        assert b'File System Type: QNX4' in run('fsstat', image)
        assert b'File System Type: QNX4' in run('fsstat', '-f', 'qnx4', image)
        listing = run('fls', '-r', '-p', image).decode()
        names = {match[2]: int(match[1]) for line in listing.splitlines()
                 if (match := re.match(r'\S+ (\d+):\t(.*)', line))}
        assert 'subdir/tiny-dir/beyond-size' not in names
        hashes = 0
        for path, content in expected.items():
            assert names[path] == nodes[path], (path, names.get(path), nodes[path])
            got = run('icat', image, names[path])
            oracle = b''.join(walker.read_file(nodes[path], len(content)))
            assert hashlib.sha256(got).digest() == hashlib.sha256(content).digest(), path
            assert got == oracle, path
            hashes += 1
        # The qnxprobe listing and native names agree for all visible entries.
        def collect(node, prefix=''):
            found = {}
            for name, child in walker.listdir(node):
                path = prefix+name
                found[path] = child
                mode, _, _ = walker.entry(child)
                if mode & 0o170000 == 0o040000:
                    found.update(collect(child, path+'/'))
            return found
        # qnxprobe's old walker scans complete final blocks; our size-bound
        # regression intentionally excludes its beyond-size synthetic entry.
        ref_names = collect(8)
        ref_names.pop('subdir/tiny-dir/beyond-size', None)
        assert names == ref_names, (names.keys() ^ ref_names.keys())
        stat = run('istat', image, names['short.txt']).decode()
        for text in ('UID: 123', 'GID: 456', 'Links: 1', 'Mode: 640',
                     'Modified: 1700000001.', 'Access: 1700000002.', 'Changed: 1700000003.'):
            assert text in stat, (text, stat)
        assert 'Created:' not in stat  # do not invent di_ftime semantics
        assert b'Links: 2' in run('istat', image, nodes['second_long_hardlink_name.bin'])
        inode_listing = run('ils', '-a', image).decode()
        for node in {8, 9, *nodes.values(), bitmap_node}:
            assert f'\n{node}|a|' in inode_listing
        free = {int(line.split('|')[0]) for line in run('blkls', '-l', image).decode().splitlines()[3:]}
        assert free == set(range(len(raw)//512))-used
        assert 700 in free and b'QNX4-FREE-MARKER' in run('blkls', image)
        # Partitions and both bitmap extents must respect the volume offset.
        offset = tmp/'offset.img'
        offset.write_bytes(bytes(8192)+raw)
        assert run('icat', '-o', 16, offset, nodes['chain63.bin']) == expected['chain63.bin']
        shifted = run('blkls', '-l', '-o', 16, offset).decode().splitlines()[3:]
        assert {int(line.split('|')[0]) for line in shifted} == free
        # An MBR-labeled QNX4 partition remains a normal TSK volume.
        disk = bytearray(bytes(8192)+raw)
        disk[446+4] = 0x4d
        struct.pack_into('<II', disk, 446+8, 16, len(raw)//512)
        disk[510:512] = b'\x55\xaa'
        offset.write_bytes(disk)
        assert b'QNX4' in run('fsstat', '-o', 16, offset)
        assert b'QNX 4.x' in run('mmls', offset)
        # Boot code resembling a plausible partition must not hide raw QNX4.
        ghost = bytearray(raw)
        ghost[446+4] = 0x4d
        struct.pack_into('<II', ghost, 446+8, 50, 100)
        raw_boot = tmp/'boot-mbr-lookalike.img'
        raw_boot.write_bytes(ghost)
        refused('mmls', raw_boot)
        assert b'QNX4' in run('fsstat', raw_boot)
        assert b'QNX 4.x' in run('mmls', '-t', 'dos', raw_boot)
        # Readable partial images can mount; inaccessible referenced data fails.
        partial = tmp/'partial.img'
        partial.write_bytes(raw[:700*512])
        assert run('icat', partial, nodes['multi.bin']) == expected['multi.bin']
        # Corrupt structures must fail explicitly, without loops or zero padding.
        cases = []
        bad = bytearray(raw);bad[512] = ord('!');cases.append(bad)
        bad = bytearray(raw);bad[16*64:16*64+7] = b'broken!';cases.append(bad)
        bad = bytearray(raw);bad[200*512+496] = 0;cases.append(bad)
        bad = bytearray(raw);struct.pack_into('<I', bad, 500*512, 501);cases.append(bad)  # self-cycle
        bad = bytearray(raw);bad[500*512+8] = 61;cases.append(bad)
        bad = bytearray(raw);bad[20*64+52] = 8;cases.append(bad)
        bad = bytearray(raw);struct.pack_into('<I', bad, 17*64+20, 99999);cases.append(bad)
        cases.extend((raw[:100*512], bytes(4096)))
        broken = tmp/'broken.img'
        for data in cases:
            broken.write_bytes(data)
            refused('fsstat', '-f', 'qnx4', broken)
        print(f'{hashes} QNX4 file hashes passed against payload and qnxprobe oracles')
        print('QNX4 metadata, links, 63-extents chain, bitmap, unallocated marker, offsets, partial images and 9 malformed cases passed')


if __name__ == '__main__':
    main()
