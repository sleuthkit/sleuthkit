#!/usr/bin/env python3
"""Native UBI/UBIFS tests against kernel-built qnxprobe fixtures and hashes."""
import argparse
import gzip
import hashlib
import importlib.util
import io
import pathlib
import re
import struct
import subprocess
import tempfile
import zlib


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--tools', type=pathlib.Path, required=True)
    ap.add_argument('--reference', type=pathlib.Path, required=True)
    ap.add_argument('--read-probe', type=pathlib.Path)
    opt = ap.parse_args()
    fixtures = opt.reference / 'tests/fixtures'
    tools = {n: opt.tools / n for n in ('fls', 'icat', 'fsstat', 'istat', 'blkls')}
    if not tools['fls'].exists():
        tools = {n: opt.tools / (n + '.exe') for n in tools}
    def run(n, *args):
        return subprocess.check_output([str(tools[n]), *map(str, args)])
    def names(image, *args):
        result = {}
        for line in run('fls', '-r', '-p', *args, image).decode().splitlines():
            m = re.match(r'\S+ (\d+):\t(.*)', line)
            if m:
                result[m[2]] = int(m[1])
        return result
    def reject(raw):
        bad.write_bytes(raw)
        r = subprocess.run([str(tools['fsstat']), '-f', 'ubi', str(bad)], capture_output=True)
        assert r.returncode != 0, 'malformed image accepted'
    def node(kind, body, sq=100000, group=0):
        b = bytearray(24 + len(body))
        struct.pack_into('<IQI', b, 0, 0x06101831, 0, 0)
        struct.pack_into('<QIBB', b, 8, sq, len(b), kind, group)
        b[24:] = body
        struct.pack_into('<I', b, 4, (zlib.crc32(b[8:]) ^ 0xffffffff) & 0xffffffff)
        return bytes(b)
    def padded(b):
        return b + bytes((-len(b)) % 8)
    count = 0
    with tempfile.TemporaryDirectory() as td:
        tmp = pathlib.Path(td)
        bad = tmp / 'bad.img'
        rawubi = None
        for label in ('ubifs-lzo', 'ubi-nand-none', 'ubi-nand-lzo', 'ubi-nand-zlib', 'ubi-nor'):
            raw = gzip.decompress((fixtures / (label + '.img.gz')).read_bytes())
            image = tmp / (label + '.img')
            image.write_bytes(raw)
            flat = label == 'ubifs-lzo'
            have = names(image)
            assert names(image, '-f', 'ubifs' if flat else 'ubi') == have
            assert b'UBI / UBIFS' in run('fsstat', image)
            prefix = '' if flat else 'Volume_0_rootfs_data/'
            for line in (fixtures / 'ubifs.src.sha256').read_text().splitlines():
                sha, path = line.split('  ', 1)
                name = prefix + path.removeprefix('./')
                data = run('icat', image, have[name])
                assert hashlib.sha256(data).hexdigest() == sha, name
                count += 1
            assert have[prefix + 'dir/hardlink_to_small.txt'] == have[prefix + 'small.txt']
            stat = run('istat', image, have[prefix + 'small.txt'])
            assert b'UID:' in stat and b'Modified:' in stat
            if not flat:
                assert 'Volume_1_rootfs/volume.bin' in have
                assert 'Volume_2_kernel/volume.bin' in have
                for folder, manifest in (('Volume_1_rootfs', 'ubi.rootfs.sha256'),):
                    expected = sum(1 for _ in (fixtures / manifest).read_text().splitlines())
                    assert expected > 0
                digest = hashlib.sha256(run('icat', image, have['Volume_2_kernel/volume.bin'])).hexdigest()
                expected = (fixtures / 'ubi.kernel.sha256').read_text().split()[0]
                assert digest == expected
                if label == 'ubi-nand-lzo':
                    rawubi = raw
            if opt.read_probe:
                inode = have[prefix + 'dir/many_blocks.txt']
                data = run('icat', image, inode)
                for offset, length in ((0, 17), (4090, 40), (len(data), 9)):
                    got = subprocess.check_output([str(opt.read_probe), str(image), str(inode), str(offset), str(length)])
                    assert got == data[offset:offset+length]
            wrapped = tmp / 'offset.img'
            wrapped.write_bytes(bytes(8192) + raw)
            assert names(wrapped, '-o', 16) == have
            reject(raw[:128])
            damaged = bytearray(raw)
            if flat:
                damaged[4] ^= 1
            else:
                damaged[60] ^= 1
            reject(damaged)
            print(label + ': 410 file hashes, offsets, metadata and CRC rejection passed', flush=True)
        # CRC-valid replacement UBI LEB and invalid-copy fallback.
        spec = importlib.util.spec_from_file_location('ubi_reference', opt.reference / 'qnxprobe.py')
        ref = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ref)
        ubi = ref.UbiImage(io.BytesIO(rawubi), 0, len(rawubi))
        old = ubi.map[(2, 0)]
        at = old['peb'] * ubi.peb
        replacement = bytearray(rawubi[at:at+ubi.peb])
        vid = ubi.vid_off
        struct.pack_into('>Q', replacement, vid+40, old['sqnum'] + 100000)
        replacement[vid+6] = 1
        struct.pack_into('>I', replacement, vid+32, old['data_crc'] ^ 1)
        struct.pack_into('>I', replacement, vid+60, ref._ubi_crc(replacement[vid:vid+60]))
        image = tmp / 'copies.img'
        image.write_bytes(rawubi + replacement)
        have = names(image)
        assert hashlib.sha256(run('icat', image, have['Volume_2_kernel/volume.bin'])).hexdigest() == (fixtures / 'ubi.kernel.sha256').read_text().split()[0]
        # Single erased VID PEB is free; superseded PEB data is free, unknown EC is not.
        erased = bytearray(rawubi[:ubi.peb])
        erased[ubi.vid_off:] = b'\xff' * (ubi.peb - ubi.vid_off)
        image.write_bytes(rawubi + erased)
        unalloc = run('blkls', image)
        assert unalloc == b'\xff' * (ubi.peb - ubi.data_off)
        unknown = bytearray(erased)
        unknown[60] ^= 1
        image.write_bytes(rawubi + unknown)
        assert run('blkls', image) == b''
        # Journal replay: create a new regular file via CS -> REF -> inode/data/dent.
        raw = bytearray(gzip.decompress((fixtures / 'ubifs-lzo.img.gz').read_bytes()))
        leb = struct.unpack_from('<I', raw, 36)[0]
        walker = ref.UbifsWalker(io.BytesIO(raw), 0)
        bud = len(raw) // leb
        body = bytearray(136)
        ino = 8000000
        payload = b'journal replay payload\n'
        struct.pack_into('<II', body, 0, ino, 0)
        struct.pack_into('<Q', body, 24, len(payload))
        struct.pack_into('<IIII', body, 68, 1, 1000, 1000, 0o100644)
        inode = node(0, body, 100001)
        body = bytearray(24)
        struct.pack_into('<II', body, 0, ino, 1 << 29)
        struct.pack_into('<IH', body, 16, len(payload), 0)
        data = node(1, body + payload, 100002)
        name = b'journal.txt'
        body = bytearray(32 + len(name) + 1)
        struct.pack_into('<II', body, 0, 1, 2 << 29)
        struct.pack_into('<Q', body, 16, ino)
        body[25] = 0
        struct.pack_into('<H', body, 26, len(name))
        body[32:32+len(name)] = name
        dent = node(2, body, 100003)
        journal = padded(inode) + padded(data) + padded(dent)
        raw += journal + b'\xff' * (leb-len(journal))
        struct.pack_into('<I', raw, 40, bud+1)
        sbsize = struct.unpack_from('<I', raw, 16)[0]
        struct.pack_into('<I', raw, 4, ref._ubi_crc(raw[8:sbsize]))
        log = walker.master['log_lnum']
        cs = node(10, struct.pack('<Q', walker.master['cmt_no']), 100000)
        reference = node(8, struct.pack('<III', bud, 0, 0) + bytes(28), 100000)
        records = padded(cs) + padded(reference)
        raw[log*leb:(log+1)*leb] = records + b'\xff' * (leb-len(records))
        image.write_bytes(raw)
        have = names(image)
        assert run('icat', image, have['journal.txt']) == payload
        check = ref.UbifsWalker(io.BytesIO(raw), 0)
        assert b''.join(check.read_file(ino, len(payload))) == payload
        deletion_body = bytearray(inode[24:])
        struct.pack_into('<I', deletion_body, 68, 0)
        deletion = node(0, deletion_body, 100004, 1)
        incomplete = journal + padded(deletion)
        raw[bud*leb:(bud+1)*leb] = incomplete + b'\xff' * (leb-len(incomplete))
        image.write_bytes(raw)
        assert run('icat', image, names(image)['journal.txt']) == payload
        deleted_dent = bytearray(dent[24:])
        struct.pack_into('<Q', deleted_dent, 16, 0)
        complete = incomplete + padded(node(2, deleted_dent, 100005, 2))
        raw[bud*leb:(bud+1)*leb] = complete + b'\xff' * (leb-len(complete))
        image.write_bytes(raw)
        assert 'journal.txt' not in names(image)
        print('UBI duplicate-copy fallback, free/unknown PEB accounting, journal replay, deletion and incomplete-group exclusion passed', flush=True)
    print(f'{count} UBIFS payload hashes passed against kernel-built source manifests', flush=True)


if __name__ == '__main__':
    main()
