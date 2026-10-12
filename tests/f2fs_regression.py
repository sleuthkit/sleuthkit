#!/usr/bin/env python3
"""End-to-end TSK tests using pinned qnxprobe images and independent SHA256s.
Usage: python tests/f2fs_regression.py --tools tools/fstools --reference ../qnxprobe
"""
import argparse
import gzip
import hashlib
import pathlib
import re
import shutil
import struct
import subprocess
import tempfile


def run(tool, *args):
    return subprocess.check_output([str(tool), *map(str, args)])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--tools', type=pathlib.Path, required=True)
    ap.add_argument('--reference', type=pathlib.Path, required=True)
    opt = ap.parse_args()
    fixtures = opt.reference / 'tests/fixtures'
    tools = {name: opt.tools / name for name in ('fls', 'icat', 'fsstat', 'blkls', 'ils')}
    total = 0
    with tempfile.TemporaryDirectory() as tmp:
        tmp = pathlib.Path(tmp)
        for fixture, listings in (
            ('f2fs-fixture', ['src', 'nodes']),
            ('f2fs-fixture-holes', ['holes']),
            ('f2fs-fixture-free', ['free']),
        ):
            image = tmp / (fixture + '.img')
            with gzip.open(fixtures / (fixture + '.img.gz'), 'rb') as src, image.open('wb') as dst:
                shutil.copyfileobj(src, dst)
            assert b'File System Type: F2FS' in run(tools['fsstat'], image)
            # Reserved node/meta NIDs must not interrupt inode enumeration.
            inode_listing = run(tools['ils'], '-a', image).decode()
            assert '\n3|a|' in inode_listing
            listing = run(tools['fls'], '-r', '-p', image).decode()
            names = {}
            for line in listing.splitlines():
                match = re.match(r'\S+ (\d+):\t(.*)', line)
                if match:
                    names[match[2]] = int(match[1])
            for suffix in listings:
                for line in (fixtures / ('f2fs-fixture.' + suffix + '.sha256')).read_text().splitlines():
                    if not line or line.startswith('#'):
                        continue
                    digest, path = line.split('  ', 1)
                    content = run(tools['icat'], image, names[path])
                    assert hashlib.sha256(content).hexdigest() == digest, (fixture, path)
                    total += 1
            # blkls' reported free blocks must match checkpoint accounting.
            raw = image.read_bytes()
            cpaddr = struct.unpack_from('<I', raw, 1024 + 76)[0]
            mainaddr = struct.unpack_from('<I', raw, 1024 + 92)[0]
            mainsegs = struct.unpack_from('<I', raw, 1024 + 68)[0]
            packs = [cpaddr * 4096, (cpaddr + 512) * 4096]
            cp = max(packs, key=lambda p: struct.unpack_from('<Q', raw, p)[0])
            valid = struct.unpack_from('<Q', raw, cp + 16)[0]
            free = {int(line.split('|')[0]) for line in run(tools['blkls'], '-l', image).decode().splitlines()[3:]}
            assert mainsegs * 512 - len(free) == valid, fixture
            assert all(mainaddr <= b < mainaddr + mainsegs * 512 for b in free)
            for match in re.finditer(rb'F2FS-FREE-MARKER-\d{4}-', raw):
                assert match.start() // 4096 in free
            # Offset-aware auto detection and extraction.
            if fixture == 'f2fs-fixture-holes':
                offset_image = tmp / 'offset.img'
                offset_image.write_bytes(bytes(8192) + raw)
                assert run(tools['icat'], '-o', '16', offset_image, names['holey.bin']) == run(tools['icat'], image, names['holey.bin'])
                # Superblock redundancy and checkpoint fallback.
                damaged = bytearray(raw)
                damaged[1024:1028] = bytes(4)
                fallback = tmp / 'fallback.img'
                fallback.write_bytes(damaged)
                assert b'F2FS' in run(tools['fsstat'], fallback)
                damaged = bytearray(raw)
                damaged[cp + 200] ^= 1  # break the newer checkpoint CRC
                fallback.write_bytes(damaged)
                assert b'F2FS' in run(tools['fsstat'], fallback)
                # Invalid/truncated images must fail, not crash or misdetect.
                for bad in (bytes(16384), raw[:16384]):
                    fallback.write_bytes(bad)
                    result = subprocess.run([str(tools['fsstat']), '-f', 'f2fs', str(fallback)], capture_output=True)
                    assert result.returncode > 0
            print(f'{fixture}: hashes, allocation and marker checks passed', flush=True)
    print(f'{total} file hashes passed')


if __name__ == '__main__':
    main()
