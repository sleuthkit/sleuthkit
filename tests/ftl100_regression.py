#!/usr/bin/env python3
"""FTL100 translation compared byte-for-byte to the user's Python recovery."""
import argparse
import importlib.util
import pathlib
import re
import struct
import subprocess
import tempfile
from ftl100_fixture import encode, fat12


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--tools', type=pathlib.Path, required=True)
    ap.add_argument('--img-tools', type=pathlib.Path)
    ap.add_argument('--reference', type=pathlib.Path, required=True)
    ap.add_argument('--read-probe', type=pathlib.Path)
    ap.add_argument('--real-dump', type=pathlib.Path, help='optional private ASK-II dump, never included in CI')
    ap.add_argument('--recovered-image', type=pathlib.Path, help='existing Python-recovered image to compare with the private dump')
    opt = ap.parse_args()
    if bool(opt.real_dump) != bool(opt.recovered_image):
        ap.error('--real-dump and --recovered-image must be provided together')
    spec = importlib.util.spec_from_file_location('ftl_reference', opt.reference / 'ftl100.py')
    ref = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ref)
    def tool(name):
        directory = (opt.img_tools or opt.tools) if name.startswith('img_') else opt.tools
        if name == 'mmls' and not (directory / name).exists() and not (directory / (name+'.exe')).exists():
            directory = opt.tools.parent / 'vstools'
        p = directory / name
        return p if p.exists() else directory / (name + '.exe')
    def run(name, *args):
        return subprocess.check_output([str(tool(name)), *map(str, args)])
    logical, payload = fat12()
    with tempfile.TemporaryDirectory() as td:
        tmp = pathlib.Path(td)
        image = tmp / 'nor.img'
        count = 0
        for absolute in (False, True):
            for prefix in (0, 137, 1048570):
                raw = encode(logical, absolute, prefix)
                image.write_bytes(raw)
                oracle, headers, units, transfers, vmap = ref.recover(raw)
                assert oracle == logical
                assert run('img_cat', '-i', 'ftl100', image) == oracle
                # Detection intentionally searches only the first MiB for a signature.
                if prefix < 1048562:
                    assert run('img_cat', image) == oracle
                stat = run('img_stat', '-i', 'ftl100', image)
                assert b'FTL100 NOR logical view' in stat
                assert b'Selected data units: 2' in stat and b'Transfer units: 1' in stat
                assert b'FAT12' in run('fsstat', '-i', 'ftl100', image)
                listing = run('fls', '-i', 'ftl100', '-p', image).decode()
                def entries(text):
                    return {name: int(ino) for line in text.splitlines()
                            for ino, name in re.findall(r'(\d+):\t(.+)', line)}
                found = entries(listing)
                assert entries(listing.replace('\r\n', '\n').replace('\n', '\r\n')) == found
                assert 'HELLO.BIN' in found and 'EMPTY.TXT' in found, repr(listing)
                assert run('icat', '-i', 'ftl100', image, found['HELLO.BIN']) == payload
                assert run('icat', '-i', 'ftl100', image, found['EMPTY.TXT']) == b''
                assert b'FTL-FREE-MARKER!' in run('blkls', '-i', 'ftl100', image)
                if opt.read_probe:
                    for off, length in ((0, 17), (509, 40), (65000, 536), (65535, 1)):
                        got = subprocess.check_output([str(opt.read_probe), str(image), str(off), str(length), 'explicit'])
                        assert got == oracle[off:off+length]
                count += 1
        # Duplicate EUN: greater erase count wins; equal counts retain first.
        raw = encode(logical)
        newer = bytearray(raw[:65536])
        struct.pack_into('<I', newer, 16, 999)
        newer[6*512] ^= 0x80  # mapped logical FAT data sector 4
        image.write_bytes(raw + newer)
        expected = ref.recover(raw + newer)[0]
        assert expected != logical and run('img_cat', image) == expected
        struct.pack_into('<I', newer, 16, 10)
        image.write_bytes(raw + newer)
        assert run('img_cat', image) == logical
        # Missing, deleted and replacement BAM slots are zero-filled recovery holes.
        for entry in (0xffffffff, 0, (20 << 9) | 0x60):
            b = bytearray(raw)
            struct.pack_into('<I', b, 512 + (20+2)*4, entry)
            image.write_bytes(b)
            expected = ref.recover(b)[0]
            assert expected[20*512:21*512] == bytes(512)
            assert run('img_cat', image) == expected
        # Explicit raw bypass retains the exact source bytes.
        image.write_bytes(raw)
        assert run('img_cat', '-i', 'raw', image) == raw
        # Split dump, header crossing segment boundary.
        a, b = tmp / 'split.001', tmp / 'split.002'
        a.write_bytes(raw[:37])
        b.write_bytes(raw[37:])
        assert run('img_cat', '-i', 'ftl100', a, b) == logical
        # Duplicate logical BAM mapping follows first-seen EUN order, like Python.
        duplicate = bytearray(raw)
        struct.pack_into('<I', duplicate, 65536+512+8, (20 << 9) | 0x40)
        image.write_bytes(duplicate)
        assert run('img_cat', image) == ref.recover(duplicate)[0]
        assert b'Duplicate logical sectors: 1' in run('img_stat', image)
        # Out-of-range BLOCK_DATA addresses are excluded, like Linux ftl.c
        # and the Python recovery, rather than invalidating all valid mappings.
        for entry in ((999 << 9) | 0x40, 0xffffec40, 0xfffffe40):
            outside = bytearray(raw)
            struct.pack_into('<I', outside, 512+8, entry)
            image.write_bytes(outside)
            assert run('img_cat', image) == ref.recover(outside)[0]
            assert b'Ignored out-of-range BAM entries: 1' in run('img_stat', image)
        # Ordinary MBR parsing occurs on the reconstructed logical image.
        disk = bytearray(256*512)
        disk[510:512] = b'\x55\xaa'
        disk[446+4] = 1
        struct.pack_into('<II', disk, 446+8, 16, 128)
        disk[16*512:144*512] = logical
        translated = encode(bytes(disk))
        image.write_bytes(translated)
        assert run('img_cat', image) == bytes(disk)
        assert b'16' in run('mmls', image)
        assert b'FAT12' in run('fsstat', '-o', 16, image)
        listing = run('fls', '-o', 16, image).decode()
        inode = re.search(r'(\d+):\tHELLO.BIN', listing)[1]
        assert run('icat', '-o', 16, image, inode) == payload
        # Malformed geometry/map must fail, including autodetection after a signature.
        variants = [raw[:65500]]
        for at, data in ((22, b'\x20'), (23, b'\x3f'), (48, struct.pack('<I', 65535)),
                         (28, struct.pack('<I', 0xffffffff)),
                         (512, struct.pack('<I', 0x40))):
            bad = bytearray(raw)
            bad[at:at+len(data)] = data
            variants.append(bad)
        for bad in variants:
            image.write_bytes(bad)
            for args in ([], ['-i', 'ftl100']):
                result = subprocess.run([str(tool('img_stat')), *args, str(image)], capture_output=True)
                assert result.returncode != 0, 'malformed recognized FTL accepted'
        # A normal raw FAT image still follows the normal raw backend.
        image.write_bytes(logical)
        assert b'FAT12' in run('fsstat', image)
        assert run('img_cat', image) == logical
        if opt.real_dump:
            physical = opt.real_dump.read_bytes()
            expected = opt.recovered_image.read_bytes()
            oracle, headers, _, _, _ = ref.recover(physical)
            assert oracle == expected, 'private recovery differs from Python reference'
            assert run('img_cat', '-i', 'ftl100', opt.real_dump) == expected, 'private native recovery differs'
            if headers[0][0] + 14 <= 1048576:
                assert run('img_cat', opt.real_dump) == expected, 'private automatic recovery differs'
            assert b'Ignored out-of-range BAM entries: 10' in run('img_stat', '-i', 'ftl100', opt.real_dump)
            recovered = tmp / 'private-recovered.img'
            recovered.write_bytes(expected)
            assert b'FAT12' in run('fsstat', '-i', 'ftl100', opt.real_dump)
            native = run('fls', '-i', 'ftl100', '-r', '-p', opt.real_dump).decode().replace('\r\n', '\n')
            comparison = run('fls', '-i', 'raw', '-r', '-p', recovered).decode().replace('\r\n', '\n')
            assert native == comparison, 'private FAT12 enumeration differs'
            print('Private ASK-II: native recovery byte-exact, FAT12 and recursive listing match existing recovery; ten out-of-range entries ignored', flush=True)
        print(f'{count} FTL100 full-image oracle comparisons passed; FAT12 contents, free-space marker, duplicates, holes, split dumps and malformed cases passed', flush=True)


if __name__ == '__main__':
    main()
