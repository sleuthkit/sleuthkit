#!/usr/bin/env python3
"""Native FlashFX / Reliance extraction versus pinned qnxprobe reference."""
import argparse
import importlib.util
import pathlib
import re
import struct
import subprocess
import tempfile
from reliance_fixture import logical, raw


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--tools', type=pathlib.Path, required=True)
    ap.add_argument('--reference', type=pathlib.Path, required=True)
    ap.add_argument('--read-probe', type=pathlib.Path)
    opt = ap.parse_args()
    spec = importlib.util.spec_from_file_location('datalight_reference', opt.reference / 'datalight_reliance.py')
    ref = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ref)
    def run(name, *args):
        p = opt.tools / name
        if not p.exists():
            p = opt.tools / (name+'.exe')
        return subprocess.check_output([str(p), *map(str, args)])
    def names(image, *args):
        result = {}
        for line in run('fls', '-r', '-p', *args, image).decode().splitlines():
            m = re.match(r'\S+ (\d+):\t(.*)', line)
            if m:
                result[m[2]] = int(m[1])
        return result
    flat, expected = logical()
    nand = raw(flat)
    tp, tu, headers, invalid = ref.scan_flashfx_units(nand)
    groups = ref.choose_flashfx_groups(headers)
    assert len(groups) == 1
    mapping, statuses = ref.build_flashfx_map(nand, groups[0])
    dev = ref.FlashFXLogical(nand, mapping)
    info = ref.find_reliance_volumes(dev)[0]
    vol = ref.RelianceVolume(dev, info)
    recs = ref.recover_directory_records(vol)
    alloc = ref.recover_allocation_records(vol)
    assert recs['transaction'] == 9
    root, byoid, children, dirs = ref.build_namespace(recs['records'])
    oracle = {}
    for r in recs['records']:
        if r['object_id'] in dirs:
            continue
        path = ref.logical_path_for_record(r, byoid, root).lstrip('/')
        ars = alloc['by_object'][r['object_id']]
        size = ref.object_size_from_lalc(ars)
        payload = b''.join(vol.block(ex['start_block']+k) for ex in ref.object_extents_from_lalc(vol, ars) for k in range(ex['block_count']))[:size]
        oracle[path] = payload
    assert oracle == expected
    with tempfile.TemporaryDirectory() as td:
        tmp = pathlib.Path(td)
        image = tmp / 'reliance.img'
        comparisons = 0
        for label, source, prefix in (('logical', flat, 'Reliance_1_0x0/'), ('raw', nand, 'FlashFX_1/Reliance_1_0x0/')):
            image.write_bytes(source)
            have = names(image)
            assert names(image, '-f', 'reliance') == have
            assert b'META transaction 9' in run('fsstat', image)
            for path, payload in expected.items():
                node = have[prefix+path]
                assert run('icat', image, node) == payload
                comparisons += 1
                if opt.read_probe:
                    for offset, length in ((0, 7), (509, 40), (4090, 40), (len(payload), 5)):
                        if offset > len(payload):
                            continue
                        got = subprocess.check_output([str(opt.read_probe), str(image), str(node), str(offset), str(length)])
                        assert got == payload[offset:offset+length]
            stat = run('istat', image, have[prefix+'a_very_long_reliance_filename.bin'])
            assert b'Modified: 1710000000.127000000' in stat
            wrapped = tmp / 'offset.img'
            wrapped.write_bytes(bytes(8192)+source)
            assert names(wrapped, '-o', 16) == have
            assert run('blkls', image) == b''
            print(label+': payloads, names, nested tree, empty files, milliseconds and offsets passed', flush=True)
        # A newer physical unit for the same logical client range wins.
        extra = bytearray(nand[:4320*128])
        struct.pack_into('<I', extra, 10+28, 999)
        # Recompute the FlashFX main-header checksum after sequence change.
        struct.pack_into('<H', extra, 10+54, sum(extra[10:10+54]) & 65535)
        extra[(8+1)*4320+10] ^= 0x80
        changed = nand + extra
        image.write_bytes(changed)
        have = names(image)
        got = run('icat', image, have['FlashFX_1/Reliance_1_0x0/a_very_long_reliance_filename.bin'])
        assert got[0] == (expected['a_very_long_reliance_filename.bin'][0] ^ 0x80)
        expected_free = b''.join(ref.extract_main(nand[p*4320:(p+1)*4320]) for p in range(1, 33))
        assert run('blkls', image) == expected_free
        # Equal sequence: higher physical page wins; lower sequence is ignored.
        struct.pack_into('<I', extra, 10+28, 10)
        struct.pack_into('<H', extra, 10+54, sum(extra[10:10+54]) & 65535)
        image.write_bytes(nand + extra)
        have = names(image)
        assert run('icat', image, have['FlashFX_1/Reliance_1_0x0/a_very_long_reliance_filename.bin']) == got
        struct.pack_into('<I', extra, 10+28, 9)
        struct.pack_into('<H', extra, 10+54, sum(extra[10:10+54]) & 65535)
        image.write_bytes(nand + extra)
        have = names(image)
        assert run('icat', image, have['FlashFX_1/Reliance_1_0x0/a_very_long_reliance_filename.bin']) == expected['a_very_long_reliance_filename.bin']
        # Two separate FlashFX serial groups become two folders/volumes.
        image.write_bytes(nand + raw(flat, 0x87654321))
        have = names(image)
        assert 'FlashFX_1' in have and 'FlashFX_2' in have
        assert b'Volume Count: 2' in run('fsstat', image)
        image.write_bytes(flat + flat)
        have = names(image)
        assert 'Reliance_2_0x131072/a_very_long_reliance_filename.bin' in have
        assert b'Volume Count: 2' in run('fsstat', image)
        # Fail closed on corrupt checksum, pointer cycles, counts and extents.
        variants = [nand[:4320*127]]
        b = bytearray(nand)
        b[10+54] ^= 1
        variants.append(b)
        b = bytearray(flat)
        struct.pack_into('<I', b, 3*4096+0xab0, 3)
        variants.append(b)
        b = bytearray(flat)
        struct.pack_into('<I', b, 4*4096+16, 1000)
        variants.append(b)
        b = bytearray(flat)
        struct.pack_into('<Q', b, 7*4096+0x808, (2 << 32) | 31)
        variants.append(b)
        for source in variants:
            image.write_bytes(source)
            p = opt.tools / 'fsstat'
            if not p.exists():
                p = opt.tools / 'fsstat.exe'
            assert subprocess.run([str(p), '-f', 'reliance', str(image)], capture_output=True).returncode != 0
        print(f'{comparisons} Reliance payload comparisons passed; FlashFX newest-page mapping, serial groups, superseded payload accounting and malformed cases passed', flush=True)


if __name__ == '__main__':
    main()
