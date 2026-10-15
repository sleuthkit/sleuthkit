#!/usr/bin/env python3
"""Round-trip FAT32 + corrupted NAND, provenance and strict failure policies."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'tools/flash'))
from preprocess_ubi import Profile, preprocess
from nand_lba_fixture import create, profile, packer, PAGE_BYTES, PHYSICAL


def must_fail(action, contains):
    try:
        action()
    except ValueError as exc:
        assert contains in str(exc), str(exc)
    else:
        raise AssertionError('expected failure: '+contains)


def check_small(tmp):
    cfg = profile(); cfg['mapping']['logical_sectors'] = 16
    path = tmp/'small.json'; path.write_text(json.dumps(cfg))
    p = Profile(path)
    a, b = b'A'*PAGE_BYTES, b'B'*PAGE_BYTES
    pack = packer()
    source, dest = tmp/'small.bin', tmp/'small.img'
    def recover(data, **kw):
        source.write_bytes(data)
        return preprocess(source, dest, p, force=True, **kw)
    first, second = pack(a, 0), pack(b, 8)
    r = recover(second+first)
    assert dest.read_bytes() == a+b and r['lba_mapping']['entries'][0]['lba'] == 8
    old = dest.read_bytes()
    for raw, message in ((first, 'missing logical'),
                         (pack(a, 16)+second, 'outside logical'),
                         (pack(a, 1)+second, 'misaligned'),
                         (first+pack(b, 0)+second, 'equal-sequence'),
                         (first[:-1], 'complete physical pages')):
        must_fail(lambda: recover(raw), message)
        assert dest.read_bytes() == old, 'failed reconstruction replaced valid output'
        assert not list(tmp.glob('.small.img.*'))
    bad = bytearray(first)
    for bit in range(9):
        bad[bit] ^= 1
    must_fail(lambda: recover(bytes(bad)+second), 'uncorrectable BCH')
    must_fail(lambda: recover(bytes(bad)+second, uncorrectable='keep'), 'uncorrectable BCH')
    assert dest.read_bytes() == old
    # Metadata signature and address are examined after correction.
    bad = bytearray(first); bad[7*526+512] ^= 1
    r = recover(bytes(bad)+second)
    assert r['corrected_bits'] == 1 and dest.read_bytes() == a+b
    for policy, expected in [('first', a+b), ('last', b+b), ('highest_sequence', b+b)]:
        cfg['mapping']['duplicates'] = policy; path.write_text(json.dumps(cfg)); p = Profile(path)
        recover(first+pack(b, 0, 11)+second)
        assert dest.read_bytes() == expected
    cfg['mapping']['holes'] = 'fill'; cfg['mapping']['fill_byte'] = 255
    path.write_text(json.dumps(cfg)); p = Profile(path)
    r = recover(second)
    assert dest.read_bytes() == b'\xff'*PAGE_BYTES+b
    assert r['status'] == 'degraded' and r['lba_mapping']['missing_ranges'] == [[0, 8]]
    for modify in (lambda c: c['mapping'].update(fill_byte=256),
                   lambda c: c['mapping']['lba_field'].update(range=[0, 4]),
                   lambda c: c['mapping'].update(duplicates='guess'),
                   lambda c: c['mapping'].update(logical_sectors=17),
                   lambda c: c['mapping'].update(unknown=True),
                   lambda c: (c['operations'][-1].update(kind='copy'), c['operations'][-1].pop('ecc_range'))):
        c = copy.deepcopy(cfg); modify(c); path.write_text(json.dumps(c))
        try:
            Profile(path)
        except ValueError:
            pass
        else:
            raise AssertionError('invalid mapping config accepted')
    print('Mapping failures, atomic output preservation, duplicate policies, holes and metadata ECC passed', flush=True)


def check_fixture(directory, tools=None):
    directory = Path(directory)
    expected = json.loads((directory/'expected.json').read_text())
    raw = directory/'synthetic-nand-ftl-ecc-fat32.bin'
    output = directory/'reconstructed-fat32.img'
    cfg = directory/'synthetic-lba-bch-fat32.json'
    # Exercise the public CLI and JSON sidecar, not only internal functions.
    subprocess.run([sys.executable, str(ROOT/'tools/flash/preprocess_ubi.py'), str(raw),
                    '--profile', str(cfg), '--output', str(output), '--force'],
                   check=True, stdout=subprocess.DEVNULL)
    report = json.loads(Path(str(output)+'.report.json').read_text())
    assert output.read_bytes() == (directory/'expected-fat32.img').read_bytes()
    for key in ('corrected_bits', 'corrected_codewords', 'duplicate_pages', 'erased_pages'):
        assert report[key] == expected[key], (key, report[key], expected[key])
    mapping = report['lba_mapping']
    assert report['status'] == 'completed' and not mapping['missing_ranges']
    assert mapping['selected_pages'] == expected['selected_pages']
    selected = {row['lba']: row for row in mapping['entries'] if row['selected']}
    assert len(selected) == len(mapping['entries'])-expected['duplicate_pages']
    with raw.open('rb') as source:
        p = Profile(cfg)
        for page in (0, 1, 140):
            row = selected[page*8]
            assert row['physical_page'] == expected['physical_page_for_logical'][str(page)]
            source.seek(row['physical_offset'])
            corrected, _, bad = p.page(source.read(PHYSICAL))
            assert not bad and p.mapping.decode(corrected)[0] == page*8
    if tools:
        def run(tool, *args):
            binary = Path(tools)/tool
            if not binary.exists(): binary = Path(tools)/(tool+'.exe')
            return subprocess.check_output([str(binary), *map(str, args)])
        stat = run('fsstat', output)
        assert b'FAT32' in stat
        listing = run('fls', '-p', output).decode()
        for name, info in expected['files'].items():
            found = re.search(r'(\d+):\t'+re.escape(name)+r'\r?$', listing, re.M)
            assert found, listing
            data = run('icat', output, found[1])
            assert len(data) == info['bytes'] and hashlib.sha256(data).hexdigest() == info['sha256']
        (directory/'fsstat.txt').write_bytes(stat)
        (directory/'fls.txt').write_text(listing)
        print('Native Sleuth Kit: FAT32 auto-detection and both file payload hashes passed', flush=True)
    print('Shuffled 34 MiB FAT32 NAND: exact reconstruction, six corrected bits, stale duplicates and physical provenance passed', flush=True)


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--fixture', type=Path, help='reuse/build and retain test files here')
    ap.add_argument('--tools', type=Path, help='directory containing native fsstat, fls and icat')
    args = ap.parse_args()
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        check_small(tmp)
        fixture = args.fixture or tmp/'fixture'
        if not (fixture/'expected.json').is_file(): create(fixture)
        check_fixture(fixture, args.tools)
