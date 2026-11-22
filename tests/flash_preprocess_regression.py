#!/usr/bin/env python3
"""Independent BCH encoder, corrupted words, profiles and real UBI round-trip."""
import argparse
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import random
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'tools/flash'))
from preprocess_ubi import Profile, preprocess


def gf_mul(a, b):
    out = 0
    while b:
        if b & 1:
            out ^= a
        b >>= 1
        a <<= 1
        if a & 8192:
            a ^= 0x201b
    return out


def generator():
    exponents = [1]
    for _ in range(8190):
        exponents.append(gf_mul(exponents[-1], 2))
    roots = set()
    for first in range(1, 17):
        i = first
        while i not in roots:
            roots.add(i)
            i = (i*2) % 8191
    polynomial = [1]
    for root in sorted(roots):
        out = [0]*(len(polynomial)+1)
        for i, coefficient in enumerate(polynomial):
            out[i] ^= gf_mul(coefficient, exponents[root])
            out[i+1] ^= coefficient
        polynomial = out
    assert len(polynomial) == 105 and set(polynomial) <= {0, 1}
    return sum(c << i for i, c in enumerate(polynomial))


def encode(payload, polynomial):
    remainder = int.from_bytes(payload, 'big') << 104
    while remainder.bit_length() > 104:
        remainder ^= polynomial << (remainder.bit_length()-105)
    return remainder.to_bytes(13, 'big')


def pack_page(data, polynomial):
    assert len(data) == 4096
    page = bytearray(b'\xff'*4352)
    for i in range(7):
        base = 532*i
        payload = data[516*i:516*(i+1)]
        page[base:base+372] = payload[:372]
        page[base+373:base+517] = payload[372:]
        page[base+517:base+530] = b'\xff'*13 if payload == b'\xff'*516 else encode(payload, polynomial)
    page[3724:4096] = data[3612:3984]
    page[4097:4209] = data[3984:]
    return bytes(page)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--reference', type=Path)
    ap.add_argument('--tools', type=Path)
    args = ap.parse_args()
    profile_path = ROOT/'config/flash_devices/qualcomm-kommbox-4352.json'
    profile = Profile(profile_path)
    assert profile.protected_bytes == 3612 and profile.unprotected_bytes == 484
    polynomial = generator()
    rng = random.Random(1337)
    payload = rng.randbytes(516)
    parity = encode(payload, polynomial)
    assert profile.decoder.correct(payload, parity) == (payload, 0, 'clean')
    reference = None
    if args.reference:
        spec = importlib.util.spec_from_file_location('qualcomm_reference', args.reference/'qualcomm_kombox.py')
        reference = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(reference)
    checks = 0
    for errors in range(1, 9):
        corrupted = bytearray(payload+parity)
        # Mixed payload/parity errors, including extreme bit positions.
        positions = [0, len(corrupted)*8-1] + rng.sample(range(1, len(corrupted)*8-1), 6)
        for bit in positions[:errors]:
            corrupted[bit//8] ^= 1 << (7-bit % 8)
        result = profile.decoder.correct(corrupted[:516], corrupted[516:])
        assert result == (payload, errors, 'corrected'), errors
        if reference:
            assert result == reference._correct_codeword(bytes(corrupted[:516]), bytes(corrupted[516:]))
        checks += 1
    # A chosen beyond-radius corruption is uncorrectable; not all >t errors are detectable.
    corrupted = bytearray(payload+parity)
    for bit in range(9):
        corrupted[bit//8] ^= 1 << (7-bit % 8)
    assert profile.decoder.correct(corrupted[:516], corrupted[516:])[2] == 'uncorrectable'
    data = rng.randbytes(4096)
    page = pack_page(data, polynomial)
    output, counts, bad = profile.page(page)
    assert output == data and counts['clean_codewords'] == 7 and not bad
    if reference:
        assert reference.process_page(page)[0] == data
    damaged = bytearray(page)
    damaged[0] ^= 0x80
    fixed, counts, bad = profile.page(damaged)
    assert fixed == data and counts['corrected_bits'] == 1 and not bad
    erased, counts, bad = profile.page(b'\xff'*4352)
    assert erased == b'\xff'*4096 and counts['erased_codewords'] == 7
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        source, dest = tmp/'raw.bin', tmp/'clean.ubi'
        source.write_bytes(damaged)
        report = preprocess(source, dest, profile)
        assert dest.read_bytes() == data and report['corrected_bits'] == 1
        assert report['input_sha256'] == hashlib.sha256(damaged).hexdigest()
        assert report['output_sha256'] == hashlib.sha256(data).hexdigest()
        assert report['unprotected_bytes'] == 484
        original = source.read_bytes()
        broken = bytearray(page)
        for bit in range(9):
            broken[bit//8] ^= 1 << (7-bit % 8)
        source.write_bytes(broken)
        try:
            preprocess(source, dest, profile, force=True)
            raise AssertionError('uncorrectable input accepted')
        except ValueError:
            pass
        assert dest.read_bytes() == data and source.read_bytes() == bytes(broken)
        assert not list(tmp.glob('.clean.ubi.*'))
        report = preprocess(source, dest, profile, force=True, uncorrectable='keep')
        assert report['status'] == 'degraded' and report['uncorrectable_codewords'] == 1
        assert report['errors'][0]['page'] == 0 and report['errors'][0]['physical_offset'] == 0
        report = preprocess(source, dest, profile, force=True, ecc=False)
        assert report['status'] == 'ecc_disabled' and report['unchecked_codewords'] == 7
        for wrong in (source, tmp/'bad-output'):
            if wrong != source:
                source.write_bytes(page[:-1])
            try:
                preprocess(source, wrong, profile)
                raise AssertionError('alias/partial-page accepted')
            except ValueError:
                pass
        # Config files are validated, not executed; reject overlap and geometry typos.
        config = json.loads(profile_path.read_text())
        invalid = tmp/'invalid.json'
        config['operations'][0]['ecc_range'] = [0, 13]
        invalid.write_text(json.dumps(config))
        try:
            Profile(invalid)
            raise AssertionError('overlapping profile accepted')
        except ValueError:
            pass
        # CLI profile lookup and sidecar report are part of the public workflow.
        source.write_bytes(page)
        cli = ROOT/'tools/flash/preprocess_ubi.py'
        dest.unlink()
        subprocess.check_output([sys.executable, str(cli), str(source), '-o', str(dest), '--profile', profile.id])
        sidecar = json.loads(Path(str(dest)+'.report.json').read_text())
        assert sidecar['output_sha256'] == hashlib.sha256(data).hexdigest()
        assert sidecar['profile_sha256'] == profile.sha256
        if args.reference:
            # Real kernel-built UBI fixture: synthetic transport encoding, then native detection.
            ubi = gzip.decompress((args.reference/'tests/fixtures/ubi-nand-lzo.img.gz').read_bytes())
            source.write_bytes(b''.join(pack_page(ubi[i:i+4096], polynomial) for i in range(0, len(ubi), 4096)))
            report = preprocess(source, dest, profile, force=True)
            assert dest.read_bytes() == ubi and report['uncorrectable_codewords'] == 0
            if args.tools:
                fsstat = args.tools/'fsstat'
                if not fsstat.exists():
                    fsstat = args.tools/'fsstat.exe'
                out = subprocess.check_output([str(fsstat), str(dest)])
                assert b'Volume Count: 3' in out
            suffix = ' and native UBI detection' if args.tools else ''
            print('Full UBI fixture transport -> ECC/cleanup -> byte-exact original'+suffix+' passed', flush=True)
    print(f'{checks} bounded BCH corruption cases passed; reference parity/geometry, profiles, reports, erased pages and failure policies passed', flush=True)


if __name__ == '__main__':
    main()
