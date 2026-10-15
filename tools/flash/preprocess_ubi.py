#!/usr/bin/env python3
"""Device-profile NAND cleanup before native UBI/UBIFS analysis; stdlib only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from collections import Counter
from bch import BCH


def profile_directory():
    bundled = Path(__file__).resolve().parent / 'profiles'
    return bundled if bundled.is_dir() else Path(__file__).resolve().parents[2] / 'config/flash_devices'


def integer(value, name):
    if type(value) is not int or value < 0:
        raise ValueError(name+' must be a nonnegative integer')
    return value


class Profile:
    def __init__(self, path):
        self.path = Path(path)
        raw = self.path.read_bytes()
        self.sha256 = hashlib.sha256(raw).hexdigest()
        obj = json.loads(raw)
        allowed = {'schema_version', 'id', 'description', 'notes', 'physical_page_bytes', 'logical_page_bytes', 'ecc', 'operations'}
        if not isinstance(obj, dict) or set(obj)-allowed or type(obj.get('schema_version')) is not int or obj.get('schema_version') != 1:
            raise ValueError('unknown profile fields or unsupported schema version')
        if not isinstance(obj.get('id'), str) or not obj['id']:
            raise ValueError('profile id must be a nonempty string')
        self.id = obj['id']
        self.physical = integer(obj.get('physical_page_bytes'), 'physical_page_bytes')
        self.logical = integer(obj.get('logical_page_bytes'), 'logical_page_bytes')
        if not 1 <= self.logical <= self.physical <= 1048576:
            raise ValueError('invalid page geometry')
        ecc = obj.get('ecc')
        if not isinstance(ecc, dict) or set(ecc) != {'algorithm', 'm', 't', 'primitive_polynomial', 'bit_order'}:
            raise ValueError('explicit ECC configuration is required')
        if ecc['algorithm'] != 'bch' or ecc['bit_order'] != 'msb-first':
            raise ValueError('only systematic MSB-first BCH is currently implemented')
        self.m, self.t = integer(ecc['m'], 'm'), integer(ecc['t'], 't')
        poly = ecc['primitive_polynomial']
        if not isinstance(poly, str):
            raise ValueError('primitive_polynomial must be a hex string')
        self.polynomial = int(poly, 0)
        self.decoder = BCH(self.m, self.t, self.polynomial)
        ops = obj.get('operations')
        if not isinstance(ops, list) or not ops:
            raise ValueError('operations must be a nonempty array')
        self.operations = []
        occupied = set()
        total, protected = 0, 0
        def region(value):
            if not isinstance(value, list) or len(value) != 2:
                raise ValueError('ranges must be [offset, length]')
            at, size = integer(value[0], 'offset'), integer(value[1], 'length')
            if not size or at+size > self.physical:
                raise ValueError('range outside page')
            pixels = set(range(at, at+size))
            if pixels & occupied:
                raise ValueError('overlapping input ranges')
            occupied.update(pixels)
            return at, size
        for op in ops:
            if not isinstance(op, dict) or op.get('kind') not in ('bch', 'copy'):
                raise ValueError('operation must be bch or copy')
            expected = {'kind', 'data_ranges', 'ecc_range'} if op['kind'] == 'bch' else {'kind', 'data_ranges'}
            if set(op) != expected or not isinstance(op['data_ranges'], list) or not op['data_ranges']:
                raise ValueError('unknown operation fields or missing data ranges')
            ranges = [region(v) for v in op['data_ranges']]
            size = sum(n for _, n in ranges)
            parity = region(op['ecc_range']) if op['kind'] == 'bch' else None
            if parity and (parity[1] != self.decoder.ecc_bytes or (size+parity[1])*8 > self.decoder.n):
                raise ValueError('ECC range/codeword length does not fit BCH configuration')
            total += size
            if parity:
                protected += size
            self.operations.append((ranges, parity))
        if total != self.logical:
            raise ValueError('operation output lengths do not equal logical_page_bytes')
        self.protected_bytes = protected
        self.unprotected_bytes = total-protected
        # Everything neither emitted nor used as parity is intentionally discarded.
        self.discarded_bytes = self.physical-total-sum(p[1] for _, p in self.operations if p)

    def page(self, source, ecc_enabled=True):
        if len(source) != self.physical:
            raise ValueError('short physical page')
        output = bytearray()
        counts, bad = Counter(), []
        for index, (ranges, parity) in enumerate(self.operations):
            payload = b''.join(source[at:at+n] for at, n in ranges)
            if not parity:
                counts['unprotected_bytes'] += len(payload)
            elif not ecc_enabled:
                counts['unchecked_codewords'] += 1
            else:
                at, size = parity
                ecc = source[at:at+size]
                if payload == b'\xff'*len(payload) and ecc == b'\xff'*len(ecc):
                    counts['erased_codewords'] += 1
                else:
                    fixed, bits, status = self.decoder.correct(payload, ecc)
                    counts[status+'_codewords'] += 1
                    counts['corrected_bits'] += bits
                    if status == 'uncorrectable':
                        bad.append({'operation': index, 'physical_page_offset': ranges[0][0]})
                    payload = fixed
            output += payload
        return bytes(output), counts, bad


def preprocess(source, destination, profile, *, ecc=True, uncorrectable='fail', force=False, progress=None):
    source, destination = Path(source), Path(destination)
    if source.resolve() == destination.resolve():
        raise ValueError('input and output must differ')
    if destination.exists() and os.path.samefile(source, destination):
        raise ValueError('output aliases the original input')
    if destination.exists() and not force:
        raise ValueError('output already exists; use --force to replace it')
    if uncorrectable not in ('fail', 'keep'):
        raise ValueError('uncorrectable policy must be fail or keep')
    size = source.stat().st_size
    if not size or size % profile.physical:
        raise ValueError('input must contain complete physical pages')
    destination.parent.mkdir(parents=True, exist_ok=True)
    report = {'schema_version': 1, 'profile': profile.id, 'profile_sha256': profile.sha256,
              'input': str(source), 'output': str(destination), 'physical_page_bytes': profile.physical,
              'logical_page_bytes': profile.logical, 'ecc_enabled': ecc, 'uncorrectable_policy': uncorrectable,
              'unprotected_bytes_per_page': profile.unprotected_bytes, 'discarded_bytes_per_page': profile.discarded_bytes,
              'input_bytes': size, 'pages': 0, 'errors': [], 'errors_omitted': 0}
    counts = Counter()
    ih, oh = hashlib.sha256(), hashlib.sha256()
    fd, temporary = tempfile.mkstemp(prefix='.'+destination.name+'.', dir=destination.parent)
    try:
        with os.fdopen(fd, 'wb') as fo, source.open('rb') as fi:
            for page in range(size//profile.physical):
                raw = fi.read(profile.physical)
                ih.update(raw)
                clean, stats, errors = profile.page(raw, ecc)
                counts.update(stats)
                if errors and uncorrectable == 'fail':
                    raise ValueError(f'uncorrectable BCH at page {page}, operation {errors[0]["operation"]}; output not committed (use --uncorrectable keep only intentionally)')
                for error in errors:
                    error = {**error, 'page': page, 'physical_offset': page*profile.physical+error['physical_page_offset']}
                    if len(report['errors']) < 10000:
                        report['errors'].append(error)
                    else:
                        report['errors_omitted'] += 1
                fo.write(clean)
                oh.update(clean)
                report['pages'] += 1
                if progress and (page % 1024 == 0 or page+1 == size//profile.physical):
                    progress(report['pages'], size//profile.physical, counts)
            if fi.read(1):
                raise ValueError('input size changed during processing')
            fo.flush()
            os.fsync(fo.fileno())
        os.replace(temporary, destination)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise
    report.update({key: counts[key] for key in ('clean_codewords', 'corrected_codewords', 'corrected_bits',
                  'uncorrectable_codewords', 'erased_codewords', 'unchecked_codewords', 'unprotected_bytes')})
    report.update(input_sha256=ih.hexdigest(), output_sha256=oh.hexdigest(), output_bytes=report['pages']*profile.logical)
    report['status'] = 'degraded' if report['uncorrectable_codewords'] else 'ecc_disabled' if not ecc else 'completed'
    return report


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('input', nargs='?', type=Path)
    ap.add_argument('-o', '--output', type=Path)
    ap.add_argument('--profile', help='profile id or path to a JSON configuration')
    ap.add_argument('--profiles-dir', type=Path, default=profile_directory())
    ap.add_argument('--list-profiles', action='store_true')
    ap.add_argument('--ecc', choices=('on', 'off'), default='on')
    ap.add_argument('--uncorrectable', choices=('fail', 'keep'), default='fail')
    ap.add_argument('--force', action='store_true')
    args = ap.parse_args()
    if args.list_profiles:
        for path in sorted(args.profiles_dir.glob('*.json')):
            p = Profile(path)
            print(f'{p.id}\t{p.physical} -> {p.logical}\t{path}')
        return
    if not args.input or not args.output or not args.profile:
        ap.error('input, --output and --profile are required; no device guessing is performed')
    try:
        path = Path(args.profile)
        if not path.is_file():
            if Path(args.profile).name != args.profile:
                raise ValueError('unknown profile path')
            path = args.profiles_dir / (args.profile+'.json')
        profile = Profile(path)
        report_path = Path(str(args.output)+'.report.json')
        if report_path.resolve() == args.input.resolve() or (report_path.exists() and os.path.samefile(report_path, args.input)):
            raise ValueError('report path aliases input')
        if report_path.exists() and not args.force:
            raise ValueError('report already exists; use a new output name or --force')
        def progress(pages, total, counts):
            print(f'{pages}/{total} pages; {counts["corrected_bits"]} corrected bits; {counts["uncorrectable_codewords"]} uncorrectable codewords', file=sys.stderr)
        report = preprocess(args.input, args.output, profile, ecc=args.ecc == 'on',
                            uncorrectable=args.uncorrectable, force=args.force, progress=progress)
        report_path.write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
        print(json.dumps(report, indent=2))
    except (OSError, ValueError) as exc:
        ap.exit(2, f'Error: {exc}\n')


if __name__ == '__main__':
    main()
