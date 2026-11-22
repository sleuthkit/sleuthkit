"""Configurable page-to-LBA reconstruction after canonical page ECC decoding.

This is an explicit mapping format, not a universal proprietary FTL decoder.
Metadata offsets refer to the ECC-corrected operation output, never stripped OOB.
"""
import hashlib
import os
from pathlib import Path
import tempfile
from collections import Counter


class Mapping:
    def __init__(self, obj, decoded_bytes):
        expected = {'sector_bytes', 'logical_sectors', 'payload_range', 'lba_field',
                    'sequence_field', 'signature', 'duplicates', 'holes', 'fill_byte'}
        if not isinstance(obj, dict) or set(obj) != expected:
            raise ValueError('mapping requires explicit fields: '+', '.join(sorted(expected)))
        def number(v, name):
            if type(v) is not int or v < 0:
                raise ValueError(name+' must be a nonnegative integer')
            return v
        def region(v):
            if not isinstance(v, list) or len(v) != 2:
                raise ValueError('mapping ranges must be [offset, length]')
            at, n = (number(x, 'mapping range') for x in v)
            if not n or at+n > decoded_bytes:
                raise ValueError('mapping range outside corrected page')
            return at, n
        self.sector_bytes = number(obj['sector_bytes'], 'sector_bytes')
        self.logical_sectors = number(obj['logical_sectors'], 'logical_sectors')
        if self.sector_bytes not in (512, 1024, 2048, 4096) or not self.logical_sectors:
            raise ValueError('unsupported mapping sector size or empty logical image')
        self.output_bytes = self.sector_bytes*self.logical_sectors
        if self.output_bytes > (1 << 40):
            raise ValueError('mapped image exceeds 1 TiB limit')
        self.payload = region(obj['payload_range'])
        if self.payload[1] % self.sector_bytes:
            raise ValueError('mapping payload must contain whole sectors')
        self.sectors_per_page = self.payload[1]//self.sector_bytes
        if self.logical_sectors % self.sectors_per_page:
            raise ValueError('logical geometry must contain whole mapped pages')
        def field(v):
            if not isinstance(v, dict) or set(v) != {'range', 'byte_order'} or v['byte_order'] not in ('little', 'big'):
                raise ValueError('mapping integer fields require range and byte_order')
            r = region(v['range'])
            if r[1] not in (1, 2, 4, 8):
                raise ValueError('mapping integer width must be 1, 2, 4 or 8 bytes')
            return r, v['byte_order']
        self.lba = field(obj['lba_field'])
        self.sequence = field(obj['sequence_field'])
        tag = obj['signature']
        if not isinstance(tag, dict) or set(tag) != {'range', 'hex'} or not isinstance(tag['hex'], str):
            raise ValueError('mapping signature requires range and hex')
        self.tag_range, self.tag = region(tag['range']), bytes.fromhex(tag['hex'])
        if len(self.tag) != self.tag_range[1]:
            raise ValueError('mapping signature length mismatch')
        regions = [self.payload, self.lba[0], self.sequence[0], self.tag_range]
        for i, (at, n) in enumerate(regions):
            if any(at < b+m and b < at+n for b, m in regions[:i]):
                raise ValueError('overlapping mapping payload/metadata fields')
        if obj['duplicates'] not in ('highest_sequence', 'first', 'last') or obj['holes'] not in ('fail', 'fill'):
            raise ValueError('unknown mapping duplicates/holes policy')
        self.duplicates, self.holes = obj['duplicates'], obj['holes']
        self.fill_byte = number(obj['fill_byte'], 'fill_byte')
        if self.fill_byte > 255:
            raise ValueError('mapping fill_byte must be <=255')
        self.metadata_ranges = [self.lba[0], self.sequence[0], self.tag_range]

    def decode(self, corrected):
        at, n = self.tag_range
        if corrected[at:at+n] != self.tag:
            raise ValueError('mapping signature mismatch in non-erased page')
        def value(field):
            (at, n), order = field
            return int.from_bytes(corrected[at:at+n], order)
        lba, sequence = value(self.lba), value(self.sequence)
        if lba % self.sectors_per_page or lba+self.sectors_per_page > self.logical_sectors:
            raise ValueError('mapping LBA outside logical geometry or misaligned')
        at, n = self.payload
        return lba, sequence, corrected[at:at+n]


def reconstruct(source, destination, profile, *, ecc, uncorrectable, force, progress):
    """One streaming read and random-access writes; selected map bounded by geometry.

    The audit list grows with the number of non-erased physical pages.
    The caller has checked input/output aliasing and complete physical pages.
    Failed reconstruction removes only its temporary output, preserving originals.
    """
    mapping = profile.mapping
    source, destination = Path(source), Path(destination)
    size = source.stat().st_size
    counts, selected, audit = Counter(), {}, []
    ih = hashlib.sha256()
    fd, temporary = tempfile.mkstemp(prefix='.'+destination.name+'.', dir=destination.parent)
    try:
        with os.fdopen(fd, 'w+b') as fo, source.open('rb') as fi:
            fo.truncate(mapping.output_bytes)
            if mapping.fill_byte:
                chunk = bytes([mapping.fill_byte])*1048576
                for at in range(0, mapping.output_bytes, len(chunk)):
                    fo.write(chunk[:min(len(chunk), mapping.output_bytes-at)])
            for page in range(size//profile.physical):
                raw = fi.read(profile.physical)
                ih.update(raw)
                if len(raw) != profile.physical:
                    raise ValueError('short physical page during mapping')
                if raw == b'\xff'*profile.physical:
                    counts['erased_pages'] += 1
                    if progress and page+1 == size//profile.physical:
                        progress(page+1, size//profile.physical, counts)
                    continue
                corrected, stats, errors = profile.page(raw, ecc)
                counts.update(stats)
                # Never select mappings whose metadata or payload cannot be verified.
                # A bad stale duplicate may contain an unreadable newest LBA/sequence.
                if errors:
                    raise ValueError(f'uncorrectable BCH at physical page {page}; mapped output not committed')
                lba, sequence, payload = mapping.decode(corrected)
                digest = hashlib.sha256(payload).hexdigest()
                row = {'physical_page': page, 'physical_offset': page*profile.physical,
                       'lba': lba, 'sectors': mapping.sectors_per_page,
                       'sequence': sequence, 'payload_sha256': digest, 'selected': False}
                previous = selected.get(lba)
                choose = previous is None
                if previous is not None:
                    counts['duplicate_pages'] += 1
                    if mapping.duplicates == 'highest_sequence':
                        if sequence == previous['sequence'] and digest != previous['payload_sha256']:
                            raise ValueError(f'ambiguous equal-sequence duplicate for LBA {lba}')
                        choose = sequence > previous['sequence']
                    else:
                        choose = mapping.duplicates == 'last'
                if choose:
                    if previous:
                        previous['selected'] = False
                    row['selected'] = True
                    selected[lba] = row
                    fo.seek(lba*mapping.sector_bytes)
                    fo.write(payload)
                audit.append(row)
                counts['mapped_physical_pages'] += 1
                if progress and (page % 1024 == 0 or page+1 == size//profile.physical):
                    progress(page+1, size//profile.physical, counts)
            if fi.read(1):
                raise ValueError('input size changed during mapping')
            missing = []
            start = None
            for lba in range(0, mapping.logical_sectors, mapping.sectors_per_page):
                if lba not in selected and start is None:
                    start = lba
                if lba in selected and start is not None:
                    missing.append([start, lba-start]); start = None
            if start is not None:
                missing.append([start, mapping.logical_sectors-start])
            if missing and mapping.holes == 'fail':
                raise ValueError('missing logical pages; mapped output not committed')
            fo.flush(); os.fsync(fo.fileno()); fo.seek(0)
            oh = hashlib.sha256()
            while True:
                chunk = fo.read(1048576)
                if not chunk:
                    break
                oh.update(chunk)
        os.replace(temporary, destination)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise
    return {'schema_version': 1, 'profile': profile.id, 'profile_sha256': profile.sha256,
            'input': str(source), 'output': str(destination), 'input_bytes': size,
            'output_bytes': mapping.output_bytes, 'input_sha256': ih.hexdigest(),
            'output_sha256': oh.hexdigest(), 'physical_page_bytes': profile.physical,
            'logical_page_bytes': profile.logical, 'pages': size//profile.physical,
            'ecc_enabled': ecc, 'uncorrectable_policy': uncorrectable,
            'status': 'degraded' if missing else 'completed' if ecc else 'ecc_disabled',
            'unprotected_bytes_per_page': profile.unprotected_bytes,
            'discarded_bytes_per_page': profile.discarded_bytes,
            **{key: counts[key] for key in ('clean_codewords', 'corrected_codewords', 'corrected_bits',
               'uncorrectable_codewords', 'erased_codewords', 'unchecked_codewords',
               'unprotected_bytes', 'erased_pages', 'duplicate_pages', 'mapped_physical_pages')},
            'errors': [], 'errors_omitted': 0,
            'lba_mapping': {'sector_bytes': mapping.sector_bytes, 'logical_sectors': mapping.logical_sectors,
                            'duplicates': mapping.duplicates, 'holes': mapping.holes,
                            'fill_byte': mapping.fill_byte, 'missing_ranges': missing,
                            'selected_pages': len(selected), 'entries': audit}}
