#!/usr/bin/env python3
"""Deterministic synthetic NAND (BCH + LBA metadata) around a real FAT32 volume.

The layout is deliberately synthetic, not a claimed controller/device format.
BCH parity is produced by the independent polynomial encoder used in the
pre-existing preprocessor regression, not the production correction routine.
"""
import argparse
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import random
import struct
from flash_preprocess_regression import generator, encode

ROOT = Path(__file__).resolve().parents[1]
SECTORS = 69632
PAGE_BYTES = 4096
PHYSICAL = 4224


def profile():
    operations = []
    for i in range(8):
        n = 512 if i < 7 else 528
        base = i*526
        operations.append({'kind': 'bch', 'data_ranges': [[base, n]],
                           'ecc_range': [base+n+1, 13]})
    return {'schema_version': 1, 'id': 'synthetic-lba-bch-fat32',
            'description': 'Synthetic test only: 4 KiB data + protected LBA/sequence, BCH-8 and 8 stuff bytes',
            'notes': ['Not a Qualcomm, Rusolut, Continental or universal FTL profile.',
                      'Mapping offsets refer to the concatenated ECC-corrected operation output.',
                      'No bad-block markers, sequence wraparound, banks or log-block merging are emulated.'],
            'physical_page_bytes': PHYSICAL, 'logical_page_bytes': 4112,
            'ecc': {'algorithm': 'bch', 'm': 13, 't': 8,
                    'primitive_polynomial': '0x201B', 'bit_order': 'msb-first'},
            'operations': operations,
            'mapping': {'sector_bytes': 512, 'logical_sectors': SECTORS,
                        'payload_range': [0, PAGE_BYTES],
                        'lba_field': {'range': [4096, 4], 'byte_order': 'little'},
                        'sequence_field': {'range': [4100, 4], 'byte_order': 'little'},
                        'signature': {'range': [4104, 4], 'hex': '4c424131'},
                        'duplicates': 'highest_sequence', 'holes': 'fail', 'fill_byte': 0}}


def fat32():
    reserved, fats = 32, 2
    fat_sectors = 1
    while True:
        clusters = SECTORS-reserved-fats*fat_sectors
        required = ((clusters+2)*4+511)//512
        if required <= fat_sectors:
            break
        fat_sectors = required
    clusters = SECTORS-reserved-fats*fat_sectors
    assert clusters >= 65525 and fat_sectors*128 >= clusters+2
    image = bytearray(SECTORS*512)
    boot = memoryview(image)[:512]
    boot[:3] = b'\xeb\x58\x90'; boot[3:11] = b'TSKTEST '
    struct.pack_into('<HBHBHHBHHHII', boot, 11, 512, 1, reserved, fats, 0, 0, 0xf8,
                     0, 63, 255, 0, SECTORS)
    struct.pack_into('<IHHIHH', boot, 36, fat_sectors, 0, 0, 2, 1, 6)
    boot[64] = 0x80; boot[66] = 0x29
    struct.pack_into('<I', boot, 67, 0x1234abcd)
    boot[71:82] = b'NANDLBATEST'; boot[82:90] = b'FAT32   '; boot[510:512] = b'\x55\xaa'
    files = {'HELLO.TXT': b'Sleuth Kit NAND LBA mapping + BCH + FAT32 test.\r\n',
             'PAYLOAD.BIN': bytes((i*37+11)%256 for i in range(16391))}
    allocated = 1+sum((len(v)+511)//512 for v in files.values())
    info = bytearray(512)
    struct.pack_into('<I', info, 0, 0x41615252)
    struct.pack_into('<III', info, 484, 0x61417272, clusters-allocated, allocated+2)
    struct.pack_into('<I', info, 508, 0xaa550000)
    image[512:1024] = info
    image[6*512:7*512] = boot
    image[7*512:8*512] = info
    fat = bytearray(fat_sectors*512)
    struct.pack_into('<III', fat, 0, 0x0ffffff8, 0x0fffffff, 0x0fffffff)
    data_start = reserved+fats*fat_sectors
    root = data_start*512
    image[root:root+11] = b'NANDLBATEST'; image[root+11] = 8
    next_cluster = 3
    for index, (name, data) in enumerate(files.items(), 1):
        first = next_cluster
        for off in range(0, len(data), 512):
            cluster = next_cluster; next_cluster += 1
            following = next_cluster if off+512 < len(data) else 0x0fffffff
            struct.pack_into('<I', fat, cluster*4, following)
            at = (data_start+cluster-2)*512
            image[at:at+min(512, len(data)-off)] = data[off:off+512]
        base, ext = name.split('.')
        at = root+index*32
        image[at:at+11] = (base.ljust(8)+ext.ljust(3)).encode('ascii')
        image[at+11] = 0x20
        struct.pack_into('<HH', image, at+22, 12 << 11, ((2026-1980) << 9) | (10 << 5) | 15)
        struct.pack_into('<H', image, at+26, first)
        struct.pack_into('<I', image, at+28, len(data))
    for copy in range(fats):
        at = (reserved+copy*fat_sectors)*512
        image[at:at+len(fat)] = fat
    return bytes(image), files


@lru_cache(maxsize=1)
def packer():
    polynomial = generator()
    @lru_cache(maxsize=256)
    def parity(data):
        return encode(data, polynomial)
    def pack(payload, lba, sequence=10):
        assert len(payload) == PAGE_BYTES
        canonical = payload+struct.pack('<II4sI', lba, sequence, b'LBA1', 0)
        raw = bytearray(PHYSICAL)
        for i in range(8):
            data = canonical[i*512:(i+1)*512] if i < 7 else canonical[3584:]
            base = i*526
            raw[base:base+len(data)] = data
            raw[base+len(data)] = 0xa5
            raw[base+len(data)+1:base+len(data)+14] = parity(data)
        return bytes(raw)
    return pack


def create(directory):
    directory = Path(directory); directory.mkdir(parents=True, exist_ok=True)
    clean, files = fat32()
    (directory/'expected-fat32.img').write_bytes(clean)
    (directory/'synthetic-lba-bch-fat32.json').write_text(json.dumps(profile(), indent=2)+'\n')
    pages = list(range(len(clean)//PAGE_BYTES))
    random.Random(20261015).shuffle(pages)
    pack = packer()
    corrections = []
    physical = {}
    path = directory/'synthetic-nand-ftl-ecc-fat32.bin'
    with path.open('wb') as out:
        # Older duplicate boot/data pages with valid ECC, superseded regardless of order.
        for page in (0, 140):
            stale = bytearray(clean[page*PAGE_BYTES:(page+1)*PAGE_BYTES]); stale[0] ^= 0x40
            out.write(pack(bytes(stale), page*8, sequence=9))
        for index, page in enumerate(pages, 2):
            raw = bytearray(pack(clean[page*PAGE_BYTES:(page+1)*PAGE_BYTES], page*8))
            physical[page] = index
            if page == 0:
                # Payload errors including the BPB; corrected before FAT parsing.
                for at in (11, 35, 77): raw[at] ^= 1
                corrections.append({'physical_page': index, 'logical_page': page, 'bits': 3, 'kind': 'data'})
            if page == 1:
                # LBA and sequence metadata are inside the last BCH codeword.
                for at in (7*526+512, 7*526+516): raw[at] ^= 1
                corrections.append({'physical_page': index, 'logical_page': page, 'bits': 2, 'kind': 'metadata'})
            if page == 140:
                raw[513] ^= 1  # parity byte in first codeword
                corrections.append({'physical_page': index, 'logical_page': page, 'bits': 1, 'kind': 'parity'})
            out.write(raw)
        out.write(b'\xff'*PHYSICAL*2)
    expected = {'description': 'Synthetic NAND FTL/BCH/FAT32 test; contains no vehicle or case data',
                'logical_bytes': len(clean), 'physical_bytes': path.stat().st_size,
                'selected_pages': len(pages), 'duplicate_pages': 2, 'erased_pages': 2,
                'corrected_bits': 6, 'corrected_codewords': 3, 'injected_errors': corrections,
                'files': {k: {'bytes': len(v), 'sha256': hashlib.sha256(v).hexdigest()} for k, v in files.items()},
                'reference_sha256': hashlib.sha256(clean).hexdigest(),
                'physical_page_for_logical': {'0': physical[0], '1': physical[1], '140': physical[140]}}
    (directory/'expected.json').write_text(json.dumps(expected, indent=2)+'\n')
    return expected


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('output', type=Path)
    args = ap.parse_args()
    print(json.dumps(create(args.output), indent=2))
