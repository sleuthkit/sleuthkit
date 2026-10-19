# NAND page-to-LBA reconstruction

`tools/flash/preprocess_ubi.py` now accepts an optional `mapping` object in a
schema-version-1 device profile. Profiles without it retain sequential cleanup.
The output can be any logical sector image (for example FAT32), despite the
historical UBI script name. This is a configurable page map, not FTL100 or a
universal proprietary NAND FTL decoder. It is not yet bundled into Autopsy.

## Processing order

1. Read a complete physical page; skip completely erased (all-FF) pages.
2. Decode each BCH codeword and concatenate the configured data ranges.
   Include the OOB mapping metadata in those ranges: it must survive cleanup.
3. Read LBA, sequence and signature from this **ECC-corrected canonical page**.
4. Validate signature, LBA alignment and logical image bounds.
5. Write the payload range to `LBA * sector_bytes` in a temporary logical image.
6. Resolve duplicates and missing pages, hash the complete logical output,
   then atomically commit the image. Write the existing JSON sidecar report.

Metadata fields must be covered by BCH operations. Mapping rejects every
uncorrectable page, including with `--uncorrectable keep`: an unreadable LBA
could conceal an unknown newest mapping. `--ecc off` remains an explicit
unverified mode and is reported as such. It cannot recover the provided fixture,
whose LBA metadata contains correctable errors.

The correction cache is bounded to 256 complete payload/parity pairs. Metadata
selection and correction statistics are still evaluated for each physical page.

## Mapping fields

See `config/flash_devices/synthetic-lba-bch-fat32.json` for a complete example.
All fields are required when `mapping` is present; unknown fields are rejected.

| Field | Meaning |
| --- | --- |
| `sector_bytes` | 512, 1024, 2048 or 4096 bytes |
| `logical_sectors` | Exact output geometry, currently capped at 1 TiB |
| `payload_range` | `[offset, length]` in the corrected canonical page |
| `lba_field`, `sequence_field` | `range` and explicit `little`/`big` byte order; widths 1, 2, 4 or 8 |
| `signature` | `range` and exact `hex` value in corrected metadata |
| `duplicates` | `highest_sequence`, `first` or `last` |
| `holes` | `fail` or `fill` |
| `fill_byte` | 0..255 for unmapped output sectors |

Payload and metadata ranges must not overlap. A payload contains whole sectors;
LBAs must align to the payload size, so partly overlapping mappings are rejected.
`highest_sequence` compares unsigned integers without wraparound. Equal sequence
and equal payload retain the first copy; conflicting equal-sequence payloads
abort instead of guessing. Multi-bank rules, bad-block markers, block-based LBN
maps, log-block merges, counter wraparound and vendor scrambling are not modeled.

The report's `lba_mapping.entries` records physical page/offset, LBA, sector
count, sequence, payload SHA256 and final selection for every non-erased page,
including discarded duplicates. `missing_ranges` contains `[start_lba, sectors]`.
Physical offsets refer to the original dump; extraction ranges are defined by
the hashed profile. All-FF skipped pages are counted separately.

## Synthetic fixture

```sh
python3 tests/nand_lba_fixture.py test-nand
python3 tools/flash/preprocess_ubi.py test-nand/synthetic-nand-ftl-ecc-fat32.bin \
  --profile config/flash_devices/synthetic-lba-bch-fat32.json \
  --output test-nand/reconstructed-fat32.img
python3 tests/nand_lba_regression.py --fixture test-nand --tools /path/to/tsk/bin
```

The deterministic volume is 34 MiB, FAT32 by cluster count, with 512-byte sectors,
two FATs, FSInfo and backup boot/FSInfo sectors. It contains `HELLO.TXT` and a
16,391-byte `PAYLOAD.BIN` crossing NAND page boundaries. FAT32 needs at least
65,525 data clusters; this is not a tiny FAT12 volume with a FAT32 label.

Each synthetic physical page has 4,096 payload bytes, 16 metadata bytes, eight
MSB-first BCH(m=13,t=8,poly=0x201B) codewords and eight A5 stuff bytes (4,224 bytes
total). The final codeword protects 512 payload bytes plus all 16 metadata bytes.
Canonical metadata: little-endian LBA, sequence, `LBA1`, reserved zero word.

The fixture shuffles all 8,704 logical pages, adds two stale valid-ECC duplicates
and two erased pages, and injects six bit errors in three codewords: three data,
two metadata and one parity error. The independent polynomial encoder does not
call the production correction routine. Full recovery must equal the reference
image byte-for-byte and native `fsstat`/`fls`/`icat` must detect FAT32 and recover
both known file hashes. Negative tests cover holes, out-of-bounds and misaligned
LBAs, equal-sequence conflicts, uncorrectable ECC, partial pages, duplicate
policies, fill policy and atomic preservation of an existing output on failure.

No private vehicle images are needed or included. The synthetic profile describes
only this fixture; it must not be used as a guessed real-device configuration.
