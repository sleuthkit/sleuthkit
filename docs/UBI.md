# Native UBI / UBIFS reader

Raw NAND cleanup is available separately through `tools/flash/preprocess_ubi.py`;
see [UBI_PREPROCESSOR.md](UBI_PREPROCESSOR.md) and `config/flash_devices/`.

Branch: `feature/ubi-ubifs`, based on `develop-4.1x` at cac76b4.

Input is a raw, page-data-only UBI image: no OOB, ECC, interleaving or stuff
bytes. A flat `.ubifs` image is also supported. Reads never modify the image.

```
fsstat flash.ubi
fls -r -p flash.ubi
icat flash.ubi INODE > output.bin
fsstat -f ubifs volume.ubifs
fls -o 2048 flash-with-prefix.img
```

Each UBI volume is a `Volume_ID_NAME` directory. UBIFS contents appear inside;
other volume types (including SquashFS, kernels and device trees) are retained
as `volume.bin`, not falsely decoded as UBIFS. Empty unmapped volumes are not
enumerated. Unknown images are not searched at arbitrary offsets: use `-o`.

Implemented: EC/VID/table CRCs, PEB geometry, dynamic/static volume mappings,
sequence-number selection and CRC-validated copy fallback, redundant layout
tables and UBIFS masters, simple-key on-flash index, journal CS/REF replay,
truncation and deletion records, incomplete-final-group exclusion, directory
trees, hardlinks, symlinks, modes/owners/timestamps and nanoseconds, sparse files,
uncompressed, LZO1X and raw-deflate/zlib data. Content is decompressed on demand
through both TSK buffered-read and file-walk interfaces, without temporary
extraction or loading whole files into memory.

Physical allocation is deliberately conservative. `blkls` exposes payloads
of valid free/superseded PEBs; current mapped PEBs and unknown/corrupt EC PEBs
are retained as allocated. EC/VID header areas remain metadata. This is NOT
UBIFS LPT free-space accounting. Flat UBIFS has no proven physical free-space
map, so its bytes remain allocated. Logical/compressed file content cannot
be described by contiguous physical block runs: address-only file walks fail
explicitly instead of reporting invented locations.

Limits: Zstd compression, fscrypt, authenticated volumes, OOB/ECC/stuff-byte
processing and deleted-file carving are not supported. Bad CRCs are rejected,
not repaired. Incomplete or structurally inconsistent volumes fail to open;
there is no silent carving fallback. Encrypted/authenticated superblocks fail
to open; encrypted file reads fail. Zstd file reads fail with an explicit error.
Optional xattrs are not exposed. Journal corruption fails closed.

Reader logic adapted from abrignoni/qnxprobe, pinned at
`de0e352b466e2e165cf5dd38652b11515ccf58f4` (MIT, ubi_LICENSE.txt), with format
cross-checks against Linux `drivers/mtd/ubi/ubi-media.h`, `attach.c`,
`fs/ubifs/ubifs-media.h`, `key.h`, and `replay.c`.

`tests/ubi_regression.py` checks kernel-built source-tree manifests for five
fixtures (410 hashes each), raw static volumes, offsets, buffered reads,
hardlinks, CRC failures, UBI bad-copy fallback, conservative free accounting
and a synthetic journal replay checked by the independent Python walker.
