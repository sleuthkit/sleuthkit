# QNX ETFS (read-only)

ETFS images are detected automatically, or selected with `-f etfs`:

```
fsstat flash.etfs
fls -r -p flash.etfs
istat flash.etfs 7
icat flash.etfs 7 > extracted.bin
blkls flash.etfs > unallocated.bin
```

`-o` and `-b` retain the usual TSK sector-offset meaning. Inode numbers are
ETFS file IDs plus one (root inode 1). Physical block/run addresses are bytes
relative to the filesystem start; this retains exact provenance despite the
16 transaction bytes between data pages. Java bindings include `TSK_FS_TYPE_ETFS`.

## Supported input

Little-endian ETFS transaction streams: each 512, 1024, 2048, 4096, 8192 or
16384-byte data page followed immediately by its 16-byte ETFS transaction.
Geometry is accepted only with a directory root and at least three reserved
file-table names at the fixed IDs. Images must contain complete records.
Both NFI real test images use 1024+16 records.

The transaction is `<fid:u32, cluster:u32, nclusters:u16, tacode:u8,
dacode:u8, sequence:u32>`. As in QNXProbe, only transaction-area status 0/1
(OK/ECC) participates in reconstruction. Highest sequence wins; equal sequence
uses the last physical page. Each record supplies its own page/cluster mapping.
This reader does not perform NAND ECC correction. Extra controller OOB, ECC
or stuffing requires device-specific preprocessing that **preserves the ETFS
transaction**; a data-only image with every spare byte removed cannot be replayed.

## Reconstructed evidence

Live files, directories, symlinks and special-file metadata; long-name extension
records; UID/GID, permissions and access/modification/change timestamps. Missing
parent chains and cycles are attached below `$ETFS_Orphans` (collision-safe).
Missing clusters, including missing final clusters, read as `0xff` placeholders;
these are not recovered evidence bytes. Size is taken from the active file table.
Obsolete, invalid and unreferenced physical pages remain accessible through
`blkls`; deleted-file name recovery is not claimed. Active page data and its
transaction are allocated; transaction bytes and file-table pages are metadata.

## Validation and provenance

The C++ reader is compared against independently specified synthetic records at
all six geometries and against Gerd1986/qnxprobe's EtfsWalker. Both committed
NetherlandsForensicInstitute/qnxmount ETFS images are compared to their QNX-made
TAR archives for names, modes, owners, modification times, symlinks and file bytes.
TSK integration additionally checks automatic/explicit opening, recursive `fls`,
`icat`, buffered `tsk_fs_file_read`, nonzero offsets, `istat`, `ils`, and historical
bytes in `blkls`. Reference revisions are pinned in the ETFS workflow.

See `tsk/fs/etfs_LICENSE.txt` for the MIT/Apache-2.0 upstream notices.
