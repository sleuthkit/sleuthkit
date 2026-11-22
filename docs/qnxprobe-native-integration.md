# QNXProbe native filesystem integration

This branch targets native TSK filesystem support, not a Python subprocess bridge.

## Verified baseline (TSK 4.15.0 fork)

- `tsk/fs/fs_open.c` registers NTFS, FAT, EXT, UFS, YAFFS2, HFS (conditional), ISO9660 and APFS for autodetection.
- `tsk/fs/Makefile.am` already compiles `yaffs.cpp`; do not add a duplicate YAFFS2 driver.
- The qnxprobe main branch documents QNX6, QNX4, QNX IFS, ETFS, EFS, SquashFS, JFFS2, UBI/UBIFS, YAFFS1/2, F2FS and other readers.
- Not appearing in the FS_OPENERS autodetection table does not prove the filesystem is unsupported by every TSK API; inspect type registration and readers separately.

## Implementation acceptance criteria (each filesystem)

1. Parse on-disk structures directly in native C/C++, with strict bounds checks and no write operations.
2. Register a distinct TSK filesystem type and explicit open routine; add autodetection only after false-positive testing.
3. Implement inode metadata, directory listing, file content, file size, and available timestamps.
4. Implement allocation reporting and unallocated block traversal **only** when the on-disk evidence supports it; otherwise mark unsupported rather than inventing allocation state.
5. Preserve physical source offsets, including NAND spare/OOB transformations, in a documented provenance map.
6. Add fixture tests for valid, truncated, corrupt, offset, and overlapping-signature images.
7. Verify CLI (`fsstat`, `fls`, `icat`, `istat`) and JNI/Autopsy interoperability.

## Suggested sequence

QNX6 -> QNX4 -> EFS -> ETFS -> QNX IFS -> SquashFS -> JFFS2 -> UBIFS/UBI -> F2FS -> YAFFS1.

## Release requirements

A tagged release must contain a Windows x64 executable archive, a Linux x64 executable archive, and Java bindings built against the same native revision. The workflow is provisional until successfully run and verified. Never label a release as supporting a filesystem until its native reader and fixture tests pass.
