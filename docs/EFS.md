# Native QNX EFS / F3S support

`feature/efs` starts at develop-4.1x, commit
497fa5100f5f5e96639b14fbe00ece9b385922b2. QNX4 and F2FS stay on separate branches.

A raw NOR image is represented as one EFS container filesystem. Its virtual
root has one folder per detected partition: `Partition_01_0x00004000`,
`Partition_02_0x00010000`, etc. Offsets in names are relative to the filesystem
start selected with `-o`; file data remains mapped to its exact physical image
bytes rather than extracted to temporary host files. Even a single partition
uses a partition folder for a consistent interface.

The parser is based on EfsWalker, efs_partitions and F3S boot validation in
abrignoni/qnxprobe at de0e352b466e2e165cf5dd38652b11515ccf58f4. Its MIT license
is in tsk/fs/efs_LICENSE.txt. F3S stat fields were checked against the qnxmount
format description. Both endian orders, relocated boot units, logical-unit
mapping, next/superseding extent chains, current files/directories, symlinks,
FIFOs, mode, UID/GID, mtime and ctime are supported. The format has no atime or
creation-time field in the parsed stat record; those are not invented.

EFS extents are variable-length byte ranges. TSK block addresses therefore
represent **bytes**, block size is 1, and physical attribute runs preserve
exact lengths, including transitions between noncontiguous extents. Driver
callbacks batch content reads/walks and block reads to avoid one image read
per byte. The custom callback dispatch is restricted to EFS, without marking
its ordinary files as compressed. Whole-container scanning is performed after
conventional probes and skipped if another filesystem is already identified;
explicit `-f efs` still scans the requested image region.

`blkls` exposes gaps inside EFS partitions and historical file data no live
file references, including deleted/superseded file extents. All extent-header
arrays and directory/system metadata remain allocated. Prefix, inter-partition
and trailing bytes outside recognized EFS partitions are reserved rather than
claimed as free EFS space. This is byte-accurate allocation accounting, not
reconstruction of deleted filenames. Corrupt live pointer chains, cycles and
out-of-range texts fail explicitly. An incomplete partition is not accepted.

Examples:

```
fsstat image.img
fls -r -p image.img
icat image.img INODE > extracted.bin
blkls image.img > unallocated.bin
fls -f efs -o 2048 disk.img
```

Regression tests use qnxprobe's independently generated LE/BE two-partition
fixtures and their known SHA256 values, plus efs-qnx.img.gz and efs-qnx.tar.gz.
The latter are an image created by QNX mkefs/devf-ram and a tar of its mounted
tree from NetherlandsForensicInstitute/qnxmount. Tests compare 37 payloads,
partition folder names/counts, four mixed-endian partitions with repeated names,
mode/mtime, current replacements, historical
carving positions, inode enumeration, prefix offsets, nonaligned image prefixes,
standalone partitions, invalid signatures and cyclic directory chains.
Linux also tests buffered public TSK reads across an extent boundary.
