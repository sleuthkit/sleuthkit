# FlashFX/VBF and Reliance Nitro: observed device profile

`feature/datalight-reliance` starts at develop-4.1x cac76b4. Its native
read-only FS container follows Gerd1986/qnxprobe's `ftl` branch at
dfa12f2231ef5900ade8fb61aefd6166357ebdcc, `datalight_reliance.py` (MIT).

## Inputs

* The same raw NAND layout as the Python reference: **4320 bytes per physical
  page**, 128 pages per erase unit; 10 prefix metadata bytes, eight interleaved
  512-byte data / 26-byte ECC chunks and 6 trailing spare bytes.
* An already reconstructed, 4096-byte-block logical Reliance image.

The raw allocation word at page offset +2 is retained and read. ECC/OOB is
removed from file contents by the same extraction used by qnxprobe; no ECC
correction is performed. A physically ordered dump from which OOB has already
been removed is NOT sufficient for this NAND mapping. Arbitrary NAND geometries,
Qualcomm stuff-byte processing, generic FlashFX NOR formats and classic
Reliance layouts are outside this observed Nitro 2.7.1 profile.

```
fsstat chip.dmp
fls -r -p chip.dmp
icat chip.dmp INODE > recovered.bin
fsstat -f reliance logical-reliance.bin
fls -f flashfx -o 16 prefixed-chip.img
```

Raw FlashFX serial groups are exposed as `FlashFX_N` folders. Discovered MAST
volumes appear below them as `Reliance_N_0xSTART` folders (START currently uses
decimal digits). Flat logical images expose Reliance volume folders directly.
No whole-image temporary extraction or Python subprocess is needed.

## Implemented interpretation

Valid DL_FS4.00 unit headers are grouped using the reference fields. Header
checksums and geometry are validated. Groups require at least two headers.
Allocation nibble 0x4 is mapped; higher unit sequence wins, with higher physical
page as the deterministic tie-break, just as in qnxprobe. No other status nibble
is guessed as a live mapping. MAST identifies 4096-byte-block volumes; newer
META transaction selects the directory and allocation roots.

Current IDIR/LDIR and IALC/LALC trees are traversed. Sixteen-byte filename
fragments, big-endian parent/object keys, class-1 packed file sizes and
millisecond timestamps, and class-0 ordered block extents follow the observed
reference decoder. Regular payloads are exposed with exact physical source-byte
runs excluding ECC/OOB, through both buffered TSK reads and file-walk callbacks.
Empty files, nested directories and multiple devices/volumes are supported.

Namespace file/directory type and modes are inferred using parent relations,
as in the reference. Mode defaults, UID/GID zero and link count are synthesized,
not claimed to be decoded original POSIX metadata. Empty directory distinctions,
symlinks, xattrs and other undocumented object classes are not established.
Unlike the recovery script's partial-file option, missing size records,
unmapped live extents or insufficient payload coverage fail to open instead of
creating placeholders or silently incomplete files. Cycles, bad counts, bad
pointers and invalid extent ranges fail closed. Reliance metadata CRC algorithms
are not provided by the reference; structural validation is not checksum proof.

## Allocation and evidence

`blkls` on raw input exposes payload bytes of **superseded status-0x4 physical
pages** proven to have lost the mapping selection. Other/unrecognized pages
remain conservatively allocated. OOB/ECC/header data is never synthesized as
unallocated filesystem content. The Reliance free-space bitmap is not decoded;
flat logical images therefore advertise no physical free-space map. Deleted-file
carving and lost mapping recovery are not implemented.

Filesystem addresses refer to physical source bytes for raw input
and logical source bytes for reconstructed input. The implementation is read-only.
The original device dump has not been retested here. Independent fixtures compare
decoded names, file bytes, metadata and FlashFX mappings with the pinned Python
reader, including sequence updates, offsets, serial groups and malformed cases.
