# Native read-only F2FS support

Branch: `feature/f2fs`. The driver is linked into libtsk on Unix and Windows,
with automatic detection and explicit `-f f2fs` selection. The Java filesystem
type enum is updated for JNI/Autopsy consumers.

Implemented: 4 KiB and 16 KiB blocks; redundant superblocks; checkpoint pack
selection with CRC validation and matching header/trailer versions; NAT copy
selection and NAT journal overrides; inline data and inline directories;
regular directory blocks; direct, indirect and double-indirect node mapping;
sparse holes; Unix metadata and timestamps; SIT copy selection and SIT journal
overrides for allocated/free block walking (`blkls`). Reads respect the
filesystem offset, including partition images opened with `-o`.

The reader uses the last valid checkpoint. It does not replay fsync roll-forward
nodes from an unclean shutdown. Deleted inode/dentry reconstruction, decryption,
compressed content, multiple devices and filesystem journal listing are not
implemented. Encrypted directories and encrypted/compressed file content fail
explicitly. Free blocks remain available for carving; the driver does not infer
file ownership from residual bytes.

Examples:

```
fsstat image.img
fls -r -p image.img
icat image.img 7 > extracted.bin
blkls image.img > unallocated.bin
fls -f f2fs -o 2048 disk.img
```

The independent reference implementation is `abrignoni/qnxprobe` at commit
`de0e352b466e2e165cf5dd38652b11515ccf58f4`, primarily `F2fsWalker` in
`qnxprobe.py`. Attribution and its MIT license are in
`tsk/fs/f2fs_LICENSE.txt`. The native regression suite uses that pinned
repository's fixtures and source-file/dump.f2fs SHA256 oracles. It tests file
contents, sparse files, directory traversal, block accounting, deleted-content
markers, partition offsets, redundant-superblock recovery, checkpoint fallback
and rejected truncated/invalid images. Windows project integration is covered
by the existing Windows TSK/JNI builds.
