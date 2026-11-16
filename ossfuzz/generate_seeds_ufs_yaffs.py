#!/usr/bin/env python3
# Structured seed generator for the sleuthkit OSS-Fuzz fls targets that have
# no downloadable reference images: UFS1/UFS2 (fls_ffs_fuzzer) and YAFFS2
# (fls_yaffs_fuzzer).
#
# The images are minimal but structurally valid: every field checked by the
# libtsk parsers (tsk/fs/ffs.c, tsk/fs/yaffs.cpp) is populated from the actual
# on-disk layouts, so the fuzzers start inside the format instead of having to
# mutate their way past the magic checks.
#
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import os
import struct
import zipfile

UFS1_SBOFF = 8192       # tsk/fs/tsk_ffs.h
UFS2_SBOFF = 65536      # tsk/fs/tsk_ffs.h
UFS1_FS_MAGIC = 0x011954
UFS2_FS_MAGIC = 0x19540119
UFS_CG_MAGIC = 0x090255

FFS_ROOTINO = 2
FFS_IN_IFDIR = 0x4000
FFS_IN_IFREG = 0x8000

# Geometry shared by both UFS variants (one cylinder group).
FRAG_SIZE = 4096        # == block size for this minimal layout
TOTAL_FRAGS = 96        # image is 96 * 4096 bytes
CG_NUM = 1
CG_INODE_NUM = 8        # inodes per cylinder group
SB_OFF, GD_OFF, INO_OFF, DAT_OFF = 2, 4, 8, 12   # frag offsets inside the CG

CG_ADDR = GD_OFF * FRAG_SIZE                     # cgtod_lcl(), cg 0
INO_ADDR = INO_OFF * FRAG_SIZE                   # cgimin_lcl(), cg 0
DATA_ADDR = DAT_OFF * FRAG_SIZE                  # cgdmin_lcl(), cg 0

DIR_INO, FILE_INO = 2, 3
DIR_FRAG, FILE_FRAG = 12, 13
FILE_CONTENT = b"hello from the sleuthkit OSS-Fuzz seed corpus\n" + b"A" * 17


def _dirsiz(namelen):
    """FFS_DIRSIZ_lcl(): on-disk length of a directory entry."""
    return (namelen + 8 + 3) & ~3


def _root_dir_data():
    """FFS1/FFS2 directory block: '.', '..' and one regular file entry."""
    entries = [
        (DIR_INO, 4, "."),      # 4 == FFS_DT_DIR
        (DIR_INO, 4, ".."),
        (FILE_INO, 8, "hello.txt"),   # 8 == FFS_DT_REG
    ]
    buf = bytearray(FRAG_SIZE)
    off = 0
    for i, (ino, dtype, name) in enumerate(entries):
        namelen = len(name)
        minlen = _dirsiz(namelen)
        # last entry of the block absorbs the remaining space
        reclen = minlen if i < len(entries) - 1 else len(buf) - off
        buf[off:off + 4] = struct.pack("<I", ino)
        buf[off + 4:off + 6] = struct.pack("<H", reclen)
        buf[off + 6] = dtype
        buf[off + 7] = namelen
        buf[off + 8:off + 8 + namelen] = name.encode()
        off += reclen
    return bytes(buf)


def _cyl_group():
    """ffs_cgd: shared by UFS1/UFS2 for everything libtsk reads."""
    cg = bytearray(FRAG_SIZE)
    cg[4:8] = struct.pack("<I", UFS_CG_MAGIC)     # magic
    cg[12:16] = struct.pack("<i", 0)              # cg_cgx
    cg[16:18] = struct.pack("<H", 1)              # cyl_num
    cg[18:20] = struct.pack("<H", CG_INODE_NUM)   # ino_num
    cg[20:24] = struct.pack("<i", TOTAL_FRAGS)    # frag_num
    cg[24:28] = struct.pack("<i", 2)              # cs.dir_num
    cg[28:32] = struct.pack("<i", TOTAL_FRAGS - 14)  # cs.blk_free
    cg[32:36] = struct.pack("<i", CG_INODE_NUM - 2)  # cs.ino_free
    cg[36:40] = struct.pack("<i", TOTAL_FRAGS - 14)  # cs.frag_free
    cg[92:96] = struct.pack("<i", 512)            # cg_iusedoff (<= bsize)
    cg[96:100] = struct.pack("<i", 1024)          # cg_freeoff (<= bsize)
    # inode-used bitmap at +512: inodes 0..7 all allocated
    cg[512:513] = b"\xff"
    # fragment-free bitmap at +1024: frags 0..13 in use, the rest free
    cg[1024:1026] = b"\x00\xc0"                   # bits 14+ set == free
    cg[1026:1026 + 12] = b"\xff" * 12
    return bytes(cg)


def ufs1_image():
    """Minimal UFS1 image: superblock at 8192, 128-byte inodes."""
    ino = bytearray(8 * 128)

    def put(idx, mode, size, frag):
        base = idx * 128
        ino[base:base + 2] = struct.pack("<H", mode)
        ino[base + 2:base + 4] = struct.pack("<h", 3)          # di_nlink
        ino[base + 8:base + 16] = struct.pack("<Q", size)      # di_size (u64)
        ino[base + 40:base + 44] = struct.pack("<I", frag)     # di_db[0]

    put(DIR_INO, FFS_IN_IFDIR | 0o755, FRAG_SIZE, DIR_FRAG)
    put(FILE_INO, FFS_IN_IFREG | 0o644, len(FILE_CONTENT), FILE_FRAG)

    sb = bytearray(1536)
    sb[8:12] = struct.pack("<i", SB_OFF)               # sb_off
    sb[12:16] = struct.pack("<i", GD_OFF)              # gd_off
    sb[16:20] = struct.pack("<i", INO_OFF)             # ino_off
    sb[20:24] = struct.pack("<i", DAT_OFF)             # dat_off
    sb[24:28] = struct.pack("<i", 0)                   # cg_delta
    sb[28:32] = struct.pack("<i", 0)                   # cg_cyc_mask
    sb[36:40] = struct.pack("<i", TOTAL_FRAGS)         # frag_num (total)
    sb[40:44] = struct.pack("<i", TOTAL_FRAGS - 14)    # data_frag_num
    sb[44:48] = struct.pack("<i", CG_NUM)              # cg_num
    sb[48:52] = struct.pack("<i", FRAG_SIZE)           # bsize_b
    sb[52:56] = struct.pack("<i", FRAG_SIZE)           # fsize_b
    sb[56:60] = struct.pack("<i", 1)                   # bsize_frag
    sb[96:100] = struct.pack("<i", 0)                  # fs_fragshift
    sb[120:124] = struct.pack("<i", FRAG_SIZE // 128)  # fs_inopb
    sb[144:152] = b"\x11" * 8                          # fs_id
    sb[152:156] = struct.pack("<i", 1)                 # cg_saddr
    sb[156:160] = struct.pack("<i", FRAG_SIZE)         # cg_ssize_b
    sb[160:164] = struct.pack("<i", FRAG_SIZE)         # fs_cgsize
    sb[176:180] = struct.pack("<i", 1)                 # fs_ncyl
    sb[180:184] = struct.pack("<i", 1)                 # fs_cpg
    sb[184:188] = struct.pack("<i", CG_INODE_NUM)      # cg_inode_num
    sb[188:192] = struct.pack("<i", TOTAL_FRAGS)       # cg_frag_num
    sb[209] = 1                                        # fs_clean
    sb[1372:1376] = struct.pack("<I", UFS1_FS_MAGIC)   # magic

    img = bytearray(TOTAL_FRAGS * FRAG_SIZE)
    img[CG_ADDR:CG_ADDR + FRAG_SIZE] = _cyl_group()
    img[INO_ADDR:INO_ADDR + 8 * 128] = bytes(ino)
    img[DATA_ADDR:DATA_ADDR + FRAG_SIZE] = _root_dir_data()
    img[FILE_FRAG * FRAG_SIZE:(FILE_FRAG + 1) * FRAG_SIZE] = (
        FILE_CONTENT.ljust(FRAG_SIZE, b"\x00"))
    img[UFS1_SBOFF:UFS1_SBOFF + 1536] = sb
    return bytes(img)


def ufs2_image():
    """Minimal UFS2 image: superblock at 65536, 256-byte inodes, u64 addrs."""
    ino = bytearray(8 * 256)

    def put(idx, mode, size, frag):
        base = idx * 256
        ino[base:base + 2] = struct.pack("<H", mode)
        ino[base + 2:base + 4] = struct.pack("<h", 3)            # di_nlink
        ino[base + 12:base + 16] = struct.pack("<I", FRAG_SIZE)  # di_blksize
        ino[base + 16:base + 24] = struct.pack("<Q", size)       # di_size
        ino[base + 112:base + 120] = struct.pack("<Q", frag)     # di_db[0]

    put(DIR_INO, FFS_IN_IFDIR | 0o755, FRAG_SIZE, DIR_FRAG)
    put(FILE_INO, FFS_IN_IFREG | 0o644, len(FILE_CONTENT), FILE_FRAG)

    sb = bytearray(1536)
    sb[8:12] = struct.pack("<i", SB_OFF)
    sb[12:16] = struct.pack("<i", GD_OFF)
    sb[16:20] = struct.pack("<i", INO_OFF)
    sb[20:24] = struct.pack("<i", DAT_OFF)
    sb[44:48] = struct.pack("<i", CG_NUM)
    sb[48:52] = struct.pack("<i", FRAG_SIZE)            # bsize_b
    sb[52:56] = struct.pack("<i", FRAG_SIZE)            # fsize_b
    sb[56:60] = struct.pack("<i", 1)                    # bsize_frag
    sb[96:100] = struct.pack("<i", 0)                   # fs_fragshift
    sb[120:124] = struct.pack("<i", FRAG_SIZE // 256)   # fs_inopb
    sb[156:160] = struct.pack("<i", FRAG_SIZE)          # cg_ssize_b
    sb[160:164] = struct.pack("<i", FRAG_SIZE)          # fs_cgsize
    sb[184:188] = struct.pack("<i", CG_INODE_NUM)       # cg_inode_num
    sb[188:192] = struct.pack("<i", TOTAL_FRAGS)        # cg_frag_num
    sb[209] = 1                                         # fs_clean
    sb[1080:1088] = struct.pack("<q", TOTAL_FRAGS)      # frag_num (s64)
    sb[1088:1096] = struct.pack("<q", TOTAL_FRAGS)      # blk_num (s64)
    sb[1372:1376] = struct.pack("<I", UFS2_FS_MAGIC)

    img = bytearray(TOTAL_FRAGS * FRAG_SIZE)
    img[CG_ADDR:CG_ADDR + FRAG_SIZE] = _cyl_group()
    img[INO_ADDR:INO_ADDR + 8 * 256] = bytes(ino)
    img[DATA_ADDR:DATA_ADDR + FRAG_SIZE] = _root_dir_data()
    img[FILE_FRAG * FRAG_SIZE:(FILE_FRAG + 1) * FRAG_SIZE] = (
        FILE_CONTENT.ljust(FRAG_SIZE, b"\x00"))
    img[UFS2_SBOFF:UFS2_SBOFF + 1536] = sb
    return bytes(img)


# ---------------------------------------------------------------------------
# YAFFS2
# ---------------------------------------------------------------------------

YAFFS_PAGE_SIZE = 2048   # YAFFS_DEFAULT_PAGE_SIZE (tsk/fs/tsk_yaffs.h)
YAFFS_SPARE_SIZE = 64    # YAFFS_DEFAULT_SPARE_SIZE
YAFFS_CHUNKS_PER_BLOCK = 64
YAFFS_SPARE_SEQ_OFF = 0  # offsets the spare-format auto-detector tries first
YAFFS_SPARE_OBJ_OFF = 4
YAFFS_SPARE_CHUNK_OFF = 8
YAFFS_TYPE_FILE = 1      # object types as interpreted by tsk/fs/yaffs.cpp
YAFFS_TYPE_DIR = 2
YAFFS_IS_HEADER = 0x80000000
YAFFS_LOWEST_SEQ = 0x00001000

CHUNK = YAFFS_PAGE_SIZE + YAFFS_SPARE_SIZE


def _yaffs_header(obj_type, parent_id, name, file_size=0, mode=0o755):
    """YaffsHeader as parsed by tsk/fs/yaffs.cpp (in-page object header)."""
    hdr = bytearray(YAFFS_PAGE_SIZE)
    hdr[0:4] = struct.pack("<I", obj_type)
    hdr[4:8] = struct.pack("<I", parent_id)
    hdr[8:8 + len(name)] = name.encode()
    hdr[264:268] = struct.pack("<I", mode)          # file_mode
    hdr[276:280] = struct.pack("<I", 1700000000)    # atime
    hdr[280:284] = struct.pack("<I", 1700000000)    # mtime
    hdr[284:288] = struct.pack("<I", 1700000000)    # ctime
    hdr[288:292] = struct.pack("<I", file_size)     # file_size
    return bytes(hdr)


def _yaffs_spare(seq, obj_id, chunk_id):
    spr = bytearray(YAFFS_SPARE_SIZE)
    spr[YAFFS_SPARE_SEQ_OFF:YAFFS_SPARE_SEQ_OFF + 4] = struct.pack("<I", seq)
    spr[YAFFS_SPARE_OBJ_OFF:YAFFS_SPARE_OBJ_OFF + 4] = struct.pack("<I", obj_id)
    spr[YAFFS_SPARE_CHUNK_OFF:YAFFS_SPARE_CHUNK_OFF + 4] = struct.pack(
        "<I", chunk_id)
    return bytes(spr)


def yaffs2_image():
    """Minimal YAFFS2 raw dump (untagged): [page][spare] chunk pairs.

    Two NAND blocks so the spare-format auto-detection sees consistent tag
    layouts; sequence numbers increase monotonically and stay inside
    [YAFFS_LOWEST_SEQUENCE_NUMBER, YAFFS_HIGHEST_SEQUENCE_NUMBER].
    """
    chunks_written = [0]
    seq = [YAFFS_LOWEST_SEQ]

    def header_chunk(obj_type, obj_id, parent_id, name, file_size=0):
        data = _yaffs_header(obj_type, parent_id, name, file_size)
        spr = _yaffs_spare(seq[0], (obj_type << 28) | obj_id,
                           YAFFS_IS_HEADER | parent_id)
        seq[0] += 1
        chunks_written[0] += 1
        return data + spr

    def data_chunk(obj_id, chunk_id, payload):
        data = payload.ljust(YAFFS_PAGE_SIZE, b"\x00")
        spr = _yaffs_spare(seq[0], obj_id, chunk_id)
        seq[0] += 1
        chunks_written[0] += 1
        return data + spr

    # object ids: 1 = root dir, 2 = regular file in root, 3 = subdirectory,
    # 4 = regular file in the subdirectory
    blk0 = [
        header_chunk(YAFFS_TYPE_DIR, 1, 1, "/"),
        header_chunk(YAFFS_TYPE_FILE, 2, 1, "hello.txt", len(FILE_CONTENT)),
        data_chunk(2, 1, FILE_CONTENT),
        header_chunk(YAFFS_TYPE_DIR, 3, 1, "subdir"),
    ]
    blk0 += [b"\x00" * CHUNK] * (YAFFS_CHUNKS_PER_BLOCK - len(blk0))

    blk1 = [
        header_chunk(YAFFS_TYPE_FILE, 4, 3, "subfile.txt", 32),
        data_chunk(4, 1, b"nested payload"),
    ]
    blk1 += [b"\x00" * CHUNK] * (YAFFS_CHUNKS_PER_BLOCK - len(blk1))

    return b"".join(blk0) + b"".join(blk1)


def main():
    ap = argparse.ArgumentParser(
        description="Generate structurally-valid UFS1/UFS2/YAFFS2 seed images")
    ap.add_argument("--outdir", required=True)
    args = ap.parse_args()
    os.makedirs(args.outdir, exist_ok=True)

    seeds = {
        "ufs1.img": ufs1_image(),
        "ufs2.img": ufs2_image(),
        "yaffs2.img": yaffs2_image(),
    }
    for name, blob in seeds.items():
        with open(os.path.join(args.outdir, name), "wb") as fh:
            fh.write(blob)

    # package per fuzz target, matching the $OUT naming convention
    def zip_seed(target, names):
        zpath = os.path.join(args.outdir, target + "_seed_corpus.zip")
        with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as zf:
            for name in names:
                zf.write(os.path.join(args.outdir, name), arcname=name)

    zip_seed("fls_ffs_fuzzer", ["ufs1.img", "ufs2.img"])
    zip_seed("fls_yaffs_fuzzer", ["yaffs2.img"])


if __name__ == "__main__":
    main()


