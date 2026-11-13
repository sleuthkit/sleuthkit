#!/usr/bin/env python3
# Structured seed generator for the sleuthkit auto-support fuzz target
# (ossfuzz/auto_support_fuzzer.cc): minimal valid ext2 and FAT16 images plus
# the encryption-signature headers probed by detectDiskEncryption, so the
# auto-detection sweep starts inside real formats.
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

SECTOR = 512
BSIZE = 1024


def ext2():
    """Minimal ext2: 64 blocks of 1024, 16 inodes, one root with one file."""
    img = bytearray(64 * BSIZE)

    sb = 1024
    img[sb + 0:sb + 4] = struct.pack("<I", 16)          # s_inodes_count
    img[sb + 4:sb + 8] = struct.pack("<I", 64)          # s_blocks_count
    img[sb + 8:sb + 12] = struct.pack("<I", 14)         # s_r_blocks_count
    img[sb + 12:sb + 16] = struct.pack("<I", 12)        # s_free_blocks_count
    img[sb + 16:sb + 20] = struct.pack("<I", 13)        # s_free_inodes_count
    img[sb + 20:sb + 24] = struct.pack("<I", 1)         # s_first_data_block
    img[sb + 24:sb + 28] = struct.pack("<I", 0)         # s_log_block_size
    img[sb + 28:sb + 32] = struct.pack("<i", -3600)     # s_log_cluster_size
    img[sb + 32:sb + 36] = struct.pack("<I", 64)        # s_blocks_per_group
    img[sb + 36:sb + 40] = struct.pack("<I", 0)         # s_clusters_per_group
    img[sb + 40:sb + 44] = struct.pack("<I", 16)        # s_inodes_per_group
    img[sb + 44:sb + 48] = struct.pack("<I", 1700000000)  # s_mtime
    img[sb + 48:sb + 52] = struct.pack("<I", 1700000000)  # s_wtime
    img[sb + 54:sb + 56] = struct.pack("<H", 0xEF53)    # s_magic
    img[sb + 76:sb + 78] = struct.pack("<H", 128)       # s_inode_size
    img[sb + 88:sb + 89] = b"\x01"                      # s_filesystem_state

    gd = 2 * BSIZE
    img[gd:gd + 4] = struct.pack("<I", 3)      # bg_block_bitmap
    img[gd + 4:gd + 8] = struct.pack("<I", 4)  # bg_inode_bitmap
    img[gd + 8:gd + 12] = struct.pack("<I", 5)  # bg_inode_table
    img[gd + 12:gd + 14] = struct.pack("<H", 13)  # bg_free_blocks_count
    img[gd + 14:gd + 16] = struct.pack("<H", 13)  # bg_free_inodes_count
    img[gd + 16:gd + 18] = struct.pack("<H", 1)   # bg_used_dirs_count

    img[3 * BSIZE:3 * BSIZE + 8] = b"\xfe\x07"      # block bitmap
    img[4 * BSIZE:4 * BSIZE + 8] = b"\xfe\x00"      # inode bitmap

    def inode(idx, mode, size, blk):
        base = 5 * BSIZE + (idx - 1) * 128
        img[base:base + 2] = struct.pack("<H", mode)
        img[base + 2:base + 4] = struct.pack("<H", 2)      # i_uid pad
        img[base + 4:base + 8] = struct.pack("<I", size)
        img[base + 24:base + 26] = struct.pack("<H", 3)    # links
        img[base + 28:base + 30] = struct.pack("<H", 512)  # blocks/512
        img[base + 40:base + 44] = struct.pack("<I", blk)  # i_block[0]

    inode(1, 0x8000, 0, 0)                    # lost+found placeholder
    inode(2, 0x41ED, 1024, 7)                 # root dir
    inode(3, 0x81A4, len(b"seeded content\n"), 8)

    d = 7 * BSIZE
    img[d:d + 12] = struct.pack("<IHBB", 2, 12, 1, 2) + b"."
    img[d + 12:d + 24] = struct.pack("<IHBB", 2, 12, 1, 2) + b".."
    img[d + 24:d + 36] = struct.pack("<IHBB", 3, 12, 6, 1) + b"hi.txt"

    img[8 * BSIZE:8 * BSIZE + 14] = b"seeded content\n"
    return bytes(img)


def fat16():
    """Minimal FAT16: 1024 sectors of 512 bytes, one file in the root dir."""
    img = bytearray(1024 * SECTOR)
    bpb = 0
    img[bpb:bpb + 3] = b"\xeb\x3c\x90"
    img[bpb + 3:bpb + 11] = b"TSKFUZZ "
    img[bpb + 11:bpb + 13] = struct.pack("<H", 512)   # bytes/sector
    img[bpb + 13] = 4                                 # sectors/cluster
    img[bpb + 14:bpb + 16] = struct.pack("<H", 1)     # reserved sectors
    img[bpb + 16] = 2                                 # fat count
    img[bpb + 17:bpb + 19] = struct.pack("<H", 16)    # root entries
    img[bpb + 19:bpb + 21] = struct.pack("<H", 1024)  # total sectors 16
    img[bpb + 21] = 0xF8                              # media
    img[bpb + 22:bpb + 24] = struct.pack("<H", 2)     # sectors per fat
    img[bpb + 24:bpb + 26] = struct.pack("<H", 32)    # sectors per track
    img[bpb + 26:bpb + 28] = struct.pack("<H", 8)     # heads
    img[bpb + 28:bpb + 32] = struct.pack("<I", 0)     # hidden sectors
    img[bpb + 32:bpb + 36] = struct.pack("<I", 0)     # total sectors 32
    img[bpb + 36] = 0x80                              # drive number
    img[bpb + 38] = 0x29                              # ext boot signature
    img[bpb + 39:bpb + 43] = b"1234"                  # volume id
    img[bpb + 43:bpb + 54] = b"SEED       "           # volume label
    img[bpb + 54:bpb + 62] = b"FAT16   "              # fs type

    fat = 1 * SECTOR
    img[fat:fat + 4] = b"\xf8\xff\xff\xff"            # cluster 2 = EOC
    img[(fat + 512):(fat + 512) + 4] = b"\xf8\xff\xff\xff"  # FAT2 copy

    rd = 5 * SECTOR
    entry = b"HI" + b" " * 6 + b"TXT" + bytes([0x20]) + b"\x00" * 10
    entry += struct.pack("<HH", 0, 0) + struct.pack("<HH", 0, 0)
    entry += struct.pack("<H", 2) + struct.pack("<I", 14)
    img[rd:rd + 32] = entry

    img[6 * SECTOR:6 * SECTOR + 14] = b"seeded content\n"
    img[510:512] = b"\x55\xaa"
    return bytes(img)


def signature_image(sig, offset, pad=512):
    img = bytearray(max(offset + len(sig), pad) + SECTOR)
    img[offset:offset + len(sig)] = sig
    return bytes(img)


SEEDS = {
    "ext2.img": ext2(),
    "fat16.img": fat16(),
    "luks.img": signature_image(b"LUKS\xba\xbe", 0),
    "bitlocker.img": signature_image(b"-FVE-FS-", 3),
    "filevault.img": signature_image(b"encrdsa", 0),
    "checkpoint.img": signature_image(b"Protect", 80),
    "safeboot.img": signature_image(b"SafeBoot", 0),
    "guardian.img": signature_image(b"PCGM", 0),
    "sophos.img": signature_image(b"SGM400", 110),
    "winmagic.img": signature_image(b"WMSD", 236),
    "pgp.img": signature_image(b"\xeb\x48\x90PGPGUARD", 0),
}


def main():
    ap = argparse.ArgumentParser(
        description="Generate auto-support seeds (ext2/FAT16/encryption)")
    ap.add_argument("--outdir", required=True)
    args = ap.parse_args()
    os.makedirs(args.outdir, exist_ok=True)

    for name, blob in SEEDS.items():
        with open(os.path.join(args.outdir, name), "wb") as fh:
            fh.write(blob)

    zpath = os.path.join(args.outdir, "auto_support_fuzzer_seed_corpus.zip")
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as zf:
        for name in SEEDS:
            zf.write(os.path.join(args.outdir, name), arcname=name)


if __name__ == "__main__":
    main()

