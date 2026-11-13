#!/usr/bin/env python3
# Structured seed generator for the sleuthkit img-vs fuzz target
# (ossfuzz/img_vs_fuzzer.cc): volume-system headers and the encryption
# signature headers probed by tsk/util/detect_encryption.c.
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


def mbr_dos():
    """Classic DOS MBR with a FAT32 and a FreeBSD slice (BSD priority path)."""
    img = bytearray(SECTOR)
    img[446:462] = bytes([0x00, 0x01, 0x00, 0x00, 0x0B, 0xFE, 0x7F, 0x0C]) + \
        struct.pack("<II", 1, 0x8000)
    img[462:478] = bytes([0x00, 0x40, 0x06, 0x00, 0xA5, 0xFE, 0x7F, 0x0C]) + \
        struct.pack("<II", 64, 0x400)
    img[510:512] = b"\x55\xaa"
    return bytes(img)


def bsd_label():
    """DOS slice + BSD disklabel in sector 1 (bsd_dlabel32 layout)."""
    img = bytearray(2 * SECTOR)
    img[446:462] = bytes([0x00, 0x01, 0x00, 0x00, 0xA5, 0xFE, 0x7F, 0x0C]) + \
        struct.pack("<II", 0, 0x800)
    img[510:512] = b"\x55\xaa"

    lbl = bytearray(SECTOR)
    lbl[0:4] = struct.pack("<I", 0x82564557)         # magic
    lbl[40:44] = struct.pack("<I", SECTOR)           # sec_size
    lbl[44:48] = struct.pack("<I", 63)               # sec_per_tr
    lbl[48:52] = struct.pack("<I", 16)               # tr_per_cyl
    lbl[52:56] = struct.pack("<I", 16)               # cyl_per_unit
    lbl[56:60] = struct.pack("<I", 1008)             # sec_per_cyl
    lbl[60:64] = struct.pack("<I", 258048)           # sec_per_unit
    lbl[132:136] = struct.pack("<I", 0x82564557)     # magic2
    lbl[138:140] = struct.pack("<H", 2)              # num_parts
    # partition a: 4.2BSD FFS spanning sectors 16..1024
    off = 148
    lbl[off:off + 4] = struct.pack("<I", 1008)       # size_sec
    lbl[off + 4:off + 8] = struct.pack("<I", 16)     # start_sec
    lbl[off + 8:off + 10] = struct.pack("<H", 1024)  # frag_size
    lbl[off + 10] = 7                                # fstype: 4.2BSD
    lbl[off + 11] = 8                                # frag_per_block
    lbl[off + 12:off + 14] = struct.pack("<H", 8)    # cyl_per_grp
    # partition c: whole disk
    lbl[off + 12:off + 24] = struct.pack("<IIHBH", 0x400, 0, 512, 8, 8)
    img[SECTOR:2 * SECTOR] = lbl
    return bytes(img)


def gpt():
    """GPT with protective MBR: primary header at LBA1, entries at LBA2."""
    img = bytearray(4 * SECTOR)
    img[446:462] = bytes([0x00, 0x00, 0x02, 0x00, 0xEE, 0xFF, 0xFF, 0xFF]) + \
        struct.pack("<II", 1, 0x7FF)
    img[510:512] = b"\x55\xaa"
    hdr = bytearray(SECTOR)
    hdr[0:8] = b"EFI PART"
    hdr[8:12] = struct.pack("<I", 0x00010000)        # revision 1.0
    hdr[12:16] = struct.pack("<I", 92)               # header size
    hdr[24:32] = struct.pack("<Q", 1)                # current LBA
    hdr[32:40] = struct.pack("<Q", 3)                # backup LBA
    hdr[40:48] = struct.pack("<Q", 2)                # first usable
    hdr[48:56] = struct.pack("<Q", 2)                # last usable
    hdr[56:72] = bytes(range(16))                    # disk guid
    hdr[72:80] = struct.pack("<Q", 2)                # part entry LBA
    hdr[80:84] = struct.pack("<I", 16)               # num entries
    hdr[84:88] = struct.pack("<I", 128)              # entry size
    img[SECTOR:2 * SECTOR] = hdr
    ent = bytearray(SECTOR)
    ent[0:8] = b"\x0c" + b"\x00" * 7                 # basic data partition guid
    ent[20:24] = struct.pack("<I", 0x1234)           # unique guid (partial)
    ent[32:40] = struct.pack("<Q", 3)                # start LBA
    ent[40:48] = struct.pack("<Q", 4)                # end LBA
    name = "seed".encode("utf-16-le")
    ent[56:56 + len(name)] = name
    img[2 * SECTOR:3 * SECTOR] = ent
    return bytes(img)


def signature_image(sig, offset, pad=512):
    img = bytearray(max(offset + len(sig), pad) + SECTOR)
    img[offset:offset + len(sig)] = sig
    return bytes(img)


def entropy_high():
    """High-entropy 128 KiB payload for the entropy calculation path."""
    out = bytearray()
    x = 0x12345678
    for _ in range(128 * 1024):
        x = (1103515245 * x + 12345) & 0xFFFFFFFF
        out.append((x >> 16) & 0xFF)
    return bytes(out)


SEEDS = {
    "mbr_dos.img": mbr_dos(),
    "bsd_label.img": bsd_label(),
    "gpt.img": gpt(),
    "luks.img": signature_image(b"LUKS\xba\xbe", 0),
    "bitlocker.img": signature_image(b"-FVE-FS-", 3),
    "filevault.img": signature_image(b"encrdsa", 0),
    "checkpoint.img": signature_image(b"Protect", 80),
    "safeboot.img": signature_image(b"SafeBoot", 0),
    "guardian.img": signature_image(b"PCGM", 0),
    "sophos.img": signature_image(b"SGM400", 110),
    "winmagic.img": signature_image(b"WMSD", 236),
    "pgp.img": signature_image(b"\xeb\x48\x90PGPGUARD", 0),
    "entropy_high.img": entropy_high(),
}


def main():
    ap = argparse.ArgumentParser(
        description="Generate img/vs-layer seed images for img_vs_fuzzer")
    ap.add_argument("--outdir", required=True)
    args = ap.parse_args()
    os.makedirs(args.outdir, exist_ok=True)

    for name, blob in SEEDS.items():
        with open(os.path.join(args.outdir, name), "wb") as fh:
            fh.write(blob)

    zpath = os.path.join(args.outdir, "img_vs_fuzzer_seed_corpus.zip")
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as zf:
        for name in SEEDS:
            zf.write(os.path.join(args.outdir, name), arcname=name)


if __name__ == "__main__":
    main()

