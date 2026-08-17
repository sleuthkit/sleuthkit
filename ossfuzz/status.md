# OSSFuzz Issue Status

This file tracks the status of every OSSFuzz issue we have triaged.

| OSSFuzz ID | GitHub ID | Branch | Status | Notes |
|------------|-----------|--------|--------|-------|
| 542909776 | 3530 | 20260817-gh3530-ossfuzz542909776-fatxxfs-name-leak | FIXED | Direct-leak: fs_name leaked on two early-return paths in fatxxfs_dent_parse_buf |
| 542853444 | 3529 | 20260817-gh3529-ossfuzz542853444-ntfs-invalid-enum | FIXED | UBSAN invalid-enum-value: NTFS attribute type read from disk not validated; values >0x100 skipped |
| 471605916 | 3432 | 20260817-gh3432-ossfuzz471605916-apfs-btree-timeout | FIXED | Timeout: APFSBtreeNode::entries() iterates corrupt key_count; now checks key_count <= storage.size() |
| 471593728 | 3430 | 20260817-gh3430-gh3416-ossfuzz471593728-471517907-apfs-null-iter | FIXED | UBSAN null-deref: APFSBtreeNodeIterator::operator==() and operator->() guard _child_it for null |
| 471587334 | 3433 | 20260817-gh3433-ossfuzz471587334-ntfs-attrlist-size | FIXED | Timeout: ntfs_proc_attrlist size capped at 100 MB before malloc/walk |
| 471568853 | 3429 | 20260817-gh3429-ossfuzz471568853-iso9660-oom | FIXED | OOM: iso9660_dir_open_meta rejects directory meta->size > 128 MB |
| 471553935 | 3428 | 20260817-gh3428-ossfuzz471553935-ntfs-undefined-shift | FIXED | UBSAN undefined-shift: signed char left-shifted in ntfs_uncompress_compunit; replaced with tsk_getu16 |
| 471519955 | 3425 | 20260817-gh3425-ossfuzz471519955-hfs-oom-nodesize | FIXED | OOM: hfs_load_extended_attrs nodeSize uncapped; now rejected if > 32768 |
| 471517907 | 3416 | 20260817-gh3430-gh3416-ossfuzz471593728-471517907-apfs-null-iter | FIXED | ASAN SEGV: APFSBtreeNodeIterator::operator->() returned null; volume_blocks() now guards e.value |
