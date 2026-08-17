# OSSFuzz Issue Status

This file tracks the status of every OSSFuzz issue we have triaged.

| OSSFuzz ID | GitHub ID | Branch | Status | Notes |
|------------|-----------|--------|--------|-------|
| 542909776 | 3530 | 20260817-gh3530-ossfuzz542909776-fatxxfs-name-leak | FIXED | Direct-leak: fs_name leaked on two early-return paths in fatxxfs_dent_parse_buf |
| 542853444 | 3529 | 20260817-gh3529-ossfuzz542853444-ntfs-invalid-enum | FIXED | UBSAN invalid-enum-value: NTFS attribute type read from disk not validated; values >0x100 are invalid |
