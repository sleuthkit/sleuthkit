#pragma once

#include <stdint.h>

#include "tsk_apfs.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct TSK_FS_INFO TSK_FS_INFO;
typedef struct TSK_FS_FILE TSK_FS_FILE;

// TSK API

typedef struct {
  char name[0x80];
  char uuid[16];
  char password_hint[0x100];
  char formatted_by[0x20];
  apfs_block_num apsb_block_num;
  uint64_t apsb_oid;
  uint64_t apsb_xid;
  uint64_t capacity_consumed;
  uint64_t capacity_reserved;
  uint64_t capacity_quota;
  uint64_t created;
  uint64_t changed;
  struct {
    char kext_ver_str[0x20];
    uint64_t timestamp;
    uint64_t last_xid;
  } unmount_logs[8];
  APFS_VOLUME_ROLE role;
  char case_sensitive;
  char encrypted;
} apfs_fsstat_info;

extern uint8_t tsk_apfs_fsstat(TSK_FS_INFO *fs_info, apfs_fsstat_info *info);

typedef struct {
  uint64_t date_added;
  uint64_t cloned_inum;
  uint32_t bsdflags;
} apfs_istat_info;

extern uint8_t tsk_apfs_istat(TSK_FS_FILE *fs_file, apfs_istat_info *info);

typedef struct {
  uint64_t snap_xid;
  uint64_t timestamp;
  char *name;
  int dataless;
} apfs_snapshot;

typedef struct {
  size_t num_snapshots;
  int _reserved;  // unused (ensures consistant alignment)
  apfs_snapshot snapshots[0];
} apfs_snapshot_list;

extern uint8_t tsk_apfs_list_snapshots(TSK_FS_INFO *fs_info,
                                       apfs_snapshot_list **list);
extern uint8_t tsk_apfs_free_snapshot_list(apfs_snapshot_list *list);
extern uint8_t tsk_apfs_set_snapshot(TSK_FS_INFO *fs_info, uint64_t snap_xid);

#ifdef __cplusplus
}
#endif
