#include <libtsk.h>

#include "apfs_compat.hpp"
#include "tsk_fs_i.h"

TSK_FS_INFO* apfs_open(const TSK_POOL_INFO* pool_info, apfs_block_num vol_block, TSK_FS_TYPE_ENUM fstype, const char* pass) {
  tsk_error_reset();

  if (pool_info == nullptr) {
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_ARG);
    tsk_error_set_errstr("tsk_apfs_open: Null pool_info");
    return nullptr;
  }

if (fstype != TSK_FS_TYPE_APFS) {
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_ARG);
    tsk_error_set_errstr("tsk_apfs_open: invalid fstype");
    return nullptr;
  }

  try {
    auto fs = new APFSFSCompat(pool_info, vol_block, pass);
    return &fs->fs_info();
  } catch (std::runtime_error& e) {
    tsk_error_set_errno(TSK_ERR_FS_GENFS);
    tsk_error_set_errstr("tsk_apfs_open: %s", e.what());
    return nullptr;
  }
}
