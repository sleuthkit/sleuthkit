/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2019-2020 Brian Carrier.  All Rights reserved
 * Copyright (c) 2018-2019 BlackBag Technologies.  All Rights reserved
 *
 * This software is distributed under the Common Public License 1.0
 */
#include "../libtsk.h"

#include "apfs_compat.hpp"
#include "../img/pool.hpp"
#include "tsk_fs_i.h"

TSK_FS_INFO* apfs_open_auto_detect(
  TSK_IMG_INFO * img_info,
  [[maybe_unused]] TSK_OFF_T offset,
  TSK_FS_TYPE_ENUM fstype,
  const char* a_pass,
  [[maybe_unused]] uint8_t test)
{
    return apfs_open(img_info, offset, fstype, a_pass);
}

TSK_FS_INFO* apfs_open(
  TSK_IMG_INFO * img_info,
  [[maybe_unused]] TSK_OFF_T offset,
  TSK_FS_TYPE_ENUM fstype,
  const char* pass)
{
  tsk_error_reset();

  if (img_info->itype != TSK_IMG_TYPE_POOL) {
      tsk_error_reset();
      tsk_error_set_errno(TSK_ERR_FS_ARG);
      tsk_error_set_errstr("tsk_apfs_open: Not a pool image");
      return nullptr;
  }
  IMG_POOL_INFO *pool_img = (IMG_POOL_INFO*)img_info;

  if (pool_img->pool_info == nullptr) {
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
    auto fs = new APFSFSCompat(img_info, pool_img->pool_info, pool_img->pvol_block, pass);
    return &fs->fs_info();
  } catch (std::runtime_error& e) {
    tsk_error_set_errno(TSK_ERR_FS_GENFS);
    tsk_error_set_errstr("tsk_apfs_open: %s", e.what());
    return nullptr;
  }
}
