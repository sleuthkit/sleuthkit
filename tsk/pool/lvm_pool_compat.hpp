/*
 * The Sleuth Kit - Add on for Linux LVM support
 *
 * Copyright (c) 2022 Joachim Metz <joachim.metz@gmail.com>
 *
 *
 * This software is distributed under the Common Public License 1.0
 */

#pragma once

#include "tsk/base/tsk_base_i.h"

#if HAVE_LIBVSLVM

#include "pool_compat.hpp"
#include "tsk_lvm.hpp"

class LVMPoolCompat : public TSKPoolCompat<LVMPool> {
 public:
  template <typename... Args>
  LVMPoolCompat(Args&&... args)
      : TSKPoolCompat<LVMPool>(TSK_POOL_TYPE_LVM, std::forward<Args>(args)...) { }

  uint8_t poolstat(FILE* hFile) const noexcept;
  TSK_IMG_INFO * getImageInfo(const TSK_POOL_INFO *pool_info, TSK_DADDR_T pvol_block) noexcept;
};

#endif /* HAVE_LIBVSLVM */

