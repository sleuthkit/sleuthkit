/*
 * The Sleuth Kit - Add on for Linux LVM support
 *
 * Copyright (c) 2022 Joachim Metz <joachim.metz@gmail.com>
 *
 * This software is distributed under the Common Public License 1.0
 */

#pragma once

#include "tsk/base/tsk_base_i.h"

#if HAVE_LIBVSLVM

#include "tsk_pool.hpp"

#include <libbfio.h>
#include <libvslvm.h>

class LVMPool;

class LVMPool : public TSKPool {
 protected:
  TSK_IMG_INFO *_img;
  // Start of the pool data within the image
  TSK_OFF_T _offset;
  libbfio_pool_t *_file_io_pool = NULL;
  libvslvm_handle_t *_lvm_handle = NULL;
  libvslvm_volume_group_t *_lvm_volume_group = NULL;

 public:
  LVMPool(std::vector<img_t> &&imgs);

  // Moveable
  LVMPool(LVMPool &&) = default;
  LVMPool &operator=(LVMPool &&) = default;

  // Not copyable because of TSK_IMG_INFO pointer
  LVMPool(const LVMPool &) = delete;
  LVMPool &operator=(const LVMPool &) = delete;

  ~LVMPool();

  std::string identifier;

  ssize_t read(uint64_t address, char *buf, size_t buf_size) const
      noexcept final;
};

#endif /* HAVE_LIBVSLVM */

