/*
 * The Sleuth Kit - Add on for Linux LVM support
 *
 * Copyright (c) 2022 Joachim Metz <joachim.metz@gmail.com>
 *
 * This software is distributed under the Common Public License 1.0
 */

#include "tsk/base/tsk_base_i.h"

#if HAVE_LIBVSLVM

#include "img_bfio_handle.h"
#include "tsk_lvm.hpp"

#include "tsk/auto/guid.h"

#include <stdexcept>
#include <tuple>

#include <libbfio.h>
#include <libvslvm.h>

#if !defined( LIBVSLVM_HAVE_BFIO )

LIBVSLVM_EXTERN \
int libvslvm_handle_open_file_io_handle(
     libvslvm_handle_t *handle,
     libbfio_handle_t *file_io_handle,
     int access_flags,
     libvslvm_error_t **error );

LIBVSLVM_EXTERN \
int libvslvm_handle_open_physical_volume_files_file_io_pool(
     libvslvm_handle_t *handle,
     libbfio_pool_t *file_io_pool,
     libcerror_error_t **error );

#endif /* !defined( LIBVSLVM_HAVE_BFIO ) */

LVMPool::LVMPool(std::vector<img_t>&& imgs)
    : TSKPool(std::forward<std::vector<img_t>>(imgs)) {
  if (_members.size() != 1) {
    throw std::runtime_error(
        "Only single physical volume LVM pools are currently supported");
  }
  std::tie(_img, _offset) = _members[0];

  libbfio_handle_t *file_io_handle = NULL;
  int file_io_pool_entry =  0;

  if (img_bfio_handle_initialize(&file_io_handle, _img, _offset, NULL) != 1) {
    throw std::runtime_error("Unable to initialize image BFIO handle");
  }
  if (libbfio_pool_initialize(&( _file_io_pool ), 0, LIBBFIO_POOL_UNLIMITED_NUMBER_OF_OPEN_HANDLES, NULL) != 1) {
    libbfio_handle_free(&file_io_handle, NULL);
    throw std::runtime_error("Unable to initialize BFIO pool");
  }
  if (libbfio_pool_append_handle(_file_io_pool, &file_io_pool_entry, file_io_handle, LIBBFIO_OPEN_READ, NULL) != 1) {
    libbfio_pool_free(&( _file_io_pool ), NULL);
    libbfio_handle_free(&file_io_handle, NULL);
    throw std::runtime_error("Unable to add image BFIO handle to BFIO pool");
  }
  if (libvslvm_handle_initialize(&( _lvm_handle ), NULL) != 1) {
    libbfio_pool_free(&( _file_io_pool ), NULL);
    throw std::runtime_error("Unable to initialize LVM handle");
  }
  if (libvslvm_handle_open_file_io_handle(_lvm_handle, file_io_handle, LIBVSLVM_OPEN_READ, NULL) != 1) {
    libvslvm_handle_free(&( _lvm_handle ), NULL);
    libbfio_pool_free(&( _file_io_pool ), NULL);
    throw std::runtime_error("Unable to open LVM handle");
  }
  if (libvslvm_handle_open_physical_volume_files_file_io_pool(_lvm_handle, _file_io_pool, NULL) != 1) {
    libvslvm_handle_free(&( _lvm_handle ), NULL);
    libbfio_pool_free(&( _file_io_pool ), NULL);
    throw std::runtime_error("Unable to open LVM handle");
  }
  if (libvslvm_handle_get_volume_group(_lvm_handle, &( _lvm_volume_group ), NULL) != 1) {
    libvslvm_handle_free(&( _lvm_handle ), NULL);
    libbfio_pool_free(&( _file_io_pool ), NULL);
    throw std::runtime_error("Unable to retrieve LVM volume group");
  }
  if (tsk_verbose) {
    tsk_fprintf(stderr, "LVMPool: retrieved LVM volume group.\n" );
  }
  char identifier_string[ 64 ];

  if (libvslvm_volume_group_get_identifier(_lvm_volume_group, identifier_string, 64, NULL) != 1) {
    libvslvm_volume_group_free(&( _lvm_volume_group ), NULL);
    libvslvm_handle_free(&( _lvm_handle ), NULL);
    libbfio_pool_free(&( _file_io_pool ), NULL);
    throw std::runtime_error("Unable to retrieve LVM volume group identifier");
  }
  identifier = std::string(identifier_string);

  _block_size = 0;
  _dev_block_size = _img->sector_size;
  _num_blocks = 0;

  _num_vols = 0;
}

LVMPool::~LVMPool() {
  if (_lvm_volume_group != nullptr) {
    libvslvm_volume_group_free(&( _lvm_volume_group ), NULL);
  }
  if (_lvm_handle != nullptr) {
    libvslvm_handle_free(&( _lvm_handle ), NULL);
  }
  if (_file_io_pool != nullptr) {
    libbfio_pool_free(&( _file_io_pool ), NULL);
  }
}

ssize_t LVMPool::read(uint64_t address, char* buf, size_t buf_size) const
    noexcept {
  // TODO implement, this functions appears to be only used by the JNI bindings
  return tsk_img_read(_img, address + _offset, buf, buf_size);
}

#endif /* HAVE_LIBVSLVM */

