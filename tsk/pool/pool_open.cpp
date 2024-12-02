/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2018-2019 BlackBag Technologies.  All Rights reserved
 * Copyright (c) 2022 Joachim Metz <joachim.metz@gmail.com>
 *
 * This software is distributed under the Common Public License 1.0
 */
#include "tsk/base/tsk_base_i.h"

#include "apfs_pool_compat.hpp"
#include "lvm_pool_compat.hpp"
#include "pool_compat.hpp"

#include "tsk/fs/tsk_apfs.hpp"
#include "tsk/img/tsk_img.h"
#include "tsk/vs/tsk_vs.h"

const TSK_POOL_INFO *tsk_pool_open_sing(const TSK_VS_PART_INFO *part,
                                        TSK_POOL_TYPE_ENUM type) {
  tsk_error_reset();

  if (part == nullptr) {
    tsk_error_set_errno(TSK_ERR_POOL_ARG);
    tsk_error_set_errstr("tsk_pool_open_sing: Null vpart handle");
    return nullptr;
  }

  if ((part->vs == nullptr) || (part->vs->tag != TSK_VS_INFO_TAG)) {
    tsk_error_set_errno(TSK_ERR_POOL_ARG);
    tsk_error_set_errstr("tsk_pool_open_sing: Null vs handle");
    return nullptr;
  }

  const auto offset = part->start * part->vs->block_size + part->vs->offset;

  return tsk_pool_open_img_sing(part->vs->img_info, offset, type);
}


/**
 * @param num_vols Number of volumes in parts array
 * @param parts List of Volume partitions to review
 * @type Type of pool to open (or auto detect)
 * @returns Pool structure
 */
const TSK_POOL_INFO *tsk_pool_open(int num_vols,
                                   const TSK_VS_PART_INFO *const parts[],
                                   TSK_POOL_TYPE_ENUM type) {
  tsk_error_reset();

  if (num_vols <= 0) {
    tsk_error_set_errno(TSK_ERR_POOL_ARG);
    tsk_error_set_errstr("tsk_pool_open_: Invalid num_vols");
    return nullptr;
  }

  if (parts == nullptr) {
    tsk_error_set_errno(TSK_ERR_POOL_ARG);
    tsk_error_set_errstr("tsk_pool_open_sing: Null parts");
    return nullptr;
  }

  // Make arrays of equal size to store the volume offset and IMG_INFO
  auto imgs = std::make_unique<TSK_IMG_INFO *[]>(num_vols);
  auto offsets = std::make_unique<TSK_OFF_T[]>(num_vols);

  for (auto i = 0; i < num_vols; i++) {
    const auto &part = parts[i];

    if ((part->vs == nullptr) || (part->vs->tag != TSK_VS_INFO_TAG)) {
      tsk_error_set_errno(TSK_ERR_POOL_ARG);
      tsk_error_set_errstr("tsk_pool_open: Null vs handle");
      return nullptr;
    }

    const auto offset = part->start * part->vs->block_size + part->vs->offset;

    imgs[i] = part->vs->img_info;
    offsets[i] = offset;
  }

  return tsk_pool_open_img(num_vols, imgs.get(), offsets.get(), type);
}

/**
 * Open a pool at the given offset in the given image.
 */
const TSK_POOL_INFO *tsk_pool_open_img_sing(TSK_IMG_INFO *img, TSK_OFF_T offset,
                                            TSK_POOL_TYPE_ENUM type) {
  return tsk_pool_open_img(1, &img, &offset, type);
}


/**
 * Open a pool at the set of image offsets
 * @param num_imgs Size of imgs array
 * @param imgs List of IMG_INFO to look for pool
 * @param offsets List of offsets to look for pool in the img at the same array index
 * @param type Pool type to open
 */
const TSK_POOL_INFO *tsk_pool_open_img(int num_imgs, TSK_IMG_INFO *const imgs[],
                                       const TSK_OFF_T offsets[],
                                       TSK_POOL_TYPE_ENUM type) {
  std::vector<APFSPool::img_t> apfs_v{};
  apfs_v.reserve(num_imgs);

  for (auto i = 0; i < num_imgs; i++) {
    apfs_v.emplace_back(imgs[i], offsets[i]);
  }
#ifdef HAVE_LIBVSLVM
  std::vector<LVMPool::img_t> lvm_v{};

  lvm_v.reserve(num_imgs);

  for (auto i = 0; i < num_imgs; i++) {
    lvm_v.emplace_back(imgs[i], offsets[i]);
  }
#endif

  const char *error_string = NULL;

  switch (type) {
    case TSK_POOL_TYPE_DETECT:
      try {
        auto apfs = new APFSPoolCompat(std::move(apfs_v), APFS_POOL_NX_BLOCK_LATEST);

        return &apfs->pool_info();
      } catch (std::runtime_error &e) {
        error_string = e.what();
      }
#ifdef HAVE_LIBVSLVM
      try {
        auto lvm = new LVMPoolCompat(std::move(lvm_v));

        return &lvm->pool_info();
      } catch (std::runtime_error &e) {
        error_string = e.what();
      }
#endif
      if (tsk_verbose) {
        tsk_fprintf(stderr, "tsk_pool_open_img: pool type detection failed: %s\n",
                    error_string);
      }
      break;
    case TSK_POOL_TYPE_APFS:
      try {
        auto apfs = new APFSPoolCompat(std::move(apfs_v), APFS_POOL_NX_BLOCK_LATEST);

        return &apfs->pool_info();
      } catch (std::runtime_error &e) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_POOL_UNKTYPE);
        tsk_error_set_errstr("%s", e.what());
      }
      return nullptr;

    // Will fallthrough to TSK_POOL_TYPE_UNSUPP if libvslvm is not available.
    case TSK_POOL_TYPE_LVM:
#ifdef HAVE_LIBVSLVM
      try {
        auto lvm = new LVMPoolCompat(std::move(lvm_v));

        return &lvm->pool_info();
      } catch (std::runtime_error &e) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_POOL_UNKTYPE);
        tsk_error_set_errstr("%s", e.what());
      }
      return nullptr;
#endif
    case TSK_POOL_TYPE_UNSUPP:
      // All other pool types are unsupported
      tsk_error_reset();
      tsk_error_set_errno(TSK_ERR_POOL_UNSUPTYPE);
      tsk_error_set_errstr("%d", type);
      return nullptr;
  }

  // All other pool types are unsupported
  tsk_error_reset();
  tsk_error_set_errno(TSK_ERR_POOL_UNSUPTYPE);
  tsk_error_set_errstr("%d", type);
  return nullptr;
}

void tsk_pool_close(const TSK_POOL_INFO *pool) {
  // sanity checks
  if ((pool == nullptr) || (pool->tag != TSK_POOL_INFO_TAG)) return;

  // each pool container is supposed to free the struct
  pool->close(pool);
}
