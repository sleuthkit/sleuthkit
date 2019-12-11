/** \@file C -> C++ compatability layer */
#pragma once

#include "pool_compat.hpp"
#include "tsk_apfs.hpp"

class APFSPoolCompat : public TSKPoolCompat<APFSPool> {
  void init_volumes();

 public:
  template <typename... Args>
  APFSPoolCompat(Args&&... args)
      : TSKPoolCompat<APFSPool>(TSK_POOL_TYPE_APFS, std::forward<Args>(args)...) {
    init_volumes();
  }

  ~APFSPoolCompat();

  uint8_t poolstat(FILE* hFile) const noexcept;
  TSK_IMG_INFO * getImageInfo(const TSK_POOL_INFO *pool_info, TSK_DADDR_T pvol_block) noexcept;
};
