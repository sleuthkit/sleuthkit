/** \@file C -> C++ compatability layer */
#pragma once

#include "pool_compat.hpp"
#include "tsk_apfs.hpp"

class APFSPoolCompat : public TSKPoolCompat<APFSPool> {
  void init_volumes();

 public:
  template <typename... Args>
  APFSPoolCompat(Args&&... args)
      : TSKPoolCompat(TSK_POOL_TYPE_APFS, std::forward<Args>(args)...) {
    init_volumes();
  }

  ~APFSPoolCompat();

  uint8_t poolstat(FILE* hFile) const noexcept final;
};
