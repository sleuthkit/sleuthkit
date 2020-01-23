/** \@file C -> C++ compatability layer */
#pragma once

#include "tsk_pool.hpp"

#include <type_traits>

template <typename T,
          typename = std::enable_if_t<std::is_base_of<TSKPool, T>::value>>
class TSKPoolCompat : public T {
 protected:
  TSK_POOL_INFO _info{};

  // disable copying so we don't mess with the C API
  TSKPoolCompat(const TSKPoolCompat &) = delete;
  TSKPoolCompat &operator=(const TSKPoolCompat &) = delete;

  // disable moving so we don't mess with the C API
  TSKPoolCompat(TSKPoolCompat &&) noexcept = delete;
  TSKPoolCompat &operator=(TSKPoolCompat &&) noexcept = delete;

 public:
  template <typename... Args>
  TSKPoolCompat(TSK_POOL_TYPE_ENUM type, Args &&... args) noexcept(
      std::is_nothrow_constructible<T, Args...>::value)
      : T(std::forward<Args>(args)...) {
    ///< \internal the C info structure
    _info.tag = TSK_POOL_INFO_TAG;
    _info.ctype = type;
    _info.block_size = this->block_size();
    _info.num_blocks = this->num_blocks();
    _info.img_offset = this->first_img_offset();
    _info.num_vols = this->num_vols();
    _info.vol_list = nullptr;
    _info.close = [](const TSK_POOL_INFO *pool) {
      delete static_cast<TSKPoolCompat *>(pool->impl);
    };
    _info.poolstat = [](const TSK_POOL_INFO *pool, FILE *hFile) {
      return static_cast<TSKPoolCompat *>(pool->impl)->poolstat(hFile);
    };
    _info.get_img_info = [](const TSK_POOL_INFO *pool, TSK_DADDR_T pvol_block) {
        return static_cast<TSKPoolCompat *>(pool->impl)->getImageInfo(pool, pvol_block);
    };
    _info.impl = this;
  }

  inline const TSK_POOL_INFO &pool_info() const noexcept { return _info; }

  virtual ~TSKPoolCompat() {
    if (_info.vol_list != nullptr) {
      for (auto vol = _info.vol_list; vol != nullptr; vol = vol->next) {
        delete[] vol->desc;
      }

      delete[] _info.vol_list;
      _info.vol_list = nullptr;
    }
  }

  virtual uint8_t poolstat(FILE *) const noexcept = 0;
  virtual TSK_IMG_INFO * getImageInfo(const TSK_POOL_INFO *pool_info, TSK_DADDR_T pvol_block) = 0;
};
