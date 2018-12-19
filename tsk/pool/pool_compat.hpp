/** \@file C -> C++ compatability layer */
#pragma once

#include "tsk_pool.hpp"

#include <type_traits>

template <typename T,
          typename = std::enable_if_t<std::is_base_of<TSKPool, T>::value>>
class TSKPoolCompat : public T {
 protected:
  TSK_POOL_INFO _info{
      ///< \internal the C info structure
      .tag = TSK_POOL_INFO_TAG,
      .ctype = TSK_POOL_TYPE_UNSUPP,
      .block_size = this->block_size(),
      .num_blocks = this->num_blocks(),
      .num_vols = this->num_vols(),
      .vol_list = nullptr,
      .close =
          [](const TSK_POOL_INFO *pool) {
            delete static_cast<TSKPoolCompat *>(pool->impl);
          },
      .poolstat =
          [](const TSK_POOL_INFO *pool, FILE *hFile) {
            return static_cast<TSKPoolCompat *>(pool->impl)->poolstat(hFile);
          },
      .impl = this,
  };

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
    _info.ctype = type;
  }

  constexpr const TSK_POOL_INFO &pool_info() const noexcept { return _info; }

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
};
