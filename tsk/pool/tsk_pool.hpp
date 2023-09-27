/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2019-2020 Brian Carrier.  All Rights reserved
 * Copyright (c) 2018-2019 BlackBag Technologies.  All Rights reserved
 *
 * This software is distributed under the Common Public License 1.0
 */
/** \@file Public C++ API */
#pragma once

#include <cstdint>
#include <utility>
#include <vector>

#include "../auto/guid.h"
#include "tsk_pool.h"

class TSKPool {
 public:
  using img_t = std::pair<TSK_IMG_INFO *const, const TSK_OFF_T>;
  using range = struct {
    uint64_t start_block;
    uint64_t num_blocks;
  };

  // Not default constructible
  TSKPool() = delete;

  // Not copyable, due the TSK_IMG_INFO pointers
  TSKPool(const TSKPool &) = delete;
  TSKPool &operator=(const TSKPool &) = delete;

  // Moveable
  TSKPool(TSKPool &&) = default;
  TSKPool &operator=(TSKPool &&) = default;

  virtual ~TSKPool() = default;

  inline const TSKGuid &uuid() const { return _uuid; }

  inline uint32_t block_size() const noexcept { return _block_size; }
  inline uint32_t dev_block_size() const noexcept { return _dev_block_size; }
  inline uint64_t num_blocks() const noexcept { return _num_blocks; }
  inline uint64_t first_img_offset() const noexcept {
      if (!_members.empty()) {
          return _members[0].second;
      }
      return 0;
  }
  inline int num_vols() const noexcept { return _num_vols; }

  virtual ssize_t read(uint64_t address, char *buf, size_t buf_size) const
      noexcept = 0;

  virtual const std::vector<range> unallocated_ranges() const { return {}; };

  TSK_IMG_INFO *getTSKImgInfo(unsigned int index) const { 
      if (index < _members.size()) {
          return _members[index].first;
      }
      return NULL;
  };

 protected:
  TSKPool(std::vector<img_t> &&imgs) noexcept : _members{std::move(imgs)} {}
  
  std::vector<img_t> _members{};
  TSKGuid _uuid{};
  uint64_t _num_blocks;
  int _num_vols;
  uint32_t _block_size{};
  uint32_t _dev_block_size{};
};

// Helper function to make it easier to set flag bits on enumerations
template <typename T, typename = std::enable_if_t<std::is_enum<T>::value>>
inline T &operator|=(T &a, T b) {
  a = static_cast<T>(a | b);

  return a;
}
