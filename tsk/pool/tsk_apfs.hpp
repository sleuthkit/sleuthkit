/** \@file Public C++ API */
#pragma once

#include "tsk_apfs.h"
#include "tsk_pool.hpp"

#include <array>
#include <memory>
#include <unordered_map>

#include "../fs/tsk_apfs.h"
#include "../util/lw_shared_ptr.hpp"

class APFSSuperblock;
class APFSFileSystem;
class APFSPool;

class APFSBlock {
 protected:
  using storage = std::array<char, APFS_BLOCK_SIZE>;

  storage _storage;
  const APFSPool &_pool;
  const apfs_block_num _block_num;

  // disable default construction
  APFSBlock() = delete;

  // Copies are expensive here, so let's disable them
  APFSBlock(const APFSBlock &) = delete;
  APFSBlock &operator=(const APFSBlock &) = delete;

 public:
  APFSBlock(const APFSPool &pool, const apfs_block_num block_num);

  // Move constructible
  APFSBlock(APFSBlock &&) = default;

  virtual ~APFSBlock() = default;

  void decrypt(const uint8_t *key, const uint8_t *key2 = nullptr) noexcept;

  void dump() const noexcept;

  inline bool operator==(const APFSBlock &rhs) const noexcept {
    if (this == &rhs) {
      return true;
    }

    return (&_pool == &rhs._pool && _block_num == rhs._block_num);
  }

  inline bool operator!=(const APFSBlock &rhs) const noexcept {
    return !this->operator==(rhs);
  }

  inline apfs_block_num block_num() const noexcept { return _block_num; }
  inline const APFSPool &pool() const noexcept { return _pool; }
  inline const char *data() const noexcept { return _storage.data(); }
};

class APFSPool : public TSKPool {
  // This should give a worst case of caching ~64 MiB of blocks
  static constexpr auto block_cache_size = 1024 * 16;

 protected:
  TSK_IMG_INFO *_img;
  TSK_OFF_T _offset;

  apfs_block_num _nx_block_num;
  std::vector<apfs_block_num> _vol_blocks;

  // TODO(JTS): make thread safe if needed. The locking in the higher-level APIs should prevent issues.
  mutable std::unordered_map<apfs_block_num, lw_shared_ptr<APFSBlock>>
      _block_cache{};

  bool _hw_crypto{};

  using nx_version = struct {
    apfs_block_num nx_block_num;
    uint64_t xid;
  };

 public:
  APFSPool(std::vector<img_t> &&imgs,
           apfs_block_num nx_block_num = APFS_POOL_NX_BLOCK_LAST_KNOWN_GOOD);

  // Moveable
  APFSPool(APFSPool &&) = default;
  APFSPool &operator=(APFSPool &&) = default;

  // Not copyable because of TSK_IMG_INFO pointer
  APFSPool(const APFSPool &) = delete;
  APFSPool &operator=(const APFSPool &) = delete;

  std::vector<APFSFileSystem> volumes() const;

  ssize_t read(uint64_t address, char *buf, size_t buf_size) const
      noexcept final;

  // This is not thread safe, but locking in the higher level APIs appears to prevent any issues.
  template <typename T, typename... Args>
  inline lw_shared_ptr<T> get_block(apfs_block_num block,
                                    Args &&... args) const {
    const auto it = _block_cache.find(block);
    if (it == _block_cache.end()) {
      if (_block_cache.size() > block_cache_size) {
        _block_cache.clear();
      }
      _block_cache[block] = make_lw_shared<T>(std::forward<Args>(args)...);
      return lw_static_pointer_cast<T>(_block_cache[block]);
    }

    return lw_static_pointer_cast<T>(it->second);
  }

  const std::vector<nx_version> known_versions() const;

  const std::vector<range> unallocated_ranges() const final;

  std::unique_ptr<APFSSuperblock> nx(bool validate = false) const;

  inline bool hardware_crypto() const noexcept { return _hw_crypto; }

  void clear_cache() noexcept;

  friend class APFSBlock;
};
