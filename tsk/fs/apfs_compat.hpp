#pragma once

#include "apfs_fs.hpp"
#include "tsk_fs.h"

#include <unordered_map>

class APFSFSCompat : public APFSJObjTree {
  class date_added_cache {
    std::unordered_map<uint64_t, uint64_t> _cache{};
    uint64_t _last_parent{};
    TSK_FS_INFO* _fs;

    void populate(uint64_t pid) noexcept;

   public:
    date_added_cache(TSK_FS_INFO* fs) noexcept : _fs{fs} {}

    uint64_t lookup(uint64_t parent_id, uint64_t private_id) noexcept;
  };

  mutable TSK_FS_INFO _fsinfo{};
  mutable date_added_cache _da_cache{&_fsinfo};

 public:
  APFSFSCompat(TSK_IMG_INFO* img_info, const TSK_POOL_INFO* pool_info, apfs_block_num vol_block,
               const char* pass = "");
  inline const TSK_FS_INFO& fs_info() const noexcept { return _fsinfo; }
  inline TSK_FS_INFO& fs_info() noexcept { return _fsinfo; }
  inline uint64_t date_added(uint64_t parent_id, uint64_t private_id) const
      noexcept {
    return _da_cache.lookup(parent_id, private_id);
  }

  uint8_t file_add_meta(TSK_FS_FILE*, TSK_INUM_T) const noexcept;
  uint8_t inode_walk(TSK_FS_INFO* fs, TSK_INUM_T start_inum, TSK_INUM_T end_inum,
      TSK_FS_META_FLAG_ENUM flags, TSK_FS_META_WALK_CB action,
      void* ptr);
  uint8_t fsstat(FILE*) const noexcept;
  uint8_t load_attrs(TSK_FS_FILE*) const noexcept;
  uint8_t istat(TSK_FS_ISTAT_FLAG_ENUM, FILE*, TSK_INUM_T, TSK_DADDR_T,
                int32_t) const noexcept;
  uint8_t block_walk(TSK_FS_INFO *, TSK_DADDR_T, TSK_DADDR_T,
      TSK_FS_BLOCK_WALK_FLAG_ENUM, TSK_FS_BLOCK_WALK_CB,
      void *);
  TSK_FS_BLOCK_FLAG_ENUM block_getflags(TSK_FS_INFO*, TSK_DADDR_T);
  uint8_t decrypt_block(TSK_DADDR_T, void*) noexcept;
  int name_cmp(const char*, const char*) const noexcept;

  TSK_RETVAL_ENUM dir_open_meta(TSK_FS_DIR**, TSK_INUM_T) const noexcept;
};
