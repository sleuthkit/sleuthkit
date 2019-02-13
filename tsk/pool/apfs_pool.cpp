#include "tsk_apfs.hpp"

#include "../libtsk.h"

#include "../fs/tsk_apfs.hpp"
#include "../fs/tsk_fs_i.h"

#include <stdexcept>

APFSPool::APFSPool(std::vector<img_t>&& imgs, apfs_block_num nx_block_num)
    : TSKPool(std::forward<std::vector<img_t>>(imgs)),
      _nx_block_num{nx_block_num} {
  if (_members.size() != 1) {
    throw std::runtime_error(
        "Only single physical store APFS pools are currently supported");
  }

  // If we're scanning for the latest NXSB then we need to start with the
  // last known good NXSB first
  if (_nx_block_num == APFS_POOL_NX_BLOCK_LATEST) {
    _nx_block_num = APFS_POOL_NX_BLOCK_LAST_KNOWN_GOOD;
  }

  std::tie(_img, _offset) = _members[0];

  auto nxsb = nx(true);

  // Update the base members
  _uuid = nxsb->uuid();
  _block_size = nxsb->block_size();
  _dev_block_size = _img->sector_size;
  _num_blocks = nxsb->num_blocks();

  // Check to see if we need to scan for a newer pool
  if (nx_block_num == APFS_POOL_NX_BLOCK_LATEST) {
    const auto versions = known_versions();

    if (versions.empty()) {
      _nx_block_num = APFS_POOL_NX_BLOCK_LAST_KNOWN_GOOD;
      if (tsk_verbose) {
        tsk_fprintf(stderr,
                    "APFSPool: No checkpoint superblocks found.  Attempting to "
                    "fall back to last known good superblock\n");
      }
    } else {
      const auto highest = std::max_element(
          versions.begin(), versions.end(),
          [](const auto& a, const auto& b) { return a.xid < b.xid; });

      // No need to do anything, we're already the highest version
      if (highest->xid != nxsb->xid()) {
        _nx_block_num = highest->nx_block_num;

        try {
          nxsb = nx(true);
        } catch (const std::runtime_error&) {
          // Fallback to last known good block if the latest block is not valid
          _nx_block_num = APFS_POOL_NX_BLOCK_LAST_KNOWN_GOOD;
          nxsb = nx(true);
        }
      }
    }
  }

  _vol_blocks = nxsb->volume_blocks();
  _num_vols = static_cast<int>(_vol_blocks.size());

  // If the software crypto bit is not set, then either hardware crypto is used
  // or there are no volumes that are encrypted.
  if (bit_is_set(nxsb->sb()->flags, APFS_NXSB_FLAGS_CRYPTO_SW) == false) {
    // We need to check each volume to determine if any of them have encryption
    // enabled.
    for (const auto& volume : volumes()) {
      if (volume.encrypted()) {
        _hw_crypto = true;
        break;
      }
    }
  }
}

std::unique_ptr<APFSSuperblock> APFSPool::nx(bool validate) const {
  auto nxsb = std::make_unique<APFSSuperblock>((*this), _nx_block_num);

  if (validate && nxsb->validate_checksum() == false) {
    throw std::runtime_error("NXSB object checksum failed");
  }

  return nxsb;
}

std::vector<APFSFileSystem> APFSPool::volumes() const {
  std::vector<APFSFileSystem> v{};
  v.reserve(_vol_blocks.size());

  for (const auto block : _vol_blocks) {
    v.emplace_back((*this), block);
  }

  return v;
}

ssize_t APFSPool::read(uint64_t address, char* buf, size_t buf_size) const
    noexcept {
  return tsk_img_read(_img, address + _offset, buf, buf_size);
}

const std::vector<APFSPool::nx_version> APFSPool::known_versions() const {
  std::vector<nx_version> vers{};

  const auto nxsb = nx();
  const auto sb = nxsb->sb();

  for (auto addr = sb->chkpt_desc_base_addr;
       addr < sb->chkpt_desc_base_addr + sb->chkpt_desc_block_count; addr++) {
    APFSObject obj{(*this), addr};

    if (obj.obj_type() != APFS_OBJ_TYPE_SUPERBLOCK ||
        obj.oid() != nxsb->oid()) {
      continue;
    }

    if (!obj.validate_checksum()) {
      continue;
    }

    vers.emplace_back(nx_version{addr, obj.xid()});
  }

  return vers;
}

const std::vector<APFSPool::range> APFSPool::unallocated_ranges() const {
  return nx()->unallocated_ranges();
}

void APFSPool::clear_cache() noexcept {
  _block_cache.clear();

  tsk_take_lock(&(_img->cache_lock));

  // Setting the lengths to zero should invalidate the cache.
  memset(_img->cache_len, 0, sizeof(_img->cache_len));

  tsk_release_lock(&(_img->cache_lock));
}
