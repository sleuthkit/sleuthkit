#include "apfs_pool_compat.hpp"

#include "../fs/apfs_fs.hpp"
#include "../fs/tsk_apfs.hpp"
#include "../fs/tsk_fs_i.h"
#include "../img/pool.hpp"

#include <stdexcept>

APFSPoolCompat::~APFSPoolCompat() {
  // Clean up the dynamic allocations
  if (_info.vol_list != nullptr) {
    auto vol = _info.vol_list;
    while (vol != nullptr) {
      if (vol->desc != nullptr) delete[] vol->desc;
      if (vol->password_hint != nullptr) delete[] vol->password_hint;
      vol = vol->next;
    }
    delete[] _info.vol_list;
    _info.vol_list = nullptr;
  }
}

void APFSPoolCompat::init_volumes() {
  if (_info.num_vols != 0) {
    _info.vol_list = new TSK_POOL_VOLUME_INFO[_info.num_vols]();

    int i = 0;
    TSK_POOL_VOLUME_INFO *last = nullptr;

    for (const auto &volume : volumes()) {
      auto &vinfo = _info.vol_list[i];

      vinfo.tag = TSK_POOL_VOL_INFO_TAG;
      vinfo.index = i;
      vinfo.block = volume.block_num();
      vinfo.num_blocks = volume.alloc_blocks();
      vinfo.prev = last;
      if (vinfo.prev != nullptr) {
        vinfo.prev->next = &vinfo;
      }

      vinfo.desc = new char[volume.name().size() + 1];
      volume.name().copy(vinfo.desc, volume.name().size());
      vinfo.desc[volume.name().size()] = '\x00';

      if (volume.encrypted()) {
        vinfo.flags |= TSK_POOL_VOLUME_FLAG_ENCRYPTED;

        vinfo.password_hint = new char[volume.password_hint().size() + 1];
        volume.password_hint().copy(vinfo.password_hint,
                                    volume.password_hint().size());
        vinfo.password_hint[volume.password_hint().size()] = '\x00';
      }

      if (volume.case_sensitive()) {
        vinfo.flags |= TSK_POOL_VOLUME_FLAG_CASE_SENSITIVE;
      }

      i++;
      last = &vinfo;
    }
  }
}

uint8_t APFSPoolCompat::poolstat(FILE *hFile) const noexcept try {
  tsk_fprintf(hFile, "POOL CONTAINER INFORMATION\n");
  tsk_fprintf(hFile, "--------------------------------------------\n\n");
  tsk_fprintf(hFile, "Container %s\n", uuid().str().c_str());
  tsk_fprintf(hFile, "==============================================\n");
  tsk_fprintf(hFile, "Type: APFS\n");

  bool has_cdb = false;

  {
    tsk_fprintf(hFile, "\n");
    tsk_fprintf(hFile, "NX Block Number: %lld\n", _nx_block_num);

    const auto nxsb = nx();

    tsk_fprintf(hFile, "NX oid: %lld\n", nxsb->oid());
    tsk_fprintf(hFile, "NX xid: %lld\n", nxsb->xid());
    tsk_fprintf(hFile, "Checkpoint Descriptor Block: ");

    const auto cdb = nxsb->checkpoint_desc_block();

    if (cdb == 0) {
      tsk_fprintf(hFile, "Not Found\n");
    } else {
      has_cdb = true;
      tsk_fprintf(hFile, "%lld\n", cdb);
    }

    tsk_fprintf(hFile, "\n");

    const auto total_space = _info.num_blocks * _info.block_size;

    tsk_fprintf(hFile, "Capacity Ceiling (Size): %llu B\n", total_space);

    if (has_cdb) {
      const auto free_space = nxsb->num_free_blocks() * _info.block_size;
      tsk_fprintf(hFile, "Capacity In Use:         %llu B\n",
                  total_space - free_space);
      tsk_fprintf(hFile, "Capacity Available:      %llu B\n", free_space);
    }

    tsk_fprintf(hFile, "\n");
    tsk_fprintf(hFile, "Block Size:            %u B\n", _info.block_size);
    tsk_fprintf(hFile, "Number of Blocks:      %llu\n", _info.num_blocks);

    if (has_cdb) {
      tsk_fprintf(hFile, "Number of Free Blocks: %llu\n",
                  nxsb->num_free_blocks());
    }
  }

  for (const auto &vol : volumes()) {
    tsk_fprintf(hFile, "|\n");
    tsk_fprintf(hFile, "+-> Volume %s\n", vol.uuid().str().c_str());
    tsk_fprintf(hFile, "|   ===========================================\n");

    const auto role = [&] {
      switch (vol.role()) {
        case APFS_VOLUME_ROLE_NONE:
          return "No specific role";
        case APFS_VOLUME_ROLE_SYSTEM:
          return "System";
        case APFS_VOLUME_ROLE_USER:
          return "User";
        case APFS_VOLUME_ROLE_RECOVERY:
          return "Recovery";
        case APFS_VOLUME_ROLE_VM:
          return "VM";
        case APFS_VOLUME_ROLE_PREBOOT:
          return "Preboot";
      }

      return "Unknown";
    }();
    tsk_fprintf(hFile, "|   APSB Block Number: %llu\n", vol.block_num());
    tsk_fprintf(hFile, "|   APSB oid: %llu\n", vol.oid());
    tsk_fprintf(hFile, "|   APSB xid: %llu\n", vol.xid());
    tsk_fprintf(hFile, "|   Name (Role): %s (%s)\n", vol.name().c_str(), role);

    tsk_fprintf(hFile, "|   Capacity Consumed: %lld B\n", vol.used());

    tsk_fprintf(hFile, "|   Capacity Reserved: ");
    if (vol.reserved() != 0) {
      tsk_fprintf(hFile, "%lld B\n", vol.reserved());
    } else {
      tsk_fprintf(hFile, "None\n");
    }

    tsk_fprintf(hFile, "|   Capacity Quota: ");
    if (vol.quota() != 0) {
      tsk_fprintf(hFile, "%lld B\n", vol.quota());
    } else {
      tsk_fprintf(hFile, "None\n");
    }
    tsk_fprintf(hFile, "|   Case Sensitive: %s\n",
                vol.case_sensitive() ? "Yes" : "No");
    tsk_fprintf(
        hFile, "|   Encrypted: %s%s\n", vol.encrypted() ? "Yes" : "No",
        (vol.encrypted() && hardware_crypto()) ? " (hardware assisted)" : "");
    tsk_fprintf(hFile, "|   Formatted by: %s\n", vol.formatted_by().c_str());
    tsk_fprintf(hFile, "|\n");

    char time_buf[1024];
    tsk_fprintf(
        hFile, "|   Created: %s\n",
        tsk_fs_time_to_str_subsecs(vol.created() / 1000000000,
                                   vol.created() % 1000000000, time_buf));
    tsk_fprintf(
        hFile, "|   Changed: %s\n",
        tsk_fs_time_to_str_subsecs(vol.changed() / 1000000000,
                                   vol.changed() % 1000000000, time_buf));

    const auto unmount_log = vol.unmount_log();
    if (unmount_log.size() != 0) {
      tsk_fprintf(hFile, "|\n");
      tsk_fprintf(hFile, "|   Unmount Logs\n");
      tsk_fprintf(hFile, "|   ------------\n");
      tsk_fprintf(hFile,
                  "|   Timestamp                            Log String\n");
      for (const auto &log : unmount_log) {
        tsk_fprintf(
            hFile, "|   %s  %s\n",
            tsk_fs_time_to_str_subsecs(log.timestamp / 1000000000,
                                       log.timestamp % 1000000000, time_buf),
            log.logstr.c_str());
      }
    }

    if (vol.encrypted() && !hardware_crypto()) {
      tsk_fprintf(hFile, "|\n");
      tsk_fprintf(hFile, "|   Encryption Info\n");
      tsk_fprintf(hFile, "|   ---------------\n");

      const auto crypto = vol.crypto_info();
      tsk_fprintf(hFile, "|   Password Hint: %s\n",
                  crypto.password_hint.c_str());

      for (const auto &kek : crypto.wrapped_keks) {
        tsk_fprintf(hFile, "|   KEK (%s):", kek.uuid.str().c_str());
        for (auto i = 0U; i < sizeof(kek.data); i++) {
          if (i % 8 == 0) {
            tsk_fprintf(hFile, "\n|      ");
          }
          tsk_fprintf(hFile, " %2.2X", kek.data[i]);
        }
        tsk_fprintf(hFile, "\n|\n");

        tsk_fprintf(hFile, "|       Salt:");
        for (auto i = 0U; i < sizeof(kek.salt); i++) {
          tsk_fprintf(hFile, " %2.2X", kek.salt[i]);
        }
        tsk_fprintf(hFile, "\n|   \n");

        tsk_fprintf(hFile, "|       Iterations: %lld\n|\n", kek.iterations);
      }

      tsk_fprintf(hFile, "|   Wrapped VEK:");
      for (auto i = 0U; i < sizeof(crypto.wrapped_vek); i++) {
        if (i % 8 == 0 && i != 0) {
          tsk_fprintf(hFile, "\n|               ");
        }
        tsk_fprintf(hFile, " %2.2X", crypto.wrapped_vek[i]);
      }
      tsk_fprintf(hFile, "\n");
    } else {
      tsk_fprintf(hFile, "|\n");
      tsk_fprintf(hFile, "|   Root Files\n");
      tsk_fprintf(hFile, "|   -------------\n");

      const auto root = vol.root_jobj_tree();
      const auto children = root.obj(APFS_ROOT_INODE_NUM).children();

      for (const auto &file : children) {
        tsk_fprintf(hFile, "|  [%8.0llu] %s\n", file.rec.file_id,
                    file.name.c_str());
      }
    }
  }

  if (has_cdb) {
    tsk_fprintf(hFile, "|\n");
    tsk_fprintf(hFile, "+-> Unallocated Container Blocks\n");
    tsk_fprintf(hFile, "|   ============================\n");
    for (const auto &range : nx()->unallocated_ranges()) {
      tsk_fprintf(hFile, "|   0x%0.8llx-0x%0.8llx\n", range.start_block,
                  range.start_block + range.num_blocks - 1);
    }
  }

  return 0;
} catch (const std::exception &e) {
  tsk_error_reset();
  tsk_error_set_errno(TSK_ERR_POOL_GENPOOL);
  tsk_error_set_errstr("%s", e.what());
  return 1;
}

static void
apfs_img_close(TSK_IMG_INFO * img_info)
{
    if (img_info == NULL) {
        return;
    }

    // Close the pool image
    tsk_deinit_lock(&(img_info->cache_lock));
    tsk_img_free(img_info);
}

static void
apfs_img_imgstat(TSK_IMG_INFO * img_info, FILE *file)
{
    IMG_POOL_INFO *pool_img_info = (IMG_POOL_INFO *)img_info;
    const auto pool = static_cast<APFSPoolCompat*>(pool_img_info->pool_info->impl);
    TSK_IMG_INFO *origInfo = pool->getTSKImgInfo(0);
    origInfo->imgstat(origInfo, file);
}

static ssize_t
apfs_img_read(TSK_IMG_INFO * img_info, TSK_OFF_T offset, char *buf, size_t len)
{
    IMG_POOL_INFO *pool_img_info = (IMG_POOL_INFO *)img_info;
    const auto pool = static_cast<APFSPoolCompat*>(pool_img_info->pool_info->impl);
    TSK_IMG_INFO *origInfo = pool->getTSKImgInfo(0);

    return origInfo->read(origInfo, offset, buf, len);
}

TSK_IMG_INFO * APFSPoolCompat::getImageInfo(const TSK_POOL_INFO *pool_info, TSK_DADDR_T pvol_block) noexcept try {

    IMG_POOL_INFO *img_pool_info;
    TSK_IMG_INFO *img_info;

    if ((img_pool_info =
        (IMG_POOL_INFO *)tsk_img_malloc(sizeof(IMG_POOL_INFO))) == NULL) {
        return NULL;
    }

    img_info = (TSK_IMG_INFO *)img_pool_info;

    img_info->tag = TSK_IMG_INFO_TAG;
    img_info->itype = TSK_IMG_TYPE_POOL;

    img_pool_info->pool_info = pool_info;
    img_pool_info->pvol_block = pvol_block;

    img_pool_info->img_info.read = apfs_img_read;
    img_pool_info->img_info.close = apfs_img_close;
    img_pool_info->img_info.imgstat = apfs_img_imgstat;

    // Copy original info from the first TSK_IMG_INFO. There was a check in the
    // APFSPool that _members has only one entry.
    IMG_POOL_INFO *pool_img_info = (IMG_POOL_INFO *)img_info;
    const auto pool = static_cast<APFSPoolCompat*>(pool_img_info->pool_info->impl);
    TSK_IMG_INFO *origInfo = pool->_members[0].first;

    img_info->size = origInfo->size;
    img_info->num_img = origInfo->num_img;
    img_info->sector_size = origInfo->sector_size;
    img_info->page_size = origInfo->page_size;
    img_info->spare_size = origInfo->spare_size;
    img_info->images = origInfo->images;

    tsk_init_lock(&(img_info->cache_lock));

    return img_info;

}
catch (const std::exception &e) {
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_POOL_GENPOOL);
    tsk_error_set_errstr("%s", e.what());
    return NULL;
}

