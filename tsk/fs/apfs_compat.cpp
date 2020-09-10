#include "../libtsk.h"

#include "decmpfs.h"
#include "tsk_fs_i.h"

#include "../pool/apfs_pool_compat.hpp"
#include "../img/pool.hpp"
#include "apfs_compat.hpp"

#include <cstring>

// Forward declarations
extern "C" void error_detected(uint32_t errnum, const char* errstr, ...);
extern "C" void error_returned(const char* errstr, ...);

static inline const APFSPoolCompat& to_pool(
    const TSK_POOL_INFO* pool_info) noexcept {

    const auto pool = static_cast<APFSPoolCompat*>(pool_info->impl);
    return *pool;
}

static inline const APFSPoolCompat& fs_info_to_pool(
    const TSK_FS_INFO* fs_info) noexcept {

    IMG_POOL_INFO *pool_img = (IMG_POOL_INFO*)fs_info->img_info;
    return to_pool(pool_img->pool_info);
}

static inline TSK_DADDR_T to_pool_vol_block(
    const TSK_FS_INFO* fs_info) noexcept {

    if (fs_info->img_info->itype != TSK_IMG_TYPE_POOL) {
        return 0;
    }

    IMG_POOL_INFO *pool_img = (IMG_POOL_INFO*)fs_info->img_info;
    return pool_img->pvol_block;
}

static inline APFSFSCompat& to_fs(const TSK_FS_INFO* fs_info) noexcept {
  const auto fs = static_cast<APFSFSCompat*>(fs_info->impl);
  return *fs;
}

static uint8_t unsupported_function(const char* func) noexcept {
  tsk_error_reset();
  tsk_error_set_errno(TSK_ERR_FS_UNSUPFUNC);
  tsk_error_set_errstr("%s not implemented for APFS yet", func);
  return 1;
}

static TSK_FS_ATTR_TYPE_ENUM xattribute_type(const std::string& name) noexcept {
  if (name == APFS_XATTR_NAME_DECOMPFS) {
    return TSK_FS_ATTR_TYPE_APFS_COMP_REC;
  }

  if (name == APFS_XATTR_NAME_RESOURCEFORK) {
    return TSK_FS_ATTR_TYPE_APFS_RSRC;
  }

  // Default to XATTR
  return TSK_FS_ATTR_TYPE_APFS_EXT_ATTR;
}

static TSK_FS_NAME_TYPE_ENUM to_name_type(APFS_ITEM_TYPE type) noexcept {
  switch (type) {
    case APFS_ITEM_TYPE_FIFO:
      return TSK_FS_NAME_TYPE_FIFO;
    case APFS_ITEM_TYPE_CHAR_DEVICE:
      return TSK_FS_NAME_TYPE_CHR;
    case APFS_ITEM_TYPE_DIRECTORY:
      return TSK_FS_NAME_TYPE_DIR;
    case APFS_ITEM_TYPE_BLOCK_DEVICE:
      return TSK_FS_NAME_TYPE_BLK;
    case APFS_ITEM_TYPE_REGULAR:
      return TSK_FS_NAME_TYPE_REG;
    case APFS_ITEM_TYPE_SYMBOLIC_LINK:
      return TSK_FS_NAME_TYPE_LNK;
    case APFS_ITEM_TYPE_SOCKET:
      return TSK_FS_NAME_TYPE_SOCK;
    case APFS_ITEM_TYPE_WHITEOUT:
      return TSK_FS_NAME_TYPE_WHT;
    default:
      return TSK_FS_NAME_TYPE_UNDEF;
  }
}

static TSK_FS_META_TYPE_ENUM to_meta_type(APFS_ITEM_TYPE type) noexcept {
  switch (type) {
    case APFS_ITEM_TYPE_FIFO:
      return TSK_FS_META_TYPE_FIFO;
    case APFS_ITEM_TYPE_CHAR_DEVICE:
      return TSK_FS_META_TYPE_CHR;
    case APFS_ITEM_TYPE_DIRECTORY:
      return TSK_FS_META_TYPE_DIR;
    case APFS_ITEM_TYPE_BLOCK_DEVICE:
      return TSK_FS_META_TYPE_BLK;
    case APFS_ITEM_TYPE_REGULAR:
      return TSK_FS_META_TYPE_REG;
    case APFS_ITEM_TYPE_SYMBOLIC_LINK:
      return TSK_FS_META_TYPE_LNK;
    case APFS_ITEM_TYPE_SOCKET:
      return TSK_FS_META_TYPE_SOCK;
    case APFS_ITEM_TYPE_WHITEOUT:
      return TSK_FS_META_TYPE_WHT;
    default:
      return TSK_FS_META_TYPE_UNDEF;
  }
}

static const char* to_string(TSK_FS_META_TYPE_ENUM type) noexcept {
  switch (type) {
    case TSK_FS_META_TYPE_FIFO:
      return "Named Pipe (FIFO)";

    case TSK_FS_META_TYPE_CHR:
      return "Character Device";

    case TSK_FS_META_TYPE_DIR:
      return "Directory";

    case TSK_FS_META_TYPE_BLK:
      return "Block Device";

    case TSK_FS_META_TYPE_REG:
      return "Regular File";

    case TSK_FS_META_TYPE_LNK:
      return "Link";

    case TSK_FS_META_TYPE_SOCK:
      return "Socket";

    case TSK_FS_META_TYPE_WHT:
      return "Whiteout";
    default:
      return "Unknown";
  }
}

static const char* attr_type_name(uint32_t typeNum) noexcept {
  switch (typeNum) {
    case TSK_FS_ATTR_TYPE_DEFAULT:
      return "DFLT";
    case TSK_FS_ATTR_TYPE_APFS_DATA:
      return "DATA";
    case TSK_FS_ATTR_TYPE_APFS_EXT_ATTR:
      return "ExATTR";
    case TSK_FS_ATTR_TYPE_APFS_COMP_REC:
      return "CMPF";
    case TSK_FS_ATTR_TYPE_APFS_RSRC:
      return "RSRC";
    default:
      return "UNKN";
  }
}

APFSFSCompat::APFSFSCompat(TSK_IMG_INFO* img_info, const TSK_POOL_INFO* pool_info,
                           apfs_block_num vol_block, const char* pass)
    : APFSJObjTree(APFSFileSystem{to_pool(pool_info), vol_block, pass}) {
  const auto& pool = to_pool(pool_info);

  const APFSFileSystem vol{pool, vol_block};

  _fsinfo.tag = TSK_FS_INFO_TAG;
  _fsinfo.root_inum = APFS_ROOT_INODE_NUM;
  _fsinfo.ftype = TSK_FS_TYPE_APFS;
  _fsinfo.duname = "Block";
  _fsinfo.flags = TSK_FS_INFO_FLAG_HAVE_NANOSEC;

  if (vol.encrypted()) {
    _fsinfo.flags |= TSK_FS_INFO_FLAG_ENCRYPTED;
  }

  _fsinfo.img_info = img_info; 
  _fsinfo.offset = pool.first_img_offset();
  _fsinfo.block_count = vol.alloc_blocks();
  _fsinfo.block_size = pool.block_size();
  _fsinfo.dev_bsize = pool.dev_block_size();
  _fsinfo.first_block = 0;
  _fsinfo.last_block = pool.num_blocks() - 1;
  _fsinfo.last_block_act = pool.num_blocks() - 1;
  _fsinfo.first_inum = APFS_ROOT_INODE_NUM;
  _fsinfo.last_inum = vol.last_inum();

  // Locks
  tsk_init_lock(&_fsinfo.list_inum_named_lock);
  tsk_init_lock(&_fsinfo.orphan_dir_lock);

  // Callbacks
  _fsinfo.block_walk = [](TSK_FS_INFO * fs, TSK_DADDR_T start, TSK_DADDR_T end, 
                          TSK_FS_BLOCK_WALK_FLAG_ENUM flags, TSK_FS_BLOCK_WALK_CB cb, 
                          void *ptr) {
      return to_fs(fs).block_walk(fs, start, end, flags, cb, ptr);
  };

  _fsinfo.block_getflags = [](TSK_FS_INFO* a_fs, TSK_DADDR_T a_addr) {
      return to_fs(a_fs).block_getflags(a_fs, a_addr);
  };

  _fsinfo.inode_walk = [](TSK_FS_INFO* fs, TSK_INUM_T start_inum, TSK_INUM_T end_inum,
                          TSK_FS_META_FLAG_ENUM flags, TSK_FS_META_WALK_CB action,
                          void* ptr) {
      return to_fs(fs).inode_walk(fs, start_inum, end_inum, flags, action, ptr); 
  };

  _fsinfo.file_add_meta = [](TSK_FS_INFO* fs, TSK_FS_FILE* fs_file,
                             TSK_INUM_T addr) {
    return to_fs(fs).file_add_meta(fs_file, addr);
  };

  _fsinfo.istat = [](TSK_FS_INFO* fs, TSK_FS_ISTAT_FLAG_ENUM flags, FILE* hFile,
                     TSK_INUM_T inode_num, TSK_DADDR_T numblock,
                     int32_t sec_skew) {
    return to_fs(fs).istat(flags, hFile, inode_num, numblock, sec_skew);
  };

  _fsinfo.dir_open_meta = [](TSK_FS_INFO* fs, TSK_FS_DIR** a_fs_dir,
                             TSK_INUM_T inode) {
    return to_fs(fs).dir_open_meta(a_fs_dir, inode);
  };

  _fsinfo.fscheck = [](TSK_FS_INFO*, FILE*) {
    return unsupported_function("fscheck");
  };

  _fsinfo.fsstat = [](TSK_FS_INFO* fs, FILE* hFile) {
    return to_fs(fs).fsstat(hFile);
  };

  _fsinfo.close = [](TSK_FS_INFO* fs) {
    delete static_cast<APFSFSCompat*>(fs->impl);
  };

  _fsinfo.decrypt_block = [](TSK_FS_INFO* fs, TSK_DADDR_T block_num,
                             void* data) {
    return to_fs(fs).decrypt_block(block_num, data);
  };

  _fsinfo.get_default_attr_type = [](const TSK_FS_FILE*) {
    return TSK_FS_ATTR_TYPE_APFS_DATA;
  };

  _fsinfo.load_attrs = [](TSK_FS_FILE* file) {
    return to_fs(file->fs_info).load_attrs(file);
  };

  _fsinfo.name_cmp = [](TSK_FS_INFO* fs, const char* s1, const char* s2) {
    return to_fs(fs).name_cmp(s1, s2);
  };

  _fsinfo.impl = this;
}

uint8_t APFSFSCompat::fsstat(FILE* hFile) const noexcept try {
  const auto& pool = fs_info_to_pool(&_fsinfo);
#ifdef HAVE_LIBOPENSSL
  APFSFileSystem vol{pool, to_pool_vol_block(&_fsinfo), _crypto.password};
#else
  APFSFileSystem vol{ pool, to_pool_vol_block(&_fsinfo) };
#endif

  tsk_fprintf(hFile, "FILE SYSTEM INFORMATION\n");
  tsk_fprintf(hFile, "--------------------------------------------\n");
  tsk_fprintf(hFile, "File System Type: APFS\n");

  tsk_fprintf(hFile, "Volume UUID %s\n", vol.uuid().str().c_str());

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
  tsk_fprintf(hFile, "APSB Block Number: %llu\n", vol.block_num());
  tsk_fprintf(hFile, "APSB oid: %llu\n", vol.oid());
  tsk_fprintf(hFile, "APSB xid: %llu\n", vol.xid());
  tsk_fprintf(hFile, "Name (Role): %s (%s)\n", vol.name().c_str(), role);

  tsk_fprintf(hFile, "Capacity Consumed: %lld B\n", vol.used());

  tsk_fprintf(hFile, "Capacity Reserved: ");
  if (vol.reserved() != 0) {
    tsk_fprintf(hFile, "%lld B\n", vol.reserved());
  } else {
    tsk_fprintf(hFile, "None\n");
  }

  tsk_fprintf(hFile, "Capacity Quota: ");
  if (vol.quota() != 0) {
    tsk_fprintf(hFile, "%lld B\n", vol.quota());
  } else {
    tsk_fprintf(hFile, "None\n");
  }
  tsk_fprintf(hFile, "Case Sensitive: %s\n",
              vol.case_sensitive() ? "Yes" : "No");
  tsk_fprintf(hFile, "Encrypted: %s%s\n", vol.encrypted() ? "Yes" : "No",
              (vol.encrypted() && pool.hardware_crypto())
                  ? " (hardware assisted)"
                  : "");
  tsk_fprintf(hFile, "Formatted by: %s\n", vol.formatted_by().c_str());
  tsk_fprintf(hFile, "\n");

  char time_buf[1024];
  tsk_fprintf(hFile, "Created: %s\n",
              tsk_fs_time_to_str_subsecs(vol.created() / 1000000000,
                                         vol.created() % 1000000000, time_buf));
  tsk_fprintf(hFile, "Changed: %s\n",
              tsk_fs_time_to_str_subsecs(vol.changed() / 1000000000,
                                         vol.changed() % 1000000000, time_buf));

  if (vol.encrypted() && !pool.hardware_crypto()) {
    tsk_fprintf(hFile, "\n");
    tsk_fprintf(hFile, "Encryption Info\n");
    tsk_fprintf(hFile, "---------------\n");

    const auto crypto = vol.crypto_info();

    if (crypto.unlocked) {
      tsk_fprintf(hFile, "Password: %s\n", crypto.password.c_str());
    }
    tsk_fprintf(hFile, "Password Hint: %s\n", crypto.password_hint.c_str());

    for (const auto& kek : crypto.wrapped_keks) {
      tsk_fprintf(hFile, "KEK (%s):", kek.uuid.str().c_str());
      for (auto i = 0U; i < sizeof(kek.data); i++) {
        if (i % 8 == 0) {
          tsk_fprintf(hFile, "\n   ");
        }
        tsk_fprintf(hFile, " %2.2X", kek.data[i]);
      }
      tsk_fprintf(hFile, "\n\n");

      tsk_fprintf(hFile, "    Salt:");
      for (auto i = 0U; i < sizeof(kek.salt); i++) {
        tsk_fprintf(hFile, " %2.2X", kek.salt[i]);
      }
      tsk_fprintf(hFile, "\n\n");

      tsk_fprintf(hFile, "    Iterations: %lld\n\n", kek.iterations);
    }

    tsk_fprintf(hFile, "Wrapped VEK:");
    for (auto i = 0U; i < sizeof(crypto.wrapped_vek); i++) {
      if (i % 8 == 0 && i != 0) {
        tsk_fprintf(hFile, "\n            ");
      }
      tsk_fprintf(hFile, " %2.2X", crypto.wrapped_vek[i]);
    }
    tsk_fprintf(hFile, "\n\n");

    if (crypto.unlocked) {
      tsk_fprintf(hFile, "VEK (AES-XTS-128):");
      for (auto i = 0U; i < sizeof(crypto.vek); i++) {
        if (i % 16 == 0 && i != 0) {
          tsk_fprintf(hFile, "\n                  ");
        }
        tsk_fprintf(hFile, " %2.2X", crypto.vek[i]);
      }
      tsk_fprintf(hFile, "\n\n");
    }
  }

  const auto snapshots = vol.snapshots();
  if (!snapshots.empty()) {
    tsk_fprintf(hFile, "\n");
    tsk_fprintf(hFile, "Snapshots\n");
    tsk_fprintf(hFile, "---------\n");
    for (const auto& snapshot : snapshots) {
      tsk_fprintf(
          hFile, "[%lld] %s %s %s\n", snapshot.snap_xid,
          tsk_fs_time_to_str_subsecs(snapshot.timestamp / 1000000000,
                                     snapshot.timestamp % 1000000000, time_buf),
          snapshot.name.c_str(), (snapshot.dataless) ? "(dataless)" : "");
    }
  }

  const auto unmount_log = vol.unmount_log();
  if (unmount_log.size() != 0) {
    tsk_fprintf(hFile, "\n");
    tsk_fprintf(hFile, "Unmount Logs\n");
    tsk_fprintf(hFile, "------------\n");
    tsk_fprintf(hFile, "Timestamp                            Log String\n");
    for (const auto& log : unmount_log) {
      tsk_fprintf(
          hFile, "%s  %s\n",
          tsk_fs_time_to_str_subsecs(log.timestamp / 1000000000,
                                     log.timestamp % 1000000000, time_buf),
          log.logstr.c_str());
    }
  }

  return 0;
} catch (const std::exception& e) {
  tsk_error_reset();
  tsk_error_set_errno(TSK_ERR_FS_GENFS);
  tsk_error_set_errstr("%s", e.what());
  return 1;
}

uint8_t tsk_apfs_fsstat(TSK_FS_INFO* fs_info, apfs_fsstat_info* info) try {
  if (fs_info == nullptr) {
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_ARG);
    tsk_error_set_errstr("tsk_apfs_fsstat: Null fs_info");
    return 1;
  }

  if (info == nullptr) {
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_ARG);
    tsk_error_set_errstr("tsk_apfs_fsstat: Null info");
    return 1;
  }

  const APFSFileSystem vol{fs_info_to_pool(fs_info), to_pool_vol_block(fs_info)};

  memset(info, 0, sizeof(*info));

  strncpy(info->name, vol.name().c_str(), sizeof(info->name) - 1);
  memcpy(info->uuid, vol.uuid().bytes().data(), 16);
  strncpy(info->password_hint, vol.password_hint().c_str(),
          sizeof(info->password_hint) - 1);
  strncpy(info->formatted_by, vol.formatted_by().c_str(),
          sizeof(info->formatted_by) - 1);

  info->apsb_block_num = vol.block_num();
  info->apsb_oid = vol.oid();
  info->apsb_xid = vol.xid();
  info->capacity_consumed = vol.used();
  info->capacity_reserved = vol.reserved();
  info->capacity_quota = vol.quota();
  info->created = vol.created();
  info->changed = vol.changed();

  const auto unmount_log = vol.unmount_log();
  auto i = 0;
  for (const auto& log : unmount_log) {
    auto& l = info->unmount_logs[i++];
    strncpy(l.kext_ver_str, log.logstr.c_str(), sizeof(l.kext_ver_str));
    l.timestamp = log.timestamp;
    l.last_xid = log.last_xid;
  }

  info->role = vol.role();
  info->case_sensitive = vol.case_sensitive();
  info->encrypted = vol.encrypted();

  return 0;

} catch (const std::exception& e) {
  tsk_error_reset();
  tsk_error_set_errno(TSK_ERR_FS_GENFS);
  tsk_error_set_errstr("%s", e.what());
  return 1;
}

TSK_RETVAL_ENUM APFSFSCompat::dir_open_meta(TSK_FS_DIR** a_fs_dir,
                                            TSK_INUM_T inode_num) const
    noexcept try {
  // Sanity checks
  if (a_fs_dir == NULL) {
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_ARG);
    tsk_error_set_errstr("APFS dir_open_meta: NULL fs_attr argument given");
    return TSK_ERR;
  }

  if (tsk_verbose) {
    tsk_fprintf(stderr,
                "APFS dir_open_meta: Processing directory %" PRIuINUM "\n",
                inode_num);
  }

  auto fs_dir = *a_fs_dir;
  if (fs_dir != nullptr) {
    tsk_fs_dir_reset(fs_dir);
    fs_dir->addr = inode_num;
  } else {
    *a_fs_dir = fs_dir = tsk_fs_dir_alloc(&_fsinfo, inode_num, 128);
  }

  if (fs_dir == nullptr) {
    return TSK_ERR;
  }

  fs_dir->fs_file = tsk_fs_file_open_meta(&_fsinfo, nullptr, inode_num);
  if (fs_dir->fs_file == nullptr) {
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_INODE_NUM);
    tsk_error_set_errstr(
        "APFS dir_open_meta: %" PRIuINUM " is not a valid inode", inode_num);
    return TSK_COR;
  }

  const auto inode_ptr =
      static_cast<APFSJObject*>(fs_dir->fs_file->meta->content_ptr);
  if (!inode_ptr->valid()) {
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_INODE_NUM);
    tsk_error_set_errstr("APFS dir_open_meta: inode_num is not valid %" PRIuINUM
                         "\n",
                         inode_num);
    return TSK_COR;
  }

  for (const auto& child : inode_ptr->children()) {
    auto fs_name = tsk_fs_name_alloc(child.name.length(), 0);
    if (fs_name == nullptr) {
      return TSK_ERR;
    }

    const auto type =
        bitfield_value(child.rec.type_and_flags, APFS_DIR_RECORD_TYPE_BITS,
                       APFS_DIR_RECORD_TYPE_SHIFT);

    strncpy(fs_name->name, child.name.c_str(), fs_name->name_size);
    fs_name->meta_addr = child.rec.file_id;
    fs_name->type = to_name_type(APFS_ITEM_TYPE(type));
    fs_name->flags = TSK_FS_NAME_FLAG_ALLOC;
    fs_name->date_added = child.rec.date_added;

    if (tsk_fs_dir_add(fs_dir, fs_name)) {
      tsk_fs_name_free(fs_name);
      return TSK_ERR;
    }

    tsk_fs_name_free(fs_name);
  }

  return TSK_OK;
} catch (const std::exception& e) {
  tsk_error_reset();
  tsk_error_set_errno(TSK_ERR_FS_GENFS);
  tsk_error_set_errstr("%s", e.what());
  return TSK_ERR;
}

uint8_t APFSFSCompat::inode_walk(TSK_FS_INFO* fs, TSK_INUM_T start_inum, TSK_INUM_T end_inum,
    TSK_FS_META_FLAG_ENUM flags, TSK_FS_META_WALK_CB action, void* ptr) {

    TSK_FS_FILE *fs_file;
    TSK_INUM_T inum;

    if (end_inum < start_inum) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("inode_walk: end object id must be >= start object id: "
            "%" PRIx32 " must be >= %" PRIx32 "",
            end_inum, start_inum);
        return 1;
    }

    if (flags & TSK_FS_META_FLAG_ORPHAN) {
        if (tsk_verbose) {
            tsk_fprintf(stderr, "inode_walk: ORPHAN flag unsupported by AFPS");
        }
    }

    if (((flags & TSK_FS_META_FLAG_ALLOC) == 0) &&
        ((flags & TSK_FS_META_FLAG_UNALLOC) == 0)) {
        flags = (TSK_FS_META_FLAG_ENUM)(flags | TSK_FS_META_FLAG_ALLOC | TSK_FS_META_FLAG_UNALLOC);
    }

    /* If neither of the USED or UNUSED flags are set, then set them both
    */
    if (((flags & TSK_FS_META_FLAG_USED) == 0) &&
        ((flags & TSK_FS_META_FLAG_UNUSED) == 0)) {
        flags = (TSK_FS_META_FLAG_ENUM)(flags | TSK_FS_META_FLAG_USED | TSK_FS_META_FLAG_UNUSED);
    }

    if ((fs_file = tsk_fs_file_alloc(fs)) == NULL)
        return 1;
    if ((fs_file->meta =
        tsk_fs_meta_alloc(sizeof(APFSJObject))) == NULL)
        return 1;

    for (inum = start_inum; inum < end_inum; inum++) {

        int result = fs->file_add_meta(fs, fs_file, inum);
        if (result == TSK_OK) {

            if ((fs_file->meta->flags & flags) == fs_file->meta->flags) {
                int retval = action(fs_file, ptr);
                if (retval == TSK_WALK_STOP) {
                    tsk_fs_file_close(fs_file);
                    return 0;
                }
                else if (retval == TSK_WALK_ERROR) {
                    tsk_fs_file_close(fs_file);
                    return 1;
                }
            }
        }
    }


    /*
    * Cleanup.
    */
    tsk_fs_file_close(fs_file);

    return TSK_OK;
}

uint8_t APFSFSCompat::file_add_meta(TSK_FS_FILE* fs_file, TSK_INUM_T addr) const
    noexcept try {
  if (fs_file == nullptr) {
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_ARG);
    tsk_error_set_errstr("APFS file_add_meta: NULL fs_file given");
    return 1;
  }

  /* Allocate or reset the TSK_FS_META struct. */
  if (fs_file->meta == nullptr) {
    if ((fs_file->meta = tsk_fs_meta_alloc(sizeof(APFSJObject))) == nullptr) {
      return 1;
    }
  } else {
    tsk_fs_meta_reset(fs_file->meta);
  }

  fs_file->meta->attr_state = TSK_FS_META_ATTR_EMPTY;

  fs_file->meta->reset_content = [](void* content_ptr) {
    // Destruct the APFSJObject
    static_cast<APFSJObject*>(content_ptr)->~APFSJObject();
  };

  auto inode_ptr = static_cast<APFSJObject*>(fs_file->meta->content_ptr);

  new (inode_ptr) APFSJObject(obj(addr));
  if (!inode_ptr->valid()) {
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_INODE_NUM);
    tsk_error_set_errstr(
        "APFS file_add_meta: inode_num is not valid %" PRIuINUM "\n", addr);
    return 1;
  }

  const auto inode_meta = inode_ptr->inode();

  const auto mode = bitfield_value(inode_meta.mode_and_type,
                                   APFS_INODE_MODE_BITS, APFS_INODE_MODE_SHIFT);
  const auto type = bitfield_value(inode_meta.mode_and_type,
                                   APFS_INODE_TYPE_BITS, APFS_INODE_TYPE_SHIFT);

  fs_file->meta->flags = TSK_FS_META_FLAG_ALLOC;
  fs_file->meta->addr = addr;
  fs_file->meta->type = to_meta_type(APFS_ITEM_TYPE(type));
  fs_file->meta->mode = TSK_FS_META_MODE_ENUM(mode);
  fs_file->meta->nlink = inode_meta.nlink;
  fs_file->meta->size = inode_ptr->size();
  fs_file->meta->uid = inode_meta.owner;
  fs_file->meta->gid = inode_meta.group;

  fs_file->meta->mtime = inode_meta.modified_time / 1000000000;
  fs_file->meta->mtime_nano = inode_meta.modified_time % 1000000000;
  fs_file->meta->atime = inode_meta.accessed_time / 1000000000;
  fs_file->meta->atime_nano = inode_meta.accessed_time % 1000000000;
  fs_file->meta->ctime = inode_meta.changed_time / 1000000000;
  fs_file->meta->ctime_nano = inode_meta.changed_time % 1000000000;
  fs_file->meta->crtime = inode_meta.create_time / 1000000000;
  fs_file->meta->crtime_nano = inode_meta.create_time % 1000000000;

  // For symlinks we need to read a special exattr to get the link
  if (fs_file->meta->type == TSK_FS_META_TYPE_LNK) {
    const auto num_attrs = tsk_fs_file_attr_getsize(fs_file);
    for (int i = 0; i < num_attrs; i++) {
      const auto attr = tsk_fs_file_attr_get_idx(fs_file, i);
      if (attr->type == TSK_FS_ATTR_TYPE_APFS_EXT_ATTR &&
          strcmp(attr->name, APFS_XATTR_NAME_SYMLINK) == 0) {
        // We've found our symlink attribute
        fs_file->meta->link = (char*)tsk_malloc(attr->size + 1);
        tsk_fs_attr_read(attr, (TSK_OFF_T)0, fs_file->meta->link, attr->size,
                         TSK_FS_FILE_READ_FLAG_NONE);
        fs_file->meta->link[attr->size] = 0;
        break;
      }
    }
  }

  return 0;
} catch (const std::exception& e) {
  tsk_error_reset();
  tsk_error_set_errno(TSK_ERR_FS_GENFS);
  tsk_error_set_errstr("%s", e.what());
  return 1;
}

uint8_t APFSFSCompat::load_attrs(TSK_FS_FILE* file) const noexcept try {
  auto fs_meta = file->meta;

  /* Check for an already populated attribute list, since a lazy strategy
   * is used to fill in attributes. If the attribute list is not yet
   * allocated, do so now. */
  if ((fs_meta->attr != nullptr) &&
      (fs_meta->attr_state == TSK_FS_META_ATTR_STUDIED)) {
    return 0;
  } else if (fs_meta->attr_state == TSK_FS_META_ATTR_ERROR) {
    return 1;
  }

  if (fs_meta->attr != nullptr) {
    tsk_fs_attrlist_markunused(fs_meta->attr);
  } else {
    fs_meta->attr = tsk_fs_attrlist_alloc();
  }

  // Load non-resident extents
  auto jobj = static_cast<APFSJObject*>(file->meta->content_ptr);

  // Default Attribute
  if (!jobj->extents().empty()) {
    auto fs_attr = tsk_fs_attrlist_getnew(fs_meta->attr, TSK_FS_ATTR_NONRES);
    if (fs_attr == nullptr) {
      fs_meta->attr_state = TSK_FS_META_ATTR_ERROR;
      return 1;
    }

    TSK_FS_ATTR_RUN* data_run_head = nullptr;
    TSK_FS_ATTR_RUN* data_run_last = nullptr;

    // Create the runs
    for (const auto& extent : jobj->extents()) {
      auto data_run = tsk_fs_attr_run_alloc();
      if (data_run == nullptr) {
        fs_meta->attr_state = TSK_FS_META_ATTR_ERROR;
        tsk_fs_attr_run_free(data_run_head);
        return 1;
      }

      data_run->addr = extent.phys;
      data_run->offset = extent.offset / _fsinfo.block_size;
      data_run->len = extent.len / _fsinfo.block_size;
      data_run->crypto_id = extent.crypto_id;
      data_run->flags = TSK_FS_ATTR_RUN_FLAG_NONE;
      data_run->next = nullptr;

      if (extent.phys == 0) {
        data_run->flags |= TSK_FS_ATTR_RUN_FLAG_SPARSE;
      }

      if (extent.crypto_id != 0) {
        data_run->flags |= TSK_FS_ATTR_RUN_FLAG_ENCRYPTED;
      }

      if (data_run_head == nullptr) {
        data_run_head = data_run;
      } else {
        data_run_last->next = data_run;
      }

      data_run_last = data_run;
    }

    // initialize the data run
    if (tsk_fs_attr_set_run(file, fs_attr, data_run_head, "",
                            TSK_FS_ATTR_TYPE_APFS_DATA, TSK_FS_ATTR_ID_DEFAULT,
                            fs_meta->size, fs_meta->size, jobj->size_on_disk(),
                            TSK_FS_ATTR_NONRES, 0)) {
      fs_meta->attr_state = TSK_FS_META_ATTR_ERROR;
      tsk_fs_attr_run_free(data_run_head);
      return 1;
    }
  } else if (jobj->is_clone()) {
    const auto clone = obj(jobj->inode().private_id);

    // We've got to add the cloned extents
    if (!clone.extents().empty()) {
      auto fs_attr = tsk_fs_attrlist_getnew(fs_meta->attr, TSK_FS_ATTR_NONRES);
      if (fs_attr == nullptr) {
        fs_meta->attr_state = TSK_FS_META_ATTR_ERROR;
        return 1;
      }

      TSK_FS_ATTR_RUN* data_run_head = nullptr;
      TSK_FS_ATTR_RUN* data_run_last = nullptr;

      // Create the runs
      for (const auto& extent : clone.extents()) {
        auto data_run = tsk_fs_attr_run_alloc();
        if (data_run == nullptr) {
          fs_meta->attr_state = TSK_FS_META_ATTR_ERROR;
          tsk_fs_attr_run_free(data_run_head);
          return 1;
        }

        data_run->addr = extent.phys;
        data_run->offset = extent.offset / _fsinfo.block_size;
        data_run->len = extent.len / _fsinfo.block_size;
        data_run->crypto_id = extent.crypto_id;
        data_run->flags = TSK_FS_ATTR_RUN_FLAG_NONE;
        data_run->next = nullptr;

        if (extent.phys == 0) {
          data_run->flags |= TSK_FS_ATTR_RUN_FLAG_SPARSE;
        }

        if (extent.crypto_id != 0) {
          data_run->flags |= TSK_FS_ATTR_RUN_FLAG_ENCRYPTED;
        }

        if (data_run_head == nullptr) {
          data_run_head = data_run;
        } else {
          data_run_last->next = data_run;
        }

        data_run_last = data_run;
      }

      // initialize the data run
      if (tsk_fs_attr_set_run(
              file, fs_attr, data_run_head, "", TSK_FS_ATTR_TYPE_APFS_DATA,
              TSK_FS_ATTR_ID_DEFAULT, fs_meta->size, fs_meta->size,
              jobj->size_on_disk(), TSK_FS_ATTR_NONRES, 0)) {
        fs_meta->attr_state = TSK_FS_META_ATTR_ERROR;
        tsk_fs_attr_run_free(data_run_head);
        return 1;
      }
    }
  }

  uint16_t attribute_counter = TSK_FS_ATTR_ID_DEFAULT + 1;
  const TSK_FS_ATTR* decmpfs_attr = nullptr;
  TSK_FS_ATTR_RUN* rsrc_runs = nullptr;

  // Inline extended attributes
  for (const auto& xattr : jobj->inline_xattrs()) {
    auto fs_attr = tsk_fs_attrlist_getnew(fs_meta->attr, TSK_FS_ATTR_RES);
    if (fs_attr == nullptr) {
      fs_meta->attr_state = TSK_FS_META_ATTR_ERROR;
      return 1;
    }

    const auto type = xattribute_type(xattr.name);

    if (type == TSK_FS_ATTR_TYPE_APFS_COMP_REC) {
      fs_meta->flags |= TSK_FS_META_FLAG_COMP;
      decmpfs_attr = fs_attr;
    }

    // set the details in the fs_attr structure
    if (tsk_fs_attr_set_str(file, fs_attr, xattr.name.c_str(), type,
                            attribute_counter++, (void*)xattr.data.c_str(),
                            xattr.data.length())) {
      fs_meta->attr_state = TSK_FS_META_ATTR_ERROR;
      return 1;
    }
  }

  // Non-Resident extended attributes
  for (const auto& xattr : jobj->nonres_xattrs()) {
    const auto xobj = obj(xattr.oid);

    if (!xobj.valid()) {
      fs_meta->attr_state = TSK_FS_META_ATTR_ERROR;
      if (tsk_verbose) {
        tsk_fprintf(
            stderr,
            "Error loading non-resident attribute %s with oid %" PRIuINUM "\n",
            xattr.name.c_str(), xattr.oid);
      }
      continue;
    }

    auto fs_attr = tsk_fs_attrlist_getnew(fs_meta->attr, TSK_FS_ATTR_NONRES);
    if (fs_attr == nullptr) {
      fs_meta->attr_state = TSK_FS_META_ATTR_ERROR;
      return 1;
    }

    TSK_FS_ATTR_RUN* data_run_head = nullptr;
    TSK_FS_ATTR_RUN* data_run_last = nullptr;

    // Create the runs
    for (const auto& extent : xobj.extents()) {
      auto data_run = tsk_fs_attr_run_alloc();
      if (data_run == nullptr) {
        fs_meta->attr_state = TSK_FS_META_ATTR_ERROR;
        tsk_fs_attr_run_free(data_run_head);
        return 1;
      }

      data_run->addr = extent.phys;
      data_run->offset = extent.offset / _fsinfo.block_size;
      data_run->len = extent.len / _fsinfo.block_size;
      data_run->crypto_id = extent.crypto_id;
      data_run->flags = TSK_FS_ATTR_RUN_FLAG_NONE;
      data_run->next = nullptr;

      if (extent.phys == 0) {
        data_run->flags |= TSK_FS_ATTR_RUN_FLAG_SPARSE;
      }

      if (extent.crypto_id != 0) {
        data_run->flags |= TSK_FS_ATTR_RUN_FLAG_ENCRYPTED;
      }

      if (data_run_head == nullptr) {
        data_run_head = data_run;
      } else {
        data_run_last->next = data_run;
      }

      data_run_last = data_run;
    }

    const auto type = xattribute_type(xattr.name);

    if (type == TSK_FS_ATTR_TYPE_APFS_COMP_REC) {
      decmpfs_attr = fs_attr;
      fs_meta->flags |= TSK_FS_META_FLAG_COMP;
    } else if (type == TSK_FS_ATTR_TYPE_APFS_RSRC) {
      rsrc_runs = data_run_head;
    }

    // initialize the data run
    if (tsk_fs_attr_set_run(file, fs_attr, data_run_head, xattr.name.c_str(),
                            type, attribute_counter++, xattr.size, xattr.size,
                            xattr.allocated_size, TSK_FS_ATTR_NONRES, 0)) {
      fs_meta->attr_state = TSK_FS_META_ATTR_ERROR;
      tsk_fs_attr_run_free(data_run_head);
      return 1;
    }
  }

  // Compression Stuff
  if (decmpfs_attr != nullptr) {
    // Read the decmpfs data

    if ((size_t)decmpfs_attr->size < sizeof(DECMPFS_DISK_HEADER)) {
      error_returned("APFS load_attrs: decmpfs attr is too small");
      return 1;
    }

    auto buffer = std::make_unique<char[]>(decmpfs_attr->size);

    const auto ret = tsk_fs_attr_read(decmpfs_attr, (TSK_OFF_T)0, buffer.get(),
                                      (size_t)decmpfs_attr->size,
                                      TSK_FS_FILE_READ_FLAG_NONE);

    if (ret == -1) {
      error_returned("APFS load_attrs: reading the compression attribute");
      return 1;
    }

    if (ret < decmpfs_attr->size) {
      error_detected(
          TSK_ERR_FS_READ,
          "APFS load_attrs: could not read the whole compression attribute");
      return 1;
    }

    const auto decmpfs_header =
        reinterpret_cast<DECMPFS_DISK_HEADER*>(buffer.get());
    const auto ct =
        tsk_getu32(TSK_LIT_ENDIAN, decmpfs_header->compression_type);
    const auto uncompressed_size =
        tsk_getu64(TSK_LIT_ENDIAN, decmpfs_header->uncompressed_size);

    switch (ct) {
        // Data is inline. We will load the uncompressed
        // data as a resident attribute.
      case DECMPFS_TYPE_ZLIB_ATTR:
        if (!decmpfs_file_read_zlib_attr(file, buffer.get(), decmpfs_attr->size,
                                         uncompressed_size)) {
          return 1;
        }
        break;

      case DECMPFS_TYPE_LZVN_ATTR:
        if (!decmpfs_file_read_lzvn_attr(file, buffer.get(), decmpfs_attr->size,
                                         uncompressed_size)) {
          return 1;
        }
        break;
      case DECMPFS_TYPE_ZLIB_RSRC:  // fallthrough
      case DECMPFS_TYPE_LZVN_RSRC: {
        if (rsrc_runs == nullptr) {
          error_returned("No resource runs for resource-compressed data");
          return 1;
        }

        auto fs_attr =
            tsk_fs_attrlist_getnew(fs_meta->attr, TSK_FS_ATTR_NONRES);
        if (fs_attr == nullptr) {
          fs_meta->attr_state = TSK_FS_META_ATTR_ERROR;
          return 1;
        }

        if (ct == DECMPFS_TYPE_ZLIB_RSRC) {
#ifdef HAVE_LIBZ
          fs_attr->w = decmpfs_attr_walk_zlib_rsrc;
          fs_attr->r = decmpfs_file_read_zlib_rsrc;
#else
          // We don't have zlib, so the uncompressed data is not
          // available to us; however, we must have a default DATA
          // attribute, or icat will misbehave.
          if (tsk_verbose)
            tsk_fprintf(stderr,
                        "APFS load_attrs: No zlib compression library, so "
                        "setting a zero-length default DATA attribute.\n");

          if (tsk_fs_attr_set_run(file, fs_attr, NULL, "DECOMP",
                                  TSK_FS_ATTR_TYPE_HFS_DATA,
                                  TSK_FS_ATTR_ID_DEFAULT, 0, 0, 0, TSK_FS_ATTR_FLAG_NONE, 0)) {
            error_returned(" - APFS load_attrs (non-file)");
            return 1;
          }
#endif
        } else if (ct == DECMPFS_TYPE_LZVN_RSRC) {
          fs_attr->w = decmpfs_attr_walk_lzvn_rsrc;
          fs_attr->r = decmpfs_file_read_lzvn_rsrc;
        }

        TSK_FS_ATTR_RUN* data_run_head = nullptr;
        TSK_FS_ATTR_RUN* data_run_last = nullptr;

        while (rsrc_runs != nullptr) {
          auto data_run = tsk_fs_attr_run_alloc();
          if (data_run == nullptr) {
            fs_meta->attr_state = TSK_FS_META_ATTR_ERROR;
            tsk_fs_attr_run_free(data_run_head);
            return 1;
          }

          // Copy the resource run
          *data_run = *rsrc_runs;

          if (data_run_head == nullptr) {
            data_run_head = data_run;
          } else {
            data_run_last->next = data_run;
          }

          data_run_last = data_run;
          rsrc_runs = rsrc_runs->next;
        }

        if (tsk_fs_attr_set_run(
                file, fs_attr, data_run_head, "DECOMP",
                TSK_FS_ATTR_TYPE_APFS_DATA, TSK_FS_ATTR_ID_DEFAULT,
                uncompressed_size, uncompressed_size, uncompressed_size,
                TSK_FS_ATTR_FLAG_ENUM(TSK_FS_ATTR_COMP | TSK_FS_ATTR_NONRES),
                0)) {
          fs_meta->attr_state = TSK_FS_META_ATTR_ERROR;
          tsk_fs_attr_run_free(data_run_head);
          return 1;
        }

        break;
      }
    }
  }

  // Mark loaded
  fs_meta->attr_state = TSK_FS_META_ATTR_STUDIED;

  return 0;
} catch (const std::exception& e) {
  tsk_error_reset();
  tsk_error_set_errno(TSK_ERR_FS_GENFS);
  tsk_error_set_errstr("%s", e.what());
  return 1;
}

#define APFS_PRINT_WIDTH   8
typedef struct {
    FILE *hFile;
    int idx;
} APFS_PRINT_ADDR;

static TSK_WALK_RET_ENUM
print_addr_act(TSK_FS_FILE * fs_file, TSK_OFF_T a_off, TSK_DADDR_T addr,
    char *buf, size_t size, TSK_FS_BLOCK_FLAG_ENUM flags, void *ptr)
{
    APFS_PRINT_ADDR *print = (APFS_PRINT_ADDR *)ptr;
    tsk_fprintf(print->hFile, "%" PRIuDADDR " ", addr);
    if (++(print->idx) == APFS_PRINT_WIDTH) {
        tsk_fprintf(print->hFile, "\n");
        print->idx = 0;
    }

    return TSK_WALK_CONT;
}

uint8_t APFSFSCompat::istat(TSK_FS_ISTAT_FLAG_ENUM istat_flags, FILE* hFile,
                            TSK_INUM_T inode_num, TSK_DADDR_T numblock,
                            int32_t sec_skew) const noexcept try {
  tsk_error_reset();

  auto fs = &_fsinfo;
  char buffer[128];

  if (tsk_verbose)
    tsk_fprintf(stderr,
                "APFS istat: inode_num: %" PRIuINUM " numblock: %" PRIu32 "\n",
                inode_num, numblock);

  const auto fs_file = tsk_fs_file_open_meta(fs, nullptr, inode_num);
  if (fs_file == nullptr) {
    error_returned("APFS istat: getting metadata for the file");
    return 1;
  }

  const auto jobj = static_cast<APFSJObject*>(fs_file->meta->content_ptr);

  tsk_fprintf(hFile, "INode Number: %" PRIuINUM, inode_num);
  if (jobj->is_clone()) {
    tsk_fprintf(hFile, " (clone of INode %" PRIuINUM ")",
                jobj->inode().private_id);
  }
  tsk_fprintf(hFile, "\n%sAllocated\n\n",
              (fs_file->meta->flags & TSK_FS_META_FLAG_UNALLOC) ? "Not " : "");

  tsk_fprintf(hFile, "Type:\t%s\n", to_string(fs_file->meta->type));

  tsk_fs_meta_make_ls(fs_file->meta, buffer, sizeof(buffer));
  tsk_fprintf(hFile, "Mode:\t%s\n", buffer);

  tsk_fprintf(hFile, "Size:\t%" PRIdOFF "\n", fs_file->meta->size);

  if (fs_file->meta->link) {
    tsk_fprintf(hFile, "Symbolic link to:\t%s\n", fs_file->meta->link);
  }

  tsk_fprintf(hFile, "owner / group: %" PRIuUID " / %" PRIuGID "\n",
              fs_file->meta->uid, fs_file->meta->gid);

  tsk_fprintf(hFile, "%s: %d\n",
              (fs_file->meta->type == TSK_FS_META_TYPE_DIR)
                  ? "Number of Children"
                  : "Number of Links",
              fs_file->meta->nlink);

  tsk_fprintf(hFile, "\n");

  tsk_fprintf(hFile, "Filename:\t%s\n", jobj->name().c_str());

  const auto bsdflags = jobj->inode().bsdflags;

  tsk_fprintf(hFile, "BSD flags:\t0x%8.8x\n", bsdflags);

  if (bsdflags & 0xFFFF0000) {
    tsk_fprintf(hFile, "Admin flags:\t");
    if (bsdflags & APFS_BSD_FLAG_SF_ARCHIVED) {
      tsk_fprintf(hFile, "archived ");
    }
    if (bsdflags & APFS_BSD_FLAG_SF_IMMUTABLE) {
      tsk_fprintf(hFile, "immutable ");
    }
    if (bsdflags & APFS_BSD_FLAG_SF_APPEND) {
      tsk_fprintf(hFile, "append-only ");
    }
    if (bsdflags & APFS_BSD_FLAG_SF_RESTRICTED) {
      tsk_fprintf(hFile, "restricted ");
    }
    if (bsdflags & APFS_BSD_FLAG_SF_NOUNLINK) {
      tsk_fprintf(hFile, "no-unlink ");
    }
    tsk_fprintf(hFile, "\n");
  }

  if (bsdflags & 0x0000FFFF) {
    tsk_fprintf(hFile, "Owner flags:\t");
    if (bsdflags & APFS_BSD_FLAG_UF_NODUMP) {
      tsk_fprintf(hFile, "no-dump ");
    }
    if (bsdflags & APFS_BSD_FLAG_UF_IMMUTABLE) {
      tsk_fprintf(hFile, "immutable ");
    }
    if (bsdflags & APFS_BSD_FLAG_UF_APPEND) {
      tsk_fprintf(hFile, "append-only ");
    }
    if (bsdflags & APFS_BSD_FLAG_UF_OPAQUE) {
      tsk_fprintf(hFile, "opaque ");
    }
    if (bsdflags & APFS_BSD_FLAG_UF_COMPRESSED) {
      tsk_fprintf(hFile, "compressed ");
    }
    if (bsdflags & APFS_BSD_FLAG_UF_TRACKED) {
      tsk_fprintf(hFile, "tracked ");
    }
    if (bsdflags & APFS_BSD_FLAG_UF_DATAVAULT) {
      tsk_fprintf(hFile, "data-vault ");
    }
    if (bsdflags & APFS_BSD_FLAG_UF_HIDDEN) {
      tsk_fprintf(hFile, "hidden ");
    }
    tsk_fprintf(hFile, "\n");
  }

  auto date_added =
      this->date_added(jobj->inode().parent_id, fs_file->meta->addr);

  if (sec_skew != 0) {
    tsk_fprintf(hFile, "\nAdjusted times:\n");
    if (fs_file->meta->mtime) fs_file->meta->mtime -= sec_skew;
    if (fs_file->meta->atime) fs_file->meta->atime -= sec_skew;
    if (fs_file->meta->ctime) fs_file->meta->ctime -= sec_skew;
    if (fs_file->meta->crtime) fs_file->meta->crtime -= sec_skew;
    if (date_added) date_added -= sec_skew * 1000000000;

    tsk_fprintf(hFile, "Created:\t\t%s\n",
                tsk_fs_time_to_str_subsecs(fs_file->meta->crtime,
                                           fs_file->meta->crtime_nano, buffer));
    tsk_fprintf(hFile, "Content Modified:\t%s\n",
                tsk_fs_time_to_str_subsecs(fs_file->meta->mtime,
                                           fs_file->meta->mtime_nano, buffer));
    tsk_fprintf(hFile, "Attributes Modified:\t%s\n",
                tsk_fs_time_to_str_subsecs(fs_file->meta->ctime,
                                           fs_file->meta->ctime_nano, buffer));
    tsk_fprintf(hFile, "Accessed:\t\t%s\n",
                tsk_fs_time_to_str_subsecs(fs_file->meta->atime,
                                           fs_file->meta->atime_nano, buffer));

    if (date_added) {
      tsk_fprintf(hFile, "Date Added:\t\t%s\n",
                  tsk_fs_time_to_str_subsecs(date_added / 1000000000,
                                             date_added % 1000000000, buffer));
    }

    if (fs_file->meta->mtime) fs_file->meta->mtime += sec_skew;
    if (fs_file->meta->atime) fs_file->meta->atime += sec_skew;
    if (fs_file->meta->ctime) fs_file->meta->ctime += sec_skew;
    if (fs_file->meta->crtime) fs_file->meta->crtime += sec_skew;
    if (date_added) date_added += sec_skew * 1000000000;

    tsk_fprintf(hFile, "\nOriginal times:\n");
  } else {
    tsk_fprintf(hFile, "\nTimes:\n");
  }

  tsk_fprintf(hFile, "Created:\t\t%s\n",
              tsk_fs_time_to_str_subsecs(fs_file->meta->crtime,
                                         fs_file->meta->crtime_nano, buffer));
  tsk_fprintf(hFile, "Content Modified:\t%s\n",
              tsk_fs_time_to_str_subsecs(fs_file->meta->mtime,
                                         fs_file->meta->mtime_nano, buffer));
  tsk_fprintf(hFile, "Attributes Modified:\t%s\n",
              tsk_fs_time_to_str_subsecs(fs_file->meta->ctime,
                                         fs_file->meta->ctime_nano, buffer));
  tsk_fprintf(hFile, "Accessed:\t\t%s\n",
              tsk_fs_time_to_str_subsecs(fs_file->meta->atime,
                                         fs_file->meta->atime_nano, buffer));

  if (date_added) {
    tsk_fprintf(hFile, "Date Added:\t\t%s\n",
                tsk_fs_time_to_str_subsecs(date_added / 1000000000,
                                           date_added % 1000000000, buffer));
  }

  // Force the loading of all attributes.
  (void)tsk_fs_file_attr_get(fs_file);

  const TSK_FS_ATTR* compressionAttr = nullptr;

  /* Print all of the attributes */
  tsk_fprintf(hFile, "\nAttributes: \n");
  if (fs_file->meta->attr != nullptr) {
    // cycle through the attributes
    const auto cnt = tsk_fs_file_attr_getsize(fs_file);
    for (auto i = 0; i < cnt; ++i) {
      const auto fs_attr = tsk_fs_file_attr_get_idx(fs_file, i);

      if (fs_attr == nullptr) {
        continue;
      }

      const auto type = attr_type_name((uint32_t)fs_attr->type);

      // print the layout if it is non-resident
      if (fs_attr->flags & TSK_FS_ATTR_NONRES) {
        // NTFS_PRINT_ADDR print_addr;

        tsk_fprintf(hFile,
                    "Type: %s (%" PRIu32 "-%" PRIu16
                    ")   Name: %s   Non-Resident%s%s%s   size: %" PRIdOFF
                    "  init_size: %" PRIdOFF "\n",
                    type, fs_attr->type, fs_attr->id,
                    (fs_attr->name) ? fs_attr->name : "N/A",
                    (fs_attr->flags & TSK_FS_ATTR_ENC) ? ", Encrypted" : "",
                    (fs_attr->flags & TSK_FS_ATTR_COMP) ? ", Compressed" : "",
                    (fs_attr->flags & TSK_FS_ATTR_SPARSE) ? ", Sparse" : "",
                    fs_attr->size, fs_attr->nrd.initsize);
        if (istat_flags & TSK_FS_ISTAT_RUNLIST) {
          if (tsk_fs_attr_print(fs_attr, hFile)) {
            tsk_fprintf(hFile, "\nError creating run lists\n");
            tsk_error_print(hFile);
            tsk_error_reset();
          }
        }
        else {
            APFS_PRINT_ADDR print_addr;
            print_addr.idx = 0;
            print_addr.hFile = hFile;
            if (tsk_fs_file_walk_type(fs_file, fs_attr->type,
                fs_attr->id,
                TSK_FS_FILE_WALK_FLAG_ENUM((TSK_FS_FILE_WALK_FLAG_AONLY |
                    TSK_FS_FILE_WALK_FLAG_SLACK)),
                print_addr_act, (void *)&print_addr)) {
                tsk_fprintf(hFile, "\nError walking file\n");
                tsk_error_print(hFile);
                tsk_error_reset();
            }
            if (print_addr.idx != 0)
                tsk_fprintf(hFile, "\n");
        }
      } else {
        // Resident attributes
        tsk_fprintf(hFile,
                    "Type: %s (%" PRIu32 "-%" PRIu16
                    ")   Name: %s   Resident%s%s%s   size: %" PRIdOFF "\n",
                    type, fs_attr->type, fs_attr->id,
                    (fs_attr->name) ? fs_attr->name : "N/A",
                    (fs_attr->flags & TSK_FS_ATTR_ENC) ? ", Encrypted" : "",
                    (fs_attr->flags & TSK_FS_ATTR_COMP) ? ", Compressed" : "",
                    (fs_attr->flags & TSK_FS_ATTR_SPARSE) ? ", Sparse" : "",
                    fs_attr->size);
      }

      if (fs_attr->type == TSK_FS_ATTR_TYPE_APFS_COMP_REC) {
        if (compressionAttr == nullptr) {
          compressionAttr = fs_attr;
        } else {
          // Problem:  there is more than one compression attribute
          error_detected(TSK_ERR_FS_CORRUPT,
                         "APFS istat: more than one compression attribute");
          return 1;
        }
      }
    }
  }

  if ((bsdflags & APFS_BSD_FLAG_UF_COMPRESSED) &&
      (compressionAttr == nullptr)) {
    tsk_fprintf(hFile,
                "WARNING: Compression Flag is set, but there"
                " is no compression record for this file.\n");
  }

  if (((bsdflags & APFS_BSD_FLAG_UF_COMPRESSED) == 0) &&
      (compressionAttr != nullptr)) {
    tsk_fprintf(hFile,
                "WARNING: Compression Flag is NOT set, but there"
                " is a compression record for this file.\n");
  }

  // TODO(JTS): compression stuff

  tsk_fs_file_close(fs_file);
  return 0;
} catch (const std::exception& e) {
  tsk_error_reset();
  tsk_error_set_errno(TSK_ERR_FS_GENFS);
  tsk_error_set_errstr("%s", e.what());
  return 1;
}

uint8_t tsk_apfs_istat(TSK_FS_FILE* fs_file, apfs_istat_info* info) try {
  if (fs_file == nullptr) {
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_ARG);
    tsk_error_set_errstr("tsk_apfs_istat: Null fs_file");
    return 1;
  }

  if (info == nullptr) {
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_ARG);
    tsk_error_set_errstr("tsk_apfs_istat: Null info");
    return 1;
  }

  memset(info, 0, sizeof(*info));

  const auto jobj = static_cast<APFSJObject*>(fs_file->meta->content_ptr);

  if (jobj->is_clone()) {
    info->cloned_inum = jobj->inode().private_id;
  }

  info->bsdflags = jobj->inode().bsdflags;

  const auto& fs = to_fs(fs_file->fs_info);

  info->date_added =
      fs.date_added(jobj->inode().parent_id, fs_file->meta->addr);

  return 0;

} catch (const std::exception& e) {
  tsk_error_reset();
  tsk_error_set_errno(TSK_ERR_FS_GENFS);
  tsk_error_set_errstr("%s", e.what());
  return 1;
}

/* Returns TSK_FS_BLOCK_FLAG_UNALLOC if the addr corresponds to an address
 * stored in the unallocated ranges for the pool and TSK_FS_BLOCK_FLAG_ALLOC
 * otherwise. Note that TSK_FS_BLOCK_FLAG_ALLOC does not mean the block belongs
 * to the current file system, just that one of the volumes in the pool or the pool
 * itself is using it.
 */
TSK_FS_BLOCK_FLAG_ENUM APFSFSCompat::block_getflags(TSK_FS_INFO* fs, TSK_DADDR_T addr) {

    TSK_FS_FILE *fs_file;
    int result;

    if (fs->img_info->itype != TSK_IMG_TYPE_POOL) {
        // No way to return an error
        return TSK_FS_BLOCK_FLAG_UNALLOC;
    }

    IMG_POOL_INFO *pool_img = (IMG_POOL_INFO*)fs->img_info;
    const APFSPoolCompat* pool = static_cast<APFSPoolCompat*>(pool_img->pool_info->impl);

    // Check if the given addr is contained in an unallocated range
    for (const TSKPool::range &range : pool->nx()->unallocated_ranges()) {
        if (range.start_block < addr
            && (range.start_block + range.num_blocks > addr)) {
            return TSK_FS_BLOCK_FLAG_UNALLOC;
        }
    }
    return TSK_FS_BLOCK_FLAG_ALLOC;
}

uint8_t APFSFSCompat::block_walk(TSK_FS_INFO * fs, TSK_DADDR_T start, TSK_DADDR_T end,
    TSK_FS_BLOCK_WALK_FLAG_ENUM flags, TSK_FS_BLOCK_WALK_CB cb,
    void *ptr) {

    TSK_FS_BLOCK *fs_block;
    TSK_DADDR_T addr;

    // clean up any error messages that are lying around
    tsk_error_reset();

    /*
    * Sanity checks.
    */
    if (start < fs->first_block || start > fs->last_block) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("APFSFSCompat::block_walk: start block: %" PRIuDADDR,
            start);
        return 1;
    }
    if (end < fs->first_block || end > fs->last_block
        || end < start) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("APFSFSCompat::block_walk: end block: %" PRIuDADDR,
            end);
        return 1;
    }

    /* Sanity check on a_flags -- make sure at least one ALLOC is set */
    if (((flags & TSK_FS_BLOCK_WALK_FLAG_ALLOC) == 0) &&
        ((flags & TSK_FS_BLOCK_WALK_FLAG_UNALLOC) == 0)) {
        flags = (TSK_FS_BLOCK_WALK_FLAG_ENUM)
            (flags | TSK_FS_BLOCK_WALK_FLAG_ALLOC |
                TSK_FS_BLOCK_WALK_FLAG_UNALLOC);
    }
    if (((flags & TSK_FS_BLOCK_WALK_FLAG_META) == 0) &&
        ((flags & TSK_FS_BLOCK_WALK_FLAG_CONT) == 0)) {
        flags = (TSK_FS_BLOCK_WALK_FLAG_ENUM)
            (flags | TSK_FS_BLOCK_WALK_FLAG_CONT | TSK_FS_BLOCK_WALK_FLAG_META);
    }

    /* Allocate memory for a block */
    if ((fs_block = tsk_fs_block_alloc(fs)) == NULL) {
        return 1;
    }

    for (addr = start; addr <= end; addr++) {
        int retval;

        /* If we're getting both alloc and unalloc, no need to load and
         * check the flags here */
        if (((flags & TSK_FS_BLOCK_WALK_FLAG_ALLOC) == 0) ||
            ((flags & TSK_FS_BLOCK_WALK_FLAG_UNALLOC) == 0)) {

            int myflags = fs->block_getflags(fs, addr);

            // Test if we should call the callback with this one
            if ((myflags & TSK_FS_BLOCK_FLAG_ALLOC)
                && (!(flags & TSK_FS_BLOCK_WALK_FLAG_ALLOC)))
                continue;
            else if ((myflags & TSK_FS_BLOCK_FLAG_UNALLOC)
                && (!(flags & TSK_FS_BLOCK_WALK_FLAG_UNALLOC)))
                continue;
        }

        /* Get the block */
        if (tsk_fs_block_get(fs, fs_block, addr) == NULL) {
            tsk_error_set_errstr2("APFSFSCompat::block_walk: block %" PRIuDADDR,
                addr);
            tsk_fs_block_free(fs_block);
            return 1;
        }

        /* Run the callback on the block */
        retval = cb(fs_block, ptr);
        if (retval == TSK_WALK_STOP) {
            break;
        }
        else if (retval == TSK_WALK_ERROR) {
            tsk_fs_block_free(fs_block);
            return 1;
        }
    }
    /*
    * Cleanup.
    */
    tsk_fs_block_free(fs_block);

    return TSK_OK;
}

uint8_t APFSFSCompat::decrypt_block(TSK_DADDR_T block_num, void* data) noexcept {
#ifdef HAVE_LIBOPENSSL
    try {
        if (_crypto.decryptor) {
            _crypto.decryptor->decrypt_buffer(data, APFS_BLOCK_SIZE,
                block_num * APFS_BLOCK_SIZE);

            return 0;
        }

        return 1;
    }
    catch (const std::exception& e) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_GENFS);
        tsk_error_set_errstr("%s", e.what());
        return 1;
    }
#else
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_GENFS);
    tsk_error_set_errstr("decrypt_block: crypto library not loaded");
    return 1;
#endif
}

int APFSFSCompat::name_cmp(const char* s1, const char* s2) const noexcept try {
#ifdef HAVE_LIBOPENSSL
    const APFSFileSystem vol{ fs_info_to_pool(&_fsinfo), to_pool_vol_block(&_fsinfo),
                           _crypto.password};
#else
    const APFSFileSystem vol{ fs_info_to_pool(&_fsinfo), to_pool_vol_block(&_fsinfo)};
#endif

  if (vol.case_sensitive()) {
    return strcmp(s1, s2);
  }

  return strcasecmp(s1, s2);
} catch (const std::exception& e) {
  tsk_error_reset();
  tsk_error_set_errno(TSK_ERR_FS_GENFS);
  tsk_error_set_errstr("%s", e.what());
  return 1;
}

uint8_t tsk_apfs_list_snapshots(TSK_FS_INFO* fs_info,
                                apfs_snapshot_list** list) try {
  if (fs_info == nullptr) {
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_ARG);
    tsk_error_set_errstr("tsk_apfs_list_snapshots: Null fs_info");
    return 1;
  }

  if (list == nullptr) {
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_ARG);
    tsk_error_set_errstr("tsk_apfs_list_snapshots: Null list");
    return 1;
  }

  const auto snapshots =
      APFSFileSystem{ fs_info_to_pool(fs_info), to_pool_vol_block(fs_info)}
          .snapshots();

  *list = (apfs_snapshot_list*)tsk_malloc(
      sizeof(apfs_snapshot_list) + sizeof(apfs_snapshot) * snapshots.size());

  (*list)->num_snapshots = snapshots.size();

  for (size_t i = 0; i < snapshots.size(); i++) {
    const auto& snapshot = snapshots[i];
    auto& dest = (*list)->snapshots[i];
    dest.snap_xid = snapshot.snap_xid;
    dest.timestamp = snapshot.timestamp;
    dest.name = new char[snapshot.name.length() + 1];
    snapshot.name.copy(dest.name, snapshot.name.length());
    dest.name[snapshot.name.length()] = 0;
    dest.dataless = snapshot.dataless ? 1 : 0;
  }

  return 0;
} catch (const std::exception& e) {
  tsk_error_reset();
  tsk_error_set_errno(TSK_ERR_FS_GENFS);
  tsk_error_set_errstr("%s", e.what());
  return 1;
}

uint8_t tsk_apfs_free_snapshot_list(apfs_snapshot_list* list) try {
  if (list == nullptr) {
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_ARG);
    tsk_error_set_errstr("tsk_apfs_free_snapshot_list: Null list");
    return 1;
  }

  for (auto i = 0; i < list->num_snapshots; i++) {
    auto& snapshot = list->snapshots[i];
    delete[] snapshot.name;
  }

  free(list);

  return 0;
} catch (const std::exception& e) {
  tsk_error_reset();
  tsk_error_set_errno(TSK_ERR_FS_GENFS);
  tsk_error_set_errstr("%s", e.what());
  return 1;
}

uint8_t tsk_apfs_set_snapshot(TSK_FS_INFO* fs_info, uint64_t snap_xid) try {
  if (fs_info == nullptr) {
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_ARG);
    tsk_error_set_errstr("tsk_apfs_set_snapshot: Null fs_info");
    return 1;
  }

  to_fs(fs_info).set_snapshot(snap_xid);

  return 0;
} catch (const std::exception& e) {
  tsk_error_reset();
  tsk_error_set_errno(TSK_ERR_FS_GENFS);
  tsk_error_set_errstr("%s", e.what());
  return 1;
}
void APFSFSCompat::date_added_cache::populate(uint64_t pid) noexcept {
  _cache.clear();
  _last_parent = pid;

  tsk_fs_dir_walk(
      _fs, pid, TSK_FS_DIR_WALK_FLAG_NONE,
      [](TSK_FS_FILE* file, const char*, void* a) -> TSK_WALK_RET_ENUM {
        auto& cache = *static_cast<std::unordered_map<uint64_t, uint64_t>*>(a);
        cache[file->name->meta_addr] = file->name->date_added;
        return TSK_WALK_CONT;
      },
      &_cache);
}

uint64_t APFSFSCompat::date_added_cache::lookup(uint64_t parent_id,
                                                uint64_t inode_num) noexcept {
  if (parent_id < APFS_ROOT_INODE_NUM) {
    return 0;
  }

  if (_last_parent != parent_id) {
    populate(parent_id);
  }

  try {
    return _cache[inode_num];
  } catch (...) {
    // Something went wrong
    return 0;
  }
}
