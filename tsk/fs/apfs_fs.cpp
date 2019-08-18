#include <cstring>

#include "apfs_fs.hpp"

APFSJObjTree::APFSJObjTree(const APFSPool& pool, apfs_block_num obj_omap,
                           uint64_t root_tree_oid,
                           const APFSFileSystem::crypto_info_t& crypto)
    : _crypto{crypto},
      _obj_root{pool, obj_omap},
      _jobj_root{&_obj_root, _obj_root.find(root_tree_oid)->value->paddr,
                 _crypto.key.get()},
      _root_tree_oid{root_tree_oid} {}

APFSJObjTree::APFSJObjTree(const APFSFileSystem& vol)
    : APFSJObjTree{vol.pool(),
                   APFSOmap{vol.pool(), vol.fs()->omap_oid}.root_block(),
                   vol.rdo(), vol.crypto_info()} {}

void APFSJObjTree::set_snapshot(uint64_t snap_xid) {
  _obj_root.snapshot(snap_xid);

  // This type isn't copyable or moveable, so we have to use in-place allocation
  // TODO(JTS): Refactor APFSObjects so that they can be move assigned
  _jobj_root.~APFSJObjBtreeNode();
#ifdef HAVE_LIBOPENSSL
  new (&_jobj_root) APFSJObjBtreeNode(
      &_obj_root, _obj_root.find(_root_tree_oid)->value->paddr,
      _crypto.key.get());
#else
  new (&_jobj_root) APFSJObjBtreeNode(
      &_obj_root, _obj_root.find(_root_tree_oid)->value->paddr, nullptr);
#endif
}

APFSJObjTree::crypto::crypto(const APFSFileSystem::crypto_info_t& crypto) {
  if (crypto.unlocked) {
    key = std::make_unique<uint8_t[]>(0x20);
    std::memcpy(key.get(), crypto.vek, 0x20);
    password = crypto.password;

#ifdef HAVE_LIBOPENSSL
    decryptor = std::make_unique<aes_xts_decryptor>(
        aes_xts_decryptor::AES_128, key.get(), nullptr, APFS_CRYPTO_SW_BLKSIZE);
#endif
  }
}

APFSJObject::APFSJObject(const std::pair<jit, jit>& jobjs)
    : APFSJObject(jobjs.first, jobjs.second) {}

APFSJObject::APFSJObject(const jit& start, const jit& end) {
  std::for_each(start, end, [this](const auto& it) { this->add_entry(it); });
}

void APFSJObject::add_entry(const jit::value_type& e) {
  const auto key = e.key.template as<key_type>();

  switch (key->type()) {
    // Inode records
    case APFS_JOBJTYPE_INODE: {
      const auto value = e.value.template as<apfs_inode>();
      _inode = *value;

      // If the private_id is not the same as the oid then we're a clone
      _is_clone = (_inode.private_id != key->oid());

      // If there's more data than the size of the inode then we have xdata
      if ((size_t)e.value.count() > sizeof(apfs_inode)) {
        // The xfield headers are right after the inode
        const auto xfield = reinterpret_cast<const apfs_xfield*>(value + 1);

        // The xfield data is after all of the xfield headers
        auto xfield_data =
            reinterpret_cast<const char*>(&xfield->entries[xfield->num_exts]);

        for (auto i = 0U; i < xfield->num_exts; i++) {
          const auto& ext = xfield->entries[i];

          switch (ext.type) {
            case APFS_XFIELD_TYPE_NAME:
              _name = std::string(xfield_data);
              break;
            case APFS_XFIELD_TYPE_DSTREAM: {
              const auto ds =
                  reinterpret_cast<const apfs_dstream*>(xfield_data);

              _size = ds->size;
              _size_on_disk = ds->alloced_size;
              break;
            }
          }

          // The next data needs to be aligned properly
          xfield_data += (ext.len + 7) & 0xFFF8;
        }
      }
      break;
    }

    // Directory records
    case APFS_JOBJTYPE_DIR_RECORD: {
#pragma pack(push, 1)
      struct dir_record_key : key_type {
        uint32_t namelen_and_hash;
        char name[0];

        inline uint32_t name_len() const noexcept {
          return bitfield_value(namelen_and_hash, 10, 0);
        }

        inline uint32_t hash() const noexcept {
          return bitfield_value(namelen_and_hash, 22, 10);
        }
      };
#pragma pack(pop)
      static_assert(sizeof(dir_record_key) == 0x0C, "invalid struct padding");

      const auto k = e.key.template as<dir_record_key>();
      const auto value = e.value.template as<apfs_dir_record>();

      _children.emplace_back(
          child_entry{std::string(k->name, k->name_len() - 1U), *value});
      break;
    }

    // File extents
    case APFS_JOBJTYPE_FILE_EXTENT: {
      struct file_extent_key : key_type {
        uint64_t offset;
      };

      const auto k = e.key.template as<file_extent_key>();
      const auto value = e.value.template as<apfs_file_extent>();
      const auto len =
          bitfield_value(value->len_and_flags, APFS_FILE_EXTENT_LEN_BITS,
                         APFS_FILE_EXTENT_LEN_SHIFT);

      _extents.emplace_back(extent{k->offset, value->phys, len, value->crypto});

      break;
    }

    // Extended Attributes
    case APFS_JOBJTYPE_XATTR: {
      struct xattr_key : key_type {
        uint16_t name_len;
        char name[0];
      };

      const auto k = e.key.template as<xattr_key>();
      const auto value = e.value.template as<apfs_xattr>();

      if (value->flags & APFS_XATTR_FLAG_INLINE) {
#pragma pack(push, 1)
        struct ixattr : apfs_xattr {
          char data[0];
        };
#pragma pack(pop)

        const auto ix = e.value.template as<ixattr>();
        _inline_xattrs.emplace_back(inline_xattr{{k->name, k->name_len - 1U},
                                                 {ix->data, ix->xdata_len}});
        break;
      }

// Non-Resident XATTRs
#pragma pack(push, 1)
      struct nrattr : apfs_xattr {
        uint64_t xattr_obj_id;
        apfs_dstream dstream;
      };
#pragma pack(pop)
      static_assert(sizeof(nrattr) == 0x34, "misaligned structure");

      const auto nrx = e.value.template as<nrattr>();

      _nonres_xattrs.emplace_back(nonres_xattr{{k->name, k->name_len - 1U},
                                               nrx->xattr_obj_id,
                                               nrx->dstream.size,
                                               nrx->dstream.alloced_size,
                                               nrx->dstream.default_crypto_id});

      break;
    }
  };
}

APFSJObjTree::iterator APFSJObjTree::begin() const {
  return {this, APFS_ROOT_INODE_NUM};
}

APFSJObjTree::iterator APFSJObjTree::end() const { return {this}; }

APFSJObjTree::iterator::iterator(const APFSJObjTree* tree, uint64_t oid)
    : _tree{tree} {
  auto range = tree->jobjs(oid);
  _jobj = {range};
  _next = std::move(range.second);
}

APFSJObjTree::iterator::iterator(const APFSJObjTree* tree) noexcept
    : _tree{tree} {}

APFSJObjTree::iterator& APFSJObjTree::iterator::operator++() {
  if (_next == _tree->_jobj_root.end()) {
    _next = {};
    _jobj = {};
    return (*this);
  }

  const auto key = _next->key.template as<APFSJObject::key_type>();

  auto end = std::find_if(
      _next,
      _tree->_jobj_root.end(), [oid = key->oid()](const auto& it) noexcept {
        const auto key = it.key.template as<APFSJObject::key_type>();
        return key->oid() > oid;
      });

  _jobj = {_next, end};
  _next = std::move(end);

  return (*this);
}
