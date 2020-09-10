#pragma once

#include "../util/crypto.hpp"
#include "apfs_fs.h"
#include "tsk_apfs.hpp"

class APFSJObject {
  using jit = APFSJObjBtreeNode::iterator;
  using child_entry = struct {
    std::string name;
    apfs_dir_record rec;
  };
  using extent = struct {
    uint64_t offset;
    uint64_t phys;
    uint64_t len;
    uint64_t crypto_id;
  };

  using inline_xattr = struct {
    std::string name;
    std::string data;
  };

  using nonres_xattr = struct {
    std::string name;
    uint64_t oid;
    uint64_t size;
    uint64_t allocated_size;
    uint64_t crypto_id;
  };

  apfs_inode _inode{};
  std::vector<child_entry> _children{};
  std::vector<extent> _extents{};
  std::vector<inline_xattr> _inline_xattrs{};
  std::vector<nonres_xattr> _nonres_xattrs{};

  std::string _name{};
  uint64_t _size{};
  uint64_t _size_on_disk{};
  bool _is_clone{};

  void add_entry(const jit::value_type &);

 public:
  using key_type = APFSJObjKey;

  APFSJObject() = default;

  APFSJObject(const std::pair<jit, jit> &);
  APFSJObject(const jit &, const jit &);

  APFSJObject(const APFSJObject &) = default;
  APFSJObject &operator=(const APFSJObject &) = default;

  APFSJObject(APFSJObject &&) = default;
  APFSJObject &operator=(APFSJObject &&) = default;

  inline bool valid() const noexcept {
    return _inode.private_id != 0 || !_extents.empty();
  }

  inline auto child_count() const noexcept { return _children.size(); }

  inline const apfs_inode &inode() const noexcept { return _inode; }

  inline const std::string &name() const noexcept { return _name; }

  inline const std::vector<extent> &extents() const noexcept {
    return _extents;
  }

  inline const std::vector<inline_xattr> &inline_xattrs() const noexcept {
    return _inline_xattrs;
  }

  inline const std::vector<nonres_xattr> &nonres_xattrs() const noexcept {
    return _nonres_xattrs;
  }

  inline const std::vector<child_entry> &children() const noexcept {
    return _children;
  }

  inline uint64_t size() const noexcept { return _size; }

  inline uint64_t size_on_disk() const noexcept { return _size_on_disk; }

  inline bool is_clone() const noexcept { return _is_clone; }
};

class APFSJObjTree {
  using jit = APFSJObjBtreeNode::iterator;

 protected:
  struct crypto {
#ifdef HAVE_LIBOPENSSL
    std::unique_ptr<aes_xts_decryptor> decryptor{};
#endif
    std::unique_ptr<uint8_t[]> key{};
    std::string password{};
    crypto(const APFSFileSystem::crypto_info_t &crypto);
  } _crypto;
  APFSObjectBtreeNode _obj_root;
  APFSJObjBtreeNode _jobj_root;
  uint64_t _root_tree_oid;

  inline auto jobjs(uint64_t oid) const {
    return _jobj_root.find_range(
        oid, [](const auto &key, const auto &b) noexcept->int64_t {
          const auto akey = key.template as<APFSJObject::key_type>();

          return akey->oid() - b;
        });
  }

  APFSJObjTree(const APFSFileSystem &vol);

 public:
  APFSJObjTree(const APFSPool &pool, apfs_block_num obj_omap,
               uint64_t root_tree_oid,
               const APFSFileSystem::crypto_info_t &crypto);

  APFSJObjTree(APFSJObjTree &&) = default;

  inline APFSJObject obj(uint64_t oid) const { return {jobjs(oid)}; }

  void set_snapshot(uint64_t snap_xid);

  // iterator stuff
  class iterator;

  iterator begin() const;
  iterator end() const;
};

class APFSJObjTree::iterator {
 public:
  using iterator_category = std::forward_iterator_tag;
  using difference_type = uint32_t;
  using value_type = APFSJObject;
  using reference = const value_type &;
  using pointer = const value_type *;

 protected:
  const APFSJObjTree *_tree;
  jit _next;
  APFSJObject _jobj;

  iterator(const APFSJObjTree *tree) noexcept;
  iterator(const APFSJObjTree *tree, uint64_t oid);

 public:
  iterator() = default;

  iterator(const iterator &) = default;
  iterator &operator=(const iterator &) = default;

  iterator(iterator &&) = default;
  iterator &operator=(iterator &&) = default;

  inline reference operator*() const noexcept { return _jobj; }

  inline pointer operator->() const noexcept { return &_jobj; }

  iterator &operator++();

  inline value_type operator++(int) {
    value_type copy{_jobj};
    this->operator++();
    return copy;
  }

  inline bool operator==(const iterator &rhs) const noexcept {
    return (_tree == rhs._tree && _next == rhs._next);
  }

  inline bool operator!=(const iterator &rhs) const noexcept {
    return !this->operator==(rhs);
  }

  friend APFSJObjTree;
};
