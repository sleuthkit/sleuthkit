#pragma once

#include "../base/tsk_base.h"
#include "../img/tsk_img.h"
#include "../pool/tsk_apfs.hpp"
#include "../util/lw_shared_ptr.hpp"
#include "../util/span.hpp"

#include "tsk_apfs.h"

#include <algorithm>
#include <array>
#include <memory>
#include <mutex>
#include <new>
#include <stack>
#include <stdexcept>
#include <type_traits>
#include <vector>

#include "../auto/guid.h"

// Helper function to see if a bitfield flag is set
template <typename T, typename U,
          typename = std::enable_if_t<std::numeric_limits<T>::is_integer &&
                                      std::numeric_limits<U>::is_integer>>
constexpr bool bit_is_set(T bitfield, U bitmask) noexcept {
  return ((bitfield & static_cast<T>(bitmask)) != 0);
}

// Helper function to extract bitfield value
template <typename T,
          typename = std::enable_if_t<std::numeric_limits<T>::is_integer>>
constexpr T bitfield_value(T bitfield, int bits, int shift) noexcept {
  return (bitfield >> shift) & ((T{1} << bits) - 1);
}

class APFSPool;

class APFSObject : public APFSBlock {
 protected:
  inline const apfs_obj_header *obj() const noexcept {
    return reinterpret_cast<const apfs_obj_header *>(_storage.data());
  }

 public:
  // Use the constructors from APFSBlock
  using APFSBlock::APFSBlock;

  bool validate_checksum() const noexcept;

  inline APFS_OBJ_TYPE_ENUM obj_type() const noexcept {
    return APFS_OBJ_TYPE_ENUM(obj()->type);
  }

  inline uint32_t obj_type_and_flags() const noexcept {
    return obj()->type_and_flags;
  }

  inline uint64_t oid() const noexcept { return obj()->oid; }

  inline uint64_t xid() const noexcept { return obj()->xid; }

  inline uint32_t subtype() const noexcept { return obj()->subtype; }
};

class APFSOmap : public APFSObject {
 protected:
  inline const apfs_omap *omap() const noexcept {
    return reinterpret_cast<const apfs_omap *>(_storage.data());
  }

 public:
  // Use constructors from APFSObject
  using APFSObject::APFSObject;

  APFSOmap(const APFSPool &pool, const apfs_block_num block_num);

  inline uint32_t snapshot_count() const noexcept {
    return omap()->snapshot_count;
  }

  inline APFS_OMAP_TREE_TYPE_ENUM tree_type() const noexcept {
    return APFS_OMAP_TREE_TYPE_ENUM(omap()->tree_type);
  }

  inline apfs_block_num root_block() const noexcept { return omap()->tree_oid; }

  struct node_tag {};  ///< Tag used to identify OMAP nodes

  template <typename T,
            typename = std::enable_if_t<std::is_base_of<node_tag, T>::value>>
  T root() const {
    return {_pool, root_block()};
  }
};

class APFSJObjBtreeNode;

template <typename Node>
class APFSBtreeNodeIterator {
 public:
  using iterator_category = std::forward_iterator_tag;
  using difference_type = uint32_t;
  using value_type = struct {
    typename Node::key_type key;
    typename Node::value_type value;
  };
  using reference = const value_type &;
  using pointer = const value_type *;

 protected:
  lw_shared_ptr<Node> _node{};
  uint32_t _index{0};

  // Leaf nodes will have values and non-leaf nodes will have iterators
  // to the child node.
  //
  // TODO(JTS): If we ever switch to c++17 then we can use a std::variant
  std::unique_ptr<typename Node::iterator> _child_it{};
  value_type _val{};

  inline lw_shared_ptr<Node> own_node(const Node *node) {
    return own_node(node, node->block_num());
  }

  inline lw_shared_ptr<Node> own_node(const Node *node,
                                      apfs_block_num block_num) {
    return node->_pool.template get_block<Node>(
        block_num, node->_pool, block_num, node->_decryption_key);
  }

  template <typename Void = void>
  auto init_value()
      -> std::enable_if_t<Node::is_variable_kv_node::value, Void> {
    if (this->_node->has_fixed_kv_size()) {
      throw std::runtime_error("btree does not have variable sized keys");
    }
    const auto &t = _node->_table_data.toc.variable[_index];
    const auto key_data = _node->_table_data.koff + t.key_offset;
    const auto val_data = _node->_table_data.voff - t.val_offset;

    memory_view key{key_data, t.key_length};

    if (_node->is_leaf()) {
      memory_view value{val_data, t.val_length};

      _val = {key, value};
    } else {
      const auto block_num = *((apfs_block_num *)val_data);

      _child_it = std::make_unique<typename Node::iterator>(
          own_node(_node.get(), block_num), 0);
    }
  }

  template <typename Void = void>
  auto init_value() -> std::enable_if_t<Node::is_fixed_kv_node::value, Void> {
    if (!this->_node->has_fixed_kv_size()) {
      throw std::runtime_error("btree does not have fixed sized keys");
    }
    const auto &t = _node->_table_data.toc.fixed[_index];
    const auto key_data = _node->_table_data.koff + t.key_offset;
    const auto val_data = _node->_table_data.voff - t.val_offset;

    if (_node->is_leaf()) {
      _val = {(typename Node::key_type)key_data,
              (typename Node::value_type)val_data};
    } else {
      const auto block_num = *((apfs_block_num *)val_data);

      _child_it = std::make_unique<typename Node::iterator>(
          own_node(_node.get(), block_num), 0);
    }
  }

 public:
  // Forward iterators must be DefaultConstructible
  APFSBtreeNodeIterator() = default;

  APFSBtreeNodeIterator(const Node *node, uint32_t index);

  APFSBtreeNodeIterator(lw_shared_ptr<Node> &&node, uint32_t index);

  APFSBtreeNodeIterator(const Node *node, uint32_t index,
                        typename Node::iterator &&child);

  virtual ~APFSBtreeNodeIterator() = default;

  APFSBtreeNodeIterator(const APFSBtreeNodeIterator &rhs) noexcept
      : _node{rhs._node}, _index{rhs._index} {
    if (_node->is_leaf()) {
      _val = rhs._val;
    } else if (rhs._child_it != nullptr) {
      _child_it = std::make_unique<typename Node::iterator>(*rhs._child_it);
    }
  }

  APFSBtreeNodeIterator &operator=(const APFSBtreeNodeIterator &rhs) noexcept {
    if (this != &rhs) {
      this->~APFSBtreeNodeIterator();
      new (this) APFSBtreeNodeIterator(rhs);
    }

    return (*this);
  };

  APFSBtreeNodeIterator(APFSBtreeNodeIterator &&rhs) noexcept
      : _node{std::move(rhs._node)}, _index{std::move(rhs._index)} {
    if (_node->is_leaf()) {
      _val = std::move(rhs._val);
    } else {
      _child_it = std::move(rhs._child_it);
    }
  };

  APFSBtreeNodeIterator &operator=(APFSBtreeNodeIterator &&rhs) noexcept {
    if (this != &rhs) {
      this->~APFSBtreeNodeIterator();
      new (this)
          APFSBtreeNodeIterator(std::forward<APFSBtreeNodeIterator>(rhs));
    }

    return (*this);
  }

  bool is_valid() const noexcept {
    if (_node == nullptr) {
      return false;
    }

    return (_index < _node->key_count());
  }

  reference operator*() const noexcept {
    if (_index >= _node->key_count()) {
      return _val;
    }

    // Leaf nodes return the value
    if (_node->is_leaf()) {
      return _val;
    }

    // Non-Leaf nodes return the pointer
    return _child_it->operator*();
  }

  pointer operator->() const noexcept {
    if (_index >= _node->key_count()) {
      return nullptr;
    }

    // Leaf nodes return the value
    if (_node->is_leaf()) {
      return &_val;
    }

    // Non-Leaf nodes return the pointer
    return _child_it->operator->();
  }

  virtual APFSBtreeNodeIterator &operator++() {
    // If we're a leaf node then we just need to iterate the count
    if (_node->is_leaf()) {
      if (_index < _node->key_count()) {
        _index++;

        auto node{std::move(_node)};
        auto index{_index};

        this->~APFSBtreeNodeIterator();
        new (this) APFSBtreeNodeIterator(std::move(node), index);
      }
      return (*this);
    }

    _child_it->operator++();

    if (*_child_it != _child_it->_node->end()) {
      return (*this);
    }

    _index++;

    auto node{std::move(_node)};
    auto index{_index};

    this->~APFSBtreeNodeIterator();
    new (this) APFSBtreeNodeIterator(std::move(node), index);

    return (*this);
  }

  APFSBtreeNodeIterator operator++(int) {
    APFSBtreeNodeIterator it{(*this)};

    this->operator++();

    return it;
  }

  bool operator==(const APFSBtreeNodeIterator &rhs) const noexcept {
    // Self check
    if (this == &rhs) {
      return true;
    }

    // If only one of the nodes is nullptr then we're not a match, but if they
    // both are then we are a match
    if (_node == nullptr || rhs._node == nullptr) {
      return (_node == rhs._node);
    }

    // Ensure we have equivalent nodes and indexes
    if (*_node != *rhs._node || _index != rhs._index) {
      return false;
    }

    // If we're leaves then we're good.
    if (_node->is_leaf()) {
      return true;
    }

    // Otherwise, let's compare the child iterators.
    return (*_child_it == *rhs._child_it);
  }

  bool operator!=(const APFSBtreeNodeIterator &rhs) const noexcept {
    return !this->operator==(rhs);
  }

  friend Node;
  friend APFSJObjBtreeNode;
};

template <typename Key = memory_view, typename Value = memory_view>
class APFSBtreeNode : public APFSObject, public APFSOmap::node_tag {
  using is_variable_kv_node = std::is_same<APFSBtreeNode, APFSBtreeNode<>>;
  using is_fixed_kv_node =
      std::integral_constant<bool, !is_variable_kv_node::value>;

  using key_type =
      std::conditional_t<is_variable_kv_node::value, Key, const Key *>;
  using value_type =
      std::conditional_t<is_variable_kv_node::value, Value, const Value *>;
  ;

 protected:
  struct {
    union {
      void *v;
      apfs_btentry_fixed *fixed;
      apfs_btentry_variable *variable;
    } toc;
    char *voff;
    char *koff;
  } _table_data;

  const uint8_t *_decryption_key{};

  inline const apfs_btree_node *bn() const noexcept {
    return reinterpret_cast<const apfs_btree_node *>(_storage.data());
  }

  inline ptrdiff_t toffset() const noexcept {
    // The table space offset is relative to the end of the header
    return sizeof(apfs_btree_node) + bn()->table_space_offset;
  }

  inline ptrdiff_t koffset() const noexcept {
    // The keys table is immediately after the table space.
    return toffset() + bn()->table_space_length;
  }

  inline ptrdiff_t voffset() const noexcept {
    // The value table is a negative index relative to the end of the block
    // unless the node is a root node then it's relative to the footer
    ptrdiff_t off = _pool.block_size();

    if (is_root()) {
      off -= sizeof(apfs_btree_info);
    }

    return off;
  }

  template <typename KeyType = key_type>
  inline auto key(uint32_t index) const
      -> std::enable_if_t<is_variable_kv_node::value, KeyType> {
    const auto &t = _table_data.toc.variable[index];
    const auto key_data = _table_data.koff + t.key_offset;

    return {key_data, t.key_length};
  }

  template <typename KeyType = key_type>
  inline auto key(uint32_t index) const
      -> std::enable_if_t<is_fixed_kv_node::value, KeyType> {
    const auto &t = _table_data.toc.fixed[index];
    const auto key_data = _table_data.koff + t.key_offset;

    return reinterpret_cast<KeyType>(key_data);
  }

  template <typename Compare>
  inline uint32_t contains_key(const key_type &key, Compare comp) const {
    for (auto i = 0U; i < key_count(); i++) {
      const auto k = this->key(i);
      if (comp(k, key) > 0) {
        if (i == 0) {
          break;
        }

        return i - 1;
      }
    }

    return key_count();
  }

 public:
  APFSBtreeNode(const APFSPool &pool, const apfs_block_num block_num,
                const uint8_t *key = nullptr)
      : APFSObject(pool, block_num), _decryption_key{key} {
    // Decrypt node if needed
    if (key != nullptr) {
      decrypt(key);
    }

    if (obj_type() != APFS_OBJ_TYPE_BTREE_NODE &&
        obj_type() != APFS_OBJ_TYPE_BTREE_ROOTNODE) {
      throw std::runtime_error("APFSBtreeNode: invalid object type");
    }

    _table_data.toc = {_storage.data() + toffset()};
    _table_data.voff = _storage.data() + voffset();
    _table_data.koff = _storage.data() + koffset();
  }

  inline bool is_root() const noexcept {
    return bit_is_set(bn()->flags, APFS_BTNODE_ROOT);
  }

  inline bool is_leaf() const noexcept {
    return bit_is_set(bn()->flags, APFS_BTNODE_LEAF);
  }

  inline bool has_fixed_kv_size() const noexcept {
    return bit_is_set(bn()->flags, APFS_BTNODE_FIXED_KV_SIZE);
  }

  inline uint16_t level() const noexcept { return bn()->level; }

  inline uint32_t key_count() const noexcept { return bn()->key_count; }

  inline auto entries() const {
    const auto vec = [&] {
      std::vector<typename iterator::value_type> v{};

      std::for_each(begin(), end(), [&v](const auto e) { v.push_back(e); });

      return v;
    }();

    return vec;
  }

  inline const apfs_btree_info *info() const noexcept {
    // Only root nodes contain the info struct
    if (!is_root()) {
      return nullptr;
    }

    // The info structure is at the end of the object
    const auto ptr =
        _storage.data() + _storage.size() - sizeof(apfs_btree_info);

    return reinterpret_cast<const apfs_btree_info *>(ptr);
  }

  // Iterators

 public:
  using iterator = APFSBtreeNodeIterator<APFSBtreeNode>;

  iterator begin() const { return {this, 0}; }
  iterator end() const { return {this, key_count()}; }

  template <typename T, typename Compare>
  iterator find(const T &value, Compare comp) const {
    // TODO(JTS): It turns out, when a disk has snapshots, there can be more
    // than one entry in the objects tree that corresponds to the same oid.
    // Since we do not currently support snapshots, we're always returning the
    // last object with the id, because that should always be the newest object.
    // When we support snapshots, this logic likely needs to change.

    // For leaf nodes we can just search the entries directly
    if (is_leaf()) {
      // Search for key that's equal to the value
      for (auto i = key_count(); i > 0; i--) {
        const auto &k = key(i - 1);

        const auto res = comp(k, value);

        if (res == 0) {
          // We've found it!
          return {this, i - 1};
        }

        if (res < 0) {
          // We've gone too far
          break;
        }
      }

      // Not found
      return end();
    }

    // For non-leaf nodes we can be more efficient by skipping searches of
    // sub-trees that don't contain the object

    // Search for the last key that's <= the value
    for (auto i = key_count(); i > 0; i--) {
      const auto &k = key(i - 1);

      if (comp(k, value) <= 0) {
        iterator it{this, i - 1};

        auto ret = it._child_it->_node->find(value, comp);
        if (ret == it._child_it->_node->end()) {
          return end();
        }

        return {this, i - 1, std::move(ret)};
      }
    }

    // Not Found
    return end();
  }

  friend iterator;

  template <typename T>
  friend class APFSBtreeNodeIterator;
};

class APFSObjectBtreeNode
    : public APFSBtreeNode<apfs_omap_key, apfs_omap_value> {
  uint64_t _xid;

 public:
  APFSObjectBtreeNode(const APFSPool &pool, apfs_block_num block_num);
  APFSObjectBtreeNode(const APFSPool &pool, apfs_block_num block_num,
                      uint64_t snap_xid);

  iterator find(uint64_t oid) const;

  inline void snapshot(uint64_t snap_xid) { _xid = snap_xid; }
};

class APFSSnapshotMetaBtreeNode : public APFSBtreeNode<> {
 public:
  APFSSnapshotMetaBtreeNode(const APFSPool &pool, apfs_block_num block_num);
};

class APFSJObjBtreeNode : public APFSBtreeNode<> {
  const APFSObjectBtreeNode *_obj_root;

 public:
  APFSJObjBtreeNode(const APFSObjectBtreeNode *obj_root,
                    apfs_block_num block_num, const uint8_t *key);


  APFSJObjBtreeNode(APFSJObjBtreeNode &&) = default;

  using iterator = APFSBtreeNodeIterator<APFSJObjBtreeNode>;

  inline bool is_leaf() const noexcept { return (bn()->level == 0); }

  inline iterator begin() const { return {this, 0}; }
  inline iterator end() const { return {this, key_count()}; }

  template <typename T, typename Compare>
  inline iterator find(const T &value, Compare comp) const {
    // For leaf nodes we can just search the entries directly
    if (is_leaf()) {
      // Search for key that's equal to the value
      for (auto i = 0U; i < key_count(); i++) {
        const auto &k = key(i);

        const auto res = comp(k, value);

        if (res == 0) {
          // We've found it!
          return {this, i};
        }

        if (res > 0) {
          // We've gone too far
          break;
        }
      }

      // Not found
      return end();
    }

    // For non-leaf nodes we can be more efficient by skipping searches of
    // sub-trees that don't contain the object

    uint32_t last = std::numeric_limits<uint32_t>::max();
    // Search for key that's <= the value
    for (auto i = 0U; i < key_count(); i++) {
      const auto &k = key(i);

      const auto v = comp(k, value);

      if (v > 0) {
        break;
      }

      last = i;

      if (v == 0) {
        // We need to see if the jobj might be in the last node
        if (last != 0) {
          iterator it{this, last - 1};

          auto ret = it._child_it->_node->find(value, comp);
          if (ret != it._child_it->_node->end()) {
            return {this, last - 1, std::move(ret)};
          }
        }

        break;
      }
    }

    if (last == std::numeric_limits<uint32_t>::max()) {
      // Not Found
      return end();
    }

    iterator it{this, last};

    auto ret = it._child_it->_node->find(value, comp);
    if (ret == it._child_it->_node->end()) {
      return end();
    }

    return {this, last, std::move(ret)};
  }

  template <typename T, typename Compare>
  inline std::pair<iterator, iterator> find_range(const T &value,
                                                  Compare comp) const {
    auto s = find(value, comp);

    if (s == end()) {
      // Not found
      return {end(), end()};
    }

    auto e = std::find_if(
        s, end(), [&](const auto &a) noexcept(noexcept(comp(a.key, value))) {
          return comp(a.key, value) != 0;
        });

    return std::make_pair(std::move(s), std::move(e));
  }

  friend iterator;
};

class APFSSpacemanCIB : public APFSObject {
 protected:
  inline const apfs_spaceman_cib *cib() const noexcept {
    return reinterpret_cast<const apfs_spaceman_cib *>(_storage.data());
  }

 public:
  using APFSObject::APFSObject;
  APFSSpacemanCIB(const APFSPool &pool, const apfs_block_num block_num);

  using bm_entry = struct {
    uint64_t offset;
    uint32_t total_blocks;
    uint32_t free_blocks;
    apfs_block_num bm_block;
  };

  const std::vector<bm_entry> bm_entries() const;
};

class APFSSpacemanCAB : public APFSObject {
 protected:
  inline const apfs_spaceman_cab *cab() const noexcept {
    return reinterpret_cast<const apfs_spaceman_cab *>(_storage.data());
  }

 public:
  using APFSObject::APFSObject;
  APFSSpacemanCAB(const APFSPool &pool, const apfs_block_num block_num);

  inline uint32_t index() const noexcept { return cab()->index; }

  inline uint32_t cib_count() const noexcept { return cab()->cib_count; }

  const std::vector<apfs_block_num> cib_blocks() const;
};

class APFSSpaceman : public APFSObject {
  mutable std::vector<APFSSpacemanCIB::bm_entry> _bm_entries{};

#ifdef TSK_MULTITHREAD_LIB
  mutable std::mutex _bm_entries_init_lock;
#endif

 protected:
  inline const apfs_spaceman *sm() const noexcept {
    return reinterpret_cast<const apfs_spaceman *>(_storage.data());
  }

  inline const apfs_block_num *entries() const noexcept {
    return reinterpret_cast<const apfs_block_num *>(
        (uintptr_t)sm() + sm()->devs[APFS_SD_MAIN].addr_offset);
  }

 public:
  using APFSObject::APFSObject;
  APFSSpaceman(const APFSPool &pool, const apfs_block_num block_num);

  const std::vector<APFSSpacemanCIB::bm_entry> &bm_entries() const;

  using range = APFSPool::range;

  inline uint64_t num_free_blocks() const noexcept {
    return sm()->devs[APFS_SD_MAIN].free_count;
  }

  const std::vector<range> unallocated_ranges() const;
};

class APFSBitmapBlock : public APFSBlock {
  enum class mode {
    unset,
    set,
  };

  // A special return value for next that is returned when there are no more
  // bits to scan.
  static constexpr auto no_bits_left = std::numeric_limits<uint32_t>::max();

  // Number of bits in cache
  static constexpr uint32_t cached_bits = sizeof(uintptr_t) * 8;

  const APFSSpacemanCIB::bm_entry _entry;
  uint32_t _hint{};
  mode _mode{mode::unset};
  uintptr_t _cache{};

  inline bool done() const noexcept { return (_hint >= _entry.total_blocks); }

  inline void reset() noexcept { _hint = 0; }

  // Find the index of the next scanned bit.  If the scan mode is
  // set to "set" then this will be a 1 bit and if the mode is
  // "unset" then it will be a zero bit.  If no more bits are found
  // then no_bits_left is returned.
  //
  // Returns the index of the next scanned bit or no_bits_left
  //
  uint32_t next() noexcept;

  // Cache the next set of bits from the buffer.
  inline void cache_next() noexcept {
    //
    // Interpret the buffer as an array of 32-bit ints.
    //
    const auto array = reinterpret_cast<uintptr_t *>(_storage.data());

    //
    // Fetch the next integer to the cache.
    //
    _cache = array[_hint / cached_bits];

    //
    // If we're scanning for unset bits then we need to invert the cached
    // bits, since we only actually have logic for searching for set bits.
    //
    if (_mode == mode::unset) {
      _cache = ~_cache;
    }
  }

  //
  // Toggles the scan mode from set to unset or vice-versa.
  //
  // Returns the new scan mode
  //
  inline void toggle_mode() noexcept {
    // Toggle the scan mode based on the current mode.
    if (_mode == mode::set) {
      _mode = mode::unset;
    } else {
      _mode = mode::set;
    }

    // Invert the cached bits
    _cache = ~_cache;
  }

 public:
  using APFSBlock::APFSBlock;

  APFSBitmapBlock(const APFSPool &pool, const APFSSpacemanCIB::bm_entry &entry);

  const std::vector<APFSSpaceman::range> unallocated_ranges();
};

class APFSKeybag : public APFSObject {
 protected:
  inline const apfs_keybag *kb() const noexcept {
    return reinterpret_cast<const apfs_keybag *>(_storage.data());
  }

  using key = struct {
    Guid uuid;
    std::unique_ptr<uint8_t[]> data;
    uint16_t type;
  };

 public:
  APFSKeybag(const APFSPool &pool, const apfs_block_num block_num,
             const uint8_t *key, const uint8_t *key2 = nullptr);

  std::unique_ptr<uint8_t[]> get_key(const Guid &uuid, uint16_t type) const;

  std::vector<key> get_keys() const;
};

class APFSSuperblock : public APFSObject {
  mutable std::unique_ptr<APFSSpaceman> _spaceman{};

#ifdef TSK_MULTITHREAD_LIB
  mutable std::mutex _spaceman_init_lock;
#endif

 protected:
  inline const apfs_nx_superblock *sb() const noexcept {
    return reinterpret_cast<const apfs_nx_superblock *>(_storage.data());
  }

  inline APFSOmap omap() const { return {_pool, sb()->omap_oid}; };

  const APFSSpaceman &spaceman() const;

  class Keybag : public APFSKeybag {
   public:
    Keybag(const APFSSuperblock &sb);
  };

 public:
  using APFSObject::APFSObject;

  APFSSuperblock(const APFSPool &pool, const apfs_block_num block_num);

  inline uint32_t block_size() const noexcept { return sb()->block_size; }

  inline uint64_t num_blocks() const noexcept { return sb()->block_count; }

  inline uint64_t num_free_blocks() const {
    return spaceman().num_free_blocks();
  }

  inline Guid uuid() const { return {sb()->uuid}; }

  const std::vector<apfs_block_num> volume_blocks() const;
  const std::vector<apfs_block_num> sm_bitmap_blocks() const;
  inline const std::vector<APFSSpaceman::range> unallocated_ranges() const {
    return spaceman().unallocated_ranges();
  }

  const std::vector<uint64_t> volume_oids() const;

  apfs_block_num checkpoint_desc_block() const;

  Keybag keybag() const;

  friend APFSPool;
};

class APFSCheckpointMap : public APFSObject {
 protected:
  inline const apfs_checkpoint_map *map() const noexcept {
    return reinterpret_cast<const apfs_checkpoint_map *>(_storage.data());
  }

 public:
  using APFSObject::APFSObject;
  APFSCheckpointMap(const APFSPool &pool, const apfs_block_num block_num);

  apfs_block_num get_object_block(uint64_t oid, APFS_OBJ_TYPE_ENUM type) const;
};

// Object representation of an APFS Physical Extent Reference
#pragma pack(push, 1)
struct APFSPhysicalExtentRef : apfs_phys_extent {
  inline apfs_phys_extent_kind kind() const noexcept {
    return static_cast<apfs_phys_extent_kind>(bitfield_value(
        len_and_kind, APFS_PHYS_EXTENT_KIND_BITS, APFS_PHYS_EXTENT_KIND_SHIFT));
  }

  inline uint64_t block_count() const noexcept {
    return bitfield_value(len_and_kind, APFS_PHYS_EXTENT_LEN_BITS,
                          APFS_PHYS_EXTENT_LEN_SHIFT);
  }

  inline uint64_t owner_oid() const noexcept { return owning_obj_id; }

  inline uint32_t ref_count() const noexcept { return refcnt; }
};
static_assert(sizeof(APFSPhysicalExtentRef) == sizeof(apfs_phys_extent),
              "No member fields can be added to APFSPhysicalExtentRef");

struct APFSPhysicalExtentKey : apfs_phys_extent_key {
  inline apfs_block_num start_block() const noexcept {
    return bitfield_value(start_block_and_type,
                          APFS_PHYS_EXTENT_START_BLOCK_BITS,
                          APFS_PHYS_EXTENT_START_BLOCK_SHIFT);
  }
};
static_assert(sizeof(APFSPhysicalExtentKey) == sizeof(apfs_phys_extent_key),
              "No member fields can be added to APFSPhysicalExtentKey");
#pragma pack(pop)

class APFSExtentRefBtreeNode : public APFSBtreeNode<> {
 public:
  APFSExtentRefBtreeNode(const APFSPool &pool, apfs_block_num block_num);

  iterator find(apfs_block_num) const;
};

class APFSJObjTree;
class APFSFileSystem : public APFSObject {
 public:
  using unmount_log_t = struct {
    uint64_t timestamp;
    std::string logstr;
    uint64_t last_xid;
  };

  using snapshot_t = struct {
    std::string name;
    uint64_t timestamp;
    uint64_t snap_xid;
    bool dataless;
  };

  struct wrapped_kek {
    Guid uuid;
    uint8_t data[0x28];
    uint64_t iterations;
    uint64_t flags;
    uint8_t salt[0x10];
    wrapped_kek(Guid &&uuid, const std::unique_ptr<uint8_t[]> &);

    inline bool hw_crypt() const noexcept {
      // If this bit is set, some sort of hardware encryption is used.
      return bit_is_set(flags, 1ULL << 56);
    }

    inline bool cs() const noexcept {
      // If this bit is set the KEK is 0x10 bytes instead of 0x20
      return bit_is_set(flags, 1ULL << 57);
    }
  };

  using crypto_info_t = struct {
    apfs_block_num recs_block_num{};
    std::string password_hint{};
    std::string password{};
    std::vector<wrapped_kek> wrapped_keks{};
    uint64_t vek_flags{};
    uint8_t wrapped_vek[0x28]{};
    uint8_t vek_uuid[0x10]{};
    uint8_t vek[0x20]{};
    bool unlocked{};

    inline uint64_t unk16() const noexcept {
      // If this byte is not zero (1) then some other sort of decryption is used
      return bitfield_value(vek_flags, 8, 16);
    }

    inline bool hw_crypt() const noexcept {
      // If this bit is set, some sort of hardware encryption is used.
      return bit_is_set(vek_flags, 1ULL << 56);
    }

    inline bool cs() const noexcept {
      // If this bit is set the VEK is 0x10 bytes instead of 0x20
      return bit_is_set(vek_flags, 1ULL << 57);
    }
  };

 protected:
  class Keybag : public APFSKeybag {
   public:
    Keybag(const APFSFileSystem &, apfs_block_num);
  };

  inline const apfs_superblock *fs() const noexcept {
    return reinterpret_cast<const apfs_superblock *>(_storage.data());
  }

  inline uint64_t rdo() const noexcept { return fs()->root_tree_oid; }

  void init_crypto_info();

  crypto_info_t _crypto{};

 public:
  using APFSObject::APFSObject;
  APFSFileSystem(const APFSPool &pool, const apfs_block_num block_num);
  APFSFileSystem(const APFSPool &pool, const apfs_block_num block_num,
                 const std::string &password);

  const std::vector<snapshot_t> snapshots() const;

  bool unlock(const std::string &password) noexcept;

  inline Guid uuid() const noexcept { return {fs()->uuid}; }

  inline std::string name() const { return {fs()->name}; }

  inline std::string formatted_by() const { return {fs()->formatted_by}; }

  inline const std::string &password_hint() const noexcept {
    return _crypto.password_hint;
  }

  inline const auto &crypto_info() const noexcept { return _crypto; }

  inline const uint8_t *decryption_key() const noexcept {
    if (_crypto.unlocked) {
      return _crypto.vek;
    }

    return nullptr;
  }

  inline APFS_VOLUME_ROLE role() const noexcept {
    return APFS_VOLUME_ROLE(fs()->role);
  }

  inline uint64_t reserved() const noexcept {
    return fs()->reserve_blocks * _pool.block_size();
  }

  inline uint64_t quota() const noexcept {
    return fs()->quota_blocks * _pool.block_size();
  }

  inline uint64_t used() const noexcept {
    return fs()->alloc_blocks * _pool.block_size();
  }

  inline uint64_t reserved_blocks() const noexcept {
    return fs()->reserve_blocks;
  }

  inline uint64_t quota_blocks() const noexcept { return fs()->quota_blocks; }

  inline uint64_t alloc_blocks() const noexcept { return fs()->alloc_blocks; }

  inline uint64_t last_inum() const noexcept { return fs()->next_inum - 1; }

  inline bool encrypted() const noexcept {
    return !bit_is_set(fs()->flags, APFS_SB_UNENCRYPTED);
  }

  inline bool case_sensitive() const noexcept {
    return !bit_is_set(fs()->incompatible_features,
                       APFS_SB_INCOMPAT_CASE_INSENSITIVE);
  }

  inline uint64_t created() const noexcept { return fs()->created_timestamp; }

  inline uint64_t changed() const noexcept { return fs()->last_mod_time; }

  const std::vector<unmount_log_t> unmount_log() const;

  apfs_block_num omap_root() const;

  APFSJObjTree root_jobj_tree() const;

  APFSExtentRefBtreeNode extent_ref_tree() const {
    return {pool(), fs()->extentref_tree_oid};
  }

  APFSSnapshotMetaBtreeNode snap_meta_tree() const {
    return {pool(), fs()->snap_meta_tree_oid};
  }

  friend APFSJObjTree;
};

struct APFSJObjKey {
  uint64_t oid_and_type;

  inline uint64_t oid() const noexcept {
    return bitfield_value(oid_and_type, 60, 0);
  }

  inline uint64_t type() const noexcept {
    return bitfield_value(oid_and_type, 4, 60);
  }
};
static_assert(sizeof(APFSJObjKey) == 0x08, "invalid struct padding");

// Template Specializations

// Initializes the value for variable-sized key/values

template <>
inline lw_shared_ptr<APFSJObjBtreeNode>
APFSBtreeNodeIterator<APFSJObjBtreeNode>::own_node(
    const APFSJObjBtreeNode *node, apfs_block_num block_num) {
  return node->_pool.template get_block<APFSJObjBtreeNode>(
      block_num, node->_obj_root, block_num, node->_decryption_key);
}

template <>
template <>
inline void APFSBtreeNodeIterator<APFSJObjBtreeNode>::init_value<void>() {
  const auto &t = _node->_table_data.toc.variable[_index];
  const auto key_data = _node->_table_data.koff + t.key_offset;
  const auto val_data = _node->_table_data.voff - t.val_offset;

  memory_view key{key_data, t.key_length};

  if (_node->is_leaf()) {
    memory_view value{val_data, t.val_length};

    _val = {key, value};
  } else {
    const auto obj_num = *((uint64_t *)val_data);

    const auto it = _node->_obj_root->find(obj_num);

    if (it == _node->_obj_root->end()) {
      throw std::runtime_error("can not find jobj");
    }

    _child_it = std::make_unique<typename APFSJObjBtreeNode::iterator>(
        own_node(_node.get(), it->value->paddr), 0);
  }
}

template <typename Node>
APFSBtreeNodeIterator<Node>::APFSBtreeNodeIterator(const Node *node,
                                                   uint32_t index)
    : _node{own_node(node)}, _index{index} {
  // If we're the end, then there's nothing to do
  if (index >= _node->key_count()) {
    return;
  }

  init_value();
}

template <typename Node>
APFSBtreeNodeIterator<Node>::APFSBtreeNodeIterator(lw_shared_ptr<Node> &&node,
                                                   uint32_t index)
    : _node{std::forward<lw_shared_ptr<Node>>(node)}, _index{index} {
  // If we're the end, then there's nothing to do
  if (index >= _node->key_count()) {
    return;
  }

  init_value();
}

template <typename Node>
APFSBtreeNodeIterator<Node>::APFSBtreeNodeIterator(
    const Node *node, uint32_t index, typename Node::iterator &&child)
    : _node{own_node(node)}, _index{index} {
  _child_it = std::make_unique<typename Node::iterator>(
      std::forward<typename Node::iterator>(child));
}
