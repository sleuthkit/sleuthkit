#include "../util/crypto.hpp"
#include "apfs_fs.hpp"
#include "tsk_apfs.hpp"

#include <cstring>

// MSVC doesn't define ffs/ffsll.
#ifdef _MSC_VER
#include <intrin.h>

#ifdef _M_X64  // 64-bit
#pragma intrinsic(_BitScanForward64)
static __forceinline int lsbset(unsigned __int64 x) {
  unsigned long i;

  if (_BitScanForward64(&i, x)) {
    return i + 1;
  }

  return 0;
}
#else  // 32-bit
#pragma intrinsic(_BitScanForward)
static __forceinline int lsbset(long x) {
  unsigned long i;

  if (_BitScanForward(&i, x)) {
    return i + 1;
  }
  return 0;
}
#endif  // _M_X64

#else  // gcc or clang

#ifdef __x86_64__
#define lsbset(x) __builtin_ffsll(x)
#else  // 32-bit
#define lsbset(x) __builtin_ffs(x)
#endif  // __x86_64__

#endif  // _MSC_VER

class wrapped_key_parser {
  // TODO(JTS): This code assume a well-formed input. It needs some sanity
  // checking!

  using tag = uint8_t;
  using view = span<const uint8_t>;

  const uint8_t* _data;

  size_t get_length(const uint8_t** pos) const noexcept {
    auto data = *pos;

    size_t len = *data++;

    if (len & 0x80) {
      len = 0;
      auto enc_len = len & 0x7F;
      while (enc_len--) {
        len <<= 8;
        len |= *data++;
      }
    }

    *pos = data;
    return len;
  }

  const view get_tag(tag t) const noexcept {
    auto data = _data;

    while (true) {
      const auto tag = *data++;
      const auto len = get_length(&data);

      if (tag == t) {
        return {data, len};
      }

      data += len;
    }
  }

  // Needed for the recursive variadic to compile, but should never be
  // called.  TODO(JTS): Use constexpr if when we enforce C++17
  const view get_data(void) const {
    throw std::logic_error("this should be unreachable");
  }

 public:
  wrapped_key_parser(const void* data) noexcept : _data{(const uint8_t*)data} {}

  template <typename... Args>
  const view get_data(tag t, Args... args) const noexcept {
    const auto data = get_tag(t);

    if (sizeof...(args) == 0 || !data.valid()) {
      return data;
    }

    return wrapped_key_parser{data.data()}.get_data(args...);
  }

  template <typename... Args>
  uint64_t get_number(tag t, Args... args) const noexcept {
    const auto data = get_data(t, args...);

    uint64_t n = 0;
    for (auto p = data.data(); p < data.data() + data.count(); p++) {
      n <<= 8;
      n |= *p;
    }

    return n;
  }
};

APFSBlock::APFSBlock(const APFSPool& pool, const apfs_block_num block_num)
    : _storage{}, _pool{pool}, _block_num{block_num} {
  const auto sz =
      pool.read(block_num * APFS_BLOCK_SIZE, _storage.data(), APFS_BLOCK_SIZE);
  if (sz != APFS_BLOCK_SIZE) {
    throw std::runtime_error("could not read APFSBlock");
  }
}

void APFSBlock::decrypt(const uint8_t* key, const uint8_t* key2) noexcept {
#ifdef HAVE_LIBOPENSSL
    // If the data is encrypted via the T2 chip, we can't decrypt it.  This means
    // that if the data wasn't decrypted at acquisition time, then processing will
    // likely fail.  Either way, there is no need to decrypt.
    if (_pool.hardware_crypto()) {
        return;
    }

    aes_xts_decryptor dec{ aes_xts_decryptor::AES_128, key, key2,
                          APFS_CRYPTO_SW_BLKSIZE };

    dec.decrypt_buffer(_storage.data(), _storage.size(),
        _block_num * APFS_BLOCK_SIZE);
#else
    return;
#endif
}

void APFSBlock::dump() const noexcept {
  // Dump contents of block to stdout for debugging
  for (const auto byte : _storage) {
    putchar(byte);
  }
}

bool APFSObject::validate_checksum() const noexcept {
  if (obj()->cksum == std::numeric_limits<uint64_t>::max()) {
    return false;
  }

  // Calculate the checksum using the modified fletcher's algorithm
  const auto checksum = [&]() -> uint64_t {
    const auto data =
        reinterpret_cast<const uint32_t*>(_storage.data() + sizeof(uint64_t));
    const auto len = (_storage.size() - sizeof(uint64_t)) / sizeof(uint32_t);

    constexpr uint64_t mod = std::numeric_limits<uint32_t>::max();

    uint64_t sum1{0};
    uint64_t sum2{0};

    for (size_t i = 0; i < len; i++) {
      sum1 = (sum1 + data[i]) % mod;
      sum2 = (sum2 + sum1) % mod;
    }

    const auto ck_low = mod - ((sum1 + sum2) % mod);
    const auto ck_high = mod - ((sum1 + ck_low) % mod);

    return (ck_high << 32) | ck_low;
  }();

  // Compare calculated checksum with the value in the object header
  return (checksum == obj()->cksum);
}

APFSSuperblock::APFSSuperblock(const APFSPool& pool,
                               const apfs_block_num block_num)
    : APFSObject(pool, block_num), _spaceman{} {
  if (obj_type() != APFS_OBJ_TYPE_SUPERBLOCK) {
    throw std::runtime_error("APFSSuperblock: invalid object type");
  }

  if (sb()->magic != APFS_NXSUPERBLOCK_MAGIC) {
    throw std::runtime_error("APFSSuperblock: invalid magic");
  }

  if (bit_is_set(sb()->incompatible_features, APFS_NXSB_INCOMPAT_VERSION1)) {
    throw std::runtime_error(
        "APFSSuperblock: Pre-release versions of APFS are not supported");
  }

  if (bit_is_set(sb()->incompatible_features, APFS_NXSB_INCOMPAT_FUSION)) {
    if (tsk_verbose) {
      tsk_fprintf(stderr,
                  "WARNING: APFS fusion drives may not be fully supported\n");
    }
  }

  if (block_size() != APFS_BLOCK_SIZE) {
    throw std::runtime_error(
        "APFSSuperblock: invalid or unsupported block size");
  }
}

const std::vector<apfs_block_num> APFSSuperblock::volume_blocks() const {
  std::vector<apfs_block_num> vec{};

  const auto root = omap().root<APFSObjectBtreeNode>();

  for (const auto& e : root.entries()) {
    vec.emplace_back(e.value->paddr);
  }

  return vec;
}

const std::vector<apfs_block_num> APFSSuperblock::sm_bitmap_blocks() const {
  const auto entries = spaceman().bm_entries();

  std::vector<apfs_block_num> v{};
  v.reserve(entries.size());

  for (const auto& entry : entries) {
    if (entry.bm_block != 0) {
      v.emplace_back(entry.bm_block);
    }
  }

  return v;
}

const std::vector<uint64_t> APFSSuperblock::volume_oids() const {
  std::vector<uint64_t> v{};

  for (auto i = 0U; i < sb()->max_fs_count; i++) {
    const auto oid = sb()->fs_oids[i];

    if (oid == 0) {
      break;
    }

    v.emplace_back(oid);
  }

  return v;
}

apfs_block_num APFSSuperblock::checkpoint_desc_block() const {
  for (auto i = 0U; i < sb()->chkpt_desc_block_count; i++) {
    const auto block_num = sb()->chkpt_desc_base_addr + i;
    const auto block = APFSObject(_pool, block_num);

    if (!block.validate_checksum()) {
      if (tsk_verbose) {
        tsk_fprintf(stderr,
                    "APFSSuperblock::checkpoint_desc_block: Block %lld did not "
                    "validate.\n",
                    block_num);
      }
      continue;
    }

    if (block.xid() == xid() &&
        block.obj_type() == APFS_OBJ_TYPE_CHECKPOINT_DESC) {
      return block_num;
    }
  }

  // We didn't find anything so return 0;
  return 0;
}

const APFSSpaceman& APFSSuperblock::spaceman() const {
  if (_spaceman != nullptr) {
    return *_spaceman;
  }

#ifdef TSK_MULTITHREAD_LIB
  // Since this function is const, and const methods generally are assumed to be
  // thread safe, we ideally want to it be thread safe so multiple threads
  // aren't trying to initialize at the same time.
  std::lock_guard<std::mutex> lock{_spaceman_init_lock};

  // Check again to make sure someone else didn't already beat us to this.
  if (_spaceman != nullptr) {
    return *_spaceman;
  }
#endif

  const APFSCheckpointMap cd{_pool, checkpoint_desc_block()};

  _spaceman = std::make_unique<APFSSpaceman>(
      _pool, cd.get_object_block(sb()->spaceman_oid, APFS_OBJ_TYPE_SPACEMAN));

  return *_spaceman;
}

APFSSuperblock::Keybag APFSSuperblock::keybag() const {
  if (sb()->keylocker.start_paddr == 0) {
    throw std::runtime_error("no keybag found");
  }

  return {(*this)};
}

APFSOmap::APFSOmap(const APFSPool& pool, const apfs_block_num block_num)
    : APFSObject(pool, block_num) {
  if (obj_type() != APFS_OBJ_TYPE_OMAP) {
    throw std::runtime_error("APFSOmap: invalid object type");
  }
}

APFSFileSystem::APFSFileSystem(const APFSPool& pool,
                               const apfs_block_num block_num)
    : APFSObject(pool, block_num) {
  if (obj_type() != APFS_OBJ_TYPE_FS) {
    throw std::runtime_error("APFSFileSystem: invalid object type");
  }

  if (fs()->magic != APFS_FS_MAGIC) {
    throw std::runtime_error("APFSFileSystem: invalid magic");
  }

  if (encrypted() && pool.hardware_crypto() == false) {
    init_crypto_info();
  }
}

APFSFileSystem::wrapped_kek::wrapped_kek(Guid&& id,
                                         const std::unique_ptr<uint8_t[]>& kp)
    : uuid{std::forward<Guid>(id)} {
  // Parse KEK
  wrapped_key_parser wp{kp.get()};

  // Get flags
  flags = wp.get_number(0x30, 0xA3, 0x82);

  // Get wrapped KEK
  auto kek_data = wp.get_data(0x30, 0xA3, 0x83);
  if (kek_data.count() != sizeof(data)) {
    throw std::runtime_error("invalid KEK size");
  }
  std::memcpy(data, kek_data.data(), sizeof(data));

  // Get iterations
  iterations = wp.get_number(0x30, 0xA3, 0x84);

  // Get salt
  kek_data = wp.get_data(0x30, 0xA3, 0x85);
  if (kek_data.count() != sizeof(salt)) {
    throw std::runtime_error("invalid salt size");
  }
  std::memcpy(salt, kek_data.data(), sizeof(salt));
}

APFSFileSystem::APFSFileSystem(const APFSPool& pool,
                               const apfs_block_num block_num,
                               const std::string& password)
    : APFSFileSystem(pool, block_num) {
  if (encrypted()) {
    unlock(password);
  }
}

// These are the known special recovery UUIDs.  The ones that are commented out
// are currently supported.
static const auto unsupported_recovery_keys = {
    Guid{"c064ebc6-0000-11aa-aa11-00306543ecac"},  // Institutional Recovery
    Guid{"2fa31400-baff-4de7-ae2a-c3aa6e1fd340"},  // Institutional User
    // Guid{"ebc6C064-0000-11aa-aa11-00306543ecac"},  // Personal Recovery
    Guid{"64c0c6eb-0000-11aa-aa11-00306543ecac"},  // iCould Recovery
    Guid{"ec1c2ad9-b618-4ed6-bd8d-50f361c27507"},  // iCloud User
};

void APFSFileSystem::init_crypto_info() {
    try {

        // Get container keybag
        const auto container_kb = _pool.nx()->keybag();

        auto data = container_kb.get_key(uuid(), APFS_KB_TYPE_VOLUME_KEY);
        if (data == nullptr) {
            throw std::runtime_error(
                "APFSFileSystem: can not find volume encryption key");
        }

        wrapped_key_parser wp{ data.get() };

        // Get Wrapped VEK
        auto kek_data = wp.get_data(0x30, 0xA3, 0x83);
        if (kek_data.count() != sizeof(_crypto.wrapped_vek)) {
            throw std::runtime_error("invalid VEK size");
        }
        std::memcpy(_crypto.wrapped_vek, kek_data.data(),
            sizeof(_crypto.wrapped_vek));

        // Get VEK Flags
        _crypto.vek_flags = wp.get_number(0x30, 0xA3, 0x82);

        // Get VEK UUID
        kek_data = wp.get_data(0x30, 0xA3, 0x81);
        if (kek_data.count() != sizeof(_crypto.vek_uuid)) {
            throw std::runtime_error("invalid UUID size");
        }
        std::memcpy(_crypto.vek_uuid, kek_data.data(), sizeof(_crypto.vek_uuid));

        data = container_kb.get_key(uuid(), APFS_KB_TYPE_UNLOCK_RECORDS);
        if (data == nullptr) {
            throw std::runtime_error(
                "APFSFileSystem: can not find volume recovery key");
        }

        const auto rec =
            reinterpret_cast<const apfs_volrec_keybag_value*>(data.get());

        if (rec->num_blocks != 1) {
            throw std::runtime_error(
                "only single block keybags are currently supported");
        }

        _crypto.recs_block_num = rec->start_block;

        Keybag recs{ (*this), _crypto.recs_block_num };

        data = recs.get_key(uuid(), APFS_KB_TYPE_PASSPHRASE_HINT);

        if (data != nullptr) {
            _crypto.password_hint = std::string((const char*)data.get());
        }

        // Get KEKs
        auto keks = recs.get_keys();
        if (keks.empty()) {
            throw std::runtime_error("could not find any KEKs");
        }

        for (auto& k : keks) {
            if (k.type != APFS_KB_TYPE_UNLOCK_RECORDS) {
                continue;
            }

            if (std::find(unsupported_recovery_keys.begin(),
                unsupported_recovery_keys.end(),
                k.uuid) != unsupported_recovery_keys.end()) {
                // Skip unparsable recovery KEKs
                if (tsk_verbose) {
                    tsk_fprintf(stderr, "apfs: skipping unsupported KEK type: %s\n",
                        k.uuid.str().c_str());
                }
                continue;
            }

            _crypto.wrapped_keks.emplace_back(wrapped_kek{ std::move(k.uuid), k.data });
        }
    }
    catch (std::exception& e) {
        if (tsk_verbose) {
            tsk_fprintf(stderr, "APFSFileSystem::init_crypto_info: %s", e.what());
        }
    }
}

bool APFSFileSystem::unlock(const std::string& password) noexcept {
#ifdef HAVE_LIBOPENSSL
  if (_crypto.unlocked) {
    // Already unlocked
    return true;
  }

  // TODO(JTS): If bits 32:16 are set to 1, some other sort of KEK decryption is
  // used (see _fv_decrypt_vek in AppleKeyStore).
  if (_crypto.unk16()) {
    if (tsk_verbose) {
      tsk_fprintf(stderr,
                  "apfs: UNK16 is set in VEK.  Decryption will likely fail.\n");
    }
  }

  // Check the password against all possible KEKs
  for (const auto& wk : _crypto.wrapped_keks) {
    // If the 57th bit of the KEK flags is set, then the kek is a CoreStorage
    // KEK
    const auto kek_len = (wk.cs()) ? 0x10 : 0x20;

    // TODO(JTS): If the 56th bit of the KEK flags is set, some sort of hardware
    // decryption is needed
    if (wk.hw_crypt()) {
      if (tsk_verbose) {
        tsk_fprintf(
            stderr,
            "apfs: hardware decryption is not yet supported. KEK decryption "
            "will likely fail\n");
      }
    }

    const auto user_key = pbkdf2_hmac_sha256(password, wk.salt, sizeof(wk.salt),
                                             wk.iterations, kek_len);
    if (user_key == nullptr) {
      if (tsk_verbose) {
        tsk_fprintf(stderr, "apfs: can not generate user key\n");
      }
      continue;
    }

    const auto kek =
        rfc3394_key_unwrap(user_key.get(), kek_len, wk.data, kek_len + 8);
    if (kek == nullptr) {
      if (tsk_verbose) {
        tsk_fprintf(stderr,
                    "apfs: KEK %s can not be unwrapped with given password\n",
                    wk.uuid.str().c_str());
      }
      continue;
    }

    // If the 57th bit of the VEK flags is set, then the VEK is a
    // CoreStorage VEK
    const auto vek_len = (_crypto.cs()) ? 0x10 : 0x20;

    // If a 128 bit VEK is wrapped with a 256 bit KEK then only the first 128
    // bits of the KEK are used.
    const auto vek = rfc3394_key_unwrap(kek.get(), std::min(kek_len, vek_len),
                                        _crypto.wrapped_vek, vek_len + 8);
    if (vek == nullptr) {
      if (tsk_verbose) {
        tsk_fprintf(stderr, "apfs: failed to unwrap VEK\n");
      }
      continue;
    }

    _crypto.password = password;
    std::memcpy(_crypto.vek, vek.get(), vek_len);

    if (_crypto.cs()) {
      // For volumes that were converted from CoreStorage, the tweak is the
      // first 128-bits of SHA256(vek + vekuuid)
      std::memcpy(_crypto.vek + 0x10, _crypto.vek_uuid,
                  sizeof(_crypto.vek_uuid));

      const auto hash = hash_buffer_sha256(_crypto.vek, sizeof(_crypto.vek));

      std::memcpy(_crypto.vek + 0x10, hash.get(), 0x10);
    }

    _crypto.unlocked = true;

    return true;
  }

  return false;
#else
    if (tsk_verbose) {
        tsk_fprintf(stderr, "apfs: crypto library not loaded\n");
    }
    return false;
#endif
}

const std::vector<APFSFileSystem::unmount_log_t> APFSFileSystem::unmount_log()
    const {
  std::vector<unmount_log_t> v{};

  for (auto i = 0; i < 8; i++) {
    const auto& log = fs()->unmount_logs[i];

    if (log.timestamp == 0) {
      return v;
    }

    v.emplace_back(
        unmount_log_t{log.timestamp, log.kext_ver_str, log.last_xid});
  }

  return v;
}

const std::vector<APFSFileSystem::snapshot_t> APFSFileSystem::snapshots()
    const {
  std::vector<snapshot_t> v{};

  const APFSSnapshotMetaBtreeNode snap_tree{_pool, fs()->snap_meta_tree_oid};

  using key_type = struct {
    uint64_t xid_and_type;

    inline uint64_t snap_xid() const noexcept {
      return bitfield_value(xid_and_type, 60, 0);
    }

    inline uint64_t type() const noexcept {
      return bitfield_value(xid_and_type, 4, 60);
    }
  };

  using value_type = apfs_snap_metadata;

  std::for_each(snap_tree.begin(), snap_tree.end(), [&](const auto& entry) {
    const auto key = entry.key.template as<key_type>();
    const auto value = entry.value.template as<value_type>();

    if (key->type() != APFS_JOBJTYPE_SNAP_METADATA) {
      return;
    }

    v.emplace_back(snapshot_t{
        {value->name, value->name_length - 1U},  // name
        value->create_time,                      // timestamp
        key->snap_xid(),                         // snap_xid
        (value->extentref_tree_oid == 0),        // dataless
    });
  });

  return v;
}

APFSJObjTree APFSFileSystem::root_jobj_tree() const {
  return {_pool, omap_root(), rdo(), crypto_info()};
}

apfs_block_num APFSFileSystem::omap_root() const {
  return APFSOmap{_pool, fs()->omap_oid}.root_block();
}

APFSJObjBtreeNode::APFSJObjBtreeNode(const APFSObjectBtreeNode* obj_root,
                                     apfs_block_num block_num,
                                     const uint8_t* key)
#ifdef HAVE_LIBOPENSSL
    : APFSBtreeNode(obj_root->pool(), block_num, key), _obj_root{obj_root} {
#else
    : APFSBtreeNode(obj_root->pool(), block_num, nullptr), _obj_root{ obj_root } {
#endif
  if (subtype() != APFS_OBJ_TYPE_FSTREE) {
    throw std::runtime_error("APFSJObjBtreeNode: invalid subtype");
  }
}


APFSObjectBtreeNode::iterator APFSObjectBtreeNode::find(uint64_t oid) const {
  return APFSBtreeNode::find(
      oid, [xid = this->_xid](const auto& key,
                              const auto oid) noexcept->int64_t {
        if ((key->oid == oid) && (key->xid > xid)) {
          return key->xid - xid;
        }

        return (key->oid - oid);
      });
}

APFSObjectBtreeNode::APFSObjectBtreeNode(const APFSPool& pool,
                                         apfs_block_num block_num)
    : APFSBtreeNode(pool, block_num), _xid{xid()} {
  if (subtype() != APFS_OBJ_TYPE_OMAP) {
    throw std::runtime_error("APFSObjectBtreeNode: invalid subtype");
  }
}

APFSObjectBtreeNode::APFSObjectBtreeNode(const APFSPool& pool,
                                         apfs_block_num block_num,
                                         uint64_t snap_xid)
    : APFSBtreeNode(pool, block_num), _xid{snap_xid} {
  if (subtype() != APFS_OBJ_TYPE_OMAP) {
    throw std::runtime_error("APFSObjectBtreeNode: invalid subtype");
  }
}

APFSSnapshotMetaBtreeNode::APFSSnapshotMetaBtreeNode(const APFSPool& pool,
                                                     apfs_block_num block_num)
    : APFSBtreeNode(pool, block_num) {
  if (subtype() != APFS_OBJ_TYPE_SNAPMETATREE) {
    throw std::runtime_error("APFSSnapshotMetaBtreeNode: invalid subtype");
  }
}

APFSExtentRefBtreeNode::APFSExtentRefBtreeNode(const APFSPool& pool,
                                               apfs_block_num block_num)
    : APFSBtreeNode(pool, block_num) {
  if (subtype() != APFS_OBJ_TYPE_BLOCKREFTREE) {
    throw std::runtime_error("APFSExtentRefBtreeNode: invalid subtype");
  }
}

APFSCheckpointMap::APFSCheckpointMap(const APFSPool& pool,
                                     const apfs_block_num block_num)
    : APFSObject(pool, block_num) {
  if (obj_type() != APFS_OBJ_TYPE_CHECKPOINT_DESC) {
    throw std::runtime_error("APFSCheckpointMap: invalid object type");
  }
}

apfs_block_num APFSCheckpointMap::get_object_block(
    uint64_t oid, APFS_OBJ_TYPE_ENUM type) const {
  const auto entries = map()->entries;

  for (auto i = 0U; i < map()->count; i++) {
    const auto& entry = entries[i];

    if (entry.oid == oid && entry.type == type) {
      return entry.paddr;
    }
  }

  // Not found
  throw std::runtime_error(
      "APFSCheckpointMap::get_object_block: object not found");
}

APFSSpaceman::APFSSpaceman(const APFSPool& pool, const apfs_block_num block_num)
    : APFSObject(pool, block_num), _bm_entries{} {
  if (obj_type() != APFS_OBJ_TYPE_SPACEMAN) {
    throw std::runtime_error("APFSSpaceman: invalid object type");
  }
}

const std::vector<APFSSpacemanCIB::bm_entry>& APFSSpaceman::bm_entries() const {
  if (!_bm_entries.empty()) {
    return _bm_entries;
  }

#ifdef TSK_MULTITHREAD_LIB
  // Since this function is const, and const methods generally are assumed to be
  // thread safe, we ideally want to it be thread safe so multiple threads
  // aren't trying to initialize at the same time.
  std::lock_guard<std::mutex> lock{_bm_entries_init_lock};

  // Check again to make sure someone else didn't already beat us to this.
  if (!_bm_entries.empty()) {
    return _bm_entries;
  }

  // Our above checks would not prevent someone from accessing the member while
  // the initialization is in progress, so let's initialize a temporary and them
  // move it into the member instead.
  decltype(_bm_entries) bm_entries{};
#else
  // There's no possibility for contention, so let's just initialize the member
  // directly so that we can save the move.
  auto& bm_entries = _bm_entries;
#endif

  bm_entries.reserve(sm()->devs[APFS_SD_MAIN].cib_count);

  const auto cib_blocks = [&] {
    std::vector<apfs_block_num> v{};
    v.reserve(sm()->devs[APFS_SD_MAIN].cib_count);

    const auto entries = this->entries();

    // Is the next level cib?
    if (sm()->devs[APFS_SD_MAIN].cab_count == 0) {
      // Our entires contain the cib blocks
      for (auto i = 0U; i < sm()->devs[APFS_SD_MAIN].cib_count; i++) {
        v.emplace_back(entries[i]);
      }

      return v;
    }

    // The next level is cab, not cib so we need to recurse them
    for (auto i = 0U; i < sm()->devs[APFS_SD_MAIN].cab_count; i++) {
      const APFSSpacemanCAB cab(_pool, entries[i]);
      const auto cab_entries = cab.cib_blocks();

      // Append the blocks to the vector
      std::copy(cab_entries.begin(), cab_entries.end(), std::back_inserter(v));
    }

    return v;
  }();

  for (const auto block : cib_blocks) {
    const APFSSpacemanCIB cib(_pool, block);

    const auto entries = cib.bm_entries();

    // Append the entries to the vector
    std::copy(entries.begin(), entries.end(), std::back_inserter(bm_entries));
  }

  // Sort the entries by offset
  std::sort(bm_entries.begin(), bm_entries.end(),
            [](const auto& a, const auto& b) { return (a.offset < b.offset); });

#ifdef TSK_MULTITHREAD_LIB
  // Now that we're fully initialized we can now move our initialized vector
  // into the member to signal that we're ready for access.
  _bm_entries = std::move(bm_entries);
#endif

  return _bm_entries;
}

const std::vector<APFSSpaceman::range> APFSSpaceman::unallocated_ranges()
    const {
  std::vector<range> v{};

  for (const auto& entry : bm_entries()) {
    if (entry.free_blocks == 0) {
      // No free ranges to add
      continue;
    }

    if (entry.total_blocks == entry.free_blocks) {
      // The entire bitmap block is free
      if (!v.empty() &&
          v.back().start_block + v.back().num_blocks == entry.offset) {
        // We're within the same range as the last one, so just update the
        // count
        v.back().num_blocks += entry.free_blocks;
      } else {
        // We're not contiguous with the last range, so add a new one
        v.emplace_back(range{entry.offset, entry.free_blocks});
      }
      continue;
    }

    // We've got to enumerate the bitmap block for it's ranges
    const auto ranges = APFSBitmapBlock{_pool, entry}.unallocated_ranges();

    // TODO(JTS): We could possibly de-duplicate the first range if it's
    // contiguous with the last range, but the overhead might outweigh the
    // convenience
    std::copy(ranges.begin(), ranges.end(), std::back_inserter(v));
  }

  return v;
}

APFSSpacemanCIB::APFSSpacemanCIB(const APFSPool& pool,
                                 const apfs_block_num block_num)
    : APFSObject(pool, block_num) {
  if (obj_type() != APFS_OBJ_TYPE_SPACEMAN_CIB) {
    throw std::runtime_error("APFSSpacemanCIB: invalid object type");
  }
}

const std::vector<APFSSpacemanCIB::bm_entry> APFSSpacemanCIB::bm_entries()
    const {
  std::vector<bm_entry> v{};
  v.reserve(cib()->entry_count);

  const auto entries = cib()->entries;
  for (auto i = 0U; i < cib()->entry_count; i++) {
    const auto& entry = entries[i];
    v.emplace_back(bm_entry{entry.addr, entry.block_count, entry.free_count,
                            entry.bm_addr});
  }

  return v;
}

APFSSpacemanCAB::APFSSpacemanCAB(const APFSPool& pool,
                                 const apfs_block_num block_num)
    : APFSObject(pool, block_num) {
  if (obj_type() != APFS_OBJ_TYPE_SPACEMAN_CAB) {
    throw std::runtime_error("APFSSpacemanCAB: invalid object type");
  }
}

const std::vector<apfs_block_num> APFSSpacemanCAB::cib_blocks() const {
  std::vector<apfs_block_num> v{};
  v.reserve(cib_count());

  const auto entries = cab()->cib_blocks;

  for (auto i = 0U; i < cib_count(); i++) {
    v.emplace_back(entries[i]);
  }

  return v;
}

APFSBitmapBlock::APFSBitmapBlock(const APFSPool& pool,
                                 const APFSSpacemanCIB::bm_entry& entry)
    : APFSBlock(pool, entry.bm_block), _entry{entry} {}

uint32_t APFSBitmapBlock::next() noexcept {
  while (!done()) {
    // Calculate the index of the bit to be evaluated.
    const auto i = _hint % cached_bits;

    // If we're evaluating the first bit then we need to cache the next set
    // from the array.
    if (i == 0) {
      cache_next();

      // If there are no set bits then there's nothing to scan for, so let's
      // try again with the next set of bits.
      if (_cache == 0) {
        _hint += cached_bits;
        continue;
      }
    }

    // Mask the fetched value and count the number of trailing zero bits.
    const auto c = lsbset((_cache >> i) << i);

    // If c is non-zero then there are set bits.
    if (c != 0) {
      // There are set bits.  We just need to make sure that they're within
      // the range we're scanning for.

      // Adjust the hint for the next call
      _hint += c - i;

      // Check to see if we're still in range
      if (_hint - 1 < _entry.total_blocks) {
        return _hint - 1;
      }

      // The hit is outside of our scanned range
      return no_bits_left;
    }

    // There are no set bits, so we need to adjust the hint to the next set of
    // bits and try again.
    _hint += cached_bits - i;
  }

  return no_bits_left;
}

const std::vector<APFSSpaceman::range> APFSBitmapBlock::unallocated_ranges() {
  // Check for special case where all blocks are allocated
  if (_entry.free_blocks == 0) {
    return {};
  }

  // Check for special cases where all blocks are free
  if (_entry.free_blocks == _entry.total_blocks) {
    return {{_entry.offset, _entry.total_blocks}};
  }

  reset();
  _mode = mode::unset;

  std::vector<APFSSpaceman::range> v{};

  while (!done()) {
    // Get the start of the range.
    const auto s = next();

    // If there's no start then we're done.
    if (s == no_bits_left) {
      break;
    }

    // Toggle the scan mode to look for the next type of bit.
    toggle_mode();

    // Get the end of the range.
    auto e = next();

    // If there's no end then we set the end of the range to the end of the
    // bitmap.
    if (e == no_bits_left) {
      e = _entry.total_blocks;
    }

    // Add the range description to the vector.
    v.emplace_back(APFSSpaceman::range{s + _entry.offset, e - s});

    // Toggle the scan mode for the next scan.
    toggle_mode();
  }

  return v;
}

APFSKeybag::APFSKeybag(const APFSPool& pool, const apfs_block_num block_num,
                       const uint8_t* key, const uint8_t* key2)
    : APFSObject(pool, block_num) {
  decrypt(key, key2);

  if (!validate_checksum()) {
    throw std::runtime_error("keybag did not decrypt properly");
  }

  if (kb()->version != 2) {
    throw std::runtime_error("keybag version not supported");
  }
}

std::unique_ptr<uint8_t[]> APFSKeybag::get_key(const Guid& uuid,
                                               uint16_t type) const {
  if (kb()->num_entries == 0) {
    return nullptr;
  }

  // First key is immediately after the header
  auto next_key = kb()->first_key;

  for (auto i = 0U; i < kb()->num_entries; i++) {
    if (next_key->type == type &&
        std::memcmp(next_key->uuid, uuid.bytes().data(), 16) == 0) {
      // We've found a matching key.  Copy it's data to a pointer and return it.
      const auto data = reinterpret_cast<const uint8_t*>(next_key + 1);

      // We're padding the data with an extra byte so we can null-terminate
      // any data strings.  There might be a better way.
      auto dp = std::make_unique<uint8_t[]>(next_key->length + 1);

      std::memcpy(dp.get(), data, next_key->length);

      return dp;
    }

    // Calculate address of next key (ensuring alignment)

    const auto nk_addr =
        (uintptr_t)next_key +
        ((sizeof(*next_key) + next_key->length + 0x0F) & ~0x0FULL);

    next_key = reinterpret_cast<const apfs_keybag_key*>(nk_addr);
  }

  // Not Found
  return nullptr;
}

std::vector<APFSKeybag::key> APFSKeybag::get_keys() const {
  std::vector<key> keys;

  // First key is immediately after the header
  auto next_key = kb()->first_key;

  for (auto i = 0U; i < kb()->num_entries; i++) {
    const auto data = reinterpret_cast<const uint8_t*>(next_key + 1);

    // We're padding the data with an extra byte so we can null-terminate
    // any data strings.  There might be a better way.
    auto dp = std::make_unique<uint8_t[]>(next_key->length + 1);

    std::memcpy(dp.get(), data, next_key->length);

    keys.emplace_back(key{{next_key->uuid}, std::move(dp), next_key->type});

    // Calculate address of next key (ensuring alignment)
    const auto nk_addr =
        (uintptr_t)next_key +
        ((sizeof(*next_key) + next_key->length + 0x0F) & ~0x0FULL);

    next_key = reinterpret_cast<const apfs_keybag_key*>(nk_addr);
  }

  return keys;
}

APFSSuperblock::Keybag::Keybag(const APFSSuperblock& sb)
    : APFSKeybag(sb.pool(), sb.sb()->keylocker.start_paddr, sb.sb()->uuid,
                 sb.sb()->uuid) {
  if (obj_type_and_flags() != APFS_OBJ_TYPE_CONTAINER_KEYBAG) {
    throw std::runtime_error("APFSSuperblock::Keybag: invalid object type");
  }

  if (sb.sb()->keylocker.block_count != 1) {
    throw std::runtime_error("only single block keybags are supported");
  }
}

APFSExtentRefBtreeNode::iterator APFSExtentRefBtreeNode::find(
    apfs_block_num block) const {
  return APFSBtreeNode::find(
      block, [](const auto& key, const auto block) noexcept->int64_t {
        return key.template as<APFSPhysicalExtentKey>()->start_block() - block;
      });
}

APFSFileSystem::Keybag::Keybag(const APFSFileSystem& vol,
                               apfs_block_num block_num)
    : APFSKeybag(vol.pool(), block_num, vol.fs()->uuid, vol.fs()->uuid) {
  if (obj_type_and_flags() != APFS_OBJ_TYPE_VOLUME_RECOVERY_KEYBAG) {
    throw std::runtime_error("APFSFileSystem::Keybag: invalid object type");
  }
}
