#pragma once

#include "../base/tsk_base.h"
#include "../img/tsk_img.h"
#include "../pool/tsk_apfs.h"

#ifdef __cplusplus
extern "C" {
#else
#define static_assert(x, y)  // static assertions are not valid in C
#endif

// All structures are defined as they exist on disk, so we need to disable
// padding
#pragma pack(push, 1)

#define APFS_BLOCK_SIZE 4096
#define APFS_CRYPTO_SW_BLKSIZE 512

#define APFS_NXSUPERBLOCK_MAGIC 0x4253584E  // NXSB
#define APFS_FS_MAGIC 0x42535041            // APSB

#define APFS_NX_MAX_FILE_SYSTEMS 100
#define APFS_NX_NUM_COUNTERS 32
#define APFS_NX_EPH_INFO_COUNT 4

#define APFS_MODIFIED_NAMELEN 0x20
#define APFS_MAX_HIST 8
#define APFS_VOLNAME_LEN 256

// Flags for apfs_obj_header.flags
#define APFS_OBJ_HEADER_VIRTUAL 0x0000
#define APFS_OBJ_HEADER_EPHEMERAL 0x8000
#define APFS_OBJ_HEADER_PHYSICAL 0x4000
#define APFS_OBJ_HEADER_NOHEADER 0x2000
#define APFS_OBJ_HEADER_ENCRYPTED 0x1000
#define APFS_OBJ_HEADER_NONPERSISTENT 0x0800

typedef struct {
  uint64_t cksum;  // 0x00
  uint64_t oid;    // 0x08
  uint64_t xid;    // 0x10
  union {          // 0x18
    struct {
      uint16_t type;
      uint16_t flags;
    };
    uint32_t type_and_flags;
  };
  uint32_t subtype;  // 0x1C
} apfs_obj_header;
static_assert(sizeof(apfs_obj_header) == 0x20, "improperly aligned struct");

typedef enum {
  APFS_OBJ_TYPE_SUPERBLOCK = 0x0001,

  APFS_OBJ_TYPE_BTREE_ROOTNODE = 0x0002,
  APFS_OBJ_TYPE_BTREE_NODE = 0x0003,
  APFS_OBJ_TYPE_MTREE = 0x0004,

  APFS_OBJ_TYPE_SPACEMAN = 0x0005,
  APFS_OBJ_TYPE_SPACEMAN_CAB = 0x0006,
  APFS_OBJ_TYPE_SPACEMAN_CIB = 0x0007,
  APFS_OBJ_TYPE_SPACEMAN_BITMAP = 0x0008,
  APFS_OBJ_TYPE_SPACEMAN_FREE_QUEUE = 0x0009,

  APFS_OBJ_TYPE_EXTENT_LIST_TREE = 0x000A,
  APFS_OBJ_TYPE_OMAP = 0x000B,
  APFS_OBJ_TYPE_CHECKPOINT_DESC = 0x000C,

  APFS_OBJ_TYPE_FS = 0x000D,
  APFS_OBJ_TYPE_FSTREE = 0x000e,
  APFS_OBJ_TYPE_BLOCKREFTREE = 0x000f,
  APFS_OBJ_TYPE_SNAPMETATREE = 0x0010,

  APFS_OBJ_TYPE_NX_REAPER = 0x0011,
  APFS_OBJ_TYPE_NX_REAP_LIST = 0x0012,
  APFS_OBJ_TYPE_OMAP_SNAPSHOT = 0x0013,
  APFS_OBJ_TYPE_EFI_JUMPSTART = 0x0014,
  APFS_OBJ_TYPE_FUSION_MIDDLE_TREE = 0x0015,
  APFS_OBJ_TYPE_NX_FUSION_WBC = 0x0016,
  APFS_OBJ_TYPE_NX_FUSION_WBC_LIST = 0x0017,
  APFS_OBJ_TYPE_ER_STATE = 0x0018,

  APFS_OBJ_TYPE_GBITMAP = 0x0019,
  APFS_OBJ_TYPE_GBITMAP_TREE = 0x001a,
  APFS_OBJ_TYPE_GBITMAP_BLOCK = 0x001b,

  APFS_OBJ_TYPE_TEST = 0x00ff,

  // Keybag
  APFS_OBJ_TYPE_CONTAINER_KEYBAG = 0x6b657973,
  APFS_OBJ_TYPE_VOLUME_RECOVERY_KEYBAG = 0x72656373,

} APFS_OBJ_TYPE_ENUM;

typedef struct {
  uint64_t start_paddr;  // 0x00
  uint64_t block_count;  // 0x08
} apfs_prange;
static_assert(sizeof(apfs_prange) == 0x10, "improperly aligned struct");

// Flags for apfs_nx_superblock.features
#define APFS_NXSB_FEATURES_DEFRAG 0x0000000000000001ULL
#define APFS_NXSB_FEATURES_LCFD 0x0000000000000002ULL

// Flags for apfs_nx_superblock.imcompatible_features
#define APFS_NXSB_INCOMPAT_VERSION1 0x0000000000000001ULL
#define APFS_NXSB_INCOMPAT_VERSION2 0x0000000000000002ULL
#define APFS_NXSB_INCOMPAT_FUSION 0x0000000000000100ULL

// Flags for apfs_nx_superblock.flags
#define APFS_NXSB_FLAGS_RESERVED_1 0x00000001LL
#define APFS_NXSB_FLAGS_RESERVED_2 0x00000002LL
#define APFS_NXSB_FLAGS_CRYPTO_SW 0x00000004LL

typedef struct {
  apfs_obj_header obj_hdr;                          // 0x00
  uint32_t magic;                                   // 0x20 (NXSB)
  uint32_t block_size;                              // 0x24
  uint64_t block_count;                             // 0x28
  uint64_t features;                                // 0x30
  uint64_t readonly_compatible_features;            // 0x38
  uint64_t incompatible_features;                   // 0x40
  uint8_t uuid[16];                                 // 0x48
  uint64_t next_oid;                                // 0x58
  uint64_t next_xid;                                // 0x60
  uint32_t chkpt_desc_block_count;                  // 0x68
  uint32_t chkpt_data_block_count;                  // 0x6C
  uint64_t chkpt_desc_base_addr;                    // 0x70
  uint64_t chkpt_data_base_addr;                    // 0x78
  uint32_t chkpt_desc_next_block;                   // 0x80
  uint32_t chkpt_data_next_block;                   // 0x84
  uint32_t chkpt_desc_index;                        // 0x88
  uint32_t chkpt_desc_len;                          // 0x8C
  uint32_t chkpt_data_index;                        // 0x90
  uint32_t chkpt_data_len;                          // 0x94
  uint64_t spaceman_oid;                            // 0x98
  uint64_t omap_oid;                                // 0xA0
  uint64_t reaper_oid;                              // 0xA8
  uint32_t test_type;                               // 0xB0
  uint32_t max_fs_count;                            // 0xB4
  uint64_t fs_oids[APFS_NX_MAX_FILE_SYSTEMS];       // 0xB8
  uint64_t counters[APFS_NX_NUM_COUNTERS];          // 0x3D8
  apfs_prange blocked_out_prange;                   // 0x4D8
  uint64_t evict_mapping_tree_oid;                  // 0x4E8
  uint64_t flags;                                   // 0x4F0
  uint64_t efi_jumpstart;                           // 0x4F8
  uint8_t fusion_uuid[16];                          // 0x500
  apfs_prange keylocker;                            // 0x510
  uint64_t ephemeral_info[APFS_NX_EPH_INFO_COUNT];  // 0x520
  uint64_t test_oid;                                // 0x540
  uint64_t fusion_mt_oid;                           // 0x548
  uint64_t fusion_wbc_oid;                          // 0x550
  uint64_t fusion_wbc;                              // 0x558
} apfs_nx_superblock;
static_assert(sizeof(apfs_nx_superblock) == 0x560, "improperly aligned struct");

// Flags for apfs_omap.flags
#define APFS_OMAP_MANUALLY_MANAGED 0x00000001
#define APFS_OMAP_ENCRYPTING 0x00000002
#define APFS_OMAP_DECRYPTING 0x00000004
#define APFS_OMAP_KEYROLLING 0x00000008
#define APFS_OMAP_CRYPTO_GENERATION 0x00000010

// Flags for apfs_omap.type_flags
#define APFS_OMAP_EPHEMERAL 0x8000
#define APFS_OMAP_PHYSICAL 0x4000

typedef struct {
  apfs_obj_header obj_hdr;      // 0x00
  uint32_t flags;               // 0x20
  uint32_t snapshot_count;      // 0x24
  uint16_t tree_type;           // 0x28
  uint16_t type_flags;          // 0x2A
  uint32_t snapshot_tree_type;  // 0x2C
  uint64_t tree_oid;            // 0x30
  uint64_t snapshot_tree_oid;   // 0x38
  uint64_t most_recent_snap;    // 0x40
  uint64_t pending_revert_min;  // 0x48
  uint64_t pending_revert_max;  // 0x50
} apfs_omap;
static_assert(sizeof(apfs_omap) == 0x58, "improperly aligned struct");

typedef enum {
  APFS_OMAP_TREE_TYPE_UNK = 0x0001,
  APFS_OMAP_TREE_TYPE_BTREE = 0x0002,
  APFS_OMAP_TREE_TYPE_MTREE = 0x0004,
} APFS_OMAP_TREE_TYPE_ENUM;

// Flags for apfs_btree_node.flags
#define APFS_BTNODE_ROOT 0x0001
#define APFS_BTNODE_LEAF 0x0002
#define APFS_BTNODE_FIXED_KV_SIZE 0x0004
#define APFS_BTNODE_CHECK_KOFF_INVAL 0x8000

typedef struct {
  apfs_obj_header obj_hdr;      // 0x00
  uint16_t flags;               // 0x20
  uint16_t level;               // 0x22
  uint32_t key_count;           // 0x24
  uint16_t table_space_offset;  // 0x28
  uint16_t table_space_length;  // 0x2A
  uint16_t free_space_offset;   // 0x2C
  uint16_t free_space_length;   // 0x2E
  uint16_t free_list_head;      // 0x30
  uint16_t free_space_avail;    // 0x32
  uint16_t val_space_head;      // 0x34
  uint16_t val_space_avail;     // 0x36
} apfs_btree_node;
static_assert(sizeof(apfs_btree_node) == 0x38, "improperly aligned struct");

typedef struct {
  uint16_t key_offset;
  uint16_t val_offset;
} apfs_btentry_fixed;
static_assert(sizeof(apfs_btentry_fixed) == 0x04, "improperly aligned struct");

typedef struct {
  uint16_t key_offset;
  uint16_t key_length;
  uint16_t val_offset;
  uint16_t val_length;
} apfs_btentry_variable;
static_assert(sizeof(apfs_btentry_variable) == 0x08,
              "improperly aligned struct");

// Flags for apfs_btree_info.flags
#define APFS_BTREE_UINT64_KEYS 0x00000001
#define APFS_BTREE_SEQUENTIAL_INSERT 0x00000002
#define APFS_BTREE_ALLOW_GHOSTS 0x00000004
#define APFS_BTREE_EPHEMERAL 0x00000008
#define APFS_BTREE_PHYSICAL 0x00000010
#define APFS_BTREE_NONPERSISTENT 0x00000020
#define APFS_BTREE_KV_NONALIGNED 0x00000040

typedef struct {
  uint32_t flags;        // 0x00
  uint32_t node_size;    // 0x04
  uint32_t key_size;     // 0x08
  uint32_t val_size;     // 0x0C
  uint32_t longest_key;  // 0x10
  uint32_t longest_val;  // 0x14
  uint64_t key_count;    // 0x18
  uint64_t node_count;   // 0x20
} apfs_btree_info;
static_assert(sizeof(apfs_btree_info) == 0x28, "improperly aligned struct");

// Flags for apfs_superblock.features
#define APFS_SB_FEATURES_DEFRAG_PRERELEASE 0x00000001LL
#define APFS_SB_FEATURES_HARDLINK_MAP_RECORDS 0x00000002LL
#define APFS_SB_FEATURES_DEFRAG 0x00000004LL

// Flags for apfs_superblock.incompatible_features
#define APFS_SB_INCOMPAT_CASE_INSENSITIVE 0x00000001LL
#define APFS_SB_INCOMPAT_DATALESS_SNAPS 0x00000002LL
#define APFS_SB_INCOMPAT_ENC_ROLLED 0x00000004LL
#define APFS_SB_INCOMPAT_NORMALIZATION_INSENSITIVE 0x00000008LL

// Flags for apfs_superblock.flags
#define APFS_SB_UNENCRYPTED 0x00000001LL
#define APFS_SB_EFFACEABLE 0x00000002LL
#define APFS_SB_RESERVED_4 0x00000004LL
#define APFS_SB_ONEKEY 0x00000008LL
#define APFS_SB_SPILLEDOVER 0x00000010LL
#define APFS_SB_RUN_SPILLOVER_CLEANER 0x00000020LL

typedef struct {
  apfs_obj_header obj_hdr;                // 0x00
  uint32_t magic;                         // 0x20
  uint32_t fs_index;                      // 0x24
  uint64_t features;                      // 0x28
  uint64_t readonly_compatible_features;  // 0x30
  uint64_t incompatible_features;         // 0x38
  uint64_t unmount_time;                  // 0x40
  uint64_t reserve_blocks;                // 0x48
  uint64_t quota_blocks;                  // 0x50
  uint64_t alloc_blocks;                  // 0x58
  struct {
    uint16_t major_version;     // 0x60
    uint16_t minor_version;     // 0x62
    uint32_t cpflags;           // 0x64
    uint32_t persistent_class;  // 0x68
    uint32_t key_os_version;    // 0x6C
    uint16_t key_revision;      // 0x70
    uint16_t unused;            // 0x72
  } meta_crypto;
  uint32_t root_tree_type;                   // 0x74
  uint32_t extentref_tree_type;              // 0x78
  uint32_t snap_meta_tree_type;              // 0x7C
  uint64_t omap_oid;                         // 0x80
  uint64_t root_tree_oid;                    // 0x88
  uint64_t extentref_tree_oid;               // 0x90
  uint64_t snap_meta_tree_oid;               // 0x98
  uint64_t revert_to_xid;                    // 0xA0
  uint64_t revert_to_sblock_oid;             // 0xA8
  uint64_t next_inum;                        // 0xB0
  uint64_t num_files;                        // 0xB8
  uint64_t num_directories;                  // 0xC0
  uint64_t num_symlinks;                     // 0xC8
  uint64_t num_other_fsobjects;              // 0xD0
  uint64_t num_snapshots;                    // 0xD8
  uint64_t total_blocks_alloced;             // 0xE0
  uint64_t total_blocks_freed;               // 0xE8
  uint8_t uuid[16];                          // 0xF0
  uint64_t last_mod_time;                    // 0x100
  uint64_t flags;                            // 0x108
  char formatted_by[APFS_MODIFIED_NAMELEN];  // 0x110
  uint64_t created_timestamp;                // 0x130
  uint64_t last_xid;                         // 0x138
  struct {
    char kext_ver_str[APFS_MODIFIED_NAMELEN];
    uint64_t timestamp;
    uint64_t last_xid;
  } unmount_logs[APFS_MAX_HIST];  // 0x140
  char name[APFS_VOLNAME_LEN];    // 0x2C0
  uint32_t next_doc_id;           // 0x3C0
  uint16_t role;                  // 0x3C4
  uint16_t reserved;              // 0x3C6
  uint64_t root_to_xid;           // 0x3C8
  uint64_t er_state_oid;          // 0x3D0
} apfs_superblock;
static_assert(sizeof(apfs_superblock) == 0x3D8, "improperly aligned struct");

typedef enum {
  APFS_VOLUME_ROLE_NONE = 0x0000,
  APFS_VOLUME_ROLE_SYSTEM = 0x0001,
  APFS_VOLUME_ROLE_USER = 0x0002,
  APFS_VOLUME_ROLE_RECOVERY = 0x0004,
  APFS_VOLUME_ROLE_VM = 0x0008,
  APFS_VOLUME_ROLE_PREBOOT = 0x0010,
} APFS_VOLUME_ROLE;

typedef enum {
  APFS_SD_MAIN = 0,
  APFS_SD_TIER2 = 1,
  APFS_SD_COUNT = 2,
} APFS_SD;

typedef enum {
  APFS_SFQ_IP = 0,
  APFS_SFQ_MAIN = 1,
  APFS_SFQ_TIER2 = 2,
  APFS_SFQ_COUNT = 3
} APFS_SFQ;

// Flags for apfs_checkpoint_map.flags
#define APFS_CHECKPOINT_MAP_LAST 0x00000001

typedef struct {
  apfs_obj_header obj_hdr;  // 0x00
  uint32_t flags;           // 0x20
  uint32_t count;           // 0x24
  struct {
    uint16_t type;     // 0x00
    uint16_t flags;    // 0x02
    uint32_t subtype;  // 0x04
    uint32_t size;     // 0x08
    uint32_t padding;  // 0x0C
    uint64_t fs_oid;   // 0x10
    uint64_t oid;      // 0x18
    uint64_t paddr;    // 0x20
  } entries[0];        // 0x28
} apfs_checkpoint_map;
static_assert(sizeof(apfs_checkpoint_map) == 0x28, "improperly aligned struct");

typedef struct {
  uint64_t block_count;  // 0x00
  uint64_t chunk_count;  // 0x08
  uint32_t cib_count;    // 0x10
  uint32_t cab_count;    // 0x14
  uint64_t free_count;   // 0x18
  uint32_t addr_offset;  // 0x20
  uint32_t reserved24;   // 0x24
  uint64_t reserved28;   // 0x28
} apfs_spaceman_device;
static_assert(sizeof(apfs_spaceman_device) == 0x30,
              "improperly aligned struct");

typedef struct {
  uint64_t count;            // 0x00
  uint64_t tree_oid;         // 0x08
  uint64_t oldest_xid;       // 0x10
  uint16_t tree_node_limit;  // 0x18
  uint16_t pad16;            // 0x1A
  uint32_t pad32;            // 0x1C
  uint64_t reserved20;       // 0x20
} apfs_spaceman_free_queue;
static_assert(sizeof(apfs_spaceman_free_queue) == 0x28,
              "improperly aligned struct");

// Flags for apfs_spaceman.flags
#define APFS_SM_FLAG_VERSIONED 0x00000001

typedef struct {
  apfs_obj_header obj_hdr;                      // 0x00
  uint32_t block_size;                          // 0x20
  uint32_t blocks_per_chunk;                    // 0x24
  uint32_t chunks_per_cib;                      // 0x28
  uint32_t cib_per_cab;                         // 0x2C
  apfs_spaceman_device devs[APFS_SD_COUNT];     // 0x30
  uint32_t flags;                               // 0x90
  uint32_t ip_tx_multiplier;                    // 0x94
  uint64_t ip_block_count;                      // 0x98
  uint32_t ip_bm_size_in_blocks;                // 0xA0
  uint32_t ip_bm_block_count;                   // 0xA4
  uint64_t ip_bm_base_address;                  // 0xA8
  uint64_t ip_base_address;                     // 0xB0
  uint64_t fs_reserve_block_count;              // 0xB8
  uint64_t fs_reserve_alloc_count;              // 0xC0
  apfs_spaceman_free_queue fq[APFS_SFQ_COUNT];  // 0xC8
  uint16_t ip_bm_free_head;                     // 0x140
  uint16_t ip_bm_free_tail;                     // 0x142
  uint32_t ip_bm_xid_offset;                    // 0x144
  uint32_t ip_bm_offset;                        // 0x148
  uint32_t ip_bm_free_next_offset;              // 0x14C
  uint32_t version;                             // 0x150
  uint32_t struct_size;                         // 0x154
} apfs_spaceman;
static_assert(sizeof(apfs_spaceman) == 0x158, "improperly aligned struct");

// Type 6
typedef struct {
  apfs_obj_header obj_header;  // 0x00
  uint32_t index;              // 0x20
  uint32_t cib_count;          // 0x24
  uint64_t cib_blocks[0];      // 0x28
} apfs_spaceman_cab;
static_assert(sizeof(apfs_spaceman_cab) == 0x28, "improperly aligned struct");

// Type 7
typedef struct {
  apfs_obj_header obj_header;  // 0x00
  uint32_t index;              // 0x20
  uint32_t entry_count;        // 0x24
  struct {
    uint64_t xid;          // + 0x00
    uint64_t addr;         // + 0x08
    uint32_t block_count;  // + 0x10
    uint32_t free_count;   // + 0x14
    uint64_t bm_addr;      // + 0x18
  } entries[0];            // 0x28
} apfs_spaceman_cib;
static_assert(sizeof(apfs_spaceman_cib) == 0x28, "improperly aligned struct");

// Flags for apfs_nx_reaper.flags
#define APFS_NR_BHM_FLAG 0x00000001
#define APFS_NR_CONTINUE 0x00000002

typedef struct {
  apfs_obj_header obj_header;  // 0x00
  uint64_t next_reap_id;       // 0x20
  uint64_t compleated_id;      // 0x28
  uint64_t head;               // 0x30
  uint64_t tail;               // 0x38
  uint32_t flags;              // 0x40
  uint32_t rlcount;            // 0x44
  uint32_t type;               // 0x48
  uint32_t size;               // 0x4C
  uint64_t fs_oid;             // 0x50
  uint64_t oid;                // 0x58
  uint64_t xid;                // 0x60
  uint32_t le_flags;           // 0x68
  uint32_t state_buffer_size;  // 0x6C
  uint8_t state_buffer[0];     // 0x70
} apfs_nx_reaper;
static_assert(sizeof(apfs_nx_reaper) == 0x70, "improperly aligned struct");

typedef struct {
  apfs_obj_header obj_header;  // 0x00
  uint64_t next;               // 0x20
  uint32_t flags;              // 0x28
  uint32_t max;                // 0x2C
  uint32_t count;              // 0x30
  uint32_t first;              // 0x34
  uint32_t last;               // 0x38
  uint32_t free;               // 0x3C
  struct {                     // 0x40
    uint32_t next;
    uint32_t flags;
    uint32_t type;
    uint32_t size;
    uint64_t fs_oid;
    uint64_t oid;
    uint64_t xid;
  } entries[0];
} apfs_nx_reap_list;
static_assert(sizeof(apfs_nx_reap_list) == 0x40, "improperly aligned struct");

typedef enum {
  APFS_KB_TYPE_WRAPPING_KEY = 1,
  APFS_KB_TYPE_VOLUME_KEY = 2,
  APFS_KB_TYPE_UNLOCK_RECORDS = 3,
  APFS_KB_TYPE_PASSPHRASE_HINT = 4,
  APFS_KB_TYPE_USER_PAYLOAD = 0xF8,
} APFS_KB_TYPE;

typedef struct {
  uint8_t uuid[16];    // 0x00
  uint16_t type;       // 0x10
  uint16_t length;     // 0x12
  uint32_t padding14;  // 0x14
} apfs_keybag_key;
static_assert(sizeof(apfs_keybag_key) == 0x18, "improperly aligned struct");

typedef struct {
  apfs_obj_header obj_header;    // 0x00
  uint16_t version;              // 0x20
  uint16_t num_entries;          // 0x22
  uint32_t size;                 // 0x24
  uint64_t padding28;            // 0x28
  apfs_keybag_key first_key[0];  // 0x30
} apfs_keybag;
static_assert(sizeof(apfs_keybag) == 0x30, "improperly aligned struct");

typedef struct {
  uint64_t start_block;
  uint64_t num_blocks;
} apfs_volrec_keybag_value;
static_assert(sizeof(apfs_volrec_keybag_value) == 0x10,
              "improperly aligned struct");

// BTreeNodes

typedef struct {
  uint64_t oid;  // 0x00
  uint64_t xid;  // 0x08
} apfs_omap_key;
static_assert(sizeof(apfs_omap_key) == 0x10, "improperly aligned struct");

// Flags for apfs_omap_value.flags
#define APFS_OMAP_VAL_DELETED 0x00000001
#define APFS_OMAP_VAL_SAVED 0x00000002
#define APFS_OMAP_VAL_ENCRYPTED 0x00000004
#define APFS_OMAP_VAL_NOHEADER 0x00000008
#define APFS_OMAP_VAL_CRYPTO_GENERATION 0x00000010

typedef struct {
  uint32_t flags;  // 0x00
  uint32_t size;   // 0x04
  uint64_t paddr;  // 0x08
} apfs_omap_value;
static_assert(sizeof(apfs_omap_value) == 0x10, "improperly aligned struct");

#define APFS_ROOT_INODE_NUM 2

typedef enum {
  APFS_JOBJTYPE_SNAP_METADATA = 1,
  APFS_JOBJTYPE_PHYS_EXTENT,
  APFS_JOBJTYPE_INODE,
  APFS_JOBJTYPE_XATTR,
  APFS_JOBJTYPE_SIBLING_LINK,
  APFS_JOBJTYPE_DSTREAM_ID,
  APFS_JOBJTYPE_CRYPTO_STATE,
  APFS_JOBJTYPE_FILE_EXTENT,
  APFS_JOBJTYPE_DIR_RECORD,
  APFS_JOBJTYPE_DIR_STATS,
  APFS_JOBJTYPE_SNAP_NAME,
  APFS_JOBJTYPE_SIBLING_MAP,
} APFS_JOBJTYPE;

typedef enum {
  APFS_ITEM_TYPE_FIFO = 1,
  APFS_ITEM_TYPE_CHAR_DEVICE = 2,
  APFS_ITEM_TYPE_DIRECTORY = 4,
  APFS_ITEM_TYPE_BLOCK_DEVICE = 6,
  APFS_ITEM_TYPE_REGULAR = 8,
  APFS_ITEM_TYPE_SYMBOLIC_LINK = 10,
  APFS_ITEM_TYPE_SOCKET = 12,
  APFS_ITEM_TYPE_WHITEOUT = 14,
} APFS_ITEM_TYPE;

typedef enum {
  APFS_XATTR_FLAG_NONRES = 0x0001,
  APFS_XATTR_FLAG_INLINE = 0x0002,
  APFS_XATTR_FLAG_SYMLINK = 0x0004,
} APFS_XATTR_FLAGS;

typedef enum {
  APFS_BSD_FLAG_UF_NODUMP = 0x00000001,
  APFS_BSD_FLAG_UF_IMMUTABLE = 0x00000002,
  APFS_BSD_FLAG_UF_APPEND = 0x00000004,
  APFS_BSD_FLAG_UF_OPAQUE = 0x00000008,
  APFS_BSD_FLAG_UF_COMPRESSED = 0x00000020,
  APFS_BSD_FLAG_UF_TRACKED = 0x00000040,
  APFS_BSD_FLAG_UF_DATAVAULT = 0x00000080,
  APFS_BSD_FLAG_UF_HIDDEN = 0x00008000,
  APFS_BSD_FLAG_SF_ARCHIVED = 0x00010000,
  APFS_BSD_FLAG_SF_IMMUTABLE = 0x00020000,
  APFS_BSD_FLAG_SF_APPEND = 0x00040000,
  APFS_BSD_FLAG_SF_RESTRICTED = 0x00080000,
  APFS_BSD_FLAG_SF_NOUNLINK = 0x00100000,
} APFS_BSD_FLAGS;

/* special xattrs */
#define APFS_XATTR_NAME_DECOMPFS "com.apple.decmpfs"
#define APFS_XATTR_NAME_FINDERINFO "com.apple.FinderInfo"
#define APFS_XATTR_NAME_RESOURCEFORK "com.apple.ResourceFork"
#define APFS_XATTR_NAME_SECURITY "com.apple.system.Security"
#define APFS_XATTR_NAME_SYMLINK "com.apple.fs.symlink"

// Flags for apfs_snap_metadata.flags
#define APFS_SNAP_METADATA_PENDING_DATALESS 0x00000001

typedef struct {
  uint64_t extentref_tree_oid;   // 0x00
  uint64_t sblock_oid;           // 0x08
  uint64_t create_time;          // 0x10
  uint64_t changed_time;         // 0x18
  uint64_t private_id;           // 0x20
  uint32_t extentref_tree_type;  // 0x28
  uint32_t flags;                // 0x2C
  uint16_t name_length;          // 0x30
  char name[0];                  // 0x32 (name_length bytes)
} apfs_snap_metadata;
static_assert(sizeof(apfs_snap_metadata) == 0x32, "improperly aligned struct");

typedef enum {
  APFS_PE_KIND_ANY = 0,
  APFS_PE_KIND_NEW = 1,
  APFS_PE_KIND_UPDATE = 2,
  APFS_PE_KIND_DEAD = 3,
  APFS_PE_KIND_UPDATE_REFCNT = 4,
  APFS_PE_KIND_INVALID = 255
} apfs_phys_extent_kind;

// Bitfields for apfs_phys_extent.len_and_kind
#define APFS_PHYS_EXTENT_LEN_BITS 60
#define APFS_PHYS_EXTENT_LEN_SHIFT 0
#define APFS_PHYS_EXTENT_KIND_BITS 4
#define APFS_PHYS_EXTENT_KIND_SHIFT 60

typedef struct {
  uint64_t len_and_kind;   // 0x00
  uint64_t owning_obj_id;  // 0x08
  uint32_t refcnt;         // 0x10
} apfs_phys_extent;
static_assert(sizeof(apfs_phys_extent) == 0x14, "improperly aligned struct");

// Bitfields for apfs_phys_extent_key.start_block_and_type
#define APFS_PHYS_EXTENT_START_BLOCK_BITS 60
#define APFS_PHYS_EXTENT_START_BLOCK_SHIFT 0
#define APFS_PHYS_EXTENT_TYPE_BITS 4
#define APFS_PHYS_EXTENT_TYPE_SHIFT 60
typedef struct {
  uint64_t start_block_and_type;
} apfs_phys_extent_key;
static_assert(sizeof(apfs_phys_extent_key) == 0x08,
              "improperly aligned struct");

// Flags for apfs_inode.flags
#define APFS_INODE_IS_APFS_PRIVATE = 0x00000001
#define APFS_INODE_MAINTAIN_DIR_STATS = 0x00000002
#define APFS_INODE_DIR_STATS_ORIGIN = 0x00000004
#define APFS_INODE_PROT_CLASS_EXPLICIT = 0x00000008
#define APFS_INODE_WAS_CLONED = 0x00000010
#define APFS_INODE_FLAG_UNUSED = 0x00000020
#define APFS_INODE_HAS_SECURITY_EA = 0x00000040
#define APFS_INODE_BEING_TRUNCATED = 0x00000080
#define APFS_INODE_HAS_FINDER_INFO = 0x00000100
#define APFS_INODE_IS_SPARSE = 0x00000200
#define APFS_INODE_WAS_EVER_CLONED = 0x00000400
#define APFS_INODE_ACTIVE_FILE_TRIMMED = 0x00000800
#define APFS_INODE_PINNED_TO_MAIN = 0x00001000
#define APFS_INODE_PINNED_TO_TIER2 = 0x00002000
#define APFS_INODE_HAS_RSRC_FORK = 0x00004000
#define APFS_INODE_NO_RSRC_FORK = 0x00008000
#define APFS_INODE_ALLOCATION_SPILLEDOVER = 0x00010000

// Bitfields for apfs_inode.mode_and_type
#define APFS_INODE_MODE_BITS 12
#define APFS_INODE_MODE_SHIFT 0
#define APFS_INODE_TYPE_BITS 4
#define APFS_INODE_TYPE_SHIFT 12

typedef struct {
  uint64_t parent_id;      // 0x00
  uint64_t private_id;     // 0x08
  uint64_t create_time;    // 0x10
  uint64_t modified_time;  // 0x18
  uint64_t changed_time;   // 0x20
  uint64_t accessed_time;  // 0x28
  uint64_t flags;          // 0x30
  union {                  // 0x38
    int32_t nlink;
    int32_t nchildren;
  };
  uint32_t default_protection_class;  // 0x3C
  uint32_t write_generation_counter;  // 0x40
  uint32_t bsdflags;                  // 0x44
  uint32_t owner;                     // 0x48
  uint32_t group;                     // 0x4C
  uint16_t mode_and_type;             // 0x50
  uint16_t padding52;                 // 0x52
  uint64_t padding54;                 // 0x54
} apfs_inode;
static_assert(sizeof(apfs_inode) == 0x5C, "improperly aligned struct");

// Flags for apfs_xattr.flags
#define APFS_XATTR_DATA_STREAM = 0x0001
#define APFS_XATTR_DATA_EMBEDDED = 0x0002
#define APFS_XATTR_FILE_SYSTEM_OWNED = 0x0004
#define APFS_XATTR_RESERVED_8 = 0x0008

typedef struct {
  uint16_t flags;      // 0x00
  uint16_t xdata_len;  // 0x02
} apfs_xattr;
static_assert(sizeof(apfs_xattr) == 0x04, "improperly aligned struct");

typedef struct {
  uint64_t parent;       // 0x00
  uint16_t name_length;  // 0x08
  char name[0];          // 0x0C (name_length bytes)
} apfs_sibling_link;
static_assert(sizeof(apfs_sibling_link) == 0x0A, "improperly aligned struct");

typedef struct {
  uint32_t refcnt;  // 0x00
} apfs_dstream_id;
static_assert(sizeof(apfs_dstream_id) == 0x04, "improperly aligned struct");

typedef struct {
  uint32_t refcount;  // 0x00
  struct {
    uint16_t major_version;     // 0x04
    uint16_t minor_version;     // 0x06
    uint32_t cpflags;           // 0x08
    uint32_t persistent_class;  // 0x0C
    uint32_t key_os_version;    // 0x10
    uint16_t key_revision;      // 0x14
    uint16_t key_len;           // 0x16
    uint8_t persistent_key[0];  // 0x18
  } state;
} apfs_crypto_state;
static_assert(sizeof(apfs_crypto_state) == 0x18, "improperly aligned struct");

// Bitfield values from apfs_file_extent.len_and_flags;
#define APFS_FILE_EXTENT_LEN_BITS 56
#define APFS_FILE_EXTENT_LEN_SHIFT 0
#define APFS_FILE_EXTENT_FLAGS_BITS 8
#define APFS_FILE_EXTENT_FLAGS_SHIFT 56

typedef struct {
  uint64_t len_and_flags;  // 0x00
  uint64_t phys;           // 0x08
  uint64_t crypto;         // 0x10
} apfs_file_extent;
static_assert(sizeof(apfs_file_extent) == 0x18, "improperly aligned struct");

// Bitfield values for apfs_dir_record.type_and_flags
#define APFS_DIR_RECORD_TYPE_BITS 4
#define APFS_DIR_RECORD_TYPE_SHIFT 0
#define APFS_DIR_RECORD_FLAGS_BITS 12
#define APFS_DIR_RECORD_FLAGS_SHIFT 4

typedef struct {
  uint64_t file_id;         // 0x00
  uint64_t date_added;      // 0x08
  uint16_t type_and_flags;  // 0x10
} apfs_dir_record;
static_assert(sizeof(apfs_dir_record) == 0x12, "improperly aligned struct");

typedef struct {
  uint64_t num_children;  // 0x00
  uint64_t total_size;    // 0x08
  uint64_t chained_key;   // 0x10
  uint64_t gen_count;     // 0x18
} apfs_dir_stats;
static_assert(sizeof(apfs_dir_stats) == 0x20, "improperly aligned struct");

typedef struct {
  uint64_t snap_xid;  // 0x00
} apfs_snap_name;
static_assert(sizeof(apfs_snap_name) == 0x08, "improperly aligned struct");

typedef struct {
  uint64_t orig_file_id;  // 0x00
} apfs_sibling_map;
static_assert(sizeof(apfs_sibling_map) == 0x08, "improperly aligned struct");

typedef enum {
  APFS_XFIELD_TYPE_SIBLING_ID = 0x01,  // used in drecs
  APFS_XFIELD_TYPE_SNAP_XID = 0x01,    // used in inodes
  APFS_XFIELD_TYPE_DELTA_TREE_OID = 0x02,
  APFS_XFIELD_TYPE_DOCUMENT_ID = 0x03,
  APFS_XFIELD_TYPE_NAME = 0x04,
  APFS_XFIELD_TYPE_PREV_FSIZE = 0x05,
  APFS_XFIELD_TYPE_FINDER_INFO = 0x07,
  APFS_XFIELD_TYPE_DSTREAM = 0x08,
  APFS_XFIELD_TYPE_DIR_STATS_KEY = 0x0A,
  APFS_XFIELD_TYPE_FS_UUID = 0x0B,
  APFS_XFIELD_TYPE_SPARSE_BYTES = 0x0D,
  APFS_XFIELD_TYPE_DEVICE = 0x0E,
} APFS_XFIELD_TYPE;

// Flags for apfs_xfield_entry.flags
#define APFS_XFIELD_ENTRY_DATA_DEPENDENT 0x01
#define APFS_XFIELD_ENTRY_DO_NOT_COPY 0x02
#define APFS_XFIELD_ENTRY_RESERVED_4 0x04
#define APFS_XFIELD_ENTRY_CHILDREN_INHERIT 0x08
#define APFS_XFIELD_ENTRY_USER_FIELD 0x10
#define APFS_XFIELD_ENTRY_SYSTEM_FIELD 0x20
#define APFS_XFIELD_ENTRY_RESERVED_40 0x40
#define APFS_XFIELD_ENTRY_RESERVED_80 0x80

typedef struct {
  uint8_t type;   // 0x00
  uint8_t flags;  // 0x01
  uint16_t len;   // 0x02
} apfs_xfield_entry;
static_assert(sizeof(apfs_xfield_entry) == 0x04, "improperly aligned struct");

typedef struct {
  uint16_t num_exts;
  uint16_t used_data;
  apfs_xfield_entry entries[0];
} apfs_xfield;
static_assert(sizeof(apfs_xfield) == 0x04, "improperly aligned struct");

typedef struct {
  uint64_t size;
  uint64_t alloced_size;
  uint64_t default_crypto_id;
  uint64_t total_bytes_written;
  uint64_t total_bytes_read;
} apfs_dstream;
static_assert(sizeof(apfs_dstream) == 0x28, "improperly aligned struct");

#pragma pack(pop)

#ifdef __cplusplus
}  // extern "C"
#else
#undef static_assert
#endif
