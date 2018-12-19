#pragma once

#include "../base/tsk_base.h"
#include "../img/tsk_img.h"
#include "../pool/tsk_apfs.h"

#ifdef __cplusplus
extern "C" {
#else
#define static_assert(x, y)  // static assertions are not valid in C
#endif

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

typedef struct {
  uint64_t cksum;  // 0x00
  uint64_t oid;    // 0x08
  uint64_t xid;    // 0x10
  union {          // 0x18
    struct {
      uint16_t type;

      // Undefined (reserved) flags
      uint16_t : 11;

      // Other flags
      uint16_t nonpersistent : 1;

      // Storage type flags
      uint16_t encrypted : 1;
      uint16_t no_header : 1;
      uint16_t physical : 1;
      uint16_t ephemeral : 1;
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

typedef struct {
  apfs_obj_header obj_hdr;  // 0x00
  uint32_t magic;           // 0x20 (NXSB)
  uint32_t block_size;      // 0x24
  uint64_t block_count;     // 0x28
  union {                   // 0x30
    uint64_t features;
    struct {
      uint64_t supports_defrag : 1;
      uint64_t supports_lcfd : 1;
      uint64_t : 62;
    };
  };
  uint64_t readonly_compatible_features;  // 0x38
  union {                                 // 0x40
    uint64_t incompatible_features;
    struct {
      uint64_t apfs_version1 : 1;
      uint64_t apfs_version2 : 1;
      uint64_t : 14;
      uint64_t supports_fusion : 1;
      uint64_t : 47;
    };
  };
  uint8_t uuid[16];                            // 0x48
  uint64_t next_oid;                           // 0x58
  uint64_t next_xid;                           // 0x60
  uint32_t chkpt_desc_block_count;             // 0x68
  uint32_t chkpt_data_block_count;             // 0x6C
  uint64_t chkpt_desc_base_addr;               // 0x70
  uint64_t chkpt_data_base_addr;               // 0x78
  uint32_t chkpt_desc_next_block;              // 0x80
  uint32_t chkpt_data_next_block;              // 0x84
  uint32_t chkpt_desc_index;                   // 0x88
  uint32_t chkpt_desc_len;                     // 0x8C
  uint32_t chkpt_data_index;                   // 0x90
  uint32_t chkpt_data_len;                     // 0x94
  uint64_t spaceman_oid;                       // 0x98
  uint64_t omap_oid;                           // 0xA0
  uint64_t reaper_oid;                         // 0xA8
  uint32_t test_type;                          // 0xB0
  uint32_t max_fs_count;                       // 0xB4
  uint64_t fs_oids[APFS_NX_MAX_FILE_SYSTEMS];  // 0xB8
  uint64_t counters[APFS_NX_NUM_COUNTERS];     // 0x3D8
  apfs_prange blocked_out_prange;              // 0x4D8
  uint64_t evict_mapping_tree_oid;             // 0x4E8
  union {                                      // 0x4F0
    uint64_t flags;
    struct {
      uint64_t reserved1 : 1;
      uint64_t reserved2 : 1;
      uint64_t crypto_sw : 1;
      uint64_t : 61;
    };
  };
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

typedef struct {
  apfs_obj_header obj_hdr;  // 0x00
  union {                   // 0x20
    uint32_t flags;
    struct {
      uint32_t manually_managed : 1;
      uint32_t encrypting : 1;
      uint32_t decrypting : 1;
      uint32_t keyrolling : 1;
      uint32_t crypto_generation : 1;
      uint32_t : 27;
    };
  };
  uint32_t snapshot_count;  // 0x24
  uint16_t tree_type;       // 0x28
  uint16_t : 14;            // 0x2A
  uint16_t physical : 1;
  uint16_t ephemeral : 1;
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

typedef struct {
  apfs_obj_header obj_hdr;  // 0x00
  union {                   // 0x20
    uint16_t flags;
    struct {
      uint16_t root : 1;
      uint16_t leaf : 1;
      uint16_t fixed_kv_size : 1;
      uint16_t : 13;
    };
  };
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

typedef struct {
  apfs_obj_header obj_hdr;  // 0x00
  uint32_t magic;           // 0x20
  uint32_t fs_index;        // 0x24
  union {                   // 0x28
    uint64_t features;
    struct {
      uint64_t supports_defrag_prerelease : 1;
      uint64_t supports_hardlink_map_records : 1;
      uint64_t supports_defrag : 1;
      uint64_t : 61;
    };
  };
  uint64_t readonly_compatible_features;  // 0x30
  union {                                 // 0x38
    uint64_t incompatible_features;
    struct {
      uint64_t case_insensitive : 1;
      uint64_t dataless_snaps : 1;
      uint64_t enc_rolled : 1;
      uint64_t normalization_insensitive : 1;
      uint64_t : 60;
    };
  };
  uint64_t unmount_time;    // 0x40
  uint64_t reserve_blocks;  // 0x48
  uint64_t quota_blocks;    // 0x50
  uint64_t alloc_blocks;    // 0x58
  struct {
    uint16_t major_version;     // 0x60
    uint16_t minor_version;     // 0x62
    uint32_t cpflags;           // 0x64
    uint32_t persistent_class;  // 0x68
    uint32_t key_os_version;    // 0x6C
    uint16_t key_revision;      // 0x70
    uint16_t unused;            // 0x72
  } meta_crypto;
  uint32_t root_tree_type;        // 0x74
  uint32_t extentref_tree_type;   // 0x78
  uint32_t snap_meta_tree_type;   // 0x7C
  uint64_t omap_oid;              // 0x80
  uint64_t root_tree_oid;         // 0x88
  uint64_t extentref_tree_oid;    // 0x90
  uint64_t snap_meta_tree_oid;    // 0x98
  uint64_t revert_to_xid;         // 0xA0
  uint64_t revert_to_sblock_oid;  // 0xA8
  uint64_t next_inum;             // 0xB0
  uint64_t num_files;             // 0xB8
  uint64_t num_directories;       // 0xC0
  uint64_t num_symlinks;          // 0xC8
  uint64_t num_other_fsobjects;   // 0xD0
  uint64_t num_snapshots;         // 0xD8
  uint64_t total_blocks_alloced;  // 0xE0
  uint64_t total_blocks_freed;    // 0xE8
  uint8_t uuid[16];               // 0xF0
  uint64_t last_mod_time;         // 0x100
  union {                         // 0x108
    uint64_t flags;
    struct {
      uint64_t unencrypted : 1;
      uint64_t effacable : 1;
      uint64_t : 1;
      uint64_t onekey : 1;
      uint64_t spilled_over : 1;
      uint64_t run_spollover_cleaner : 1;
      uint64_t : 58;
    };
  };
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

typedef struct {
  apfs_obj_header obj_hdr;  // 0x00
  union {                   // 0x20
    uint32_t flags;
    struct {
      uint32_t last : 1;
      uint32_t : 31;
    };
  };
  uint32_t count;  // 0x24
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
  uint16_t padd32;           // 0x1C
  uint64_t reserved20;       // 0x20
} apfs_spaceman_free_queue;
static_assert(sizeof(apfs_spaceman_free_queue) == 0x28,
              "improperly aligned struct");

typedef struct {
  apfs_obj_header obj_hdr;                   // 0x00
  uint32_t block_size;                       // 0x20
  uint32_t blocks_per_chunk;                 // 0x24
  uint32_t chunks_per_cib;                   // 0x28
  uint32_t cib_per_cab;                      // 0x2C
  apfs_spaceman_device devs[APFS_SD_COUNT];  // 0x30
  union {                                    // 0x90
    uint32_t flags;
    struct {
      uint32_t versioned : 1;
      uint32_t : 31;
    };
  };
  uint32_t ip_tx_multiplier;                    // 0x94
  uint32_t ip_block_count;                      // 0x98
  uint32_t ip_bm_block_count;                   // 0x9C
  uint64_t ip_bm_base_address;                  // 0xA0
  uint64_t ip_base_address;                     // 0xA8
  uint64_t fs_reserve_block_count;              // 0xB0
  uint64_t fs_reserve_alloc_count;              // 0xB8
  apfs_spaceman_free_queue fq[APFS_SFQ_COUNT];  // 0xC0
  uint16_t ip_bm_free_head;                     // 0x138
  uint16_t ip_bm_free_tail;                     // 0x13A
  uint32_t ip_bm_xid_offset;                    // 0x13C
  uint32_t ip_bm_offset;                        // 0x140
  uint32_t ip_bm_free_next_offset;              // 0x144
  uint32_t version;                             // 0x148
  uint32_t struct_size;                         // 0x14C
} apfs_spaceman;
static_assert(sizeof(apfs_spaceman) == 0x150, "improperly aligned struct");

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

typedef struct {
  apfs_obj_header obj_header;  // 0x00
  uint64_t next_reap_id;       // 0x20
  uint64_t compleated_id;      // 0x28
  uint64_t head;               // 0x30
  uint64_t tail;               // 0x38
  union {                      // 0x40
    uint32_t flags;            // 0x40
    struct {
      uint32_t bhm_flag : 1;  // always set
      uint32_t being_reaped : 1;
      uint32_t : 30;
    };
  };
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
  uint8_t data[0];
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

typedef struct {
  union {  // 0x00
    uint32_t flags;
    struct {
      uint32_t deleted : 1;
      uint32_t saved : 1;
      uint32_t encrypted : 1;
      uint32_t noheader : 1;
      uint32_t crypto_gen : 1;
      uint32_t : 27;
    };
  };
  uint32_t size;   // 0x04
  uint64_t paddr;  // 0x08
} apfs_omap_value;
static_assert(sizeof(apfs_omap_value) == 0x10, "improperly aligned struct");

#ifdef __cplusplus
}  // extern "C"
#else
#undef static_assert
#endif
