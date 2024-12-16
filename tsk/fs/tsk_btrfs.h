/*
** The Sleuth Kit
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2003-2011 Brian Carrier.  All rights reserved
**
** TASK
** Copyright (c) 2015 Stefan Pöschel.  All rights reserved
**
** This software is distributed under the Common Public License 1.0
*/

/*
 * Contains the structures and function APIs for Btrfs file system support.
 */

#ifndef TSK_BTRFS_H_
#define TSK_BTRFS_H_

#include <list>
#include <map>
#include <set>
#include <vector>

#ifdef HAVE_LIBZ
#include <zlib.h>
#endif


/* If at least one supported compression available,
 * enable special read/walk code.
 */
#if defined(HAVE_LIBZ)
#define BTRFS_COMP_SUPPORT
#endif

#ifdef __cplusplus
extern "C" {
#endif



/*
 * Btrfs constants
 */

// general
#define BTRFS_ENDIAN                    TSK_LIT_ENDIAN
#define BTRFS_SUPERBLOCK_MIRRORS_MAX    3       // use at most two SB mirror copies - as the third one at 1PB ist not used in btrfs kernel/tools code!
#define BTRFS_SUPERBLOCK_MAGIC_OFFSET   0x40
#define BTRFS_SUPERBLOCK_MAGIC_VALUE    "_BHRfS_M"
#define BTRFS_NAME_LEN_MAX              255

// raw lens
#define BTRFS_SUPERBLOCK_RAWLEN         4096
#define BTRFS_KEY_RAWLEN                17
#define BTRFS_TREE_HEADER_RAWLEN        101
#define BTRFS_KEY_POINTER_RAWLEN        33
#define BTRFS_ITEM_RAWLEN               25
#define BTRFS_CSUM_RAWLEN               32

// superblock values
#define BTRFS_CSUM_TYPE_CRC32C          0x00

#define BTRFS_SUPERBLOCK_INCOMPAT_FLAGS_MIXED_BACKREF   (1ULL << 0)     // not relevant
#define BTRFS_SUPERBLOCK_INCOMPAT_FLAGS_DEFAULT_SUBVOL  (1ULL << 1)     // supported (only for fsstat - we use FS_TREE as root!)
#define BTRFS_SUPERBLOCK_INCOMPAT_FLAGS_MIXED_GROUPS    (1ULL << 2)     // not relevant
#define BTRFS_SUPERBLOCK_INCOMPAT_FLAGS_COMPRESS_LZO    (1ULL << 3)     // TODO: not (yet) supported (but we handle this on EXTENT_DATA level)
#define BTRFS_SUPERBLOCK_INCOMPAT_FLAGS_COMPRESS_LZOv2  (1ULL << 4)     // reserved flag so far
#define BTRFS_SUPERBLOCK_INCOMPAT_FLAGS_BIG_METADATA    (1ULL << 5)     // not relevant
#define BTRFS_SUPERBLOCK_INCOMPAT_FLAGS_EXTENDED_IREF   (1ULL << 6)     // not relevant
#define BTRFS_SUPERBLOCK_INCOMPAT_FLAGS_RAID56          (1ULL << 7)     // not relevant
#define BTRFS_SUPERBLOCK_INCOMPAT_FLAGS_SKINNY_METADATA (1ULL << 8)     // supported
#define BTRFS_SUPERBLOCK_INCOMPAT_FLAGS_NO_HOLES        (1ULL << 9)     // supported

#define BTRFS_SUPERBLOCK_INCOMPAT_FLAGS_SUPPORTED         \
    (BTRFS_SUPERBLOCK_INCOMPAT_FLAGS_MIXED_BACKREF      | \
     BTRFS_SUPERBLOCK_INCOMPAT_FLAGS_DEFAULT_SUBVOL     | \
     BTRFS_SUPERBLOCK_INCOMPAT_FLAGS_MIXED_GROUPS       | \
     BTRFS_SUPERBLOCK_INCOMPAT_FLAGS_COMPRESS_LZO       | \
     BTRFS_SUPERBLOCK_INCOMPAT_FLAGS_BIG_METADATA       | \
     BTRFS_SUPERBLOCK_INCOMPAT_FLAGS_EXTENDED_IREF      | \
     BTRFS_SUPERBLOCK_INCOMPAT_FLAGS_RAID56             | \
     BTRFS_SUPERBLOCK_INCOMPAT_FLAGS_SKINNY_METADATA    | \
     BTRFS_SUPERBLOCK_INCOMPAT_FLAGS_NO_HOLES)


// EXTENT_DATA
#define BTRFS_EXTENT_DATA_TYPE_INLINE       0
#define BTRFS_EXTENT_DATA_TYPE_REGULAR      1
#define BTRFS_EXTENT_DATA_TYPE_PREALLOC     2

#define BTRFS_EXTENT_DATA_COMPRESSION_NONE  0
#define BTRFS_EXTENT_DATA_COMPRESSION_ZLIB  1

#define BTRFS_EXTENT_DATA_ENCRYPTION_NONE   0

#define BTRFS_EXTENT_DATA_OTHER_ENCODING_NONE   0

#define BTRFS_EXTENT_DATA_IS_RAW(ed) \
    ((ed)->compression == BTRFS_EXTENT_DATA_COMPRESSION_NONE && \
     (ed)->encryption == BTRFS_EXTENT_DATA_ENCRYPTION_NONE && \
     (ed)->other_encoding == BTRFS_EXTENT_DATA_OTHER_ENCODING_NONE)


// EXTENT_ITEM
#define BTRFS_EXTENT_ITEM_FLAGS_DATA        0x01
#define BTRFS_EXTENT_ITEM_FLAGS_TREE_BLOCK  0x02


// key parts
#define BTRFS_OBJID_MIN      256ULL
#define BTRFS_OBJID_MAX     -256ULL

#define BTRFS_OBJID_EXTENT_TREE       2ULL
#define BTRFS_OBJID_FS_TREE           5ULL
#define BTRFS_OBJID_CHUNK_ITEM      256ULL

#define BTRFS_ITEM_TYPE_INODE_ITEM          0x01
#define BTRFS_ITEM_TYPE_INODE_REF           0x0C
#define BTRFS_ITEM_TYPE_XATTR_ITEM          0x18
#define BTRFS_ITEM_TYPE_DIR_ITEM            0x54
#define BTRFS_ITEM_TYPE_DIR_INDEX           0x60
#define BTRFS_ITEM_TYPE_EXTENT_DATA         0x6C
#define BTRFS_ITEM_TYPE_ROOT_ITEM           0x84
#define BTRFS_ITEM_TYPE_EXTENT_ITEM         0xA8
#define BTRFS_ITEM_TYPE_METADATA_ITEM       0xA9
#define BTRFS_ITEM_TYPE_DEV_ITEM            0xD8
#define BTRFS_ITEM_TYPE_CHUNK_ITEM          0xE4


// inode type/mode (modified adopted from stat.h)
#define BTRFS_S_IFMT    0170000

#define BTRFS_S_IFSOCK  0140000
#define BTRFS_S_IFLNK   0120000
#define BTRFS_S_IFREG   0100000
#define BTRFS_S_IFBLK   0060000
#define BTRFS_S_IFDIR   0040000
#define BTRFS_S_IFCHR   0020000
#define BTRFS_S_IFIFO   0010000

#define BTRFS_S_ISUID   0004000
#define BTRFS_S_ISGID   0002000
#define BTRFS_S_ISVTX   0001000

#define BTRFS_S_IRUSR   0000400
#define BTRFS_S_IWUSR   0000200
#define BTRFS_S_IXUSR   0000100

#define BTRFS_S_IRGRP   0000040
#define BTRFS_S_IWGRP   0000020
#define BTRFS_S_IXGRP   0000010

#define BTRFS_S_IROTH   0000004
#define BTRFS_S_IWOTH   0000002
#define BTRFS_S_IXOTH   0000001



/*
 * Btrfs data types (basic)
 */


    typedef struct {
        uint64_t device_id;
        uint64_t total_bytes;
        uint64_t bytes_used;
        uint32_t optimal_io_align;
        uint32_t optimal_io_width;
        uint32_t minimal_io_size;
        uint64_t type;
        uint64_t generation;
        uint64_t start_offset;
        uint32_t dev_group;
        uint8_t seek_speed;
        uint8_t bandwidth;
        uint8_t device_uuid[16];
        uint8_t fs_uuid[16];
    } BTRFS_DEV_ITEM;


    typedef struct {
        // csum ignored (checked on raw item)
        uint8_t uuid[16];
        uint64_t physical_address;
        uint64_t flags;
        // magic ignored (checked on raw item)
        uint64_t generation;
        uint64_t root_tree_root;
        uint64_t chunk_tree_root;
        uint64_t log_tree_root;
        uint64_t log_root_transid;
        uint64_t total_bytes;
        uint64_t bytes_used;
        uint64_t root_dir_objectid;
        uint64_t num_devices;
        uint32_t sectorsize;
        uint32_t nodesize;
        uint32_t leafsize;
        uint32_t stripesize;
        uint32_t n;
        uint64_t chunk_root_generation;
        uint64_t compat_flags;
        uint64_t compat_ro_flags;
        uint64_t incompat_flags;
        uint16_t csum_type;
        uint8_t root_level;
        uint8_t chunk_root_level;
        uint8_t log_root_level;
        BTRFS_DEV_ITEM dev_item;
        uint8_t label[256];
        uint8_t reserved[256];
        uint8_t system_chunks[2048];
        uint8_t _unused[1237];  // remaining bytes unused
    } BTRFS_SUPERBLOCK;


    typedef struct {
        // csum ignored (checked on raw item)
        uint8_t uuid[16];
        uint64_t logical_address;
        uint64_t flags;         // 7 bytes
        uint8_t backref_rev;
        uint8_t chunk_tree_uuid[16];
        uint64_t generation;
        uint64_t parent_tree_id;
        uint32_t number_of_items;
        uint8_t level;
    } BTRFS_TREE_HEADER;


    typedef struct {
        uint64_t object_id;
        uint8_t item_type;
        uint64_t offset;
    } BTRFS_KEY;


    typedef struct {
        int64_t seconds;
        uint32_t nanoseconds;
    } BTRFS_TIME;


// Key Pointer minus Key
    typedef struct {
        uint64_t block_number;
        uint64_t generation;
    } BTRFS_KEY_POINTER_REST;


// Item minus Key
    typedef struct {
        uint32_t data_offset;
        uint32_t data_size;
    } BTRFS_ITEM_REST;



/*
 * Btrfs data types (tree items)
 */


    typedef struct {
        uint64_t generation;
        uint64_t transid;
        uint64_t size;
        uint64_t blocks;
        uint64_t block_group;
        uint32_t nlink;
        uint32_t uid;
        uint32_t gid;
        uint32_t mode;
        uint64_t rdev;
        uint64_t flags;
        uint64_t sequence;
        uint8_t _reserved[20];
        BTRFS_TIME atime;
        BTRFS_TIME ctime;
        BTRFS_TIME mtime;
        BTRFS_TIME otime;       // reserved
    } BTRFS_INODE_ITEM;


    typedef struct BTRFS_INODE_REF {
        BTRFS_INODE_REF *next;  // NULL if no next entry

        uint64_t index_in_dir;
        char *name_in_dir;
    } BTRFS_INODE_REF;


// used for XATTR_ITEM, DIR_ITEM and DIR_INDEX
    typedef struct BTRFS_DIR_ENTRY {
        BTRFS_DIR_ENTRY *next;  // NULL if no next entry

        BTRFS_KEY child;
        uint64_t transid;
        uint8_t type;

        char *name;

        uint16_t data_len;
        uint8_t *data;
    } BTRFS_DIR_ENTRY;


    typedef struct {
        uint64_t generation;
        uint64_t size_decoded;
        uint8_t compression;
        uint8_t encryption;
        uint16_t other_encoding;
        uint8_t type;

        union {
            struct {
                uint8_t *data;
                uint32_t data_len;
            } rd;               // resident data
            struct {
                uint64_t extent_address;
                uint64_t extent_size;
                uint64_t file_offset;
                uint64_t file_bytes;
            } nrd;              // non-resident data
        };
    } BTRFS_EXTENT_DATA;


    typedef struct {
        BTRFS_INODE_ITEM inode;
        uint64_t expected_generation;
        uint64_t root_dir_object_id;
        uint64_t root_node_block_number;
        uint64_t byte_limit;
        uint64_t bytes_used;
        uint64_t last_snapshot_generation;
        uint64_t flags;
        uint32_t number_of_references;
        BTRFS_KEY drop_progress;
        uint8_t drop_level;
        uint8_t root_node_level;
    } BTRFS_ROOT_ITEM;


// used for EXTENT_ITEM and METADATA_ITEM
    typedef struct {
        uint64_t reference_count;
        uint64_t generation;
        uint64_t flags;
        // depending on the flags, different fields follow - ATM they are not needed and therefore ignored
    } BTRFS_EXTENT_ITEM;


// see above for BTRFS_DEV_ITEM


    typedef struct {
        uint64_t device_id;
        uint64_t offset;
        uint8_t device_uuid[16];
    } BTRFS_CHUNK_ITEM_STRIPE;


    typedef struct {
        uint64_t chunk_size;
        uint64_t referencing_root;
        uint64_t stripe_length;
        uint64_t type;
        uint32_t optimal_io_align;
        uint32_t optimal_io_width;
        uint32_t minimal_io_size;
        uint16_t number_of_stripes;
        uint16_t sub_stripes;
        BTRFS_CHUNK_ITEM_STRIPE *stripes;
    } BTRFS_CHUNK_ITEM;



/*
 * internal parameters/constants
 */

// direction of treenode operations
    typedef enum {
        BTRFS_FIRST,
        BTRFS_LAST
    } BTRFS_DIRECTION;

// flags for key comparison
#define BTRFS_CMP_IGNORE_OBJID      0x01        // ignore object ID
#define BTRFS_CMP_IGNORE_TYPE       0x02        // ignore item type
#define BTRFS_CMP_IGNORE_OFFSET     0x04        // ignore offset
#define BTRFS_CMP_IGNORE_LSB_TYPE   0x08        // ignore item type LSB (special flag to cover two types which only differ in LSB)

// flags for treenode search
#define BTRFS_SEARCH_ALLOW_LEFT_NEIGHBOUR   0x01        // if no item with desired key is found, return left neighbour of the in fact position

// flags for treenode steps
#define BTRFS_STEP_INITIAL  0x01        // do an initial step before key comparison
#define BTRFS_STEP_REPEAT   0x02        // do repeated steps until key matches

// special inodes: superblock + $OrphanFiles
#define BTRFS_VINUM_COUNT_SPECIAL           2
#define BTRFS_SUPERBLOCK_VINUM(fs_info)     ((fs_info)->last_inum - 1)
#define BTRFS_SUPERBLOCK_NAME               "$Superblock"

// len of custom file content
#define BTRFS_FILE_CONTENT_LEN  sizeof(BTRFS_INODE_ITEM)


/*
 * internal data types
 */


// physical <-> logical address mapping
    typedef struct BTRFS_CACHED_CHUNK {
        TSK_DADDR_T source_address;
        TSK_OFF_T size;
        TSK_DADDR_T target_address;

        /*
         * Chunks don't overlap, therefore operator< ensures
         * the correct order within the set.
         * We take advantage of this for finding the corresponding chunk
         * to an address with the help of a temporary chunk:
         * If two chunks overlap, they are treated as equal.
         */
        bool operator<(const BTRFS_CACHED_CHUNK & chunk_range) const {
            return source_address + size - 1 < chunk_range.source_address;
    }}
    BTRFS_CACHED_CHUNK;

    typedef std::set < BTRFS_CACHED_CHUNK > btrfs_cached_chunks_t;

    typedef struct {
        btrfs_cached_chunks_t log2phys;
        btrfs_cached_chunks_t phys2log;
    } BTRFS_CACHED_CHUNK_MAPPING;


// treenode cache
    typedef std::map < TSK_DADDR_T, uint8_t * >btrfs_treenode_cache_map_t;
    typedef std::list < TSK_DADDR_T > btrfs_treenode_cache_lru_t;


// real -> virtual inum mapping
    typedef std::map < TSK_INUM_T, TSK_INUM_T > btrfs_real2virt_inums_t;

    typedef struct {
        BTRFS_ROOT_ITEM ri;
        btrfs_real2virt_inums_t real2virt_inums;
    } BTRFS_SUBVOLUME;

    typedef std::map < uint64_t, BTRFS_SUBVOLUME > btrfs_subvolumes_t;


// virtual -> real inum mapping
    typedef std::pair < uint64_t, TSK_INUM_T > btrfs_real_inum_t;
    typedef std::vector < btrfs_real_inum_t > btrfs_virt2real_inums_t;


// FS info
    typedef struct {
        // super class
        TSK_FS_INFO fs_info;

        // Btrfs specific fields
        bool test;
        BTRFS_SUPERBLOCK *sb;
        int sb_mirror_index;
        uint64_t extent_tree_root_node_address;

        BTRFS_CACHED_CHUNK_MAPPING *chunks;

        btrfs_subvolumes_t *subvolumes;
        btrfs_virt2real_inums_t *virt2real_inums;

        // protects treenode_cache_map and treenode_cache_lru
        tsk_lock_t treenode_cache_lock;
        btrfs_treenode_cache_map_t *treenode_cache_map;
        btrfs_treenode_cache_lru_t *treenode_cache_lru;
    } BTRFS_INFO;


// treenode operations related
    typedef enum {
        BTRFS_TREENODE_FOUND,
        BTRFS_TREENODE_NOT_FOUND,
        BTRFS_TREENODE_ERROR
    } BTRFS_TREENODE_RESULT;

    typedef struct BTRFS_TREENODE {
        BTRFS_TREENODE *prev;   // NULL if no previous level

        BTRFS_TREE_HEADER header;
        uint8_t *data;

        uint32_t index;
        BTRFS_KEY key;
        union {
            BTRFS_KEY_POINTER_REST kp;
            BTRFS_ITEM_REST item;
        };
    } BTRFS_TREENODE;


// block walk related
    typedef struct {
        BTRFS_INFO *btrfs;
        uint64_t block;

        bool no_more_ei;
        BTRFS_KEY ei_key;
        BTRFS_TREENODE *ei_node;
        TSK_DADDR_T ei_start;
        TSK_DADDR_T ei_end;
        TSK_FS_BLOCK_FLAG_ENUM ei_flags;

        bool no_more_cc;
        const BTRFS_CACHED_CHUNK *cc;
    } BTRFS_BLOCKWALK;


// EXTENT_DATA walk related
    typedef struct {
        BTRFS_INFO *btrfs;
        size_t size;
        size_t offset;

        BTRFS_KEY key;
        BTRFS_TREENODE *node;
    } BTRFS_EXTENT_DATAWALK;


// inode walk related
    typedef struct {
        BTRFS_INFO *btrfs;
        TSK_INUM_T vinum;
        uint64_t subvol;

        BTRFS_KEY key;
        BTRFS_TREENODE *node;
        BTRFS_INODE_ITEM ii;
    } BTRFS_INODEWALK;


#ifdef BTRFS_COMP_SUPPORT
// (attribute) data walk related
    typedef enum {
        BTRFS_ED_TYPE_RAW,
        BTRFS_ED_TYPE_SPARSE,
#ifdef HAVE_LIBZ
        BTRFS_ED_TYPE_COMP_ZLIB,
#endif
        BTRFS_ED_TYPE_UNKNOWN
    } BTRFS_ED_TYPE;

    typedef struct {
        BTRFS_INFO *btrfs;
        const TSK_FS_ATTR *attr;
        TSK_OFF_T size;

        uint8_t *in_blockbuffer;
        uint8_t *tmp_blockbuffer;

        BTRFS_EXTENT_DATAWALK *edw;
        BTRFS_EXTENT_DATA *ed;
        TSK_DADDR_T ed_offset;
        bool ed_resident;
        BTRFS_ED_TYPE ed_type;

        TSK_DADDR_T last_raw_addr;
        size_t ed_raw_offset;
        size_t ed_raw_size;

        size_t ed_out_offset;
        size_t ed_out_size;

#ifdef HAVE_LIBZ
        bool zlib_state_used;
        z_stream_s zlib_state;
#endif

        const BTRFS_CACHED_CHUNK *cc;
    } BTRFS_DATAWALK;
#endif



/*
 * helper functions
 */

    extern unsigned long btrfs_csum_crc32c(const unsigned char *a_data,
        const int a_len);



#ifdef __cplusplus
}
#endif
#endif                          /* TSK_BTRFS_H_ */
