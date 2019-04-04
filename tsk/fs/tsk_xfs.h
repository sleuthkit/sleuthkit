/*
 * Contains the structures and function APIs for XFS file system support.
 */

#include <map>


#ifdef __cplusplus
extern "C" {
#endif

/*
 * Generic data types
 */

typedef uint64_t xfs_ino_t;
typedef uint32_t xfs_agino_t;
typedef int64_t  xfs_off_t;
typedef int64_t  xfs_daddr_t;
typedef uint32_t xfs_agnumber_t;
typedef uint32_t xfs_agblock_t;
typedef uint32_t xfs_extlen_t;
typedef int32_t  xfs_extnum_t;
typedef uint32_t xfs_dablk_t;
typedef uint32_t xfs_dahash_t;
typedef uint64_t xfs_dfsbno_t;
typedef uint64_t xfs_drfsbno_t;
typedef uint64_t xfs_drtbno_t;
typedef uint64_t xfs_dfiloff_t;
typedef uint64_t xfs_dfilblks_t;
typedef int64_t  xfs_lsn_t;
typedef int64_t  xfs_fsize_t;
typedef int16_t  xfs_aextnum_t;
typedef uint64_t xfs_fsblock_t;    /* blockno in filesystem (agno|agbno) */
typedef uint64_t xfs_rfsblock_t;   /* blockno in filesystem (raw) */
typedef uint64_t xfs_rtblock_t;    /* extent (block) in realtime area */
typedef uint64_t xfs_fileoff_t;    /* block number in a file */
typedef uint64_t xfs_filblks_t;    /* number of blocks in a file */

#define UUID_SIZE 16
typedef struct {
    uint8_t b[UUID_SIZE];
} xfs_uuid_t;


/*
/* Blocks
 */

typedef enum {
    XFS_EXT_NORM, XFS_EXT_UNWRITTEN,
} xfs_exntst_t;

 /*
 * Bmap btree record and extent descriptor.
 *  l0:63 is an extent flag (value 1 indicates non-normal).
 *  l0:9-62 are startoff.
 *  l0:0-8 and l1:21-63 are startblock.
 *  l1:0-20 are blockcount.
 */
#define BMBT_EXNTFLAG_BITLEN    1
#define BMBT_STARTOFF_BITLEN    54
#define BMBT_STARTBLOCK_BITLEN  52
#define BMBT_BLOCKCOUNT_BITLEN  21

typedef struct xfs_bmbt_irec
{
    xfs_fileoff_t    br_startoff;    /* starting file offset */
    xfs_fsblock_t    br_startblock;  /* starting block number */
    xfs_filblks_t    br_blockcount;  /* number of blocks */
    xfs_exntst_t     br_state;       /* extent state */
} xfs_bmbt_irec_t;

typedef struct xfs_btree_sblock {
    uint32_t    bb_magic;
    uint16_t    bb_level;
    uint16_t    bb_numrecs;
    uint32_t    bb_leftsib;
    uint32_t    bb_rightsib;
} xfs_btree_sblock_t;

typedef struct xfs_alloc_rec {
    uint32_t    ar_startblock;
    uint32_t    ar_blockcount;
} xfs_alloc_rec_t, xfs_alloc_key_t;

typedef uint32_t xfs_alloc_ptr_t;


/*
/* Inodes
 */

/*
 * Values for di_flags
 */
#define XFS_DIFLAG_REALTIME_BIT      0    /* file's blocks come from rt area */
#define XFS_DIFLAG_PREALLOC_BIT      1    /* file space has been preallocated */
#define XFS_DIFLAG_NEWRTBM_BIT       2    /* for rtbitmap inode, new format */
#define XFS_DIFLAG_IMMUTABLE_BIT     3    /* inode is immutable */
#define XFS_DIFLAG_APPEND_BIT        4    /* inode is append-only */
#define XFS_DIFLAG_SYNC_BIT          5    /* inode is written synchronously */
#define XFS_DIFLAG_NOATIME_BIT       6    /* do not update atime */
#define XFS_DIFLAG_NODUMP_BIT        7    /* do not dump */
#define XFS_DIFLAG_RTINHERIT_BIT     8    /* create with realtime bit set */
#define XFS_DIFLAG_PROJINHERIT_BIT   9    /* create with parents projid */
#define XFS_DIFLAG_NOSYMLINKS_BIT   10    /* disallow symlink creation */
#define XFS_DIFLAG_EXTSIZE_BIT      11    /* inode extent size allocator hint */
#define XFS_DIFLAG_EXTSZINHERIT_BIT 12    /* inherit inode extent size */
#define XFS_DIFLAG_NODEFRAG_BIT     13    /* do not reorganize/defragment */
#define XFS_DIFLAG_FILESTREAM_BIT   14    /* use filestream allocator */
/* Do not use bit 15, di_flags is legacy and unchanging now */

#define XFS_DIFLAG_REALTIME      (1 << XFS_DIFLAG_REALTIME_BIT)
#define XFS_DIFLAG_PREALLOC      (1 << XFS_DIFLAG_PREALLOC_BIT)
#define XFS_DIFLAG_NEWRTBM       (1 << XFS_DIFLAG_NEWRTBM_BIT)
#define XFS_DIFLAG_IMMUTABLE     (1 << XFS_DIFLAG_IMMUTABLE_BIT)
#define XFS_DIFLAG_APPEND        (1 << XFS_DIFLAG_APPEND_BIT)
#define XFS_DIFLAG_SYNC          (1 << XFS_DIFLAG_SYNC_BIT)
#define XFS_DIFLAG_NOATIME       (1 << XFS_DIFLAG_NOATIME_BIT)
#define XFS_DIFLAG_NODUMP        (1 << XFS_DIFLAG_NODUMP_BIT)
#define XFS_DIFLAG_RTINHERIT     (1 << XFS_DIFLAG_RTINHERIT_BIT)
#define XFS_DIFLAG_PROJINHERIT   (1 << XFS_DIFLAG_PROJINHERIT_BIT)
#define XFS_DIFLAG_NOSYMLINKS    (1 << XFS_DIFLAG_NOSYMLINKS_BIT)
#define XFS_DIFLAG_EXTSIZE       (1 << XFS_DIFLAG_EXTSIZE_BIT)
#define XFS_DIFLAG_EXTSZINHERIT  (1 << XFS_DIFLAG_EXTSZINHERIT_BIT)
#define XFS_DIFLAG_NODEFRAG      (1 << XFS_DIFLAG_NODEFRAG_BIT)
#define XFS_DIFLAG_FILESTREAM    (1 << XFS_DIFLAG_FILESTREAM_BIT)

#define XFS_DIFLAG_ANY \
    (XFS_DIFLAG_REALTIME | XFS_DIFLAG_PREALLOC | XFS_DIFLAG_NEWRTBM | \
     XFS_DIFLAG_IMMUTABLE | XFS_DIFLAG_APPEND | XFS_DIFLAG_SYNC | \
     XFS_DIFLAG_NOATIME | XFS_DIFLAG_NODUMP | XFS_DIFLAG_RTINHERIT | \
     XFS_DIFLAG_PROJINHERIT | XFS_DIFLAG_NOSYMLINKS | XFS_DIFLAG_EXTSIZE | \
     XFS_DIFLAG_EXTSZINHERIT | XFS_DIFLAG_NODEFRAG | XFS_DIFLAG_FILESTREAM)

/* Values for di_mode */
#define XFS_IN_FMT  0170000
#define XFS_IN_SOCK 0140000
#define XFS_IN_LNK  0120000
#define XFS_IN_REG  0100000
#define XFS_IN_BLK  0060000
#define XFS_IN_DIR  0040000
#define XFS_IN_CHR  0020000
#define XFS_IN_FIFO 0010000

#define XFS_IN_ISUID   0004000
#define XFS_IN_ISGID   0002000
#define XFS_IN_ISVTX   0001000
#define XFS_IN_IRUSR   0000400
#define XFS_IN_IWUSR   0000200
#define XFS_IN_IXUSR   0000100
#define XFS_IN_IRGRP   0000040
#define XFS_IN_IWGRP   0000020
#define XFS_IN_IXGRP   0000010
#define XFS_IN_IROTH   0000004
#define XFS_IN_IWOTH   0000002
#define XFS_IN_IXOTH   0000001

typedef struct xfs_btree_sblock xfs_inobt_block_t;

typedef struct xfs_inobt_rec {
    uint32_t    ir_startino;
    uint32_t    ir_freecount;
    uint64_t    ir_free;
} xfs_inobt_rec_t;

typedef struct xfs_inobt_key {
    uint32_t    ir_startino;
} xfs_inobt_key_t;
typedef uint32_t xfs_inobt_ptr_t;

typedef struct xfs_timestamp {
    int32_t    t_sec;
    int32_t    t_nsec;
} xfs_timestamp_t;

typedef enum xfs_dinode_fmt {
     XFS_DINODE_FMT_DEV,
     XFS_DINODE_FMT_LOCAL,
     XFS_DINODE_FMT_EXTENTS,
     XFS_DINODE_FMT_BTREE,
     XFS_DINODE_FMT_UUID,
     XFS_DINODE_FMT_RMAP,
} xfs_dinode_fmt_t;

typedef struct xfs_dinode_core {
    uint16_t            di_magic;
    uint16_t            di_mode;
    int8_t              di_version;
    int8_t              di_format;
    uint16_t            di_onlink;
    uint32_t            di_uid;
    uint32_t            di_gid;
    uint32_t            di_nlink;
    uint16_t            di_projid;
    uint16_t            di_projid_hi;
    uint8_t             di_pad[6];
    uint16_t            di_flushiter;
    xfs_timestamp_t     di_atime;
    xfs_timestamp_t     di_mtime;
    xfs_timestamp_t     di_ctime;
    xfs_fsize_t         di_size;
    xfs_drfsbno_t       di_nblocks;
    xfs_extlen_t        di_extsize;
    xfs_extnum_t        di_nextents;
    xfs_aextnum_t       di_anextents;
    uint8_t             di_forkoff;
    int8_t              di_aformat;
    uint32_t            di_dmevmask;
    uint16_t            di_dmstate;
    uint16_t            di_flags;
    uint32_t            di_gen;
} xfs_dinode_core_t;

typedef struct xfs_bmdr_block {
    uint16_t    bb_level;    /* 0 is a leaf */
    uint16_t    bb_numrecs;  /* current # of data records */
} xfs_bmdr_block_t;

typedef struct xfs_btree_lblock xfs_bmbt_block_t;
typedef struct xfs_btree_lblock {
    uint32_t   bb_magic;
    uint16_t   bb_level;
    uint16_t   bb_numrecs;
    uint64_t   bb_leftsib;
    uint64_t   bb_rightsib;
} xfs_btree_lblock_t;

typedef struct xfs_bmbt_key {
    xfs_dfiloff_t    br_startoff;
} xfs_bmbt_key_t, xfs_bmdr_key_t;

typedef struct xfs_bmbt_rec_32
{
    uint32_t    l0, l1, l2, l3;
} xfs_bmbt_rec_32_t;
typedef struct xfs_bmbt_rec_64
{
    uint64_t    l0, l1;
} xfs_bmbt_rec_64_t;

typedef uint64_t xfs_bmbt_rec_base_t;
typedef xfs_bmbt_rec_64_t xfs_bmbt_rec_t, xfs_bmdr_rec_t;
 
typedef struct { uint8_t i[8]; } xfs_dir2_ino8_t;
typedef struct { uint8_t i[4]; } xfs_dir2_ino4_t;
typedef union {
    xfs_dir2_ino8_t i8;
    xfs_dir2_ino4_t i4;
} xfs_dir2_inou_t;

typedef uint16_t xfs_dir2_sf_off_t;

typedef xfs_fsblock_t xfs_bmbt_ptr_t, xfs_bmdr_ptr_t;

typedef struct xfs_dir2_sf_entry {
    uint8_t namelen;
    xfs_dir2_sf_off_t offset;
    uint8_t name[1];
    xfs_dir2_inou_t inumber;
} xfs_dir2_sf_entry_t;

typedef struct xfs_dir2_sf_hdr {
    uint8_t count;
    uint8_t i8count;
    xfs_dir2_inou_t parent;
} xfs_dir2_sf_hdr_t;

typedef struct xfs_dir2_sf {
    xfs_dir2_sf_hdr_t hdr;
    xfs_dir2_sf_entry_t list[1];
} xfs_dir2_sf_t;

typedef struct xfs_attr_shortform {
    struct xfs_attr_sf_hdr {
        uint16_t totsize;
        uint8_t count;
 } hdr;
    struct xfs_attr_sf_entry {
        uint8_t namelen;
        uint8_t valuelen;
        uint8_t flags;
        uint8_t nameval[1];
    } list[1];
} xfs_attr_shortform_t;

typedef struct xfs_dinode
{
    xfs_dinode_core_t      di_core;

    uint32_t                di_next_unlinked; /* agi unlinked list ptr */

    /* version 5 filesystem (inode version 3) fields start here */
    uint32_t                di_crc;
    uint64_t                di_changecount;
    uint64_t                di_lsn;
    uint64_t                di_flags2;
    uint32_t                di_cowextsize;
    uint8_t                 di_pad2[12];
    xfs_timestamp_t         di_crtime;
    uint64_t                di_ino;
    xfs_uuid_t              di_uuid;

    union {
        xfs_bmdr_block_t    di_bmbt;       /* btree root block */
        xfs_bmbt_rec_t      di_bmx[1];     /* extent list */
        xfs_dir2_sf_t       di_dir2sf;     /* shortform directory v2 */
        char                di_c[1];       /* local contents */
        uint32_t            di_dev;        /* device for S_IFCHR/S_IFBLK */
        xfs_uuid_t          di_muuid;      /* mount point value */
        char                di_symlink[1]; /* local symbolic link */
    } di_u;
    union {
        xfs_bmdr_block_t     di_abmbt;     /* btree root block */
        xfs_bmbt_rec_32_t    di_abmx[1];   /* extent list */
        xfs_attr_shortform_t di_attrsf;    /* shortform attribute list */
    }        di_a;
} xfs_dinode_t;

/*
 * Size of the core inode on disk.  Version 1 and 2 inodes have
 * the same size, but version 3 has grown a few additional fields.
 */
static inline uint8_t xfs_dinode_size(int version)
{
    if (version == 3)
    {
        return 176;
    }
    else
    {
        return 100;
    }
}

/*
 * Inode fork identifiers.
 */
#define    XFS_DATA_FORK    0
#define    XFS_ATTR_FORK    1
#define    XFS_COW_FORK     2

/*
 * Inode size for given fs.
 */
#define XFS_LITINO(mp, version) \
    ((int)(((mp)->fs->sb_inodesize) - xfs_dinode_size(version)))

#define XFS_DFORK_Q(dip)        ((dip)->di_forkoff != 0)
#define XFS_DFORK_BOFF(dip)     ((int)((dip)->di_forkoff << 3))

#define XFS_DFORK_DSIZE(dip,mp) \
    (XFS_DFORK_Q(dip) ? \
        XFS_DFORK_BOFF(dip) : \
        XFS_LITINO(mp, (dip)->di_version))
#define XFS_DFORK_ASIZE(dip,mp) \
    (XFS_DFORK_Q(dip) ? \
        XFS_LITINO(mp, (dip)->di_version) - XFS_DFORK_BOFF(dip) : \
        0)

#define XFS_DFORK_SIZE(dip,mp,w) \
    ((w) == XFS_DATA_FORK ? \
        XFS_DFORK_DSIZE(dip, mp) : \
        XFS_DFORK_ASIZE(dip, mp))

/*
 * Return pointers to the data or attribute forks.
 */
#define XFS_DFORK_DPTR(dip) \
    ((char *)dip + xfs_dinode_size(dip->di_version))
#define XFS_DFORK_APTR(dip)    \
    (XFS_DFORK_DPTR(dip) + XFS_DFORK_BOFF(dip))
#define XFS_DFORK_PTR(dip,w)    \
    ((w) == XFS_DATA_FORK ? XFS_DFORK_DPTR(dip) : XFS_DFORK_APTR(dip))

/*
 * XFS_MAXNAMELEN is the length (including the terminating null) of
 * the longest permissible file (component) name.
 */
#define XFS_MAXNAMELEN    256

/*
 * Byte offset in data block and shortform entry.
 */
typedef uint16_t xfs_dir2_data_off_t;

/*
 * Describe a free area in the data block.
 *
 * The freespace will be formatted as a xfs_dir2_data_unused_t.
 */
typedef struct xfs_dir2_data_free {
    uint16_t                offset;        /* start of freespace */
    uint16_t                length;        /* length of freespace */
} xfs_dir2_data_free_t;

#define    XFS_DIR2_DATA_FD_COUNT    3
/*
 * Header for the data blocks.
 */
typedef struct xfs_dir2_data_hdr {
    uint32_t                magic;        /* XFS_DIR2_DATA_MAGIC or */
                                          /* XFS_DIR2_BLOCK_MAGIC */
    xfs_dir2_data_free_t    bestfree[XFS_DIR2_DATA_FD_COUNT];
} xfs_dir2_data_hdr_t;

/*
 * Active entry in a data block.
 *
 * Aligned to 8 bytes.  After the variable length name field there is a
 * 2 byte tag field, which can be accessed using xfs_dir3_data_entry_tag_p.
 *
 * For dir3 structures, there is file type field between the name and the tag.
 * This can only be manipulated by helper functions. It is packed hard against
 * the end of the name so any padding for rounding is between the file type and
 * the tag.
 */
typedef struct xfs_dir2_data_entry {
    uint64_t                inumber;    /* inode number */
    uint8_t                 namelen;    /* name length */
    // uint8_t              name[];      /* name bytes, no null */
    // uint8_t              filetype;    /* type of inode we point to */
    // uint16_t             tag;         /* starting offset of us */
} xfs_dir2_data_entry_t;

typedef struct xfs_dir2_data_unused {
    uint16_t                freetag; /* 0xffff */
    xfs_dir2_data_off_t     length;
    xfs_dir2_data_off_t     tag;
} xfs_dir2_data_unused_t;

#define XFS_DIR2_DATA_UNUSED_SIZE 6

typedef struct xfs_dir2_block_tail {
    uint32_t                count;
    uint32_t                stale;
} xfs_dir2_block_tail_t;

typedef uint32_t xfs_dahash_t;
typedef uint32_t xfs_dir2_dataptr_t;
typedef struct xfs_dir2_leaf_entry {
    xfs_dahash_t            hashval;
    xfs_dir2_dataptr_t      address;
} xfs_dir2_leaf_entry_t;

#define    XFS_DIR2_DATA_ALIGN_LOG    3        /* i.e., 8 bytes */
#define    XFS_DIR2_SPACE_SIZE        (1ULL << (32 + XFS_DIR2_DATA_ALIGN_LOG))
#define    XFS_DIR2_LEAF_SPACE        1
#define    XFS_DIR2_LEAF_OFFSET       (XFS_DIR2_LEAF_SPACE * XFS_DIR2_SPACE_SIZE)
#define    XFS_DIR2_FREE_SPACE        2
#define    XFS_DIR2_FREE_OFFSET       (XFS_DIR2_FREE_SPACE * XFS_DIR2_SPACE_SIZE)


/*
** Super Block and related definitions 
*/

/*
 * There are two words to hold XFS "feature" bits: the original
 * word, sb_versionnum, and sb_features2.  Whenever a bit is set in
 * sb_features2, the feature bit XFS_SB_VERSION_MOREBITSBIT must be set.
 *
 * These defines represent bits in sb_features2.
 */
#define XFS_SB_VERSION2_RESERVED1BIT      0x00000001
#define XFS_SB_VERSION2_LAZYSBCOUNTBIT    0x00000002    /* Superblk counters */
#define XFS_SB_VERSION2_RESERVED4BIT      0x00000004
#define XFS_SB_VERSION2_ATTR2BIT          0x00000008    /* Inline attr rework */
#define XFS_SB_VERSION2_PARENTBIT         0x00000010    /* parent pointers */
#define XFS_SB_VERSION2_PROJID32BIT       0x00000080    /* 32 bit project id */
#define XFS_SB_VERSION2_CRCBIT            0x00000100    /* metadata CRCs */
#define XFS_SB_VERSION2_FTYPE             0x00000200    /* inode type in dir */

#define    XFS_SB_VERSION2_OKBITS        \
    (XFS_SB_VERSION2_LAZYSBCOUNTBIT    | \
     XFS_SB_VERSION2_ATTR2BIT    | \
     XFS_SB_VERSION2_PROJID32BIT    | \
     XFS_SB_VERSION2_FTYPE)

#define XFS_SB_FEAT_RO_COMPAT_FINOBT   (1 << 0)        /* free inode btree */
#define XFS_SB_FEAT_RO_COMPAT_RMAPBT   (1 << 1)        /* reverse map btree */
#define XFS_SB_FEAT_RO_COMPAT_REFLINK  (1 << 2)        /* reflinked files */

#define XFS_SB_FEAT_INCOMPAT_FTYPE     (1 << 0)        /* filetype in dirent */
#define XFS_SB_FEAT_INCOMPAT_SPINODES  (1 << 1)        /* sparse inode chunks */
#define XFS_SB_FEAT_INCOMPAT_META_UUID (1 << 2)        /* metadata UUID */

#define    XFS_SB_VERSION_NUMBITS        0x000f
#define    XFS_SB_VERSION_NUM(sbp)    ((sbp)->sb_versionnum & XFS_SB_VERSION_NUMBITS)

#define XFS_BTNUM_AGF 2

typedef struct xfs_agf {
    uint32_t              agf_magicnum;
    uint32_t              agf_versionnum;
    uint32_t              agf_seqno;
    uint32_t              agf_length;
    uint32_t              agf_roots[XFS_BTNUM_AGF];
    uint32_t              agf_spare0;
    uint32_t              agf_levels[XFS_BTNUM_AGF];
    uint32_t              agf_spare1;
    uint32_t              agf_flfirst;
    uint32_t              agf_fllast;
    uint32_t              agf_flcount;
    uint32_t              agf_freeblks;
    uint32_t              agf_longest;
    uint32_t              agf_btreeblks;
} xfs_agf_t;

#define XFS_AGFL_SIZE 36
typedef struct xfs_agfl {
    uint32_t              agfl_magicnum;
    uint32_t              agfl_seqno;
    xfs_uuid_t            agfl_uuid;
    uint64_t              agfl_lsn;
    uint32_t              agfl_crc;
} xfs_agfl_t;

typedef struct xfs_agi {
    uint32_t              agi_magicnum;
    uint32_t              agi_versionnum;
    uint32_t              agi_seqno;
    uint32_t              agi_length;
    uint32_t              agi_count;
    uint32_t              agi_root;
    uint32_t              agi_level;
    uint32_t              agi_freecount;
    uint32_t              agi_newino;
    uint32_t              agi_dirino;
    uint32_t              agi_unlinked[64];

    /*
    * v5 filesystem fields start here; this marks the end of logging region 1
    * and start of logging region 2.
    * /
    xfs_uuid_t            agi_uuid;
    uint32_t              agi_crc;
    uint32_t              agi_pad32;
    uint64_t              agi_lsn;
    uint32_t              agi_free_root;
    uint32_t              agi_free_level;
    */
} xfs_agi_t;

typedef struct xfs_sb
{
    uint32_t              sb_magicnum;
    uint32_t              sb_blocksize;
    xfs_drfsbno_t         sb_dblocks;
    xfs_drfsbno_t         sb_rblocks;
    xfs_drtbno_t          sb_rextents;
    xfs_uuid_t            sb_uuid;
    xfs_dfsbno_t          sb_logstart;
    xfs_ino_t             sb_rootino;
    xfs_ino_t             sb_rbmino;
    xfs_ino_t             sb_rsumino;
    xfs_agblock_t         sb_rextsize;
    xfs_agblock_t         sb_agblocks;
    xfs_agnumber_t        sb_agcount;
    xfs_extlen_t          sb_rbmblocks;
    xfs_extlen_t          sb_logblocks;
    uint16_t              sb_versionnum;
    uint16_t              sb_sectsize;
    uint16_t              sb_inodesize;
    uint16_t              sb_inopblock;
    char                  sb_fname[12];
    uint8_t               sb_blocklog;
    uint8_t               sb_sectlog;
    uint8_t               sb_inodelog;
    uint8_t               sb_inopblog;
    uint8_t               sb_agblklog;
    uint8_t               sb_rextslog;
    uint8_t               sb_inprogress;
    uint8_t               sb_imax_pct;
    uint64_t              sb_icount;
    uint64_t              sb_ifree;
    uint64_t              sb_fdblocks;
    uint64_t              sb_frextents;
    xfs_ino_t             sb_uquotino;
    xfs_ino_t             sb_gquotino;
    uint16_t              sb_qflags;
    uint8_t               sb_flags;
    uint8_t               sb_shared_vn;
    xfs_extlen_t          sb_inoalignmt;
    uint32_t              sb_unit;
    uint32_t              sb_width;
    uint8_t               sb_dirblklog;
    uint8_t               sb_logsectlog;
    uint16_t              sb_logsectsize;
    uint32_t              sb_logsunit;
    uint32_t              sb_features2;
    uint32_t              sb_bad_features2;

    /* version 5 superblock fields start here */
    uint32_t              sb_features_compat;
    uint32_t              sb_features_ro_compat;
    uint32_t              sb_features_incompat;
    uint32_t              sb_features_log_incompat;
    uint32_t              sb_crc;
    xfs_extlen_t          sb_spino_align;
    xfs_ino_t             sb_pquotino;
    xfs_lsn_t             sb_lsn;
    xfs_uuid_t            sb_meta_uuid;
    xfs_ino_t             sb_rrmapino;
} xfs_sb_t;


/*
 * Structure of an xfs file system handle.
 */
typedef struct {
    TSK_FS_INFO            fs_info;       /* super class */
    xfs_sb_t               *fs;
    xfs_agi_t              *agi;
    int                    autoDetect;
    uint16_t               inode_size;    /* size of each inode */

} XFSFS_INFO;

#ifdef __cplusplus
}
#endif
