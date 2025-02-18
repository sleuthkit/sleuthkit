/*
** The Sleuth Kit
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2003-2011 Brian Carrier.  All rights reserved
**
** ICS Laboratory [515lab.ics <at> gmail [dot] com]
** Copyright (c) 2019 ICS Laboratory.  All rights reserved.
**
** This software is distributed under the Common Public License 1.0
*/

#ifndef _TSK_XFS_H
#define _TSK_XFS_H
#endif

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int64_t  xfs_off_t;  /* <file offset> type */
typedef uint32_t xfs_rfsblock_t; /* blockno in filesystem (raw) */
typedef uint64_t XFS_AGNUM_T;
typedef uint32_t xfs_dir2_data_aoff_t;   /* argument form */
typedef uint32_t xfs_dir2_dataptr_t;

#define _MSC_VER  // Uncomment for MSVC, comment for GCC/Clang
#ifdef _MSC_VER
    // For MSVC
    #define __round_mask(x, y) ((x) < (y) ? 0 : ((y) - 1))
#else
    // For GCC
    #define __round_mask(x, y) ((__typeof__(x))((y) - 1))
#endif
#define round_up(x, y) ((((x)-1) | __round_mask(x, y))+1)

#define 	XFS_MIN_AG_BLOCKS   64
// for checking filesystem sanity checking
#define XFS_MAX_DBLOCKS(fs, s) ( \
    tsk_getu32(&(fs->endian), (s)->sb_agcount) * \
    tsk_getu32(&(fs->endian), (s)->sb_agblocks))

#define XFS_MIN_DBLOCKS(fs, s) ( \
    (tsk_getu32(&(fs->endian), ((s)->sb_agcount)) - 1) * \
     tsk_getu32(&(fs->endian), (s)->sb_agblocks) + XFS_MIN_AG_BLOCKS)


/*
 * masks with n high/low bits set, 64-bit values
 */
static inline uint64_t xfs_mask64hi(int n)
{
    return (uint64_t)-1 << (64 - (n));
}

static inline uint32_t xfs_mask32lo(int n)
{
    return ((uint32_t)1 << (n)) - 1;
}

static inline uint64_t xfs_mask64lo(int n)
{
    return ((uint64_t)1 << (n)) - 1;
}


#define XFS_FSB_TO_AGNO(xfs,fsbno)   \
    ((uint32_t)((fsbno) >> (xfs)->fs->sb_agblklog))

#define XFS_FSB_TO_AGBNO(xfs,fsbno)  \
    ((uint32_t)((fsbno) & xfs_mask32lo((xfs)->fs->sb_agblklog)))

#define XFS_FSB_TO_SECNO(xfs,fsbno)  \
    ((uint32_t)((fsbno) & xfs_mask32lo((xfs)->fs->sb_agblklog)))

#define XFS_MAXNAMELEN 255

#define XFS_INODE_CORE_SIZE_VER4 96
#define XFS_INODE_CORE_SIZE_VER5 176

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

#define XFS_CONTENT_LEN_V4(xfs) (tsk_getu16((xfs)->fs_info.endian, (xfs)->fs->sb_inodesize) - XFS_INODE_CORE_SIZE_VER4)
#define XFS_CONTENT_LEN_V5(xfs) (tsk_getu16((xfs)->fs_info.endian, (xfs)->fs->sb_inodesize) - XFS_INODE_CORE_SIZE_VER5)

/*
 * Minimum and maximum blocksize and sectorsize.
 * The blocksize upper limit is pretty much arbitrary.
 * The sectorsize upper limit is due to sizeof(sb_sectsize).
 * CRC enable filesystems use 512 byte inodes, meaning 512 byte block sizes
 * cannot be used.
 */
#define XFS_MIN_BLOCKSIZE_LOG   9   /* i.e. 512 bytes */
#define XFS_MAX_BLOCKSIZE_LOG   16  /* i.e. 65536 bytes */
#define XFS_MIN_BLOCKSIZE   (1 << XFS_MIN_BLOCKSIZE_LOG)
#define XFS_MAX_BLOCKSIZE   (1 << XFS_MAX_BLOCKSIZE_LOG)
#define XFS_MIN_CRC_BLOCKSIZE   (1 << (XFS_MIN_BLOCKSIZE_LOG + 1))
#define XFS_MIN_SECTORSIZE_LOG  9   /* i.e. 512 bytes */
#define XFS_MAX_SECTORSIZE_LOG  15  /* i.e. 32768 bytes */
#define XFS_MIN_SECTORSIZE  (1 << XFS_MIN_SECTORSIZE_LOG)
#define XFS_MAX_SECTORSIZE  (1 << XFS_MAX_SECTORSIZE_LOG)
    
/*
 * Inode minimum and maximum sizes.
 */
#define XFS_DINODE_MIN_LOG  8
#define XFS_DINODE_MAX_LOG  11
#define XFS_DINODE_MIN_SIZE (1 << XFS_DINODE_MIN_LOG)
#define XFS_DINODE_MAX_SIZE (1 << XFS_DINODE_MAX_LOG)

// XFS Log (journal) constants
#define XLOG_MIN_ICLOGS     2
#define XLOG_MAX_ICLOGS     8
#define XLOG_HEADER_MAGIC_NUM   0xFEEDbabe  /* Invalid cycle number */
#define XLOG_VERSION_1      1
#define XLOG_VERSION_2      2       /* Large IClogs, Log sunit */
#define XLOG_VERSION_OKBITS (XLOG_VERSION_1 | XLOG_VERSION_2)
#define XLOG_MIN_RECORD_BSIZE   (16*1024)   /* eventually 32k */
#define XLOG_BIG_RECORD_BSIZE   (32*1024)   /* 32k buffers */
#define XLOG_MAX_RECORD_BSIZE   (256*1024)
#define XLOG_HEADER_CYCLE_SIZE  (32*1024)   /* cycle data in header */
#define XLOG_MIN_RECORD_BSHIFT  14      /* 16384 == 1 << 14 */
#define XLOG_BIG_RECORD_BSHIFT  15      /* 32k == 1 << 15 */
#define XLOG_MAX_RECORD_BSHIFT  18      /* 256k == 1 << 18 */
#define XLOG_BTOLSUNIT(log, b)  (((b)+(log)->l_mp->m_sb.sb_logsunit-1) / \
                                 (log)->l_mp->m_sb.sb_logsunit)
#define XLOG_LSUNITTOB(log, su) ((su) * (log)->l_mp->m_sb.sb_logsunit)
#define XLOG_HEADER_SIZE    512

/* Minimum number of transactions that must fit in the log (defined by mkfs) */
#define XFS_MIN_LOG_FACTOR  3

/*
 * RealTime Device format definitions
 */

/* Min and max rt extent sizes, specified in bytes */
#define XFS_MAX_RTEXTSIZE   (1024 * 1024 * 1024)    /* 1GB */
#define XFS_DFL_RTEXTSIZE   (64 * 1024)         /* 64kB */
#define XFS_MIN_RTEXTSIZE   (4 * 1024)      /* 4kB */

// start offset of superblock
#define XFS_SBOFF 0

// fs magicnumber
#define XFS_FS_MAGIC 0x58465342

// first inode number
#define XFS_FIRSTINO 0 // it

// superblock related constants & macros
// sb version
#define XFS_SB_VERSION_1    1       /* 5.3, 6.0.1, 6.1 */
#define XFS_SB_VERSION_2    2       /* 6.2 - attributes */
#define XFS_SB_VERSION_3    3       /* 6.2 - new inode version */
#define XFS_SB_VERSION_4    4       /* 6.2+ - bitmask version */
#define XFS_SB_VERSION_5    5       /* CRC enabled filesystem */

#define XFS_SB_FEAT_COMPAT_ALL 0
#define XFS_SB_FEAT_COMPAT_UNKNOWN	~XFS_SB_FEAT_COMPAT_ALL
// sb version checker


// sb version bitmask
#define XFS_SB_VERSION_NUMBITS      0x000f
#define XFS_SB_VERSION_ALLFBITS     0xfff0
#define XFS_SB_VERSION_ATTRBIT      0x0010
#define XFS_SB_VERSION_NLINKBIT     0x0020
#define XFS_SB_VERSION_QUOTABIT     0x0040
#define XFS_SB_VERSION_ALIGNBIT     0x0080
#define XFS_SB_VERSION_DALIGNBIT    0x0100
#define XFS_SB_VERSION_SHAREDBIT    0x0200
#define XFS_SB_VERSION_LOGV2BIT     0x0400
#define XFS_SB_VERSION_SECTORBIT    0x0800
#define XFS_SB_VERSION_EXTFLGBIT    0x1000
#define XFS_SB_VERSION_DIRV2BIT     0x2000
#define XFS_SB_VERSION_BORGBIT      0x4000  /* ASCII only case-insens. */
#define XFS_SB_VERSION_MOREBITSBIT  0x8000

// Checking if sb has compat feature


// superblock feature ro compat: for normal blocks
#define XFS_SB_FEAT_RO_COMPAT_FINOBT   (1 << 0)     /* free inode btree */
#define XFS_SB_FEAT_RO_COMPAT_RMAPBT   (1 << 1)     /* reverse map btree */
#define XFS_SB_FEAT_RO_COMPAT_REFLINK  (1 << 2)     /* reflinked files */
#define XFS_SB_FEAT_RO_COMPAT_ALL \
        (XFS_SB_FEAT_RO_COMPAT_FINOBT | \
         XFS_SB_FEAT_RO_COMPAT_RMAPBT | \
         XFS_SB_FEAT_RO_COMPAT_REFLINK)
#define XFS_SB_FEAT_RO_COMPAT_UNKNOWN   ~XFS_SB_FEAT_RO_COMPAT_ALL


// superblock feature ro compat: for journal
#define XFS_SB_FEAT_INCOMPAT_FTYPE  (1 << 0)    /* filetype in dirent */
#define XFS_SB_FEAT_INCOMPAT_SPINODES   (1 << 1)    /* sparse inode chunks */
#define XFS_SB_FEAT_INCOMPAT_META_UUID  (1 << 2)    /* metadata UUID */
#define XFS_SB_FEAT_INCOMPAT_ALL \
        (XFS_SB_FEAT_INCOMPAT_FTYPE|    \
         XFS_SB_FEAT_INCOMPAT_SPINODES| \
         XFS_SB_FEAT_INCOMPAT_META_UUID)
#define XFS_SB_FEAT_INCOMPAT_UNKNOWN    ~XFS_SB_FEAT_INCOMPAT_ALL

#define XFS_SB_FEAT_INCOMPAT_LOG_ALL 0
#define XFS_SB_FEAT_INCOMPAT_LOG_UNKNOWN    ~XFS_SB_FEAT_INCOMPAT_LOG_ALL

#define XFS_HAS_INCOMPAT_FEATURE(fs, sb, mask)\
    ((tsk_fs_guessu32(fs->endian, sb->sb_features_incompat) & mask) != 0)
/*    
static inline bool xfs_sb_has_incompat_feature(
    struct xfs_sb   *sbp,
    uint32_t    feature)
{
    return !tsk_fs_guessu32(sbp->sb_features_incompat & feature, 0);
}
*/
#define XFS_HAS_INCOMPAT_LOG_FEATURE(fs, sb, mask)\
    ((tsk_fs_guessu32(fs->endian, sb->sb_features_log_incompat) & mask) != 0)
/*    
static inline bool xfs_sb_has_incompat_log_feature(
    struct xfs_sb   *sbp,
    uint32_t    feature)
{
    return !tsk_fs_guessu32(sbp->sb_features_log_incompat & feature, 0);
}
*/
// Macros
// crc offset of sb
#define XFS_SB_CRC_OFF      offsetof(struct xfs_sb, sb_crc)

#define XFS_DIR3_FT_UNKNOWN		0
#define XFS_DIR3_FT_REG_FILE		1
#define XFS_DIR3_FT_DIR			2
#define XFS_DIR3_FT_CHRDEV		3
#define XFS_DIR3_FT_BLKDEV		4
#define XFS_DIR3_FT_FIFO		5
#define XFS_DIR3_FT_SOCK		6
#define XFS_DIR3_FT_SYMLINK		7
#define XFS_DIR3_FT_WHT			8
#define XFS_DIR3_FT_MAX			9

/*
 * For special situations, the dirent size ends up fixed because we always know
 * what the size of the entry is. That's true for the "." and "..", and
 * therefore we know that they are a fixed size and hence their offsets are
 * constant, as is the first entry.
 *
 * Hence, this calculation is written as a macro to be able to be calculated at
 * compile time and so certain offsets can be calculated directly in the
 * structure initaliser via the macro. There are two macros - one for dirents
 * with ftype and without so there are no unresolvable conditionals in the
 * calculations. We also use round_up() as XFS_DIR2_DATA_ALIGN is always a power
 * of 2 and the compiler doesn't reject it (unlike roundup()).
 */
#define XFS_DIR2_DATA_ENTSIZE(n)                    \
    round_up((offsetof(struct xfs_dir2_data_entry, name[0]) + (n) + \
         sizeof(uint16_t)), XFS_DIR2_DATA_ALIGN)

#define XFS_DIR3_DATA_ENTSIZE(n)                    \
    round_up((offsetof(struct xfs_dir2_data_entry, name[0]) + (n) + \
         sizeof(uint16_t) + sizeof(uint8_t)),    \
        XFS_DIR2_DATA_ALIGN)

/*
    Superblock - Must be padded to 64 bit alignment.
*/
typedef struct xfs_sb {
    uint8_t      sb_magicnum[4];    /* magic number == XFS_SB_MAGIC */
    uint8_t      sb_blocksize[4];   /* logical block size, bytes */
    uint8_t      sb_dblocks[8]; /* number of data blocks */
    uint8_t      sb_rblocks[8]; /* number of realtime blocks */
    uint8_t      sb_rextents[8];    /* number of realtime extents */
    uint8_t      sb_uuid[16];    /* user-visible file system unique id */
    uint8_t      sb_logstart[8];    /* starting block of log if internal */
    uint8_t      sb_rootino[8]; /* root inode number */
    uint8_t      sb_rbmino[8];  /* bitmap inode for realtime extents */
    uint8_t      sb_rsumino[8]; /* summary inode for rt bitmap */
    uint8_t      sb_rextsize[4];    /* realtime extent size, blocks */
    uint8_t      sb_agblocks[4];    /* size of an allocation group */
    uint8_t      sb_agcount[4]; /* number of allocation groups */
    uint8_t      sb_rbmblocks[4];   /* number of rt bitmap blocks */
    uint8_t      sb_logblocks[4];   /* number of log blocks */
    uint8_t      sb_versionnum[2];  /* header version == XFS_SB_VERSION */
    uint8_t      sb_sectsize[2];    /* volume sector size, bytes */
    uint8_t      sb_inodesize[2];   /* inode size, bytes */
    uint8_t      sb_inopblock[2];   /* inodes per block */
    char        sb_fname[12];   /* file system name */
    uint8_t        sb_blocklog;    /* log2 of sb_blocksize */
    uint8_t        sb_sectlog; /* log2 of sb_sectsize */
    uint8_t        sb_inodelog;    /* log2 of sb_inodesize */
    uint8_t        sb_inopblog;    /* log2 of sb_inopblock */
    uint8_t        sb_agblklog;    /* log2 of sb_agblocks (rounded up) */
    uint8_t        sb_rextslog;    /* log2 of sb_rextents */
    uint8_t        sb_inprogress;  /* mkfs is in progress, don't mount */
    uint8_t        sb_imax_pct;    /* max % of fs for inode space */
                    /* statistics */
    /*
     * These fields must remain contiguous.  If you really
     * want to change their layout, make sure you fix the
     * code in xfs_trans_apply_sb_deltas().
     */
    uint8_t      sb_icount[8];  /* allocated inodes */
    uint8_t      sb_ifree[8];   /* free inodes */
    uint8_t      sb_fdblocks[8];    /* free data blocks */
    uint8_t      sb_frextents[8];   /* free realtime extents */
    /*
     * End contiguous fields.
     */
    uint8_t      sb_uquotino[8];    /* user quota inode */
    uint8_t      sb_gquotino[8];    /* group quota inode */
    uint8_t      sb_qflags[2];  /* quota flags */
    uint8_t        sb_flags;   /* misc. flags */
    uint8_t        sb_shared_vn;   /* shared version number */
    uint8_t      sb_inoalignmt[4];  /* inode chunk alignment, fsblocks */
    uint8_t      sb_unit[4];    /* stripe or raid unit */
    uint8_t      sb_width[4];   /* stripe or raid width */
    uint8_t        sb_dirblklog;   /* log2 of dir block size (fsbs) */
    uint8_t        sb_logsectlog;  /* log2 of the log sector size */
    uint8_t      sb_logsectsize[2]; /* sector size for the log, bytes */
    uint8_t      sb_logsunit[4];    /* stripe unit size for the log */
    uint8_t      sb_features2[4];   /* additional feature bits */
    /*
     * bad features2 field as a result of failing to pad the sb
     * structure to 64 bits. Some machines will be using this field
     * for features2 bits. Easiest just to mark it bad and not use
     * it for anything else.
     */
    uint8_t      sb_bad_features2[4];

    /* version 5 superblock fields start here */

    /* feature masks */
    uint8_t      sb_features_compat[4];
    uint8_t      sb_features_ro_compat[4];
    uint8_t      sb_features_incompat[4];
    uint8_t      sb_features_log_incompat[4];

    uint8_t      sb_crc[4];     /* superblock crc:: ->little endian<- */
    uint8_t      sb_spino_align[4]; /* sparse inode chunk alignment */

    uint8_t      sb_pquotino[8];    /* project quota inode */
    uint8_t      sb_lsn[8];     /* last write sequence */
    uint8_t      sb_meta_uuid[16];   /* metadata file system unique id */

    /* must be padded to 64 bit alignment */
} xfs_sb;

/* Journal Info */
typedef struct {

    TSK_FS_FILE *fs_file;
    TSK_INUM_T j_inum;

    uint32_t bsize;
    TSK_DADDR_T first_block;
    TSK_DADDR_T last_block;

    uint32_t start_seq;
    TSK_DADDR_T start_blk;

} XFS_JINFO;

/*
 * Structure of an XFS file system handle.
 */
typedef struct {
    TSK_FS_INFO fs_info;    /* super class */
    xfs_sb *fs;          /* super block */ // modified by kyu
    
    /* lock protects */
    tsk_lock_t lock;
    
    // one of the below will be allocated and populated by XFS_group_load depending on the FS type
    //XFS_agheader *XFS_ag_buf; /* cached AG header for XFS r/w shared - lock */
    XFS_AGNUM_T ag_num;  /* cached AG number r/w shared - lock */

    uint8_t *bmap_buf;      /* cached block allocation bitmap r/w shared - lock */
    XFS_AGNUM_T bmap_grp_num;     /* cached block bitmap nr r/w shared - lock */

    uint8_t *imap_buf;      /* cached inode allocation bitmap r/w shared - lock */
    XFS_AGNUM_T imap_grp_num;     /* cached inode bitmap nr r/w shared - lock */

    TSK_OFF_T ags_offset;        /* offset to first group desc */
    XFS_AGNUM_T ags_count;     /* nr of descriptor group blocks */
    
    uint16_t inode_size;    /* size of each inode */
    TSK_DADDR_T first_data_block;

    XFS_JINFO *jinfo;
} XFS_INFO;


/*
 * Byte offset in a directory.
 */
typedef xfs_off_t   xfs_dir2_off_t;

#define XFS_DIR2_DATA_ALIGN_LOG 3       /* i.e., 8 bytes */
#define XFS_DIR2_DATA_ALIGN (1 << XFS_DIR2_DATA_ALIGN_LOG)



/*
 * Convert byte in space to offset in a block
 */
static inline xfs_dir2_data_aoff_t
xfs_dir2_byte_to_off(XFS_INFO *xfs, xfs_dir2_off_t by)
{
    TSK_FS_INFO * fs = (TSK_FS_INFO *) &xfs->fs_info;
    return (xfs_dir2_data_aoff_t)(by & (
        tsk_getu32(fs->endian, xfs->fs->sb_blocksize) - 1));
}
/*
 * Convert dataptr to byte in file space
 */
static inline xfs_dir2_off_t
xfs_dir2_dataptr_to_byte(xfs_dir2_dataptr_t dp)
{
    return (xfs_dir2_off_t)dp << XFS_DIR2_DATA_ALIGN_LOG;
}

/*
 * Convert dataptr to a byte offset in a block
 */
static inline xfs_dir2_data_aoff_t
xfs_dir2_dataptr_to_off(XFS_INFO *xfs, xfs_dir2_dataptr_t dp)
{
    return xfs_dir2_byte_to_off(xfs, xfs_dir2_dataptr_to_byte(dp));
}


 // kyu
typedef enum {
    XFS_BTNUM_BNOi, XFS_BTNUM_CNTi, XFS_BTNUM_BMAPi, XFS_BTNUM_INOi,
    XFS_BTNUM_MAX
} xfs_btnum_t;
 // kyu
#define	XFS_BTNUM_AGF	((int)XFS_BTNUM_CNTi + 1)
/*
    AG Free Block Info
*/
typedef struct xfs_agf {
    /*
     * Common allocation group header information
     */
    uint8_t      agf_magicnum[4];   /* magic number == XFS_AGF_MAGIC */
    uint8_t      agf_versionnum[4]; /* header version == XFS_AGF_VERSION */
    uint8_t      agf_seqno[4];  /* sequence # starting from 0 */
    uint8_t      agf_length[4]; /* size in blocks of a.g. */
    /*
     * Freespace and rmap information
     */
    uint8_t      agf_roots[XFS_BTNUM_AGF * 4];   /* root blocks */
    uint8_t      agf_levels[XFS_BTNUM_AGF * 4];  /* btree levels */

    uint8_t      agf_flfirst[4];    /* first freelist block's index */
    uint8_t      agf_fllast[4]; /* last freelist block's index */
    uint8_t      agf_flcount[4];    /* count of blocks in freelist */
    uint8_t      agf_freeblks[4];   /* total free blocks */

    uint8_t      agf_longest[4];    /* longest free space */
    uint8_t      agf_btreeblks[4];  /* # of blocks held in AGF btrees */
    uint8_t      agf_uuid[16];   /* uuid of filesystem */

    uint8_t      agf_rmap_blocks[4];    /* rmapbt blocks used */
    uint8_t      agf_refcount_blocks[4];    /* refcountbt blocks used */

    uint8_t      agf_refcount_root[4];  /* refcount tree root block */
    uint8_t      agf_refcount_level[4]; /* refcount btree levels */

    /*
     * reserve some contiguous space for future logged fields before we add
     * the unlogged fields. This makes the range logging via flags and
     * structure offsets much simpler.
     */
    uint8_t      agf_spare64[14*8];

    /* unlogged fields, written during buffer writeback. */
    uint8_t      agf_lsn[8];    /* last write sequence */
    uint8_t      agf_crc[4];    /* crc of agf sector */
    uint8_t      agf_spare2[4];

    /* structure must be padded to 64 bit alignment */
} xfs_agf_t;

#define 	XFS_AGI_UNLINKED_BUCKETS   64 // kyu

/*
    AG Inode B+ Tree Info
*/
typedef struct xfs_agi {
    /*
     * Common allocation group header information
     */
    uint8_t      agi_magicnum[4];   /* magic number == XFS_AGI_MAGIC */
    uint8_t      agi_versionnum[4]; /* header version == XFS_AGI_VERSION */
    uint8_t      agi_seqno[4];  /* sequence # starting from 0 */
    uint8_t      agi_length[4]; /* size in blocks of a.g. */
    /*
     * Inode information
     * Inodes are mapped by interpreting the inode number, so no
     * mapping data is needed here.
     */
    uint8_t      agi_count[4];  /* count of allocated inodes */
    uint8_t      agi_root[4];   /* root of inode btree */
    uint8_t      agi_level[4];  /* levels in inode btree */
    uint8_t      agi_freecount[4];  /* number of free inodes */

    uint8_t      agi_newino[4]; /* new inode just allocated */
    uint8_t      agi_dirino[4]; /* last directory inode chunk */
    /*
     * Hash table of inodes which have been unlinked but are
     * still being referenced.
     */
    uint8_t      agi_unlinked[XFS_AGI_UNLINKED_BUCKETS * 4];
    /*
     * This marks the end of logging region 1 and start of logging region 2.
     */
    uint8_t      agi_uuid[16];   /* uuid of filesystem */
    uint8_t      agi_crc[4];    /* crc of agi sector */
    uint8_t      agi_pad32[4];
    uint8_t      agi_lsn[8];    /* last write sequence */

    uint8_t      agi_free_root[4]; /* root of the free inode btree */
    uint8_t      agi_free_level[4];/* levels in free inode btree */

    /* structure must be padded to 64 bit alignment */
} xfs_agi_t;

typedef uint64_t	xfs_ino_t;

/*
    AG Free space B+ Tree Info
*/

//typedef struct xfs_agfl {
//    uint8_t      agfl_magicnum[4];
//    uint8_t      agfl_seqno[4];
 //   uint8_t      agfl_uuid[16];
//    uint8_t      agfl_lsn[8];
//    uint8_t      agfl_crc[4];
//    uint8_t      agfl_bno[*4]; /* actually XFS_AGFL_SIZE(mp) ->should be defined before compile<- */
//} __attribute__((packed)) xfs_agfl_t;

typedef struct xfs_timestamp {
	uint32_t		t_sec;		/* timestamp seconds */
	uint32_t		t_nsec;		/* timestamp nanoseconds */
} xfs_timestamp_t;

/*
    Inode
*/
typedef struct xfs_dinode {
    uint8_t      di_magic[2];   /* inode magic # = XFS_DINODE_MAGIC */
    uint8_t      di_mode[2];    /* mode and type of file */
    uint8_t        di_version; /* inode version */
    uint8_t        di_format;  /* format of di_c data */
    uint8_t      di_onlink[2];  /* old number of links to file */
    uint8_t      di_uid[4];     /* owner's user id */
    uint8_t      di_gid[4];     /* owner's group id */
    uint8_t      di_nlink[4];   /* number of links to file */
    uint8_t      di_projid_lo[2];   /* lower part of owner's project id */
    uint8_t      di_projid_hi[2];   /* higher part owner's project id */
    uint8_t        di_pad[6];  /* unused, zeroed space */
    uint8_t      di_flushiter[2];   /* incremented on flush */
    xfs_timestamp_t di_atime;   /* time last accessed */
    xfs_timestamp_t di_mtime;   /* time last modified */
    xfs_timestamp_t di_ctime;   /* time created/inode modified */
    uint8_t      di_size[8];    /* number of bytes in file */
    uint8_t      di_nblocks[8]; /* # of direct & btree blocks used */
    uint8_t      di_extsize[4]; /* basic/minimum extent size for file */
    uint8_t      di_nextents[4];    /* number of extents in data fork */
    uint8_t      di_anextents[2];   /* number of extents in attribute fork*/
    uint8_t        di_forkoff; /* attr fork offs, <<3 for 64b align */
    int8_t        di_aformat; /* format of attr fork's data */
    uint8_t      di_dmevmask[4];    /* DMIG event mask */
    uint8_t      di_dmstate[2]; /* DMIG state info */
    uint8_t      di_flags[2];   /* random flags, XFS_DIFLAG_... */
    uint8_t      di_gen[4];     /* generation number */

    /* di_next_unlinked is the only non-core field in the old dinode */
    uint8_t      di_next_unlinked[4];/* agi unlinked list ptr */

    /* start of the extended dinode, writable fields */
    uint8_t      di_crc[4];     /* CRC of the inode -->little endian<-*/
    uint8_t      di_changecount[8]; /* number of attribute changes */
    uint8_t      di_lsn[8];     /* flush sequence */
    uint8_t      di_flags2[8];  /* more random flags */
    uint8_t      di_cowextsize[4];  /* basic cow extent size for file */
    uint8_t        di_pad2[12];    /* more padding for future expansion */

    /* fields only written to during inode creation */
    xfs_timestamp_t di_crtime;  /* time created */
    uint8_t      di_ino[8];     /* inode number */
    uint8_t      di_uuid[16];    /* UUID of the filesystem */

    /* structure must be padded to 64 bit alignment */
} xfs_dinode;

/*
    Internal Inode - Quota Inode
*/
typedef struct xfs_disk_dquot {
    uint8_t      d_magic[2];    /* dquot magic = XFS_DQUOT_MAGIC */
    uint8_t      d_version;  /* dquot version */
    uint8_t      d_flags;    /* XFS_DQ_USER/PROJ/GROUP */
    uint8_t      d_id[4];       /* user,project,group id */
    uint8_t      d_blk_hardlimit[8];/* absolute limit on disk blks */
    uint8_t      d_blk_softlimit[8];/* preferred limit on disk blks */
    uint8_t      d_ino_hardlimit[8];/* maximum # allocated inodes */
    uint8_t      d_ino_softlimit[8];/* preferred inode limit */
    uint8_t      d_bcount[8];   /* disk blocks owned by the user */
    uint8_t      d_icount[8];   /* inodes owned by the user */
    uint8_t      d_itimer[4];   /* zero if within inode limits if not,
                       this is when we refuse service */
    uint8_t      d_btimer[4];   /* similar to above; for disk blocks */
    uint8_t      d_iwarns[2];   /* warnings issued wrt num inodes */
    uint8_t      d_bwarns[2];   /* warnings issued wrt disk blocks */
    uint8_t      d_pad0[4];     /* 64 bit align */
    uint8_t      d_rtb_hardlimit[8];/* absolute limit on realtime blks */
    uint8_t      d_rtb_softlimit[8];/* preferred limit on RT disk blks */
    uint8_t      d_rtbcount[4]; /* realtime blocks owned */
    uint8_t      d_rtbtimer[4]; /* similar to above; for RT disk blocks */
    uint8_t      d_rtbwarns[2]; /* warnings issued wrt RT disk blocks */
    uint8_t      d_pad[2];
} xfs_disk_dquot_t;

/*
    Internal Inode - Quota block
*/
typedef struct xfs_dqblk {
    xfs_disk_dquot_t  dd_diskdq;    /* portion that lives incore as well */
    char          dd_fill[4];   /* filling for posterity */

    /*
     * These two are only present on filesystems with the CRC bits set.
     */
    uint8_t        dd_crc[4];   /* checksum ->BIG ENDIAN<-*/
    uint8_t        dd_lsn[8];   /* last modification in log */
    uint8_t        dd_uuid[16];  /* location information */
} xfs_dqblk_t;

/*
    Inode record
*/
typedef struct xfs_inobt_rec {
    uint8_t      ir_startino[4];    /* starting inode number */
    union {
        struct {
            uint8_t  ir_freecount[4];   /* count of free inodes */
        } f;
        struct {
            uint8_t  ir_holemask[2];/* hole mask for sparse chunks */
            uint8_t  ir_count;   /* total inode count */
            uint8_t  ir_freecount;   /* count of free inodes */
        } sp; // sparse inode
    } ir_u;
    uint8_t      ir_free[8];    /* free inode mask */
} xfs_inobt_rec_t;

/*
    Bmap root header
*/
typedef struct xfs_bmdr_block {
    uint8_t      bb_level[2];   /* 0 is a leaf */
    uint8_t      bb_numrecs[2]; /* current # of data records */
} xfs_bmdr_block_t;

typedef uint64_t	xfs_bmbt_rec_base_t;	/* use this for casts */
//typedef xfs_bmbt_rec_t xfs_bmdr_rec_t;

/*
    Key structure -> Non-leaf level Tree
*/
typedef struct xfs_bmbt_key {
    uint8_t      br_startoff[8];    /* starting file offset */
} xfs_bmbt_key_t, xfs_bmdr_key_t;

/*
    Directory:: 1. Shortform directory - header
*/

typedef struct xfs_dir2_sf_hdr {
    uint8_t         count;      /* count of entries */
    uint8_t         i8count;    /* count of 8-byte inode #s */
    uint8_t         parent[8];  /* parent dir inode number */
} xfs_dir2_sf_hdr_t;

/*
    Directory:: 1. Shortform directory - entry
*/
typedef struct xfs_dir2_sf_entry {
    uint8_t            namelen;    /* actual name length */
    uint8_t            offset[2];  /* saved offset */
    uint8_t            name[];     /* name, variable size */
    /*
     * A single byte containing the file type field follows the inode
     * number for version 3 directory entries.
     *
     * A 64-bit or 32-bit inode number follows here, at a variable offset
     * after the name.
     */
} xfs_dir2_sf_entry_t;

typedef struct xfs_dir2_sf {
    xfs_dir2_sf_hdr_t *hdr;
    xfs_dir2_sf_entry_t *entry;
} xfs_dir2_sf_t;

static inline uint32_t get_unaligned_be32(const uint8_t *p)
{
	return p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3];
}

static inline uint64_t get_unaligned_be64(const uint8_t *p)
{
	return (uint64_t)get_unaligned_be32(p) << 32 |
	       get_unaligned_be32(p + 4);
}

/*
    Data block structure:: Free area in data block
*/
typedef struct xfs_dir2_data_free {
    uint16_t          offset;     /* start of freespace */
    uint16_t          length;     /* length of freespace */
} xfs_dir2_data_free_t;

/*
    Data block structure:: Header for the data block
*/

#define XFS_DIR3_DATA_CRC_OFF  offsetof(struct xfs_dir3_data_hdr, hdr.crc)
#define XFS_DIR2_DATA_FD_COUNT 3

/*
 * define a structure for all the verification fields we are adding to the
 * directory block structures. This will be used in several structures.
 * The magic number must be the first entry to align with all the dir2
 * structures so we determine how to decode them just by the magic number.
 */
struct xfs_dir3_blk_hdr {
    uint32_t          magic;  /* magic number */
    uint32_t          crc;    /* CRC of block */
    uint64_t          blkno;  /* first block of the buffer */
    uint64_t          lsn;    /* sequence number of last write */
    uint64_t          uuid[2];
    uint64_t          owner;  /* inode that owns the block */
};

struct xfs_dir3_data_hdr {
    struct xfs_dir3_blk_hdr hdr;
    xfs_dir2_data_free_t    best_free[XFS_DIR2_DATA_FD_COUNT];
    uint32_t          pad;    /* 64 bit alignment */
};

typedef struct xfs_dir2_data_hdr {
    uint32_t          magic;      /* XFS_DIR2_DATA_MAGIC or */
                        /* XFS_DIR2_BLOCK_MAGIC */
    xfs_dir2_data_free_t    bestfree[XFS_DIR2_DATA_FD_COUNT];
} xfs_dir2_data_hdr_t;

/*
    Data block structure:: Active entry
*/
typedef struct xfs_dir2_data_entry {
    uint8_t            inumber[8];    /* inode number */
    uint8_t            namelen;    /* name length */
    uint8_t            name[];     /* name bytes, no null */
     /* uint8_t            filetype; */    /* type of inode we point to */
     /* uint16_t                  tag; */     /* starting offset of us */
} xfs_dir2_data_entry_t;

/*
    Data block structure:: empty entry
*/
typedef struct xfs_dir2_data_unused {
    uint16_t          freetag;    /* XFS_DIR2_DATA_FREE_TAG */
    uint16_t          length;     /* total free length */
                        /* variable offset */
    uint16_t          tag;        /* starting offset of us */
} xfs_dir2_data_unused_t;

/*
 * Leaf block structures.
 *
 *    +---------------------------+
 *    | xfs_dir2_leaf_hdr_t       |
 *    +---------------------------+
 *    | xfs_dir2_leaf_entry_t     |
 *    | xfs_dir2_leaf_entry_t     |
 *    | xfs_dir2_leaf_entry_t     |
 *    | xfs_dir2_leaf_entry_t     |
 *    | ...                       |
 *    +---------------------------+
 *    | xfs_dir2_data_off_t       |
 *    | xfs_dir2_data_off_t       |
 *    | xfs_dir2_data_off_t       |
 *    | ...                       |
 *    +---------------------------+
 *    | xfs_dir2_leaf_tail_t      |
 *    +---------------------------+
*/
typedef struct xfs_da_blkinfo {
    uint32_t    forw;
    uint32_t    back;
    uint32_t    magic;
    uint16_t    pad;
} xfs_da_blkinfo_t;
/*
    Leaf block structure: header
*/
typedef struct xfs_dir2_leaf_hdr {
    xfs_da_blkinfo_t    info;       /* header for da routines */
    uint16_t          count;      /* count of entries */
    uint16_t          stale;      /* count of stale entries */
} xfs_dir2_leaf_hdr_t;

/*
    Leaf block structure: entry
*/
typedef struct xfs_dir2_leaf_entry {
    uint32_t          hashval;    /* hash value of name */
    uint32_t          address;    /* address of data entry */
} xfs_dir2_leaf_entry_t;

/*
    Leaf block structure: tail
*/
typedef struct xfs_dir2_leaf_tail {
    uint32_t          bestcount;
} xfs_dir2_leaf_tail_t;

/*
    Freeindex block:: header
*/
typedef struct xfs_dir2_free_hdr {
    uint32_t          magic;      /* XFS_DIR2_FREE_MAGIC */
    uint32_t          firstdb;    /* db of first entry */
    uint32_t          nvalid;     /* count of valid entries */
    uint32_t          nused;      /* count of used entries */
} xfs_dir2_free_hdr_t;

/*
    Freeindex block:: entry
*/
typedef struct xfs_dir2_free {
    xfs_dir2_free_hdr_t hdr;        /* block header */
    uint16_t          bests[];    /* best free counts */
                        /* unused entries are -1 */
} xfs_dir2_free_t;

/*
 * Single block format.
 *
 * The single block format looks like the following drawing on disk:
 *
 *    +-------------------------------------------------+
 *    | xfs_dir2_data_hdr_t                             |
 *    +-------------------------------------------------+
 *    | xfs_dir2_data_entry_t OR xfs_dir2_data_unused_t |
 *    | xfs_dir2_data_entry_t OR xfs_dir2_data_unused_t |
 *    | xfs_dir2_data_entry_t OR xfs_dir2_data_unused_t :
 *    | ...                                             |
 *    +-------------------------------------------------+
 *    | unused space                                    |
 *    +-------------------------------------------------+
 *    | ...                                             |
 *    | xfs_dir2_leaf_entry_t                           |
 *    | xfs_dir2_leaf_entry_t                           |
 *    +-------------------------------------------------+
 *    | xfs_dir2_block_tail_t                           |
 *    +-------------------------------------------------+
 *
 * As all the entries are variable size structures the accessors below should
 * be used to iterate over them.
 */

/*
    Single block format:: tail
*/
typedef struct xfs_dir2_block_tail {
    uint32_t      count;          /* count of leaf entries */
    uint32_t      stale;          /* count of stale lf entries */
} xfs_dir2_block_tail_t;

/*
    Shortform directory: attributes
*/
typedef struct xfs_attr_shortform {
    struct xfs_attr_sf_hdr {    /* constant-structure header block */
        uint16_t  totsize;    /* total bytes in shortform list */
        uint8_t    count;  /* count of active entries */
        uint8_t    padding;
    } hdr;
    struct xfs_attr_sf_entry {
        uint8_t namelen;    /* actual length of name (no NULL) */
        uint8_t valuelen;   /* actual length of value (no NULL) */
        uint8_t flags;  /* flags bits (see xfs_attr_leaf.h) */
        uint8_t nameval[1]; /* name & value bytes concatenated */
    } list[1];          /* variable sized array */
} xfs_attr_shortform_t;


typedef union {
    uint8_t i8[8];
    uint8_t i4[4];
} xfs_dir2_inou_t;

// Btree block format
struct xfs_btree_block_shdr {
    uint32_t      bb_leftsib;
    uint32_t      bb_rightsib;

    uint64_t      bb_blkno;
    uint64_t      bb_lsn;
    uint64_t      bb_uuid[2];
    uint32_t      bb_owner;
    uint32_t      bb_crc;
    //__le32      bb_crc;
};

/* long form block header */
struct xfs_btree_block_lhdr {
    uint64_t      bb_leftsib;
    uint64_t      bb_rightsib;

    uint64_t      bb_blkno;
    uint64_t      bb_lsn;
    uint64_t      bb_uuid[2];
    uint64_t      bb_owner;
    uint32_t    bb_crc;
    //__le32      bb_crc;
    uint32_t      bb_pad; /* padding for alignment */
};

struct xfs_btree_block {
    uint32_t      bb_magic;   /* magic number for block type */
    uint16_t      bb_level;   /* 0 is a leaf */
    uint16_t      bb_numrecs; /* current # of data records */
    union {
        struct xfs_btree_block_shdr s;
        struct xfs_btree_block_lhdr l;
    } bb_u;             /* rest */
};

/* MODE */
#define XFS_IN_FMT  0170000
#define XFS_IN_SOCK 0140000
#define XFS_IN_LNK  0120000
#define XFS_IN_REG  0100000
#define XFS_IN_BLK  0060000
#define XFS_IN_DIR  0040000
#define XFS_IN_CHR  0020000
#define XFS_IN_FIFO  0010000

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


#define XFS_IN_SECDEL      0x00000001      /* Secure deletion */
#define XFS_IN_UNRM        0x00000002      /* Undelete */
#define XFS_IN_COMP        0x00000004      /* Compress file */
#define XFS_IN_SYNC        0x00000008      /* Synchronous updates */
#define XFS_IN_IMM         0x00000010      /* Immutable file */
#define XFS_IN_APPEND      0x00000020      /* writes to file may only append */
#define XFS_IN_NODUMP      0x00000040      /* do not dump file */
#define XFS_IN_NOA         0x00000080      /* do not update atime */
#define XFS_IN_DIRTY                   0x00000100
#define XFS_IN_COMPRBLK                0x00000200      /* One or more compressed clusters */
#define XFS_IN_NOCOMPR                 0x00000400      /* Don't compress */
#define XFS_IN_ECOMPR                  0x00000800      /* Compression error */
#define XFS_IN_INDEX                   0x00001000      /* hash-indexed directory */
#define XFS_IN_IMAGIC                  0x00002000      /* AFS directory */
#define XFS_IN_JOURNAL_DATA            0x00004000      /* file data should be journaled */
#define XFS_IN_NOTAIL                  0x00008000      /* file tail should not be merged */
#define XFS_IN_DIRSYNC                 0x00010000      /* dirsync behaviour (directories only) */
#define XFS_IN_TOPDIR                  0x00020000      /* Top of directory hierarchies */
#define XFS_IN_HUGE_FILE               0x00040000      /* Set to each huge file */
#define XFS_IN_EXTENTS                 0x00080000      /* Inode uses extents */
#define XFS_IN_EA_INODE                0x00200000      /* Inode used for large EA */
#define XFS_IN_EOFBLOCKS               0x00400000      /* Blocks allocated beyond EOF */
#define XFS_IN_RESERVED                0x80000000      /* reserved for XFS lib */
#define XFS_IN_USER_VISIBLE            0x004BDFFF      /* User visible flags */
#define XFS_IN_USER_MODIFIABLE         0x004B80FF      /* User modifiable flags */

/* XFS directory file types  */
#define XFS_DE_UNKNOWN         0
#define XFS_DE_REG             1
#define XFS_DE_DIR             2
#define XFS_DE_CHR             3
#define XFS_DE_BLK             4
#define XFS_DE_FIFO            5
#define XFS_DE_SOCK            6
#define XFS_DE_LNK             7
#define XFS_DE_MAX             8

/*
 * Values for di_format
 */
typedef enum xfs_dinode_fmt {
	XFS_DINODE_FMT_DEV,		/* xfs_dev_t */
	XFS_DINODE_FMT_LOCAL,		/* bulk data */
	XFS_DINODE_FMT_EXTENTS,		/* struct xfs_bmbt_rec */
	XFS_DINODE_FMT_BTREE,		/* struct xfs_bmdr_block */
	XFS_DINODE_FMT_UUID		/* added long ago, but never used */
} xfs_dinode_fmt_t;

/************** JOURNAL ******************/

/* These values are always in big endian */

#define XFS_JMAGIC 0xC03b3998

/*JBD2 Feature Flags */
#define JBD2_FEATURE_COMPAT_CHECKSUM        0x00000001

#define JBD2_FEATURE_INCOMPAT_REVOKE        0x00000001
#define JBD2_FEATURE_INCOMPAT_64BIT         0x00000002
#define JBD2_FEATURE_INCOMPAT_ASYNC_COMMIT  0x00000004

#define XFS_J_ETYPE_DESC   1       /* descriptor block */
#define XFS_J_ETYPE_COM    2       /* commit */
#define XFS_J_ETYPE_SB1    3       /* super block v1 */
#define XFS_J_ETYPE_SB2    4       /* sb v2 */
#define XFS_J_ETYPE_REV    5       /* revoke */

/* JBD2 Checksum types */
#define JBD2_CRC32_CHKSUM   1
#define JBD2_MD5_CHKSUM     2
#define JBD2_SHA1_CHKSUM    3

#define JBD2_CRC32_CHKSUM_SIZE  4
#define JBD2_CHECKSUM_BYTES (32/ sizeof(unsigned int))

#define NSEC_PER_SEC 1000000000L

/* dentry flags */
#define XFS_J_DENTRY_ESC   1       /* The orig block starts with magic */
#define XFS_J_DENTRY_SAMEID    2       /* Entry is for same id, so do not skip 16 ahead */
#define XFS_J_DENTRY_DEL   4       /* not currently used in src */
#define XFS_J_DENTRY_LAST  8       /* Last tag */

extern TSK_RETVAL_ENUM
    xfs_dir_open_meta(TSK_FS_INFO * a_fs, TSK_FS_DIR ** a_fs_dir,
    TSK_INUM_T a_addr, int recursion_depth);
extern uint8_t xfs_jentry_walk(TSK_FS_INFO *, int,
    TSK_FS_JENTRY_WALK_CB, void *);
extern uint8_t xfs_jblk_walk(TSK_FS_INFO *, TSK_DADDR_T,
    TSK_DADDR_T, int, TSK_FS_JBLK_WALK_CB, void *);
extern uint8_t xfs_jopen(TSK_FS_INFO *, TSK_INUM_T);


static inline bool xfs_sb_good_version(TSK_FS_INFO* fs, struct xfs_sb *sbp)
{
    if (tsk_fs_guessu16(fs, sbp->sb_versionnum, XFS_SB_VERSION_5))
        return true;
    if (tsk_fs_guessu16(fs, sbp->sb_versionnum, XFS_SB_VERSION_4))
    {
        tsk_fprintf(stderr, "Found superblock version 4, continuing with version 5 analyzer");
        return true;
    }
    return false;
}

static inline bool
xfs_sb_has_compat_feature(
    TSK_FS_INFO * fs,
    xfs_sb * sb,
    uint32_t    feature)
{

    return (tsk_getu32(fs->endian, sb->sb_features_compat) & feature) != 0;
}

#define XFS_HAS_COMPAT_FEATURE(fs, sb, mask)\
    ((tsk_fs_guessu32(&(fs->endian), sb->sb_features_compat) & mask) != 0)

// checking if sb has ro compat feature
#define XFS_HAS_RO_COMPAT_FEATURE(fs, sb, mask)\
    ((tsk_fs_guessu32(fs->endian, sb->sb_features_ro_compat) & mask) != 0)

static inline bool xfs_sb_has_ro_compat_feature(
    TSK_FS_INFO * fs,
    xfs_sb   *sbp,
    uint32_t    feature)
{
    uint32_t oper = tsk_getu32(fs->endian, sbp->sb_features_ro_compat) & feature;
    if (oper == 0)
        return 1;
    else
        return 0;
}

static inline bool xfs_sb_has_incompat_feature(
    TSK_FS_INFO * fs,
    xfs_sb   *sbp,
    uint32_t    feature)
{
    uint32_t oper = tsk_getu32(fs->endian, sbp->sb_features_incompat) & feature;
    if (oper == 0)
        return 1;
    else
        return 0;
}


/*
 * Directory tail pointer accessor functions. Based on block geometry.
 */
static inline struct xfs_dir2_block_tail *
xfs_dir2_block_tail_p(XFS_INFO *xfs, struct xfs_dir2_data_hdr *hdr)
{
    TSK_FS_INFO * fs = (TSK_FS_INFO *) &xfs->fs_info;
    return ((struct xfs_dir2_block_tail *)
        ((char *)hdr + tsk_getu32(fs->endian, xfs->fs->sb_blocksize))) - 1;
}

/*
 * Pointer to the leaf entries embedded in a data block (1-block format)
 */
static inline struct xfs_dir2_leaf_entry *
xfs_dir2_block_leaf_p([[maybe_unused]] XFS_INFO *xfs, struct xfs_dir2_block_tail *btp)
{
    uint32_t count = btp->count;
    return ((struct xfs_dir2_leaf_entry *)btp) - count;
}

static inline 
TSK_OFF_T xfs_inode_get_offset(XFS_INFO * xfs, TSK_INUM_T a_addr){
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & xfs->fs_info;
    TSK_OFF_T offset;
    uint8_t sb_agblklog = xfs->fs->sb_agblklog;
    uint8_t sb_inopblog = xfs->fs->sb_inopblog;

    /* lock access to grp_buf */
    tsk_take_lock(&xfs->lock);

    uint64_t ag_num = a_addr >> (sb_agblklog + sb_inopblog);
    uint64_t blk_num = (a_addr - (ag_num << (sb_agblklog + sb_inopblog))) >> sb_inopblog;
    uint64_t sec_num = (a_addr - (ag_num << (sb_agblklog + sb_inopblog)) - (blk_num << sb_inopblog));

    tsk_release_lock(&xfs->lock);

    TSK_OFF_T ag_offset = ag_num * (tsk_getu32(fs->endian, xfs->fs->sb_agblocks) * tsk_getu32(fs->endian, xfs->fs->sb_blocksize));
    TSK_OFF_T blk_offset = blk_num * tsk_getu32(fs->endian, xfs->fs->sb_blocksize);
    TSK_OFF_T sec_offset = sec_num * tsk_getu16(fs->endian, xfs->fs->sb_sectsize);
    
    offset = ag_offset + blk_offset + sec_offset;

    return offset;
}

typedef enum {
    XFS_EXT_NORM, XFS_EXT_UNWRITTEN,
} xfs_exntst_t;

typedef struct xfs_bmbt_irec {
    uint64_t        br_startoff;
    uint32_t 	    br_startblock;
    uint64_t        br_blockcount;
    xfs_exntst_t     br_state;
} xfs_bmbt_irec_t;

typedef struct xfs_bmbt_rec
{
	uint8_t			l0[8], l1[8];
} xfs_bmbt_rec_t;

typedef xfs_off_t   xfs_dir2_off_t;
typedef uint32_t    xfs_dir2_db_t;
typedef uint32_t    xfs_dir2_data_aoff_t;   /* argument form */

static inline uint16_t get_unaligned_be16(const uint8_t *p)
{
    return p[0] << 8 | p[1];
}

static inline xfs_dir2_data_aoff_t
xfs_dir2_sf_get_offset(xfs_dir2_sf_entry_t *sfep)
{
    return get_unaligned_be16(sfep->offset);
}

/*
 * Convert block and offset to byte in space
 */
static inline xfs_dir2_off_t
xfs_dir2_db_off_to_byte(XFS_INFO *xfs, xfs_dir2_db_t db,
            xfs_dir2_data_aoff_t o)
{
    return ((xfs_dir2_off_t)db << xfs->fs->sb_blocklog) + o;
}

/*
 * Convert byte in file space to dataptr.  It had better be aligned.
 */
static inline xfs_dir2_dataptr_t
xfs_dir2_byte_to_dataptr(xfs_dir2_off_t by)
{
    return (xfs_dir2_dataptr_t)(by >> XFS_DIR2_DATA_ALIGN_LOG);
}


#define XFS_INO32_SIZE	4
#define XFS_INO64_SIZE	8

static void
xfs_bmbt_disk_get_all(
    XFS_INFO* xfs,
    struct xfs_bmbt_rec *rec,
    struct xfs_bmbt_irec    *irec)
{
    uint64_t        l0 = tsk_getu64(xfs->fs_info.endian, rec->l0);
    uint64_t        l1 = tsk_getu64(xfs->fs_info.endian, rec->l1);

    irec->br_startoff = (l0 & xfs_mask64lo(64 - BMBT_EXNTFLAG_BITLEN)) >> 9;
    irec->br_startblock = ((l0 & xfs_mask64lo(9)) << 43) | (l1 >> 21);
    irec->br_blockcount = l1 & xfs_mask64lo(21);

    if (l0 >> (64 - BMBT_EXNTFLAG_BITLEN))
        irec->br_state = XFS_EXT_UNWRITTEN;
    else
        irec->br_state = XFS_EXT_NORM;
}

static struct xfs_dir2_data_entry *
xfs_dir2_data_nextentry(
    struct xfs_dir2_data_entry *daen)
{
    return (struct xfs_dir2_data_entry *)
    ((char*)daen + XFS_DIR3_DATA_ENTSIZE(daen->namelen));
}

/*
 * Convert block and offset to dataptr
 */
static inline xfs_dir2_dataptr_t
xfs_dir2_db_off_to_dataptr(XFS_INFO *xfs, xfs_dir2_db_t db,
               xfs_dir2_data_aoff_t o)
{
    return xfs_dir2_byte_to_dataptr(xfs_dir2_db_off_to_byte(xfs, db, o));
}

#ifdef __cplusplus
}
#endif