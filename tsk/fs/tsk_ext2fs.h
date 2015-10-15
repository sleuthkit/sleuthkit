/*
** The Sleuth Kit
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2003-2011 Brian Carrier.  All rights reserved
**
** TASK
** Copyright (c) 2002 Brian Carrier, @stake Inc.  All rights reserved
**
** This software is distributed under the Common Public License 1.0
*/

/*
 * Contains the structures and function APIs for EXT2FS file system support.
 */

#ifndef _TSK_EXT2FS_H
#define _TSK_EXT2FS_H

#ifdef __cplusplus
extern "C" {
#endif

    typedef uint64_t EXT2_GRPNUM_T;
#define PRI_EXT2GRP	PRIu64


/** \internal
* Read a 48-bit unsigned value.
* @param endian Flag that identifies local ordering.
* @param x 16-bit MSB byte array to read from
* @param y 32-bit byte array to read from
* @returns 48-bit unsigned value
*/
#define ext4_getu48(endian, x, y)   \
(uint64_t)( ((endian) == TSK_LIT_ENDIAN)  ?	\
            ((uint64_t) \
             ((uint64_t)((uint8_t *)(y))[0] <<  0) + \
             ((uint64_t)((uint8_t *)(y))[1] <<  8) + \
             ((uint64_t)((uint8_t *)(y))[2] << 16) + \
             ((uint64_t)((uint8_t *)(y))[3] << 24) + \
             ((uint64_t)((uint8_t *)(x))[0] << 32) + \
             ((uint64_t)((uint8_t *)(x))[1] << 40)) \
                                          : \
            ((uint64_t) \
             ((uint64_t)((uint8_t *)(y))[3] <<  0) + \
             ((uint64_t)((uint8_t *)(y))[2] <<  8) + \
             ((uint64_t)((uint8_t *)(y))[1] << 16) + \
             ((uint64_t)((uint8_t *)(y))[0] << 24) + \
             ((uint64_t)((uint8_t *)(x))[1] << 32) + \
             ((uint64_t)((uint8_t *)(x))[0] << 40)) )\


/** \internal
* Read a 48-bit unsigned value.
* @param endian Flag that identifies local ordering.
* @param x 32-bit MSB byte array to read from
* @param y 32-bit byte array to read from
* @returns 48-bit unsigned value
*/
#define ext4_getu64(endian, x, y)   \
(uint64_t)( ((endian) == TSK_LIT_ENDIAN)  ?	\
            ((uint64_t) \
             ((uint64_t)((uint8_t *)(y))[0] <<  0) + \
             ((uint64_t)((uint8_t *)(y))[1] <<  8) + \
             ((uint64_t)((uint8_t *)(y))[2] << 16) + \
             ((uint64_t)((uint8_t *)(y))[3] << 24) + \
             ((uint64_t)((uint8_t *)(x))[0] << 32) + \
             ((uint64_t)((uint8_t *)(x))[1] << 40) + \
             ((uint64_t)((uint8_t *)(x))[2] << 48) + \
             ((uint64_t)((uint8_t *)(x))[3] << 56))\
                                          : \
            ((uint64_t) \
             ((uint64_t)((uint8_t *)(y))[3] <<  0) + \
             ((uint64_t)((uint8_t *)(y))[2] <<  8) + \
             ((uint64_t)((uint8_t *)(y))[1] << 16) + \
             ((uint64_t)((uint8_t *)(y))[0] << 24) + \
             ((uint64_t)((uint8_t *)(x))[3] << 32) + \
             ((uint64_t)((uint8_t *)(x))[2] << 40) + \
             ((uint64_t)((uint8_t *)(x))[1] << 48) + \
             ((uint64_t)((uint8_t *)(x))[0] << 56)) )\


/*
** Constants
*/
#define EXT2FS_FIRSTINO    1    /* inode 1 contains the bad blocks */
#define EXT2FS_ROOTINO     2    /* location of root directory inode */
#define EXT2FS_NDADDR      12
#define EXT2FS_NIADDR      3
#define EXT2FS_SBOFF       1024
#define EXT2FS_FS_MAGIC    0xef53
#define EXT2FS_MAXNAMLEN	255
#define EXT2FS_MAXPATHLEN	4096
#define EXT2FS_MIN_BLOCK_SIZE	1024
#define EXT2FS_MAX_BLOCK_SIZE	4096
#define EXT2FS_FILE_CONTENT_LEN     ((EXT2FS_NDADDR + EXT2FS_NIADDR) * sizeof(TSK_DADDR_T))

/*
** Super Block
*/
    typedef struct {
        uint8_t s_inodes_count[4];      /* u32 */
        uint8_t s_blocks_count[4];      /* u32 */
        uint8_t s_r_blocks_count[4];
        uint8_t s_free_blocks_count[4]; /* u32 */
        uint8_t s_free_inode_count[4];  /* u32 */
        uint8_t s_first_data_block[4];  /* u32 */
        uint8_t s_log_block_size[4];    /* u32 */
        uint8_t s_log_frag_size[4];     /* s32 */
        uint8_t s_blocks_per_group[4];  /* u32 */
        uint8_t s_frags_per_group[4];   /* u32 */
        uint8_t s_inodes_per_group[4];  /* u32 */
        uint8_t s_mtime[4];     /* u32 *//* mount time */
        uint8_t s_wtime[4];     /* u32 *//* write time */
        uint8_t s_mnt_count[2]; /* u16 *//* mount count */
        uint8_t s_max_mnt_count[2];     /* s16 */
        uint8_t s_magic[2];     /* u16 */
        uint8_t s_state[2];     /* u16 *//* fs state */
        uint8_t s_errors[2];    /* u16 */
        uint8_t s_minor_rev_level[2];   /* u16 */
        uint8_t s_lastcheck[4]; /* u32 */
        uint8_t s_checkinterval[4];     /* u32 */
        uint8_t s_creator_os[4];        /* u32 */
        uint8_t s_rev_level[4]; /* u32 */
        uint8_t s_def_resuid[2];        /* u16 */
        uint8_t s_def_resgid[2];        /* u16 */
        uint8_t s_first_ino[4]; /* u32 */
        uint8_t s_inode_size[2];        /* u16 */
        uint8_t s_block_group_nr[2];    /* u16 */
        uint8_t s_feature_compat[4];    /* u32 */
        uint8_t s_feature_incompat[4];  /* u32 */
        uint8_t s_feature_ro_compat[4]; /* u32 */
        uint8_t s_uuid[16];     /* u8[16] */
        char s_volume_name[16];
        char s_last_mounted[64];
        uint8_t s_algorithm_usage_bitmap[4];    /* u32 */
        uint8_t s_prealloc_blocks;      /* u8 */
        uint8_t s_prealloc_dir_blocks;  /* u8 */
        union pad_or_gdt {
            uint8_t s_padding1[2];      /* u16 */
            uint8_t s_reserved_gdt_blocks[2];   /*u16 */
        } pad_or_gdt;
/* Valid if EXT2_FEATURE_COMPAT_HAS_JOURNAL */
        uint8_t s_journal_uuid[16];     /* u8[16] */
        uint8_t s_journal_inum[4];      /* u32 */
        uint8_t s_journal_dev[4];       /* u32 */
        uint8_t s_last_orphan[4];       /* u32 */
        uint8_t s_hash_seed[16];        /* u32[4] */
        uint8_t s_def_hash_version;     /* u8 */
        uint8_t s_jnl_backup_type;      /* u8 */
        uint8_t s_desc_size[2]; /* u16 */
        uint8_t s_default_mount_opts[4];        /* u32 */
        uint8_t s_first_meta_bg[4];     /* u32 */
        uint8_t s_mkfs_time[4]; /* u32 */
        uint8_t s_jnl_blocks[17 * 4];   /* u32[17] */
/* Valid if EXT4_FEATURE_INCOMPAT_64BIT*/
        uint8_t s_blocks_count_hi[4];   /* u32 */
        uint8_t s_r_blocks_count_hi[4]; /* u32 */
        uint8_t s_free_blocks_count_hi[4];      /* u32 */
        uint8_t s_min_extra_isize[2];   /* u16 */
        uint8_t s_want_extra_isize[2];  /* u16 */
        uint8_t s_flags[4];     /* u32 */
        uint8_t s_raid_stride[2];       /* u16 */
        uint8_t s_mmp_interval[2];      /* u16 */
        uint8_t s_mmp_block[8]; /* u64 */
        uint8_t s_raid_stripe_width[4]; /* u32 */
        uint8_t s_log_groups_per_flex;  /* u8 */
        uint8_t s_reserved_char_pad;    /* u8 */
        uint8_t s_reserved_pad[2];      /* u16 */
        uint8_t s_kbytes_written[8];    /* u64 */
        uint8_t s_snapshot_inum[4];     /* u32 */
        uint8_t s_snapshot_id[4];       /* u32 */
        uint8_t s_snapshot_r_blocks_count[8];   /* u64 */
        uint8_t s_snapshot_list[4];     /* u32 */
        uint8_t s_error_count[4];       /* u32 */
        uint8_t s_first_error_time[4];  /* u32 */
        uint8_t s_first_error_ino[4];   /* u32 */
        uint8_t s_first_error_block[8]; /* u64 */
        uint8_t s_first_error_func[32]; /* u8[32] */
        uint8_t s_first_error_line[4];  /* u32 */
        uint8_t s_last_error_time[4];   /* u32 */
        uint8_t s_last_error_ino[4];    /* u32 */
        uint8_t s_last_error_line[4];   /* u32 */
        uint8_t s_last_error_block[8];  /* u64 */
        uint8_t s_last_error_func[32];  /* u8[32] */
        uint8_t s_mount_opts[64];       /* u8[64] */
        uint8_t s_usr_quota_inum[4];    /* u32 */
        uint8_t s_grp_quota_inum[4];    /* u32 */
        uint8_t s_overhead_clusters[4]; /* u32 */
        uint8_t s_padding[109 * 4];
    } ext2fs_sb;

/* File system State Values */
#define EXT2FS_STATE_VALID	0x0001  /* unmounted correctly */
#define EXT2FS_STATE_ERROR	0x0002  /* errors detected */

/* Operating System Codes */
#define EXT2FS_OS_LINUX		0
#define EXT2FS_OS_HURD		1
#define	EXT2FS_OS_MASIX		2
#define EXT2FS_OS_FREEBSD	3
#define EXT2FS_OS_LITES		4

/* Revision Levels */
#define EXT2FS_REV_ORIG		0
#define EXT2FS_REV_DYN		1

/* feature flags */
#define EXT2FS_HAS_COMPAT_FEATURE(fs,sb,mask)\
    ((tsk_getu32(fs->endian,sb->s_feature_compat) & mask) != 0)

#define EXT2FS_FEATURE_COMPAT_DIR_PREALLOC	0x0001
#define EXT2FS_FEATURE_COMPAT_IMAGIC_INODES	0x0002
#define EXT2FS_FEATURE_COMPAT_HAS_JOURNAL	0x0004
#define EXT2FS_FEATURE_COMPAT_EXT_ATTR		0x0008
#define EXT2FS_FEATURE_COMPAT_RESIZE_INO	0x0010
#define EXT2FS_FEATURE_COMPAT_DIR_INDEX		0x0020

#define EXT2FS_HAS_INCOMPAT_FEATURE(fs,sb,mask)\
    ((tsk_getu32(fs->endian,sb->s_feature_incompat) & mask) != 0)

#define EXT2FS_FEATURE_INCOMPAT_COMPRESSION	0x0001
#define EXT2FS_FEATURE_INCOMPAT_FILETYPE	0x0002
#define EXT2FS_FEATURE_INCOMPAT_RECOVER		0x0004
#define EXT2FS_FEATURE_INCOMPAT_JOURNAL_DEV	0x0008
#define EXT2FS_FEATURE_INCOMPAT_META_BG         0x0010
#define EXT2FS_FEATURE_INCOMPAT_EXTENTS         0x0040
#define EXT2FS_FEATURE_INCOMPAT_64BIT           0x0080
#define EXT2FS_FEATURE_INCOMPAT_MMP             0x0100
#define EXT2FS_FEATURE_INCOMPAT_FLEX_BG         0x0200
#define EXT2FS_FEATURE_INCOMPAT_EA_INODE        0x0400
#define EXT2FS_FEATURE_INCOMPAT_DIRDATA         0x1000
#define EXT4FS_FEATURE_INCOMPAT_INLINEDATA      0x2000  /* data in inode */
#define EXT4FS_FEATURE_INCOMPAT_LARGEDIR        0x4000  /* >2GB or 3-lvl htree */

#define EXT2FS_HAS_RO_COMPAT_FEATURE(fs,sb,mask)\
    ((tsk_getu32(fs->endian,sb->s_feature_ro_compat) & mask) != 0)

#define EXT2FS_FEATURE_RO_COMPAT_SPARSE_SUPER	0x0001
#define EXT2FS_FEATURE_RO_COMPAT_LARGE_FILE 	0x0002
#define EXT2FS_FEATURE_RO_COMPAT_BTREE_DIR  	0x0004
#define EXT2FS_FEATURE_RO_COMPAT_HUGE_FILE      0x0008
#define EXT2FS_FEATURE_RO_COMPAT_GDT_CSUM       0x0010
#define EXT2FS_FEATURE_RO_COMPAT_DIR_NLINK      0x0020
#define EXT2FS_FEATURE_RO_COMPAT_EXTRA_ISIZE    0x0040
#define EXT4FS_FEATURE_RO_COMPAT_QUOTA          0x0100
#define EXT4FS_FEATURE_RO_COMPAT_BIGALLOC       0x0200
#define EXT4FS_FEATURE_RO_COMPAT_METADATA_CSUM  0x0400


/*
 * Group Descriptor
 */
    typedef struct ext2fs_gd {
        uint8_t bg_block_bitmap[4];     /* u32: block of blocks bitmap */
        uint8_t bg_inode_bitmap[4];     /* u32: block of inodes bitmap */
        uint8_t bg_inode_table[4];      /* u32: block of inodes table */
        uint8_t bg_free_blocks_count[2];        /* u16: num of free blocks */
        uint8_t bg_free_inodes_count[2];        /* u16: num of free inodes */
        uint8_t bg_used_dirs_count[2];  /* u16: num of use directories  */
        uint8_t f1[14];
    } ext2fs_gd;

#define EXT4_BG_INODE_UNINIT    0x0001  /* Inode table/bitmap not in use */
#define EXT4_BG_BLOCK_UNINIT    0x0002  /* Block bitmap not in use */
#define EXT4_BG_INODE_ZEROED    0x0004  /* On-disk itable initialized to zero */

#define EXT4BG_HAS_FLAG(fs,gd,flag)\
    ((tsk_getu16(fs->endian,gd->bg_flags) & flag) != 0)

    typedef struct ext4fs_gd {
        uint8_t bg_block_bitmap_lo[4];  /* u32 */
        uint8_t bg_inode_bitmap_lo[4];  /* u32 */
        uint8_t bg_inode_table_lo[4];   /* u32 */
        uint8_t bg_free_blocks_count_lo[2];     /* u16 */
        uint8_t bg_free_inodes_count_lo[2];     /* u16 */
        uint8_t bg_used_dirs_count_lo[2];       /* u16 */
        uint8_t bg_flags[2];    /* u16 */
        uint8_t bg_reserved[4 * 2];     /* u32 */
        uint8_t bg_itable_unused_lo[2]; /* u16 */
        uint8_t bg_checksum[2]; /* u16 */
        uint8_t bg_block_bitmap_hi[4];  /* u32 */
        uint8_t bg_inode_bitmap_hi[4];  /* u32 */
        uint8_t bg_inode_table_hi[4];   /* u32 */
        uint8_t bg_free_blocks_count_hi[2];     /* u16 */
        uint8_t bg_free_inodes_count_hi[2];     /* u16 */
        uint8_t bg_used_dirs_count_hi[2];       /* u16 */
        uint8_t bg_itable_unused_hi[2]; /* u16 */
        uint8_t bg_reserved2[4 * 3];    /* u32 */
    } ext4fs_gd;


/* data address to group number */
#define ext2_dtog_lcl(fsi, fs, d)	\
	(EXT2_GRPNUM_T)(((d) - tsk_getu32(fsi->endian, fs->s_first_data_block)) / \
	tsk_getu32(fsi->endian, fs->s_blocks_per_group))


/* first fragment of group */
#define ext2_cgbase_lcl(fsi, fs, c)	\
	((TSK_DADDR_T)((tsk_getu32(fsi->endian, fs->s_blocks_per_group) * (c)) + \
	tsk_getu32(fsi->endian, fs->s_first_data_block)))

#define ext4_cgbase_lcl(fsi, fs, c)	\
	((TSK_DADDR_T)((uint64_t)(tsk_getu32(fsi->endian, fs->s_blocks_per_group) * (uint64_t)(c)) + \
	(uint64_t)tsk_getu32(fsi->endian, fs->s_first_data_block)))

/*
 * Inode
 */
    typedef struct {
        uint8_t i_mode[2];      /* u16 */
        uint8_t i_uid[2];       /* u16 */
        uint8_t i_size[4];      /* u32 */
        uint8_t i_atime[4];     /* u32 */
        uint8_t i_ctime[4];     /* u32 */
        uint8_t i_mtime[4];     /* u32 */
        uint8_t i_dtime[4];     /* u32 */
        uint8_t i_gid[2];       /* u16 */
        uint8_t i_nlink[2];     /* u16 */
        uint8_t i_nblk[4];
        uint8_t i_flags[4];
        uint8_t i_f5[4];
        uint8_t i_block[15][4]; /*s32 */
        uint8_t i_generation[4];
        uint8_t i_file_acl[4];
        uint8_t i_size_high[4]; /* u32 - also i_dir_acl for non-regular  */
        uint8_t i_faddr[4];
        uint8_t i_frag;
        uint8_t i_fsize;
        uint8_t f1[2];
        uint8_t i_uid_high[2];  /* u16 */
        uint8_t i_gid_high[2];  /* u16 */
        uint8_t f7[4];          /* u32 */
        uint8_t i_extra_isize[2];       /* u16 */
        uint8_t i_pad1[2];      /* u16 */
        uint8_t i_ctime_extra[4];       /* u32 */
        uint8_t i_mtime_extra[4];       /* u32 */
        uint8_t i_atime_extra[4];       /* u32 */
        uint8_t i_crtime[4];    /* u32 */
        uint8_t i_crtime_extra[4];      /* u32 */
        uint8_t i_version_hi[4];        /* u32 */
    } ext2fs_inode;

    typedef struct ext2fs_extent {
        uint8_t ee_block[4];    /* u32 */
        uint8_t ee_len[2];      /* u16 */
        uint8_t ee_start_hi[2]; /* u16 */
        uint8_t ee_start_lo[4]; /* u32 */
    } ext2fs_extent;

    typedef struct ext2fs_extent_idx {
        uint8_t ei_block[4];    /* u32 */
        uint8_t ei_leaf_lo[4];  /* u32 */
        uint8_t ei_leaf_hi[2];  /* u16 */
        uint8_t ei_unused[2];   /* u16 */
    } ext2fs_extent_idx;

    typedef struct ext2fs_extent_header {
        uint8_t eh_magic[2];    /* u16 */
        uint8_t eh_entries[2];  /* u16 */
        uint8_t eh_max[2];      /* u16 */
        uint8_t eh_depth[2];    /* u16 */
        uint8_t eh_generation[4];       /* u32 */
    } ext2fs_extent_header;

/* MODE */
#define EXT2_IN_FMT  0170000
#define EXT2_IN_SOCK 0140000
#define EXT2_IN_LNK  0120000
#define EXT2_IN_REG  0100000
#define EXT2_IN_BLK  0060000
#define EXT2_IN_DIR  0040000
#define EXT2_IN_CHR  0020000
#define EXT2_IN_FIFO  0010000

#define EXT2_IN_ISUID   0004000
#define EXT2_IN_ISGID   0002000
#define EXT2_IN_ISVTX   0001000
#define EXT2_IN_IRUSR   0000400
#define EXT2_IN_IWUSR   0000200
#define EXT2_IN_IXUSR   0000100
#define EXT2_IN_IRGRP   0000040
#define EXT2_IN_IWGRP   0000020
#define EXT2_IN_IXGRP   0000010
#define EXT2_IN_IROTH   0000004
#define EXT2_IN_IWOTH   0000002
#define EXT2_IN_IXOTH   0000001


#define EXT2_IN_SECDEL 		0x00000001      /* Secure deletion */
#define EXT2_IN_UNRM 		0x00000002      /* Undelete */
#define EXT2_IN_COMP 		0x00000004      /* Compress file */
#define EXT2_IN_SYNC		0x00000008      /* Synchronous updates */
#define EXT2_IN_IMM		 	0x00000010      /* Immutable file */
#define EXT2_IN_APPEND 		0x00000020      /* writes to file may only append */
#define EXT2_IN_NODUMP 		0x00000040      /* do not dump file */
#define EXT2_IN_NOA		 	0x00000080      /* do not update atime */
#define EXT2_IN_DIRTY                   0x00000100
#define EXT2_IN_COMPRBLK                0x00000200      /* One or more compressed clusters */
#define EXT2_IN_NOCOMPR                 0x00000400      /* Don't compress */
#define EXT2_IN_ECOMPR                  0x00000800      /* Compression error */
#define EXT2_IN_INDEX                   0x00001000      /* hash-indexed directory */
#define EXT2_IN_IMAGIC                  0x00002000      /* AFS directory */
#define EXT2_IN_JOURNAL_DATA            0x00004000      /* file data should be journaled */
#define EXT2_IN_NOTAIL                  0x00008000      /* file tail should not be merged */
#define EXT2_IN_DIRSYNC                 0x00010000      /* dirsync behaviour (directories only) */
#define EXT2_IN_TOPDIR                  0x00020000      /* Top of directory hierarchies */
#define EXT2_IN_HUGE_FILE               0x00040000      /* Set to each huge file */
#define EXT2_IN_EXTENTS                 0x00080000      /* Inode uses extents */
#define EXT2_IN_EA_INODE                0x00200000      /* Inode used for large EA */
#define EXT2_IN_EOFBLOCKS               0x00400000      /* Blocks allocated beyond EOF */
#define EXT2_IN_RESERVED                0x80000000      /* reserved for ext4 lib */
#define EXT2_IN_USER_VISIBLE            0x004BDFFF      /* User visible flags */
#define EXT2_IN_USER_MODIFIABLE         0x004B80FF      /* User modifiable flags */


/*
 * directory entries
 */
    typedef struct {
        uint8_t inode[4];       /* u32 */
        uint8_t rec_len[2];     /* u16 */
        uint8_t name_len[2];    /* u16 */
        char name[EXT2FS_MAXNAMLEN];
    } ext2fs_dentry1;

/* new structure starting at 2.2 */
    typedef struct {
        uint8_t inode[4];       /* u32 */
        uint8_t rec_len[2];     /* u16 */
        uint8_t name_len;
        uint8_t type;
        char name[EXT2FS_MAXNAMLEN];
    } ext2fs_dentry2;

#define EXT2FS_DIRSIZ_lcl(len) \
    ((len + 8 + 3) & ~(3))


/* Ext2 directory file types  */
#define EXT2_DE_UNKNOWN         0
#define EXT2_DE_REG        1
#define EXT2_DE_DIR             2
#define EXT2_DE_CHR          3
#define EXT2_DE_BLK          4
#define EXT2_DE_FIFO            5
#define EXT2_DE_SOCK            6
#define EXT2_DE_LNK         7
#define EXT2_DE_MAX             8


#define EXT2_DE_V1	1
#define EXT2_DE_V2	2




/* Extended Attributes
 */

#define EXT2_EA_MAGIC	0xEA020000

    typedef struct {
        uint8_t magic[4];
        uint8_t refcount[4];
        uint8_t blocks[4];
        uint8_t hash[4];
        uint8_t f1[16];
        uint8_t entry;
    } ext2fs_ea_header;


#define EXT2_EA_IDX_USER                   1
#define EXT2_EA_IDX_POSIX_ACL_ACCESS       2
#define EXT2_EA_IDX_POSIX_ACL_DEFAULT      3
#define EXT2_EA_IDX_TRUSTED                4
#define EXT2_EA_IDX_LUSTRE                 5
#define EXT2_EA_IDX_SECURITY               6

/* Entries follow the header and are aligned to 4-byte boundaries
 * the value of the attribute is stored at the bottom of the block
 */
    typedef struct {
        uint8_t nlen;
        uint8_t nidx;
        uint8_t val_off[2];
        uint8_t val_blk[4];
        uint8_t val_size[4];
        uint8_t hash[4];
        uint8_t name;
    } ext2fs_ea_entry;

#define EXT2_EA_LEN(nlen) \
	((((nlen) + 19 ) / 4) * 4)


    typedef struct {
        uint8_t ver[4];
    } ext2fs_pos_acl_head;


#define EXT2_PACL_TAG_USERO	0x01
#define EXT2_PACL_TAG_USER	0x02
#define EXT2_PACL_TAG_GRPO	0x04
#define EXT2_PACL_TAG_GRP	0x08
#define EXT2_PACL_TAG_MASK	0x10
#define EXT2_PACL_TAG_OTHER	0x20


#define EXT2_PACL_PERM_EXEC	0x01
#define EXT2_PACL_PERM_WRITE	0x02
#define EXT2_PACL_PERM_READ	0x04


    typedef struct {
        uint8_t tag[2];
        uint8_t perm[2];
    } ext2fs_pos_acl_entry_sh;

    typedef struct {
        uint8_t tag[2];
        uint8_t perm[2];
        uint8_t id[4];
    } ext2fs_pos_acl_entry_lo;




/************** JOURNAL ******************/

/* These values are always in big endian */

#define EXT2_JMAGIC	0xC03b3998

/*JBD2 Feature Flags */
#define JBD2_FEATURE_COMPAT_CHECKSUM        0x00000001

#define JBD2_FEATURE_INCOMPAT_REVOKE        0x00000001
#define JBD2_FEATURE_INCOMPAT_64BIT         0x00000002
#define JBD2_FEATURE_INCOMPAT_ASYNC_COMMIT  0x00000004

    typedef struct {
        uint8_t magic[4];
        uint8_t entrytype[4];
        uint8_t entryseq[4];    /* sequence of this entry */
        uint8_t bsize[4];       /* size of block */

        uint8_t num_blk[4];     /* num of blks in journal */
        uint8_t first_blk[4];   /* bl where log starts */
        uint8_t start_seq[4];   /* first commit ID in log */
        uint8_t start_blk[4];   /* journ blk for 1st valid entry */

        uint8_t j_errno[4];     /* signed error number */

/* the rest are not valid for v1 sb */
        uint8_t feature_compat[4];
        uint8_t feature_incompat[4];
        uint8_t feature_ro_incompat[4];
        uint8_t uuid[16];
        uint8_t num_fs[4];      /* num of fs sharing log */
        uint8_t dynsuper[4];    /* fs block of sb copy */
        uint8_t max_trans[4];   /* limit of blk per trans */
        uint8_t max_trans_data[4];      /* limit of data blocks per */
        uint8_t reserved[176];
        uint8_t id_fs[16][48];  /* Ids of fs sharing log */
    } ext2fs_journ_sb;


#define EXT2_J_ETYPE_DESC	1       /* descriptor block */
#define EXT2_J_ETYPE_COM	2       /* commit */
#define EXT2_J_ETYPE_SB1	3       /* super block v1 */
#define EXT2_J_ETYPE_SB2	4       /* sb v2 */
#define EXT2_J_ETYPE_REV	5       /* revoke */


/* Header that is used for all structures */
    typedef struct {
        uint8_t magic[4];
        uint8_t entry_type[4];
        uint8_t entry_seq[4];
    } ext2fs_journ_head;

/* JBD2 Checksum types */
#define JBD2_CRC32_CHKSUM   1
#define JBD2_MD5_CHKSUM     2
#define JBD2_SHA1_CHKSUM    3

#define JBD2_CRC32_CHKSUM_SIZE  4
#define JBD2_CHECKSUM_BYTES (32/ sizeof(unsigned int))

#define NSEC_PER_SEC 1000000000L

/* Header for ext4 commit blocks */
    typedef struct {
        ext2fs_journ_head c_header;
        uint8_t chksum_type;
        uint8_t chksum_size;
        uint8_t padding[2];
        uint8_t chksum[4 * JBD2_CHECKSUM_BYTES];
        uint8_t commit_sec[8];
        uint8_t commit_nsec[4];
    } ext4fs_journ_commit_head;


/* dentry flags */
#define EXT2_J_DENTRY_ESC	1       /* The orig block starts with magic */
#define EXT2_J_DENTRY_SAMEID	2       /* Entry is for same id, so do not skip 16 ahead */
#define EXT2_J_DENTRY_DEL	4       /* not currently used in src */
#define EXT2_J_DENTRY_LAST	8       /* Last tag */

/* Entry in the descriptor table */
    typedef struct {
        uint8_t fs_blk[4];
        uint8_t flag[4];
    } ext2fs_journ_dentry;


/* Journal Info */
    typedef struct {

        TSK_FS_FILE *fs_file;
        TSK_INUM_T j_inum;

        uint32_t bsize;
        TSK_DADDR_T first_block;
        TSK_DADDR_T last_block;

        uint32_t start_seq;
        TSK_DADDR_T start_blk;

    } EXT2FS_JINFO;



    /*
     * Structure of an ext2fs file system handle.
     */
    typedef struct {
        TSK_FS_INFO fs_info;    /* super class */
        ext2fs_sb *fs;          /* super block */

        /* lock protects grp_buf, grp_num, bmap_buf, bmap_grp_num, imap_buf, imap_grp_num */
        tsk_lock_t lock;

        // one of the below will be allocated and populated by ext2fs_group_load depending on the FS type
        ext4fs_gd *ext4_grp_buf; /* cached group descriptor for 64-bit ext4 r/w shared - lock */
        ext2fs_gd *grp_buf;     /* cached group descriptor for ext2,ext3,32-bit ext4 r/w shared - lock */

        EXT2_GRPNUM_T grp_num;  /* cached group number r/w shared - lock */

        uint8_t *bmap_buf;      /* cached block allocation bitmap r/w shared - lock */
        EXT2_GRPNUM_T bmap_grp_num;     /* cached block bitmap nr r/w shared - lock */

        uint8_t *imap_buf;      /* cached inode allocation bitmap r/w shared - lock */
        EXT2_GRPNUM_T imap_grp_num;     /* cached inode bitmap nr r/w shared - lock */

        TSK_OFF_T groups_offset;        /* offset to first group desc */
        EXT2_GRPNUM_T groups_count;     /* nr of descriptor group blocks */
        uint8_t deentry_type;   /* v1 or v2 of dentry */
        uint16_t inode_size;    /* size of each inode */
        TSK_DADDR_T first_data_block;

        EXT2FS_JINFO *jinfo;
    } EXT2FS_INFO;


    extern TSK_RETVAL_ENUM
        ext2fs_dir_open_meta(TSK_FS_INFO * a_fs, TSK_FS_DIR ** a_fs_dir,
        TSK_INUM_T a_addr);
    extern uint8_t ext2fs_jentry_walk(TSK_FS_INFO *, int,
        TSK_FS_JENTRY_WALK_CB, void *);
    extern uint8_t ext2fs_jblk_walk(TSK_FS_INFO *, TSK_DADDR_T,
        TSK_DADDR_T, int, TSK_FS_JBLK_WALK_CB, void *);
    extern uint8_t ext2fs_jopen(TSK_FS_INFO *, TSK_INUM_T);

#ifdef __cplusplus
}
#endif
#endif
