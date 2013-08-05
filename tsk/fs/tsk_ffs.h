/*
** The Sleuth Kit 
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2003-2011 Brian Carrier.  All rights reserved
**
** TASK
** Copyright (c) 2002 @stake Inc.  All rights reserved
** 
** This software is distributed under the Common Public License 1.0
*/

/*
 * Contains the structures and function APIs for FFS file system support.
 */


#ifndef _TSK_FFS_H
#define _TSK_FFS_H

#ifdef __cplusplus
extern "C" {
#endif


    typedef uint32_t FFS_GRPNUM_T;
#define PRI_FFSGRP PRIu32

/*
** CONSTANTS
**/
#define FFS_FIRSTINO	0       /* 0 & 1 are reserved (1 was bad blocks) */
#define FFS_ROOTINO		2       /* location of root directory inode */
#define FFS_NDADDR		12
#define FFS_NIADDR		3

#define UFS1_SBOFF	8192
#define UFS2_SBOFF	65536
#define UFS2_SBOFF2	262144

#define UFS1_FS_MAGIC	0x011954
#define UFS2_FS_MAGIC	0x19540119

#define FFS_MAXNAMLEN 	255
#define FFS_MAXPATHLEN	1024
#define FFS_DIRBLKSIZ	512

#define FFS_FILE_CONTENT_LEN     ((FFS_NDADDR + FFS_NIADDR) * sizeof(TSK_DADDR_T))

    typedef struct {
        uint8_t dir_num[4];
        uint8_t blk_free[4];
        uint8_t ino_free[4];
        uint8_t frag_free[4];
    } ffs_csum1;

    typedef struct {
        uint8_t dir_num[8];
        uint8_t blk_free[8];
        uint8_t ino_free[8];
        uint8_t frag_free[8];
        uint8_t clust_free[8];
        uint8_t f1[24];
    } ffs_csum2;



/*
 * Super Block Structure
 */

// UFS 1
    typedef struct {
        uint8_t f1[8];
        /* Offsets in each cylinder group */
        uint8_t sb_off[4];      /* s32 */
        uint8_t gd_off[4];      /* s32 */
        uint8_t ino_off[4];     /* s32 */
        uint8_t dat_off[4];     /* s32 */

        /* How much the base of the admin data in each cyl group changes */
        uint8_t cg_delta[4];    /* s32 */
        uint8_t cg_cyc_mask[4]; /* s32 */

        uint8_t wtime[4];       /* u32 : last written time */
        uint8_t frag_num[4];    /* s32 - number of fragments in FS */
        uint8_t data_frag_num[4];       /* s32 - number of frags not being used for admin data */
        uint8_t cg_num[4];      /* s32 - number of cyl grps in FS */

        uint8_t bsize_b[4];     /* s32 - size of block */
        uint8_t fsize_b[4];     /* s32 - size of fragment */
        uint8_t bsize_frag[4];  /* s32 - num of frag in block */
        uint8_t f5[36];
        uint8_t fs_fragshift[4];        /* s32 */
        uint8_t f6[20];
        uint8_t fs_inopb[4];    /* s32 */
        uint8_t f7[20];
        uint8_t fs_id[8];
        uint8_t cg_saddr[4];    /* s32 */
        uint8_t cg_ssize_b[4];  /* s32 */
        uint8_t fs_cgsize[4];   /* s32 */
        uint8_t f7c[12];
        uint8_t fs_ncyl[4];     /* s32 */
        uint8_t fs_cpg[4];      /* s32 */
        uint8_t cg_inode_num[4];        /* s32 */
        uint8_t cg_frag_num[4]; /* s32 */

        ffs_csum1 cstotal;

        uint8_t fs_fmod;
        uint8_t fs_clean;
        uint8_t fs_ronly;
        uint8_t fs_flags;
        uint8_t last_mnt[512];
        uint8_t f8[648];
        uint8_t magic[4];       /* s32 */
        uint8_t f9[160];        /* filler so it is a multiple of 512 */
    } ffs_sb1;


// UFS 2
    typedef struct {
        uint8_t f0[8];
        /* Offsets in each cylinder group */
        uint8_t sb_off[4];      /* s32 */
        uint8_t gd_off[4];      /* s32 */
        uint8_t ino_off[4];     /* s32 */
        uint8_t dat_off[4];     /* s32 */

        uint8_t f1[20];         /* s32 */

        uint8_t cg_num[4];      /* s32 - number of cyl grps in FS */
        uint8_t bsize_b[4];     /* s32 - size of block */
        uint8_t fsize_b[4];     /* s32 - size of fragment */
        uint8_t bsize_frag[4];  /* s32 - num of frag in block */
        uint8_t f2[36];
        uint8_t fs_fragshift[4];        /* s32 */
        uint8_t f3[20];
        uint8_t fs_inopb[4];    /* s32 */
        uint8_t f4[32];
        uint8_t cg_ssize_b[4];  /* s32 */
        uint8_t fs_cgsize[4];   /* s32 */
        uint8_t f5[20];
        uint8_t cg_inode_num[4];        /* s32 */
        uint8_t cg_frag_num[4]; /* s32 - fs_fpg */

        uint8_t f6[16];
        uint8_t fs_fmod;
        uint8_t fs_clean;
        uint8_t fs_ronly;
        uint8_t f7;
        uint8_t last_mnt[468];
        uint8_t volname[32];
        uint8_t swuid[8];
        uint8_t f8[288];

        ffs_csum2 cstotal;

        uint8_t wtime[8];       /* u32 : last written time */
        uint8_t frag_num[8];    /* s32 - number of fragments in FS */
        uint8_t blk_num[8];     /* s32 - number of blocks in FS */
        uint8_t cg_saddr[8];

        uint8_t f9[208];
        uint8_t fs_flags[4];
        uint8_t f10[56];

        uint8_t magic[4];       /* s32 */
        uint8_t f11[160];       /* filler so it is a multiple of 512 */
    } ffs_sb2;


#define FFS_SB_FLAG_UNCLEAN	0x01
#define FFS_SB_FLAG_SOFTDEP	0x02
#define FFS_SB_FLAG_NEEDFSCK	0x04
#define FFS_SB_FLAG_INDEXDIR	0x08
#define FFS_SB_FLAG_ACL		0x10
#define FFS_SB_FLAG_MULTILABEL	0x20
#define FFS_SB_FLAG_UPDATED	0x80


/* How the file system is optimized */
#define FFS_SB_OPT_TIME		0
#define FFS_SB_OPT_SPACE	1



/*
 * Cylinder Group Descriptor
 *
 * UFS1 and UFS2 are the same for the data that we care about unless we 
 * want the wtime for 'fsstat'.  
 */
    typedef struct {
        uint8_t f1[4];
        uint8_t magic[4];       /* 0x090255 */
        uint8_t wtime[4];       /* last written time */
        uint8_t cg_cgx[4];      /* s32 - my group number */
        uint8_t cyl_num[2];     /* number of cyl in this group */
        uint8_t ino_num[2];     /* number of inodes in this group */
        uint8_t frag_num[4];    /* number of fragments in this group */
        ffs_csum1 cs;
        uint8_t last_alloc_blk[4];      /* last allocated blk relative to start */
        uint8_t last_alloc_frag[4];     /* last alloc frag relative to start */
        uint8_t last_alloc_ino[4];
        uint8_t avail_frag[8][4];
        uint8_t f2b[8];
        uint8_t cg_iusedoff[4]; /* s32 */
        uint8_t cg_freeoff[4];  /* s32 */
        uint8_t f3[72];
    } ffs_cgd;

    typedef struct {
        uint8_t f1[4];
        uint8_t magic[4];       /* 0x090255 */
        uint8_t f2[4];
        uint8_t cg_cgx[4];      /* s32 - my group number */
        uint8_t f2a[4];         /* number of cyl in this group */
        uint8_t frag_num[4];    /* number of fragments in this group */
        ffs_csum1 cs;
        uint8_t last_alloc_blk[4];      /* last allocated blk relative to start */
        uint8_t last_alloc_frag[4];     /* last alloc frag relative to start */
        uint8_t last_alloc_ino[4];
        uint8_t avail_frag[8][4];
        uint8_t f2b[8];
        uint8_t cg_iusedoff[4]; /* s32 */
        uint8_t cg_freeoff[4];  /* s32 */

        uint8_t cg_nextfreeoff[4];
        uint8_t cg_clustersumoff[4];
        uint8_t cg_clusteroff[4];
        uint8_t cg_nclustersblks[4];
        uint8_t cg_niblk[4];
        uint8_t cg_initediblk[4];
        uint8_t f3a[12];
        uint8_t wtime[8];
        uint8_t f3[24];
    } ffs_cgd2;


/*
 * inode
 */

/* ffs_inode1: OpenBSD & FreeBSD etc. */
    typedef struct {
        uint8_t di_mode[2];     /* u16 */
        uint8_t di_nlink[2];    /* s16 */
        uint8_t f1[4];
        uint8_t di_size[8];     /* u64 */
        uint8_t di_atime[4];    /* s32 */
        uint8_t di_atimensec[4];
        uint8_t di_mtime[4];    /* s32 */
        uint8_t di_mtimensec[4];
        uint8_t di_ctime[4];    /* s32 */
        uint8_t di_ctimensec[4];
        uint8_t di_db[12][4];   /* s32 */
        uint8_t di_ib[3][4];    /* s32 */
        uint8_t f5[8];
        uint8_t gen[4];
        uint8_t di_uid[4];      /* u32 */
        uint8_t di_gid[4];      /* u32 */
        uint8_t f6[8];
    } ffs_inode1;

/* ffs_inode1b: Solaris */
    typedef struct {
        uint8_t di_mode[2];     /* u16 */
        uint8_t di_nlink[2];    /* s16 */
        uint8_t f1[4];
        uint8_t di_size[8];     /* u64 */
        uint8_t di_atime[4];    /* s32 */
        uint8_t f2[4];
        uint8_t di_mtime[4];    /* s32 */
        uint8_t f3[4];
        uint8_t di_ctime[4];    /* s32 */
        uint8_t f4[4];
        uint8_t di_db[12][4];   /* s32 */
        uint8_t di_ib[3][4];    /* s32 */
        uint8_t f5[16];
        uint8_t di_uid[4];      /* u32 */
        uint8_t di_gid[4];      /* u32 */
        uint8_t f6[4];
    } ffs_inode1b;

    typedef struct {
        uint8_t di_mode[2];     /* u16 */
        uint8_t di_nlink[2];    /* s16 */
        uint8_t di_uid[4];
        uint8_t di_gid[4];
        uint8_t di_blksize[4];  /* u32 inode block size */
        uint8_t di_size[8];     /* u64 */
        uint8_t di_blocks[8];   /* u64 - bytes held */
        uint8_t di_atime[8];    /* s64 */
        uint8_t di_mtime[8];    /* s64 */
        uint8_t di_ctime[8];    /* s64 */
        uint8_t di_crtime[8];   /* s64 */
        uint8_t di_mtimensec[4];        /* s32 */
        uint8_t di_atimensec[4];
        uint8_t di_ctimensec[4];
        uint8_t di_crtimensec[4];
        uint8_t di_gen[4];      /* s32 generation number */
        uint8_t di_kflags[4];   /* u32 kernel flags */
        uint8_t di_flags[4];    /* u32 flags */
        uint8_t di_extsize[4];  /* s32 size of ext attributes block */
        uint8_t di_extb[2][8];  /* Address of ext attribute blocks */
        uint8_t di_db[12][8];   /* s32 */
        uint8_t di_ib[3][8];    /* s32 */
        uint8_t f2[24];         /* s32 */
    } ffs_inode2;

    typedef struct {
        union {
            ffs_inode1 in1;
            ffs_inode1b in1b;
            ffs_inode2 in2;
        } in;
    } ffs_inode;

#define FFS_IN_FMT       0170000        /* Mask of file type. */
#define FFS_IN_FIFO      0010000        /* Named pipe (fifo). */
#define FFS_IN_CHR       0020000        /* Character device. */
#define FFS_IN_DIR       0040000        /* Directory file. */
#define FFS_IN_BLK       0060000        /* Block device. */
#define FFS_IN_REG       0100000        /* Regular file. */
#define FFS_IN_LNK       0120000        /* Symbolic link. */
#define FFS_IN_SHAD		 0130000        /* SOLARIS ONLY */
#define FFS_IN_SOCK      0140000        /* UNIX domain socket. */
#define FFS_IN_WHT       0160000        /* Whiteout. */

#define FFS_IN_ISUID   0004000
#define FFS_IN_ISGID   0002000
#define FFS_IN_ISVTX   0001000
#define FFS_IN_IRUSR   0000400
#define FFS_IN_IWUSR   0000200
#define FFS_IN_IXUSR   0000100
#define FFS_IN_IRGRP   0000040
#define FFS_IN_IWGRP   0000020
#define FFS_IN_IXGRP   0000010
#define FFS_IN_IROTH   0000004
#define FFS_IN_IWOTH   0000002
#define FFS_IN_IXOTH   0000001


    typedef struct {
        uint8_t reclen[4];
        uint8_t nspace;
        uint8_t contpad;
        uint8_t nlen;
        uint8_t name[1];        /* of length nlen and padded so contents are on 8-byte boundary */

    } ffs_extattr;

#define FFS_ATTR_CONT(x)	\
  ((((x) + 7 + 7) / 8) * 2)


/*
 * Directory Entries
 */
/* ffs_dentry1: new OpenBSD & FreeBSD etc. */
    typedef struct {
        uint8_t d_ino[4];       /* u32 */
        uint8_t d_reclen[2];    /* u16 */
        uint8_t d_type;         /* u8 */
        uint8_t d_namlen;       /* u8 */
        char d_name[256];
    } ffs_dentry1;

/* type field values */
#define FFS_DT_UNKNOWN   0
#define FFS_DT_FIFO      1
#define FFS_DT_CHR       2
#define FFS_DT_DIR       4
#define FFS_DT_BLK       6
#define FFS_DT_REG       8
#define FFS_DT_LNK      10
#define FFS_DT_SOCK     12
#define FFS_DT_WHT      14

/* ffs_dentry2: Solaris and old xBSDs (no type field) */
    typedef struct {
        uint8_t d_ino[4];       /* u32 */
        uint8_t d_reclen[2];    /* u16 */
        uint8_t d_namlen[2];    /* u16 */
        char d_name[256];
    } ffs_dentry2;


#define FFS_DIRSIZ_lcl(len) \
    ((len + 8 + 3) & ~(3))








/* Return the base fragment for group c
*/
#define cgbase_lcl(fsi, fs, c)	\
	((TSK_DADDR_T)(tsk_gets32(fsi->endian, (fs)->cg_frag_num) * (c)))


/* Macros to calc the locations of structures in cyl groups */

#define cgstart_lcl(fsi, fs, c)                          \
	((TSK_DADDR_T)((tsk_getu32((fsi)->endian, (fs)->magic) == UFS2_FS_MAGIC) ? \
	(cgbase_lcl(fsi, fs, c)) :  \
	(cgbase_lcl(fsi, fs, c) + tsk_gets32((fsi)->endian, (fs)->cg_delta) * \
	 ((c) & ~(tsk_gets32((fsi)->endian, (fs)->cg_cyc_mask)))) ))

/* cyl grp block */
#define cgtod_lcl(fsi, fs, c)	\
	((TSK_DADDR_T)(cgstart_lcl(fsi, fs, c) + tsk_gets32(fsi->endian, (fs)->gd_off)))

/* Offset to inode table in cylinder group */
#define cgimin_lcl(fsi, fs, c)	\
	((TSK_DADDR_T)(cgstart_lcl(fsi, fs, c) + tsk_gets32(fsi->endian, (fs)->ino_off)))

/* 1st data  block in cyl grp*/
#define cgdmin_lcl(fsi, fs, c)   \
	((TSK_DADDR_T)(cgstart_lcl(fsi, fs, c) + tsk_gets32(fsi->endian, (fs)->dat_off)))

/* super blk in cyl grp*/
#define cgsblock_lcl(fsi, fs, c) 	\
	((TSK_DADDR_T)(cgstart_lcl(fsi, fs, c) + tsk_gets32(fsi->endian, (fs)->sb_off)))

/* original:
** blkstofrags(fs, blks)  
**    ((blks) << (fs)->fs_fragshift)
*/
#define blkstofrags_lcl(fsi, fs, blks)  \
    ((blks) << tsk_gets32(fsi->endian, (fs)->fs_fragshift))

/* original:
** itod(fs, x) \
**      ((TSK_DADDR_T)(cgimin(fs, itog(fs, x)) + \
**      (blkstofrags((fs), (((x)%(ulong_t)(fs)->cg_inode_num)/(ulong_t)INOPB(fs))))))
*/
#define itod_lcl(fsi, fs, x) \
      ((TSK_DADDR_T)(cgimin_lcl(fsi, fs, itog_lcl(fsi, fs, x)) + \
      (blkstofrags_lcl(fsi, (fs), (((x)%(TSK_DADDR_T)tsk_gets32(fsi->endian, (fs)->cg_inode_num))/ \
	  (TSK_DADDR_T)tsk_gets32(fsi->endian, (fs)->fs_inopb))))))

/* original:
** itoo(fs, x) ((x) % (uint32_t)INOPB(fs))
*/
#define itoo_lcl(fsi, fs, x) 	\
	((x) % (uint32_t)tsk_getu32(fsi->endian, (fs)->fs_inopb))

/* original:
** #define itog(fs, x)    ((x) / (fs)->fs_cg_inode_num)
*/
#define itog_lcl(fsi, fs, x)	\
	(FFS_GRPNUM_T)((x) / tsk_gets32(fsi->endian, (fs)->cg_inode_num))

/* original:
** dtog(fs, d) ((d) / (fs)->fs_cg_frag_num)
*/
#define dtog_lcl(fsi, fs, d)	\
	(FFS_GRPNUM_T)((d) / tsk_gets32(fsi->endian, (fs)->cg_frag_num))

#define cg_inosused_lcl(fsi, cgp)	\
	((uint8_t *)((uint8_t *)(cgp) + tsk_gets32(fsi->endian, (cgp)->cg_iusedoff)))

#define cg_blksfree_lcl(fsi, cgp) \
	((uint8_t *)((uint8_t *)(cgp) + tsk_gets32(fsi->endian, (cgp)->cg_freeoff)))




/*
 * Structure of a fast file system handle.
 */
    typedef struct {
        TSK_FS_INFO fs_info;    /* super class */
        union {
            ffs_sb1 *sb1;       /* super block buffer */
            ffs_sb2 *sb2;       /* super block buffer */
        } fs;

        /* lock protects itbl_buf, itbl_addr, grp_buf, grp_num, grp_addr */
        tsk_lock_t lock;

        char *itbl_buf;         ///< Cached inode block buffer (r/w shared - lock)
        TSK_DADDR_T itbl_addr;  ///< Address where inode block buf was read from (r/w shared - lock)

        char *grp_buf;          ///< Cached cylinder group buffer (r/w shared - lock)
        FFS_GRPNUM_T grp_num;   ///< Cyl grp num that is cached (r/w shared - lock)
        TSK_DADDR_T grp_addr;   ///< Address where cached cyl grp data was read from (r/w shared - lock)

        FFS_GRPNUM_T groups_count;      /* nr of descriptor group blocks */

        unsigned int ffsbsize_f;        /* num of frags in an FFS block */
        unsigned int ffsbsize_b;        /* size of an FFS block in bytes */
    } FFS_INFO;

    extern TSK_RETVAL_ENUM ffs_dir_open_meta(TSK_FS_INFO * a_fs,
        TSK_FS_DIR ** a_fs_dir, TSK_INUM_T a_addr);

#ifdef __cplusplus
}
#endif
#endif                          /* _FFS_H */
