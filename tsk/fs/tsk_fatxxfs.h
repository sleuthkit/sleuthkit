/*
** The Sleuth Kit 
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2003-2013 Brian Carrier.  All rights reserved
**
** TASK
** Copyright (c) 2002 @stake Inc.  All rights reserved
**
** This software is distributed under the Common Public License 1.0
**
*/

/**
 * \file fatxxfs.h
 * Contains the structures and function APIs for TSK FATXX (FAT12, FAT16,
 * FAT32) file system support.
 */

#ifndef _TSK_FATXXFS_H
#define _TSK_FATXXFS_H

#include "tsk_fs_i.h"
#include "tsk_fatfs.h"

/**
 * RJCTODO: comment 
 */
#define FATXXFS_INODE_BUFFER_SIZE FATFS_DENTRY_SIZE

#define FATFS_ROOTNAME   "$ROOT"

#define FATFS_MBRINO(fs_info) \
    (TSK_FS_ORPHANDIR_INUM(fs_info) - 3)        // inode for master boot record "special file"
#define FATFS_MBRNAME   "$MBR"

#define FATFS_FAT1INO(fs_info) \
    (TSK_FS_ORPHANDIR_INUM(fs_info) - 2)        // inode for FAT1 "special file"
#define FATFS_FAT1NAME  "$FAT1"

#define FATFS_FAT2INO(fs_info) \
    (TSK_FS_ORPHANDIR_INUM(fs_info) - 1)        // inode for FAT2 "special file"
#define FATFS_FAT2NAME  "$FAT2"

#define FATFS_SBOFF		0
#define FATFS_FS_MAGIC	0xaa55
#define FATFS_MAXNAMLEN	256
#define FATFS_MAXNAMLEN_UTF8	1024

/* Macro to combine the upper and lower 2-byte parts of the starting
 * cluster 
 */
#define FATFS_DENTRY_CLUST(fsi, de)	\
	(TSK_DADDR_T)((tsk_getu16(fsi->endian, de->startclust)) | (tsk_getu16(fsi->endian, de->highclust)<<16))

/* constants for first byte of name[] */
#define FATFS_SLOT_EMPTY	0x00
#define FATFS_SLOT_E5		0x05    /* actual value is 0xe5 */
#define FATFS_SLOT_DELETED	0xe5

/* 
 *Return 1 if c is an valid charactor for a short file name 
 *
 * NOTE: 0x05 is allowed in name[0], and 0x2e (".") is allowed for name[0]
 * and name[1] and 0xe5 is allowed for name[0]
 */

#define FATFS_IS_83_NAME(c)		\
	((((c) < 0x20) || \
	  ((c) == 0x22) || \
	  (((c) >= 0x2a) && ((c) <= 0x2c)) || \
	  ((c) == 0x2e) || \
	  ((c) == 0x2f) || \
	  (((c) >= 0x3a) && ((c) <= 0x3f)) || \
	  (((c) >= 0x5b) && ((c) <= 0x5d)) || \
	  ((c) == 0x7c)) == 0)

// extensions are to be ascii / latin
#define FATFS_IS_83_EXT(c)		\
    (FATFS_IS_83_NAME((c)) && ((c) < 0x7f))

/* flags for lowercase field */
#define FATFS_CASE_LOWER_BASE	0x08    /* base is lower case */
#define FATFS_CASE_LOWER_EXT	0x10    /* extension is lower case */
#define FATFS_CASE_LOWER_ALL	0x18    /* both are lower */

/* flags for seq field */
#define FATFS_LFN_SEQ_FIRST	0x40    /* This bit is set for the first lfn entry */
#define FATFS_LFN_SEQ_MASK	0x3f    /* These bits are a mask for the decreasing
                                         * sequence number for the entries */
#ifdef __cplusplus
extern "C" {
#endif

	/*
	 * Boot sector structure for FATXX file systems (TSK_FS_INFO_TYPE_FAT_12, 
	 * TSK_FS_INFO_TYPE_FAT_16, and TSK_FS_INFO_TYPE_FAT_32).
	 */
    typedef struct {
        uint8_t f1[3];
        char oemname[8];
        uint8_t ssize[2];       /* sector size in bytes */
        uint8_t csize;          /* cluster size in sectors */
        uint8_t reserved[2];    /* number of reserved sectors for boot sectors */
        uint8_t numfat;         /* Number of FATs */
        uint8_t numroot[2];     /* Number of Root dentries */
        uint8_t sectors16[2];   /* number of sectors in FS */
        uint8_t f2[1];
        uint8_t sectperfat16[2];        /* size of FAT */
        uint8_t f3[4];
        uint8_t prevsect[4];    /* number of sectors before FS partition */
        uint8_t sectors32[4];   /* 32-bit value of number of FS sectors */

        /* The following are different for fat12/fat16 and fat32 */
        union {
            struct {
                uint8_t f5[3];
                uint8_t vol_id[4];
                uint8_t vol_lab[11];
                uint8_t fs_type[8];
                uint8_t f6[448];
            } f16;
            struct {
                uint8_t sectperfat32[4];
                uint8_t ext_flag[2];
                uint8_t fs_ver[2];
                uint8_t rootclust[4];   /* cluster where root directory is stored */
                uint8_t fsinfo[2];      /* TSK_FS_INFO Location */
                uint8_t bs_backup[2];   /* sector of backup of boot sector */
                uint8_t f5[12];
                uint8_t drvnum;
                uint8_t f6[2];
                uint8_t vol_id[4];
                uint8_t vol_lab[11];
                uint8_t fs_type[8];
                uint8_t f7[420];
            } f32;
        } a;

        uint8_t magic[2];       /* MAGIC for all versions */

    } fatfs_sb; //RJCTODO: Change name

    typedef struct {
        uint8_t magic1[4];      /* 41615252 */
        uint8_t f1[480];
        uint8_t magic2[4];      /* 61417272 */
        uint8_t freecnt[4];     /* free clusters 0xfffffffff if unknown */
        uint8_t nextfree[4];    /* next free cluster */
        uint8_t f2[12];
        uint8_t magic3[4];      /* AA550000 */
    } fatfs_fsinfo;


	/* directory entry short name structure */
    typedef struct {
        uint8_t name[8];
        uint8_t ext[3];
        uint8_t attrib;
        uint8_t lowercase;
        uint8_t ctimeten;       /* create times (ctimeten is 0-199) */
        uint8_t ctime[2];
        uint8_t cdate[2];
        uint8_t adate[2];       /* access time */
        uint8_t highclust[2];
        uint8_t wtime[2];       /* last write time */
        uint8_t wdate[2];
        uint8_t startclust[2];
        uint8_t size[4];
    } FATXXFS_DENTRY;

	/* 
	 * Long file name support for windows 
	 *
	 * Contents of this are in UNICODE, not ASCII 
	 */
    typedef struct {
        uint8_t seq;
        uint8_t part1[10];
        uint8_t attributes;
        uint8_t reserved1;
        uint8_t chksum;
        uint8_t part2[12];
        uint8_t reserved2[2];
        uint8_t part3[4];
    } fatfs_dentry_lfn;

	// RJCTODO: Comment
	extern int fatxxfs_open(FATFS_INFO *fatfs);

    // RJCTODO: Add comment
    extern int8_t fatxxfs_is_clust_alloc(FATFS_INFO *fatfs, TSK_DADDR_T clust);

    extern uint8_t fatxxfs_is_dentry(FATFS_INFO *fatfs, FATFS_DENTRY *a_dentry, uint8_t a_basic);

    extern TSK_RETVAL_ENUM
        fatfs_dir_open_meta(TSK_FS_INFO * a_fs, TSK_FS_DIR ** a_fs_dir,
        TSK_INUM_T a_addr);

    extern int fatfs_name_cmp(TSK_FS_INFO *, const char *, const char *);
    extern uint8_t fatfs_dir_buf_add(FATFS_INFO * fatfs,
        TSK_INUM_T par_inum, TSK_INUM_T dir_inum);
    extern void fatfs_dir_buf_free(FATFS_INFO *fatfs);

    // RJCTODO: Update
    /**
     * \internal
     * Copy the contents of a raw directry entry into a TSK_FS_INFO structure.
     *
     * @param a_fatfs File system that directory entry is from.
     * @param a_fs_meta Generic inode structure to copy data into.
     * @param a_in Generic directory entry to copy data from.
     * @param a_sect Sector address where directory entry is from -- used
     * to determine allocation status.
     * @param a_inum Address of the inode.
     *
     * @returns 1 on error and 0 on success.  Errors should only occur for
     * Unicode conversion problems and when this occurs the name will be
     * NULL terminated (but with unknown contents).
     *
     */
    extern TSK_RETVAL_ENUM
    fatxxfs_dinode_copy(FATFS_INFO *a_fatfs, TSK_FS_META *a_fs_meta,
        FATFS_DENTRY *a_dentry, TSK_DADDR_T a_sect, TSK_INUM_T a_inum);

    extern uint8_t
    fatxxfs_inode_lookup(FATFS_INFO *a_fatfs, TSK_FS_FILE *a_fs_file,
        TSK_INUM_T a_inum);

    extern uint8_t 
    fatxxfs_istat_attr_flags(FATFS_INFO *a_fatfs, TSK_INUM_T a_inum, 
        FILE *a_hFile);

#ifdef __cplusplus
}
#endif

#endif
