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
 * \file tsk_fatxxfs.h
 * Contains the structures and function APIs for TSK FATXX (FAT12, FAT16,
 * FAT32) file system support.
 */

#ifndef _TSK_FATXXFS_H
#define _TSK_FATXXFS_H

#include "tsk_fs_i.h"
#include "tsk_fatfs.h"

/* Macro to combine the upper and lower 2-byte parts of the starting
 * cluster 
 */
#define FATXXFS_DENTRY_CLUST(fsi, de)	\
	(TSK_DADDR_T)((tsk_getu16(fsi->endian, de->startclust)) | (tsk_getu16(fsi->endian, de->highclust)<<16))

/* constants for first byte of name[] */
#define FATXXFS_SLOT_E5		0x05    /* actual value is 0xe5 */
#define FATXXFS_SLOT_DELETED	0xe5
#define FATXXFS_SLOT_EMPTY 0x00

/* Macro to test allocation status
 * Have seen FAT image that uses non-standard flags in the short name (00 00 -> unallocated, 20 00 -> allocated)
 */
#define FATXXFS_IS_DELETED(name, fatfs)	\
	(fatfs->subtype == TSK_FATFS_SUBTYPE_ANDROID_1) ? \
	((name[0] == 0) && (name[1] == 0)) : \
	(name[0] == FATXXFS_SLOT_DELETED) 

/* 
 *Return 1 if c is an valid character for a short file name 
 *
 * NOTE: 0x05 is allowed in name[0], and 0x2e (".") is allowed for name[0]
 * and name[1] and 0xe5 is allowed for name[0]
 */
#define FATXXFS_IS_83_NAME(c)		\
	((((c) < 0x20) || \
	  ((c) == 0x22) || \
	  (((c) >= 0x2a) && ((c) <= 0x2c)) || \
	  ((c) == 0x2e) || \
	  ((c) == 0x2f) || \
	  (((c) >= 0x3a) && ((c) <= 0x3f)) || \
	  (((c) >= 0x5b) && ((c) <= 0x5d)) || \
	  ((c) == 0x7c)) == 0)

// extensions are to be ascii / latin
#define FATXXFS_IS_83_EXT(c)		\
    (FATXXFS_IS_83_NAME((c)) && ((c) < 0x7f))

/* flags for lowercase field */
#define FATXXFS_CASE_LOWER_BASE	0x08    /* base is lower case */
#define FATXXFS_CASE_LOWER_EXT	0x10    /* extension is lower case */
#define FATXXFS_CASE_LOWER_ALL	0x18    /* both are lower */

/* flags for seq field */
#define FATXXFS_LFN_SEQ_FIRST	0x40    /* This bit is set for the first lfn entry */
#define FATXXFS_LFN_SEQ_MASK	0x3f    /* These bits are a mask for the decreasing
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

    } FATXXFS_SB;

    typedef struct {
        uint8_t magic1[4];      /* 41615252 */
        uint8_t f1[480];
        uint8_t magic2[4];      /* 61417272 */
        uint8_t freecnt[4];     /* free clusters 0xfffffffff if unknown */
        uint8_t nextfree[4];    /* next free cluster */
        uint8_t f2[12];
        uint8_t magic3[4];      /* AA550000 */
    } FATXXFS_FSINFO;

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
    } FATXXFS_DENTRY_LFN;

	extern uint8_t fatxxfs_open(FATFS_INFO *fatfs);

    extern int8_t fatxxfs_is_cluster_alloc(FATFS_INFO *fatfs, TSK_DADDR_T clust);

    extern uint8_t 
    fatxxfs_is_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_dentry, 
        FATFS_DATA_UNIT_ALLOC_STATUS_ENUM a_cluster_is_alloc, 
        uint8_t a_do_basic_tests_only);

    extern TSK_RETVAL_ENUM
    fatxxfs_dinode_copy(FATFS_INFO *a_fatfs, TSK_INUM_T a_inum, 
        FATFS_DENTRY *a_dentry, uint8_t a_cluster_is_alloc, TSK_FS_FILE *a_fs_file);

    extern uint8_t
    fatxxfs_inode_lookup(FATFS_INFO *a_fatfs, TSK_FS_FILE *a_fs_file,
        TSK_INUM_T a_inum);

    extern uint8_t 
    fatxxfs_istat_attr_flags(FATFS_INFO *a_fatfs, TSK_INUM_T a_inum, 
        FILE *a_hFile);

    extern uint8_t
    fatxxfs_inode_walk_should_skip_dentry(FATFS_INFO *a_fatfs, TSK_INUM_T a_inum,
        FATFS_DENTRY *a_dentry, unsigned int a_selection_flags, 
        int a_cluster_is_alloc);

    extern TSK_RETVAL_ENUM
    fatxxfs_dent_parse_buf(FATFS_INFO * fatfs, TSK_FS_DIR * a_fs_dir, char *buf,
        TSK_OFF_T len, TSK_DADDR_T * addrs);

#ifdef __cplusplus
}
#endif

#endif
