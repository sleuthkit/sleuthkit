/*
** The Sleuth Kit
**
** Copyright (c) 2013 Basis Technology Corp.  All rights reserved
** Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
**
** This software is distributed under the Common Public License 1.0
**
*/

/**
 * \file tsk_fatfs.h
 * Contains the structures and function APIs for TSK FAT (FAT12, FAT16, FAT32, 
 * exFAT) file system support.
 */

#ifndef _TSK_FATFS_H
#define _TSK_FATFS_H

#include "tsk_fs_i.h"

/**
 * \internal
 *
 * Per TSK convention, FAT file system functions return integer 0 on success
 * and integer 1 on failure. 
 */
#define FATFS_OK 0

/**
 * \internal
 *
 * Per TSK convention, FAT file system functions return integer 0 on success
 * and integer 1 on failure. 
 */
#define FATFS_FAIL 1

#define FATFS_FS_MAGIC	0xaa55

#define FATFS_FIRST_CLUSTER_ADDR 2

#define FATFS_FIRSTINO	2
#define FATFS_ROOTINO	2       /* location of root directory inode */
#define FATFS_FIRST_NORMINO 3

#define FATFS_ROOTNAME "$ROOT"
#define FATFS_MBRNAME  "$MBR"
#define FATFS_FAT1NAME "$FAT1"
#define FATFS_FAT2NAME "$FAT2"

#define FATFS_NUM_VIRT_FILES(fatfs) \
    (fatfs->numfat + 2)

/* size of FAT to read into FATFS_INFO each time */
/* This must be at least 1024 bytes or else fat12 will get messed up */
#define FATFS_FAT_CACHE_N		4       // number of caches
#define FATFS_FAT_CACHE_B		4096

#define FATFS_MASTER_BOOT_RECORD_SIZE 512

/** 
 * Directory entries for all FAT file systems are currently 32 bytes long.
 */
#define FATFS_DENTRY_SIZE 32

/* MASK values for FAT entries */
#define FATFS_12_MASK	0x00000fff
#define FATFS_16_MASK	0x0000ffff
#define FATFS_32_MASK	0x0fffffff
#define EXFATFS_MASK	0x0fffffff

#define FATFS_FILE_CONTENT_LEN sizeof(TSK_DADDR_T)      // we will store the starting cluster

/* flags for attributes field */
#define FATFS_ATTR_NORMAL	0x00    /* normal file */
#define FATFS_ATTR_READONLY	0x01    /* file is readonly */
#define FATFS_ATTR_HIDDEN	0x02    /* file is hidden */
#define FATFS_ATTR_SYSTEM	0x04    /* file is a system file */
#define FATFS_ATTR_VOLUME	0x08    /* entry is a volume label */
#define FATFS_ATTR_DIRECTORY	0x10    /* entry is a directory name */
#define FATFS_ATTR_ARCHIVE	0x20    /* file is new or modified */
#define FATFS_ATTR_LFN		0x0f    /* A long file name entry */
#define FATFS_ATTR_ALL		0x3f    /* all flags set */

#define FATFS_CLUST_2_SECT(fatfs, c)	\
	(TSK_DADDR_T)(fatfs->firstclustsect + ((((c) & fatfs->mask) - 2) * fatfs->csize))

#define FATFS_SECT_2_CLUST(fatfs, s)	\
	(TSK_DADDR_T)(2 + ((s)  - fatfs->firstclustsect) / fatfs->csize)

/* given an inode address, determine in which sector it is located
 * i must be larger than 3 (2 is the root and it doesn't have a sector)
 */
#define FATFS_INODE_2_SECT(fatfs, i)    \
    (TSK_DADDR_T)((i - FATFS_FIRST_NORMINO)/(fatfs->dentry_cnt_se) + fatfs->firstdatasect)

#define FATFS_INODE_2_OFF(fatfs, i)     \
    (size_t)(((i - FATFS_FIRST_NORMINO) % fatfs->dentry_cnt_se) * sizeof(FATFS_DENTRY))

/* given a sector IN THE DATA AREA, return the base inode for it */
#define FATFS_SECT_2_INODE(fatfs, s)    \
    (TSK_INUM_T)((s - fatfs->firstdatasect) * fatfs->dentry_cnt_se + FATFS_FIRST_NORMINO)

/* Constants for the FAT entry */
#define FATFS_UNALLOC	0
#define FATFS_BAD		0x0ffffff7
#define FATFS_EOFS		0x0ffffff8
#define FATFS_EOFE		0x0fffffff

/* macro to identify if the FAT value is End of File
 * returns 1 if it is and 0 if it is not 
 */
#define FATFS_ISEOF(val, mask)	\
	((val >= (FATFS_EOFS & mask)) && (val <= (FATFS_EOFE)))

#define FATFS_ISBAD(val, mask) \
	((val) == (FATFS_BAD & mask))

#define FATFS_SEC_MASK		0x1f    /* number of seconds div by 2 */
#define FATFS_SEC_SHIFT		0
#define FATFS_SEC_MIN		0
#define FATFS_SEC_MAX		30
#define FATFS_MIN_MASK		0x7e0   /* number of minutes 0-59 */
#define FATFS_MIN_SHIFT		5
#define FATFS_MIN_MIN		0
#define FATFS_MIN_MAX		59
#define FATFS_HOUR_MASK		0xf800  /* number of hours 0-23 */
#define FATFS_HOUR_SHIFT	11
#define FATFS_HOUR_MIN		0
#define FATFS_HOUR_MAX		23

/* return 1 if x is a valid FAT time */
#define FATFS_ISTIME(x)	\
	(((((x & FATFS_SEC_MASK) >> FATFS_SEC_SHIFT) > FATFS_SEC_MAX) || \
	  (((x & FATFS_MIN_MASK) >> FATFS_MIN_SHIFT) > FATFS_MIN_MAX) || \
	  (((x & FATFS_HOUR_MASK) >> FATFS_HOUR_SHIFT) > FATFS_HOUR_MAX) ) == 0)

#define FATFS_DAY_MASK		0x1f    /* day of month 1-31 */
#define FATFS_DAY_SHIFT		0
#define FATFS_DAY_MIN		1
#define FATFS_DAY_MAX		31
#define FATFS_MON_MASK		0x1e0   /* month 1-12 */
#define FATFS_MON_SHIFT		5
#define FATFS_MON_MIN		1
#define FATFS_MON_MAX		12
#define FATFS_YEAR_MASK		0xfe00  /* year, from 1980 0-127 */
#define FATFS_YEAR_SHIFT	9
#define FATFS_YEAR_MIN		0
#define FATFS_YEAR_MAX		127

/* return 1 if x is a valid FAT date */
#define FATFS_ISDATE(x)	\
	 (((((x & FATFS_DAY_MASK) >> FATFS_DAY_SHIFT) > FATFS_DAY_MAX) || \
	   (((x & FATFS_DAY_MASK) >> FATFS_DAY_SHIFT) < FATFS_DAY_MIN) || \
	   (((x & FATFS_MON_MASK) >> FATFS_MON_SHIFT) > FATFS_MON_MAX) || \
	   (((x & FATFS_MON_MASK) >> FATFS_MON_SHIFT) < FATFS_MON_MIN) || \
	   (((x & FATFS_YEAR_MASK) >> FATFS_YEAR_SHIFT) > FATFS_YEAR_MAX) ) == 0)

/**
 * \internal
 * Buffer size for conversion of exFAT UTF-16 strings to UTF-8 strings.
 */
#define FATFS_MAXNAMLEN_UTF8	1024

#ifdef __cplusplus
extern "C" {
#endif
    typedef struct FATFS_INFO FATFS_INFO; 

    enum FATFS_DATA_UNIT_ALLOC_STATUS_ENUM {
        FATFS_DATA_UNIT_ALLOC_STATUS_UNALLOC = 0,
        FATFS_DATA_UNIT_ALLOC_STATUS_ALLOC = 1,
        FATFS_DATA_UNIT_ALLOC_STATUS_UNKNOWN = 2
    };
    typedef enum FATFS_DATA_UNIT_ALLOC_STATUS_ENUM FATFS_DATA_UNIT_ALLOC_STATUS_ENUM;

	typedef enum {
		TSK_FATFS_SUBTYPE_SPEC = 0,
		TSK_FATFS_SUBTYPE_ANDROID_1 = 1
	} TSK_FATFS_SUBTYPE_ENUM;

    typedef struct
    {
        uint8_t data[FATFS_MASTER_BOOT_RECORD_SIZE - 2];
        uint8_t magic[2];
    } FATFS_MASTER_BOOT_RECORD;

	/** 
     * Generic directory entry structure for FAT file systems.
     */
    typedef struct {
        uint8_t data[FATFS_DENTRY_SIZE];
    } FATFS_DENTRY;

    /* 
     * Internal TSK_FS_INFO derived structure for FATXX and exFAT file systems.  
     */
    struct FATFS_INFO {
        TSK_FS_INFO fs_info;    /* super class */

        /* FAT cache */
        /* cache_lock protects fatc_buf, fatc_addr, fatc_ttl */
        tsk_lock_t cache_lock;
        char fatc_buf[FATFS_FAT_CACHE_N][FATFS_FAT_CACHE_B];        //r/w shared - lock
        TSK_DADDR_T fatc_addr[FATFS_FAT_CACHE_N];     // r/w shared - lock
        uint8_t fatc_ttl[FATFS_FAT_CACHE_N];  //r/w shared - lock

        /* First sector of FAT */
        TSK_DADDR_T firstfatsect;

        /* First sector after FAT  - For TSK_FS_INFO_TYPE_FAT_12 and TSK_FS_INFO_TYPE_FAT_16, this is where the
         * root directory entries are.  For TSK_FS_INFO_TYPE_FAT_32, this is the the first 
         * cluster */
        TSK_DADDR_T firstdatasect;

        /* The sector number were cluster 2 (the first one) is
         * for TSK_FS_INFO_TYPE_FAT_32, it will be the same as firstdatasect, but for TSK_FS_INFO_TYPE_FAT_12 & 16
         * it will be the first sector after the Root directory  */
        TSK_DADDR_T firstclustsect;

        /* size of data area in clusters, starting at firstdatasect */
        TSK_DADDR_T clustcnt;

        TSK_DADDR_T lastclust;

        /* sector where the root directory is located */
        TSK_DADDR_T rootsect;

        uint32_t dentry_cnt_se; /* max number of dentries per sector */
        uint32_t dentry_cnt_cl; /* max number of dentries per cluster */

        uint16_t ssize;         /* size of sectors in bytes */
        uint16_t ssize_sh;      /* power of 2 for size of sectors.  >> to divide by sector size.  << to multiply by sector size */
        uint32_t csize;          /* size of clusters in sectors */
        uint8_t numfat;         /* number of fat tables */
        uint32_t sectperfat;    /* sectors per fat table */
        uint16_t numroot;       /* number of 32-byte dentries in root dir */
        uint32_t mask;          /* the mask to use for the sectors */

        TSK_INUM_T mbr_virt_inum;
        TSK_INUM_T fat1_virt_inum;
        TSK_INUM_T fat2_virt_inum;

        tsk_lock_t dir_lock;    //< Lock that protects inum2par.
        void *inum2par;         //< Maps subfolder metadata address to parent folder metadata addresses.

		char boot_sector_buffer[FATFS_MASTER_BOOT_RECORD_SIZE];
        int using_backup_boot_sector;

		TSK_FATFS_SUBTYPE_ENUM subtype; // Identifies any variations on the standard FAT format

        int8_t (*is_cluster_alloc)(FATFS_INFO *fatfs, TSK_DADDR_T clust);

        uint8_t (*is_dentry)(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_dentry, 
            FATFS_DATA_UNIT_ALLOC_STATUS_ENUM a_cluster_is_alloc, 
            uint8_t a_do_basic_tests_only);

        uint8_t (*inode_lookup)(FATFS_INFO *a_fatfs, TSK_FS_FILE *a_fs_file,
            TSK_INUM_T a_inum);

        uint8_t (*inode_walk_should_skip_dentry)(FATFS_INFO *a_fatfs, 
            TSK_INUM_T a_inum, FATFS_DENTRY *a_dentry, 
            unsigned int a_selection_flags, int a_cluster_is_alloc);

        uint8_t (*istat_attr_flags) (FATFS_INFO *a_fatfs, TSK_INUM_T a_inum,  FILE *a_hFile);

        TSK_RETVAL_ENUM (*dent_parse_buf)(FATFS_INFO *a_fatfs, 
            TSK_FS_DIR *a_fs_dir, char *a_buf, TSK_OFF_T a_buf_len, 
            TSK_DADDR_T *a_sector_addrs);

        TSK_RETVAL_ENUM (*dinode_copy)(FATFS_INFO *a_fatfs, TSK_INUM_T a_inum, 
            FATFS_DENTRY *a_dentry, uint8_t a_cluster_is_alloc, TSK_FS_FILE *a_fs_file);

        struct {
            uint64_t first_sector_of_alloc_bitmap;
            uint64_t length_of_alloc_bitmap_in_bytes;
        } EXFATFS_INFO;
	};

    extern uint8_t
    fatfs_inum_is_in_range(FATFS_INFO *a_fatfs, TSK_INUM_T a_inum);

    extern uint8_t
    fatfs_ptr_arg_is_null(void *ptr, const char *param_name, const char *func_name);

    extern uint8_t
    fatfs_inum_arg_is_in_range(FATFS_INFO *a_fatfs, TSK_INUM_T a_inum, const char *func_name);

    extern time_t fatfs_dos_2_unix_time(uint16_t date, uint16_t time, uint8_t timetens);

    extern uint32_t
    fatfs_dos_2_nanosec(uint8_t timetens);

    extern TSKConversionResult
    fatfs_utf16_inode_str_2_utf8(FATFS_INFO *a_fatfs, UTF16 *src, size_t src_len, UTF8 *dest, size_t dest_len, TSK_INUM_T a_inum, const char *a_desc);

    extern void fatfs_cleanup_ascii(char *);

	extern TSK_FS_INFO 
    *fatfs_open(TSK_IMG_INFO *a_img_info, TSK_OFF_T a_offset, TSK_FS_TYPE_ENUM a_ftype, uint8_t a_test);

    extern uint8_t
    fatfs_fscheck(TSK_FS_INFO *fs, FILE *hFile);

    extern int8_t fatfs_is_sectalloc(FATFS_INFO *, TSK_DADDR_T);

    extern uint8_t
    fatfs_block_walk(TSK_FS_INFO * fs, TSK_DADDR_T a_start_blk,
        TSK_DADDR_T a_end_blk, TSK_FS_BLOCK_WALK_FLAG_ENUM a_flags,
        TSK_FS_BLOCK_WALK_CB a_action, void *a_ptr);

    extern TSK_FS_BLOCK_FLAG_ENUM
    fatfs_block_getflags(TSK_FS_INFO * a_fs, TSK_DADDR_T a_addr);

    extern TSK_FS_ATTR_TYPE_ENUM
    fatfs_get_default_attr_type(const TSK_FS_FILE * a_file);

    extern uint8_t fatfs_make_data_runs(TSK_FS_FILE * a_fs_file);

    extern uint8_t fatfs_getFAT(FATFS_INFO * fatfs, TSK_DADDR_T clust,
        TSK_DADDR_T * value);

    extern uint8_t 
    fatfs_dir_buf_add(FATFS_INFO * fatfs, TSK_INUM_T par_inum, TSK_INUM_T dir_inum); 

    extern uint8_t
    fatfs_dir_buf_get(FATFS_INFO * fatfs, TSK_INUM_T dir_inum,
    TSK_INUM_T *par_inum);

    extern TSK_WALK_RET_ENUM
    fatfs_find_parent_act(TSK_FS_FILE * fs_file, const char *a_path, void *ptr);

    extern uint8_t
    fatfs_istat(TSK_FS_INFO * fs, TSK_FS_ISTAT_FLAG_ENUM istat_flags, FILE * hFile, TSK_INUM_T inum,
        TSK_DADDR_T numblock, int32_t sec_skew);

    extern uint8_t fatfs_inode_walk(TSK_FS_INFO * fs,
        TSK_INUM_T start_inum, TSK_INUM_T end_inum,
        TSK_FS_META_FLAG_ENUM a_flags, TSK_FS_META_WALK_CB a_action,
        void *a_ptr);

    extern uint8_t fatfs_inode_lookup(TSK_FS_INFO *a_fs,
        TSK_FS_FILE *a_fs_file, TSK_INUM_T a_inum);

    extern uint8_t fatfs_dentry_load(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_dentry, 
        TSK_INUM_T a_inum);

    extern TSK_RETVAL_ENUM
        fatfs_dir_open_meta(TSK_FS_INFO * a_fs, TSK_FS_DIR ** a_fs_dir,
        TSK_INUM_T a_addr);

    extern int fatfs_name_cmp(TSK_FS_INFO *, const char *, const char *);

    extern uint8_t fatfs_dir_buf_add(FATFS_INFO * fatfs,
        TSK_INUM_T par_inum, TSK_INUM_T dir_inum);

    extern void fatfs_cleanup_ascii(char *);
    extern void fatfs_dir_buf_free(FATFS_INFO * fatfs);

    extern uint8_t
    fatfs_jopen(TSK_FS_INFO * fs, TSK_INUM_T inum);

    extern uint8_t
    fatfs_jentry_walk(TSK_FS_INFO * fs, int a_flags,
        TSK_FS_JENTRY_WALK_CB a_action, void *a_ptr);

    extern uint8_t
    fatfs_jblk_walk(TSK_FS_INFO * fs, TSK_DADDR_T start, TSK_DADDR_T end,
        int a_flags, TSK_FS_JBLK_WALK_CB a_action, void *a_ptr);

    extern void fatfs_close(TSK_FS_INFO *fs);

#ifdef __cplusplus
}
#endif

#endif
