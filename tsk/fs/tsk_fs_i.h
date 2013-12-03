/*
** The Sleuth Kit 
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2003-2011 Brian Carrier.  All rights reserved
**
** TASK
** Copyright (c) 2002 @stake Inc.  All rights reserved
** 
** Copyright (c) 1997,1998,1999, International Business Machines          
** Corporation and others. All Rights Reserved.
*/

/* LICENSE
* .ad
* .fi
*	This software is distributed under the IBM Public License.
* AUTHOR(S)
*	Wietse Venema
*	IBM T.J. Watson Research
*	P.O. Box 704
*	Yorktown Heights, NY 10598, USA
--*/

/**
 * \file tsk_fs_i.h
 * Contains the internal library definitions for the file system functions.  This should
 * be included by the code in the file system library.
 */

#ifndef _TSK_FS_I_H
#define _TSK_FS_I_H

// Include the other internal TSK header files
#include "tsk/base/tsk_base_i.h"
#include "tsk/img/tsk_img_i.h"
#include "tsk/vs/tsk_vs_i.h"

// Include the external file 
#include "tsk_fs.h"

#include <time.h>
#include <locale.h>

#ifdef __cplusplus
extern "C" {

#endif                          /*  */

#if !defined (TSK_WIN32)
#include <sys/fcntl.h>
#include <sys/time.h>
#endif                          /*  */

// set to 1 to open HFS+ file systems -- which is not fully tested
#ifndef TSK_USE_HFS
#define TSK_USE_HFS 1
#endif                          /*  */

#ifndef NBBY
#define NBBY 8
#endif                          /*  */

#ifndef isset
#define isset(a,i)	(((uint8_t *)(a))[(i)/NBBY] &  (1<<((i)%NBBY)))
#endif                          /*  */

#ifndef setbit
#define setbit(a,i)     (((uint8_t *)(a))[(i)/NBBY] |= (1<<((i)%NBBY)))
#endif                          /*  */

/* Data structure and action to internally load a file */
    typedef struct {
        char *base;
        char *cur;
        size_t total;
        size_t left;
    } TSK_FS_LOAD_FILE;
    extern TSK_WALK_RET_ENUM tsk_fs_load_file_action(TSK_FS_FILE *
        fs_file, TSK_OFF_T, TSK_DADDR_T, char *, size_t,
        TSK_FS_BLOCK_FLAG_ENUM, void *);

    /* BLOCK */
    extern TSK_FS_BLOCK *tsk_fs_block_alloc(TSK_FS_INFO * fs);
    extern int tsk_fs_block_set(TSK_FS_INFO * fs, TSK_FS_BLOCK * fs_block,
        TSK_DADDR_T a_addr, TSK_FS_BLOCK_FLAG_ENUM a_flags, char *a_buf);

    /* FS_DATA */
    extern TSK_FS_ATTR *tsk_fs_attr_alloc(TSK_FS_ATTR_FLAG_ENUM);
    extern void tsk_fs_attr_free(TSK_FS_ATTR *);
    extern void tsk_fs_attr_clear(TSK_FS_ATTR *);
    extern uint8_t tsk_fs_attr_set_str(TSK_FS_FILE *, TSK_FS_ATTR *,
        const char *, TSK_FS_ATTR_TYPE_ENUM, uint16_t, void *, size_t);
    extern uint8_t tsk_fs_attr_set_run(TSK_FS_FILE *,
        TSK_FS_ATTR * a_fs_attr, TSK_FS_ATTR_RUN * data_run_new,
        const char *name, TSK_FS_ATTR_TYPE_ENUM type, uint16_t id,
        TSK_OFF_T size, TSK_OFF_T initsize, TSK_OFF_T allocsize,
        TSK_FS_ATTR_FLAG_ENUM flags, uint32_t compsize);
    extern uint8_t tsk_fs_attr_add_run(TSK_FS_INFO * fs,
        TSK_FS_ATTR * a_fs_attr, TSK_FS_ATTR_RUN * data_run_new);
    extern void tsk_fs_attr_append_run(TSK_FS_INFO * fs,
        TSK_FS_ATTR * a_fs_attr, TSK_FS_ATTR_RUN * a_data_run);

    /* FS_DATALIST */
    extern TSK_FS_ATTRLIST *tsk_fs_attrlist_alloc();
    extern void tsk_fs_attrlist_free(TSK_FS_ATTRLIST *);
    extern uint8_t tsk_fs_attrlist_add(TSK_FS_ATTRLIST *, TSK_FS_ATTR *);
    extern TSK_FS_ATTR *tsk_fs_attrlist_getnew(TSK_FS_ATTRLIST *,
        TSK_FS_ATTR_FLAG_ENUM a_atype);
    extern void tsk_fs_attrlist_markunused(TSK_FS_ATTRLIST *);
    extern const TSK_FS_ATTR *tsk_fs_attrlist_get(const TSK_FS_ATTRLIST *,
        TSK_FS_ATTR_TYPE_ENUM);
    extern const TSK_FS_ATTR *tsk_fs_attrlist_get_id(const TSK_FS_ATTRLIST
        *, TSK_FS_ATTR_TYPE_ENUM, uint16_t);
    extern const TSK_FS_ATTR *tsk_fs_attrlist_get_name_type(const
        TSK_FS_ATTRLIST *, TSK_FS_ATTR_TYPE_ENUM, const char *);
    extern const TSK_FS_ATTR *tsk_fs_attrlist_get_idx(const
        TSK_FS_ATTRLIST *, int);
    extern int tsk_fs_attrlist_get_len(const TSK_FS_ATTRLIST *
        a_fs_attrlist);

    /* FS_DATA_RUN */
    extern TSK_FS_ATTR_RUN *tsk_fs_attr_run_alloc();
    extern void tsk_fs_attr_run_free(TSK_FS_ATTR_RUN *);

    /* FS_META */
    extern TSK_FS_META *tsk_fs_meta_alloc(size_t);
    extern TSK_FS_META *tsk_fs_meta_realloc(TSK_FS_META *, size_t);
    extern void tsk_fs_meta_reset(TSK_FS_META *);
    extern void tsk_fs_meta_close(TSK_FS_META * fs_meta);

    /* FS_FILE */
    extern TSK_FS_FILE *tsk_fs_file_alloc(TSK_FS_INFO *);

    /* FS_DIR */
    extern TSK_FS_DIR *tsk_fs_dir_alloc(TSK_FS_INFO * a_fs,
        TSK_INUM_T a_addr, size_t a_cnt);
    extern uint8_t tsk_fs_dir_realloc(TSK_FS_DIR * a_fs_dir, size_t a_cnt);
    extern uint8_t tsk_fs_dir_add(TSK_FS_DIR * a_fs_dir,
        const TSK_FS_NAME * a_fs_dent);
    extern void tsk_fs_dir_reset(TSK_FS_DIR * a_fs_dir);

    /* Orphan Directory Support */
    TSK_RETVAL_ENUM tsk_fs_dir_load_inum_named(TSK_FS_INFO * a_fs);
    uint8_t tsk_fs_dir_find_inum_named(TSK_FS_INFO * a_fs,
        TSK_INUM_T a_inum);
    extern uint8_t tsk_fs_dir_make_orphan_dir_meta(TSK_FS_INFO * a_fs,
        TSK_FS_META * a_fs_meta);
    extern uint8_t tsk_fs_dir_make_orphan_dir_name(TSK_FS_INFO * a_fs,
        TSK_FS_NAME * a_fs_name);
    extern TSK_RETVAL_ENUM tsk_fs_dir_find_orphans(TSK_FS_INFO * a_fs,
        TSK_FS_DIR * a_fs_dir);

    /* FS_DENT */
    extern TSK_FS_NAME *tsk_fs_name_alloc(size_t, size_t);
    extern uint8_t tsk_fs_name_realloc(TSK_FS_NAME *, size_t);
    extern void tsk_fs_name_free(TSK_FS_NAME *);
    extern void tsk_fs_name_print(FILE *, const TSK_FS_FILE *,
        const char *, TSK_FS_INFO *, const TSK_FS_ATTR *, uint8_t);
    extern void tsk_fs_name_print_long(FILE *, const TSK_FS_FILE *,
        const char *, TSK_FS_INFO *, const TSK_FS_ATTR *, uint8_t,
        int32_t);
    extern void tsk_fs_name_print_mac(FILE *, const TSK_FS_FILE *,
        const char *, const TSK_FS_ATTR * fs_attr, const char *, int32_t);
    extern void tsk_fs_name_print_mac_md5(FILE *, const TSK_FS_FILE *,
        const char *, const TSK_FS_ATTR * fs_attr, const char *, int32_t,
		const unsigned char *);
    extern uint8_t tsk_fs_name_copy(TSK_FS_NAME * a_fs_name_to,
        const TSK_FS_NAME * a_fs_name_from);
    extern void tsk_fs_name_reset(TSK_FS_NAME * a_fs_name);
    extern char *tsk_fs_time_to_str(time_t, char buf[128]);
    extern char *tsk_fs_time_to_str_subsecs(time_t, unsigned int subsecs,
        char buf[128]);

    /* Utilities */
    extern uint8_t tsk_fs_unix_make_data_run(TSK_FS_FILE * fs_file);
    extern TSK_FS_ATTR_TYPE_ENUM tsk_fs_unix_get_default_attr_type(const
        TSK_FS_FILE * a_file);
    extern int tsk_fs_unix_name_cmp(TSK_FS_INFO * a_fs_info,
        const char *s1, const char *s2);

    /* Specific file system routines */
    extern TSK_FS_INFO *ext2fs_open(TSK_IMG_INFO *, TSK_OFF_T,
        TSK_FS_TYPE_ENUM, uint8_t);
    extern TSK_FS_INFO *fatfs_open(TSK_IMG_INFO *, TSK_OFF_T,
        TSK_FS_TYPE_ENUM, uint8_t);
    extern TSK_FS_INFO *ffs_open(TSK_IMG_INFO *, TSK_OFF_T,
        TSK_FS_TYPE_ENUM);
    extern TSK_FS_INFO *ntfs_open(TSK_IMG_INFO *, TSK_OFF_T,
        TSK_FS_TYPE_ENUM, uint8_t);
    extern TSK_FS_INFO *rawfs_open(TSK_IMG_INFO *, TSK_OFF_T);
    extern TSK_FS_INFO *swapfs_open(TSK_IMG_INFO *, TSK_OFF_T);
    extern TSK_FS_INFO *iso9660_open(TSK_IMG_INFO *, TSK_OFF_T,
        TSK_FS_TYPE_ENUM, uint8_t);
    extern TSK_FS_INFO *hfs_open(TSK_IMG_INFO *, TSK_OFF_T,
        TSK_FS_TYPE_ENUM, uint8_t);
    extern TSK_FS_INFO *yaffs2_open(TSK_IMG_INFO *, TSK_OFF_T,
        TSK_FS_TYPE_ENUM, uint8_t);

    /* Generic functions for swap and raw -- many say "not supported" */
    extern uint8_t tsk_fs_nofs_fsstat(TSK_FS_INFO * fs, FILE * hFile);
    extern void tsk_fs_nofs_close(TSK_FS_INFO * fs);
    extern TSK_FS_ATTR_TYPE_ENUM tsk_fs_nofs_get_default_attr_type(const
        TSK_FS_FILE * a_file);
    extern uint8_t tsk_fs_nofs_make_data_run(TSK_FS_FILE *);
    extern int tsk_fs_nofs_name_cmp(TSK_FS_INFO *, const char *,
        const char *);
    extern TSK_FS_BLOCK_FLAG_ENUM tsk_fs_nofs_block_getflags(TSK_FS_INFO
        * a_fs, TSK_DADDR_T a_addr);
    extern uint8_t tsk_fs_nofs_block_walk(TSK_FS_INFO * fs,
        TSK_DADDR_T a_start_blk, TSK_DADDR_T a_end_blk,
        TSK_FS_BLOCK_WALK_FLAG_ENUM a_flags,
        TSK_FS_BLOCK_WALK_CB a_action, void *a_ptr);
    extern uint8_t tsk_fs_nofs_file_add_meta(TSK_FS_INFO * fs,
        TSK_FS_FILE * a_fs_file, TSK_INUM_T inum);
    extern uint8_t tsk_fs_nofs_inode_walk(TSK_FS_INFO * fs,
        TSK_INUM_T a_start_inum, TSK_INUM_T a_end_inum,
        TSK_FS_META_FLAG_ENUM a_flags, TSK_FS_META_WALK_CB a_action,
        void *a_ptr);
    extern uint8_t tsk_fs_nofs_istat(TSK_FS_INFO * a_fs, FILE * hFile,
        TSK_INUM_T inum, TSK_DADDR_T numblock, int32_t sec_skew);
    extern TSK_RETVAL_ENUM tsk_fs_nofs_dir_open_meta(TSK_FS_INFO * a_fs,
        TSK_FS_DIR ** a_fs_dir, TSK_INUM_T a_addr);
    extern uint8_t tsk_fs_nofs_jopen(TSK_FS_INFO * a_fs, TSK_INUM_T inum);
    extern uint8_t tsk_fs_nofs_jentry_walk(TSK_FS_INFO * a_fs,
        int a_flags, TSK_FS_JENTRY_WALK_CB a_action, void *a_ptr);
    extern uint8_t tsk_fs_nofs_jblk_walk(TSK_FS_INFO * a_fs,
        TSK_INUM_T start, TSK_INUM_T end, int a_flags,
        TSK_FS_JBLK_WALK_CB a_action, void *a_ptr);

    /* malloc/free with lock init/deinit */
    extern TSK_FS_INFO *tsk_fs_malloc(size_t);
    extern void tsk_fs_free(TSK_FS_INFO *);

// Endian macros - actual functions in misc/

#define tsk_fs_guessu16(fs, x, mag)   \
     tsk_guess_end_u16(&(fs->endian), (x), (mag))
#define tsk_fs_guessu32(fs, x, mag)   \
     tsk_guess_end_u32(&(fs->endian), (x), (mag))
#ifdef __cplusplus
}
#endif                          /*  */
#endif                          /*  */
