/*
** The Sleuth Kit
**
** Copyright (c) 2022 Basis Technology Corp.  All rights reserved
** Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
**
** This software is distributed under the Common Public License 1.0
**
*/

/*
 * Contains the structures and function APIs for logcial file system support.
 */

#ifndef _TSK_LOGICALFS_H
#define _TSK_LOGICALFS_H

#ifdef __cplusplus
extern "C" {
#endif

#define LOGICAL_INUM_DIR_MASK  0xffffffff00000000
#define LOGICAL_INUM_FILE_MASK 0x00000000ffffffff

#define LOGICAL_ROOT_INUM 0x100000000
#define LOGICAL_INUM_DIR_INC 0x100000000
#define LOGICAL_BLOCK_SIZE TSK_IMG_INFO_CACHE_LEN
#define LOGICAL_MAX_PATH_UNICODE 32767
#define LOGICAL_INUM_DIR_MAX 0xffffffff00000000

/*
* Structure of an logcial file system handle.
*/
typedef struct {
	TSK_FS_INFO fs_info;    /* super class */
	TSK_TCHAR * base_path;  // Base path - pointer to data in IMG_DIR_INFO 
} LOGICALFS_INFO;

typedef enum  {
	LOGICALFS_NO_SEARCH = 0,         ///< Traverse entire file system
	LOGICALFS_SEARCH_BY_PATH = 1,    ///< Search file system for given path
	LOGICALFS_SEARCH_BY_INUM = 2     ///< Search file system for given inum
} LOGICALFS_SEARCH_TYPE;

typedef struct {
	LOGICALFS_SEARCH_TYPE search_type;
	TSK_TCHAR* target_path;
	TSK_INUM_T target_inum;
	int target_found;
	TSK_TCHAR* found_path;
	TSK_INUM_T found_inum;
} LOGICALFS_SEARCH_HELPER;

enum LOGICALFS_DIR_LOADING_MODE {
	LOGICALFS_LOAD_ALL = 0,
	LOGICALFS_LOAD_DIRS_ONLY = 1,
	LOGICALFS_LOAD_FILES_ONLY = 2
};

extern ssize_t logicalfs_read_block(TSK_FS_INFO *a_fs, TSK_FS_FILE *a_fs_file, TSK_DADDR_T a_offset, char *buf);
extern ssize_t logicalfs_read(TSK_FS_INFO *a_fs, TSK_FS_FILE *a_fs_file, TSK_DADDR_T a_offset, size_t len, char *buf);

/*
 * Logical-FS-specific path → inum resolver. The single entry point for
 * tsk_fs_path2inum's logical-FS fast path. Encapsulates UTF-8 → UTF-16 conversion,
 * slash normalization, host-filesystem existence check, and inum resolution.
 *
 * On non-Windows builds the underlying host enumeration isn't available, so any
 * logical-FS path resolves to "not found" (returns 1).
 *
 * @param a_fs       File system. Must be of type TSK_FS_TYPE_LOGICAL.
 * @param a_path     UTF-8 path relative to the FS root. Either '/' or '\' separators
 *                   are accepted.
 * @param a_result   OUT: the resolved inum on success.
 * @param a_fs_name  OUT: optional. If non-NULL, populated with the resolved
 *                   entry's name/type/flags/meta_addr on success. Caller is
 *                   responsible for pre-allocating the name and shrt_name buffers
 *                   on the TSK_FS_NAME struct. Pass NULL if name details aren't
 *                   needed (the hot path).
 *
 * @returns  0 if found,
 *           1 if the path does not exist (or on any non-Windows build),
 *          -1 on system error — invalid arguments (NULL a_fs / a_path / a_result),
 *             wrong filesystem type (a_fs->ftype != TSK_FS_TYPE_LOGICAL),
 *             allocation failure, or UTF-8 conversion failure.
 */
extern int8_t tsk_logical_fs_path2inum(TSK_FS_INFO *a_fs, const char *a_path,
    TSK_INUM_T *a_result, TSK_FS_NAME *a_fs_name);

#ifdef __cplusplus
}
#endif
#endif
