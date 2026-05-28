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
 * Result of probing the host filesystem for a logical-FS path.
 * Used to drive path-resolution dispatch (file paths and directory paths follow
 * different resolution strategies because of how logical-FS inums are encoded).
 */
typedef enum {
	TSK_LOGICAL_PATH_NOT_FOUND = 0,
	TSK_LOGICAL_PATH_FILE = 1,
	TSK_LOGICAL_PATH_DIRECTORY = 2
} TSK_LOGICAL_PATH_TYPE;

/*
 * Probe the host filesystem for a path inside a logical FS image. Returns whether
 * the path exists and, if so, whether it's a file or directory. Only meaningful for
 * logical filesystems on Windows (returns NOT_FOUND otherwise).
 *
 * Caller is responsible for converting the path to wide-char with backslash separators
 * before calling. The dispatcher in tsk_fs_path2inum already does this once for both
 * logical-FS helpers, so callers should not need to do the conversion themselves.
 *
 * @param a_fs        File system. Must be of type TSK_FS_TYPE_LOGICAL.
 * @param a_path_wide Wide-char path with backslash separators, relative to the FS root.
 *
 * @return TSK_LOGICAL_PATH_NOT_FOUND, TSK_LOGICAL_PATH_FILE, or TSK_LOGICAL_PATH_DIRECTORY
 */
extern TSK_LOGICAL_PATH_TYPE tsk_logical_fs_check_path(TSK_FS_INFO *a_fs, const TSK_TCHAR *a_path_wide);

/*
 * Logical-FS-specific path → inum resolver. Caller passes the result of an
 * earlier tsk_logical_fs_check_path call to avoid re-probing the host filesystem.
 *
 * Same wide-char convention as tsk_logical_fs_check_path - caller should pre-convert
 * once and pass the converted path to both functions.
 *
 * @param a_fs        File system. Must be of type TSK_FS_TYPE_LOGICAL.
 * @param a_path_wide Wide-char path with backslash separators, relative to the FS root.
 * @param path_type   Result of tsk_logical_fs_check_path(a_fs, a_path_wide).
 * @param a_result    OUT: the resolved inum on success.
 *
 * @returns -1 on (system) error, 0 if found, and 1 if not found.
 */
extern int8_t tsk_logical_fs_path2inum(TSK_FS_INFO *a_fs, const TSK_TCHAR *a_path_wide,
    TSK_LOGICAL_PATH_TYPE path_type, TSK_INUM_T *a_result);

#ifdef __cplusplus
}
#endif
#endif
