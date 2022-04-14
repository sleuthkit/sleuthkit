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

#define LOGICAL_DEBUG_PRINT 0

#define LOGICAL_ROOT_INUM 0x10000
#define LOGICAL_INUM_DIR_INC 0x10000
#define LOGICAL_INVALID_INUM 0

/*
* Structure of an logcial file system handle.
*/
typedef struct {
	TSK_FS_INFO fs_info;    /* super class */
	TSK_TCHAR * base_path;  // Base path - pointer to data in IMG_DIR_INFO 
} LOGICALFS_INFO;


enum LOGICALFS_SEARCH_TYPE {
	LOGICALFS_NO_SEARCH = 0,         ///< Traverse entire file system
	LOGICALFS_SEARCH_BY_PATH = 1,    ///< Search file system for given path
	LOGICALFS_SEARCH_BY_INUM = 2,    ///< Search file system for given inum
};

typedef struct {
	LOGICALFS_SEARCH_TYPE search_type;
	TSK_TCHAR* target_path;
	TSK_INUM_T target_inum;
	bool target_found;
	TSK_TCHAR* found_path;
	TSK_INUM_T found_inum;
} LOGICALFS_SEARCH_HELPER;

enum LOGICALFS_DIR_LOADING_MODE {
	LOGICALFS_LOAD_ALL = 0,
	LOGICALFS_LOAD_DIRS_ONLY = 1,
	LOGICALFS_LOAD_FILES_ONLY = 2
};

#ifdef __cplusplus
}
#endif
#endif
