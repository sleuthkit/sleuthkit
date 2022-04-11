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
 * Contains the structures and function APIs for logcial file system support.
 */

#ifndef _TSK_LOGICALFS_H
#define _TSK_LOGICALFS_H

#ifdef __cplusplus
#include <map>
extern "C" {
#endif

#define LOGICAL_ROOT_INUM 0x10000
#define LOGICAL_INVALID_INUM 0

#define MAX_LOGICAL_NAME_LEN 512 // TODO put in real value

	/*
	* Structure of an logcial file system handle.
	*/
	typedef struct {
		TSK_FS_INFO fs_info;    /* super class */
		TSK_TCHAR * base_path;  // Base path - pointer to data in IMG_DIR_INFO 
	} LOGICALFS_INFO;

#ifdef __cplusplus
}
#endif
#endif
