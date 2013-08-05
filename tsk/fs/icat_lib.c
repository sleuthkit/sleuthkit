/*
** icat_lib 
** The Sleuth Kit 
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2006-2011 Brian Carrier, Basis Technology.  All Rights reserved
** Copyright (c) 2003-2005 Brian Carrier.  All rights reserved 
**
** TASK
** Copyright (c) 2002 Brian Carrier, @stake Inc.  All rights reserved
** 
** Copyright (c) 1997,1998,1999, International Business Machines          
** Corporation and others. All Rights Reserved.

 * LICENSE
 *	This software is distributed under the IBM Public License.
 * AUTHOR(S)
 *	Wietse Venema
 *	IBM T.J. Watson Research
 *	P.O. Box 704
 *	Yorktown Heights, NY 10598, USA
 --*/

/**
 * \file icat_lib.c
 * Contains the library API functions used by the TSK icat command
 * line tool.
 */

#include "tsk_fs_i.h"



/* Call back action for file_walk
 */
static TSK_WALK_RET_ENUM
icat_action(TSK_FS_FILE * fs_file, TSK_OFF_T a_off, TSK_DADDR_T addr,
    char *buf, size_t size, TSK_FS_BLOCK_FLAG_ENUM flags, void *ptr)
{
    if (size == 0)
        return TSK_WALK_CONT;

    if (fwrite(buf, size, 1, stdout) != 1) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WRITE);
        tsk_error_set_errstr("icat_action: error writing to stdout: %s",
            strerror(errno));
        return TSK_WALK_ERROR;
    }

    return TSK_WALK_CONT;
}

/* Return 1 on error and 0 on success */
uint8_t
tsk_fs_icat(TSK_FS_INFO * fs, TSK_INUM_T inum,
    TSK_FS_ATTR_TYPE_ENUM type, uint8_t type_used,
    uint16_t id, uint8_t id_used, TSK_FS_FILE_WALK_FLAG_ENUM flags)
{
    TSK_FS_FILE *fs_file;

#ifdef TSK_WIN32
    if (-1 == _setmode(_fileno(stdout), _O_BINARY)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WRITE);
        tsk_error_set_errstr
            ("icat_lib: error setting stdout to binary: %s",
            strerror(errno));
        return 1;
    }
#endif

    fs_file = tsk_fs_file_open_meta(fs, NULL, inum);
    if (!fs_file) {
        return 1;
    }

    if (type_used) {
        if (id_used == 0) {
            flags |= TSK_FS_FILE_WALK_FLAG_NOID;
        }
        if (tsk_fs_file_walk_type(fs_file, type, id, flags, icat_action,
                NULL)) {
            tsk_fs_file_close(fs_file);
            return 1;
        }
    }
    else {
        if (tsk_fs_file_walk(fs_file, flags, icat_action, NULL)) {
            tsk_fs_file_close(fs_file);
            return 1;
        }
    }


    tsk_fs_file_close(fs_file);

    return 0;
}
