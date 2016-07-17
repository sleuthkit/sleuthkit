/*
** usnjls
** The Sleuth Kit
**
** Given an NTFS image and UsnJrnl file inode, parses its content showing
** the list of recent changes wihtin the File System.
**
** Matteo Cafasso [noxdafox <at> gmail [dot] com]
**
** This software is distributed under the Common Public License 1.0
**
*/

/** \file usnjls_lib.c
 * Contains the library code associated with the TSK usnjs tool
 * to list changes within a NTFS File System.
 */


#include "tsk_fs_i.h"


/*
 * call back action function for usnjentry_walk
 */
static TSK_WALK_RET_ENUM
print_usnjent_act(TSK_USN_RECORD_HEADER *a_header, void *a_record, void *a_ptr)
{
    switch(a_header->major_version) {
    case 2: {
        TSK_USN_RECORD_V2 *record = (TSK_USN_RECORD_V2 *) a_record;

        tsk_fprintf(stdout, "%" PRIu32 ".%" PRIu32 " " "%" PRIu32 " "
                    "%" PRIu64 "-%" PRIu32 " " "%" PRIu64 "-%" PRIu32 " "
                    "%" PRIu32 " " "%" PRIu32 ".%" PRIu32 " " "%" PRIu32 " "
                    "%" PRIu32 " " "%" PRIu32 " " "%" PRIu32 " ",
                    a_header->major_version, a_header->minor_version,
                    a_header->length, record->refnum, record->refnum_seq,
                    record->parent_refnum, record->parent_refnum_seq,
                    record->usn, record->time_sec, record->time_nsec,
                    record->reason, record->source_info, record->security,
                    record->attributes);
        if (tsk_print_sanitized(stdout, record->fname) == 1)
            return TSK_WALK_ERROR;
        tsk_fprintf(stdout, "\n");

        break;
    }
    default: return TSK_WALK_ERROR;
    }

    return TSK_WALK_CONT;
}


/* Returns 0 on success and 1 on error */
uint8_t
tsk_fs_usnjls(TSK_FS_INFO * fs, TSK_INUM_T inode)
{
    uint8_t ret = 0;

    tsk_error_reset();

    ret = tsk_ntfs_usnjopen(fs, inode);
    if (ret == 1)
        return 1;

    tsk_fprintf(stdout,
                "Version Length Inode ParentInode Usn Timestamp Reason "
                "SourceInfo Security Attributes Name\n");

    return tsk_ntfs_usnjentry_walk(fs, print_usnjent_act, NULL);
}
