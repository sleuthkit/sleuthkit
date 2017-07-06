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
#include "tsk_ntfs.h"


static void
print_date(time_t secs, time_t subsecs)
{
    char buf[128];

    tsk_fs_time_to_str_subsecs(secs, subsecs, buf);
    tsk_fprintf(stdout, "%s", buf);
}


/*
 * unpack reason field and print its content
 */
static void
print_usn_reason(TSK_FS_USN_REASON reason)
{
    uint32_t flag = 1;

    for (flag = 1; flag > 0 && flag <= reason; flag *= 2)
        if (reason & flag)
            switch (flag) {
            case TSK_FS_USN_REASON_DATA_OVERWRITE:
                tsk_fprintf(stdout, "DATA_OVERWRITE ");
                break;
            case TSK_FS_USN_REASON_DATA_EXTEND:
                tsk_fprintf(stdout, "DATA_EXTEND ");
                break;
            case TSK_FS_USN_REASON_DATA_TRUNCATION:
                tsk_fprintf(stdout, "DATA_TRUNCATION ");
                break;
            case TSK_FS_USN_REASON_NAMED_DATA_OVERWRITE:
                tsk_fprintf(stdout, "NAMED_DATA_OVERWRITE ");
                break;
            case TSK_FS_USN_REASON_NAMED_DATA_EXTEND:
                tsk_fprintf(stdout, "NAMED_DATA_EXTEND ");
                break;
            case TSK_FS_USN_REASON_NAMED_DATA_TRUNCATION:
                tsk_fprintf(stdout, "NAMED_DATA_TRUNCATION ");
                break;
            case TSK_FS_USN_REASON_FILE_CREATE:
                tsk_fprintf(stdout, "FILE_CREATE ");
                break;
            case TSK_FS_USN_REASON_FILE_DELETE:
                tsk_fprintf(stdout, "FILE_DELETE ");
                break;
            case TSK_FS_USN_REASON_EA_CHANGE:
                tsk_fprintf(stdout, "EA_CHANGE ");
                break;
            case TSK_FS_USN_REASON_SECURITY_CHANGE:
                tsk_fprintf(stdout, "SECURITY_CHANGE ");
                break;
            case TSK_FS_USN_REASON_RENAME_OLD_NAME:
                tsk_fprintf(stdout, "RENAME_OLD_NAME ");
                break;
            case TSK_FS_USN_REASON_RENAME_NEW_NAME:
                tsk_fprintf(stdout, "RENAME_NEW_NAME ");
                break;
            case TSK_FS_USN_REASON_INDEXABLE_CHANGE:
                tsk_fprintf(stdout, "INDEXABLE_CHANGE ");
                break;
            case TSK_FS_USN_REASON_BASIC_INFO_CHANGE:
                tsk_fprintf(stdout, "BASIC_INFO_CHANGE ");
                break;
            case TSK_FS_USN_REASON_HARD_LINK_CHANGE:
                tsk_fprintf(stdout, "HARD_LINK_CHANGE ");
                break;
            case TSK_FS_USN_REASON_COMPRESSION_CHANGE:
                tsk_fprintf(stdout, "COMPRESSION_CHANGE ");
                break;
            case TSK_FS_USN_REASON_ENCRYPTION_CHANGE:
                tsk_fprintf(stdout, "ENCRYPTION_CHANGE ");
                break;
            case TSK_FS_USN_REASON_OBJECT_ID_CHANGE:
                tsk_fprintf(stdout, "OBJECT_ID_CHANGE ");
                break;
            case TSK_FS_USN_REASON_REPARSE_POINT_CHANGE:
                tsk_fprintf(stdout, "REPARSE_POINT_CHANGE ");
                break;
            case TSK_FS_USN_REASON_STREAM_CHANGE:
                tsk_fprintf(stdout, "STREAM_CHANGE ");
                break;
            case TSK_FS_USN_REASON_CLOSE:
                tsk_fprintf(stdout, "CLOSE ");
                break;
            default:
                tsk_fprintf(stdout, "UNKNOWN ");
                break;
            }
}


/*
 * unpack source info field and print its content
 */
static void
print_usn_source_info(TSK_FS_USN_SOURCE_INFO sinfo)
{
    uint32_t flag = 1;

    for (flag = 1; flag > 0 && flag <= sinfo; flag *= 2)
        if (sinfo & flag)
            switch (flag) {
            case TSK_FS_USN_SOURCE_INFO_DATA_MANAGEMENT:
                tsk_fprintf(stdout, "DATA_MANAGEMENT ");
                break;
            case TSK_FS_USN_SOURCE_INFO_AUXILIARY_DATA:
                tsk_fprintf(stdout, "AUXILIARY_DATA ");
                break;
            case TSK_FS_USN_SOURCE_INFO_REPLICATION_MANAGEMENT:
                tsk_fprintf(stdout, "REPLICATION_MANAGEMENT ");
                break;
            case TSK_FS_USN_SOURCE_INFO_CLIENT_REPLICATION_MANAGEMENT:
                tsk_fprintf(stdout, "CLIENT_REPLICATION_MANAGEMENT ");
                break;
            default:
                tsk_fprintf(stdout, "UNKNOWN ");
                break;
            }
}


/*
 * unpack attributes field and print its content
 */
static void
print_usn_attributes(TSK_FS_NTFS_FILE_ATTRIBUTES attributes)
{
    uint32_t flag = 1;

    for (flag = 1; flag > 0 && flag <= attributes; flag *= 2)
        if (attributes & flag)
            switch (flag) {
            case TSK_FS_NTFS_FILE_ATTRIBUTE_READONLY:
                tsk_fprintf(stdout, "READONLY ");
                break;
            case TSK_FS_NTFS_FILE_ATTRIBUTE_HIDDEN:
                tsk_fprintf(stdout, "HIDDEN ");
                break;
            case TSK_FS_NTFS_FILE_ATTRIBUTE_SYSTEM:
                tsk_fprintf(stdout, "SYSTEM ");
                break;
            case TSK_FS_NTFS_FILE_ATTRIBUTE_DIRECTORY:
                tsk_fprintf(stdout, "DIRECTORY ");
                break;
            case TSK_FS_NTFS_FILE_ATTRIBUTE_ARCHIVE:
                tsk_fprintf(stdout, "ARCHIVE ");
                break;
            case TSK_FS_NTFS_FILE_ATTRIBUTE_DEVICE:
                tsk_fprintf(stdout, "DEVICE ");
                break;
            case TSK_FS_NTFS_FILE_ATTRIBUTE_NORMAL:
                tsk_fprintf(stdout, "NORMAL ");
                break;
            case TSK_FS_NTFS_FILE_ATTRIBUTE_TEMPORARY:
                tsk_fprintf(stdout, "TEMPORARY ");
                break;
            case TSK_FS_NTFS_FILE_ATTRIBUTE_SPARSE_FILE:
                tsk_fprintf(stdout, "SPARSE_FILE ");
                break;
            case TSK_FS_NTFS_FILE_ATTRIBUTE_REPARSE_POINT:
                tsk_fprintf(stdout, "REPARSE_POINT ");
                break;
            case TSK_FS_NTFS_FILE_ATTRIBUTE_COMPRESSED:
                tsk_fprintf(stdout, "COMPRESSED ");
                break;
            case TSK_FS_NTFS_FILE_ATTRIBUTE_OFFLINE:
                tsk_fprintf(stdout, "OFFLINE ");
                break;
            case TSK_FS_NTFS_FILE_ATTRIBUTE_NOT_CONTENT_INDEXED:
                tsk_fprintf(stdout, "NOT_CONTENT_INDEXED ");
                break;
            case TSK_FS_NTFS_FILE_ATTRIBUTE_ENCRYPTED:
                tsk_fprintf(stdout, "ENCRYPTED ");
                break;
            case TSK_FS_NTFS_FILE_ATTRIBUTE_INTEGRITY_STREAM:
                tsk_fprintf(stdout, "INTEGRITY_STREAM ");
                break;
            case TSK_FS_NTFS_FILE_ATTRIBUTE_VIRTUAL:
                tsk_fprintf(stdout, "VIRTUAL ");
                break;
            case TSK_FS_NTFS_FILE_ATTRIBUTE_NO_SCRUB_DATA:
                tsk_fprintf(stdout, "NO_SCRUB_DATA ");
                break;
            default:
                tsk_fprintf(stdout, "UNKNOWN ");
                break;
            }
}


static TSK_WALK_RET_ENUM
print_v2_record(TSK_USN_RECORD_HEADER *header, TSK_USN_RECORD_V2 *record)
{
    tsk_fprintf(stdout, "%" PRIu64 "-%" PRIu32 "\t" "%" PRIu64 "-%" PRIu32 "\t"
                "%" PRIu32 ".%" PRIu32 "\t",
                record->refnum, record->refnum_seq, record->parent_refnum,
                record->parent_refnum_seq, record->time_sec, record->time_nsec);
    print_usn_reason(record->reason);
    tsk_fprintf(stdout, "\t");
    if (tsk_print_sanitized(stdout, record->fname) == 1)
        return TSK_WALK_ERROR;
    tsk_fprintf(stdout, "\n");

    return TSK_WALK_CONT;
}


static TSK_WALK_RET_ENUM
print_v2_record_long(TSK_USN_RECORD_HEADER *header, TSK_USN_RECORD_V2 *record)
{
    tsk_fprintf(stdout,
                "Version: %" PRIu32 ".%" PRIu32 " Length: %" PRIu32 "\n"
                "Reference Number: %" PRIu64 "-%" PRIu32 "\n"
                "Parent Reference Number: %" PRIu64 "-%" PRIu32 "\n"
                "Update Sequence Number: %" PRIu32 "\n",
                header->major_version, header->minor_version,
                header->length, record->refnum, record->refnum_seq,
                record->parent_refnum, record->parent_refnum_seq, record->usn);
    tsk_fprintf(stdout, "Time: ");
    print_date(record->time_sec, record->time_nsec);
    tsk_fprintf(stdout, "\n");
    tsk_fprintf(stdout, "Reason: ");
    print_usn_reason(record->reason);
    tsk_fprintf(stdout, "\n");
    tsk_fprintf(stdout, "Source Info: ");
    print_usn_source_info(record->source_info);
    tsk_fprintf(stdout, "\n");
    tsk_fprintf(stdout, "Security Id: %" PRIu32 "\n", record->security);
    tsk_fprintf(stdout, "Attributes: ");
    print_usn_attributes(record->attributes);
    tsk_fprintf(stdout, "\n");
    tsk_fprintf(stdout, "Name: ");
    if (tsk_print_sanitized(stdout, record->fname) == 1)
        return TSK_WALK_ERROR;
    tsk_fprintf(stdout, "\n\n");

    return TSK_WALK_CONT;
}


static TSK_WALK_RET_ENUM
print_v2_record_mac(TSK_USN_RECORD_HEADER *header, TSK_USN_RECORD_V2 *record)
{
    tsk_fprintf(stdout, "%" PRIu32 ".%" PRIu32 "|" "%" PRIu32 "|"
                "%" PRIu64 "-%" PRIu32 "|" "%" PRIu64 "-%" PRIu32 "|"
                "%" PRIu32 "|" "%" PRIu32 ".%" PRIu32 "|" "%" PRIu32 "|"
                "%" PRIu32 "|" "%" PRIu32 "|" "%" PRIu32 "|",
                header->major_version, header->minor_version,
                header->length, record->refnum, record->refnum_seq,
                record->parent_refnum, record->parent_refnum_seq,
                record->usn, record->time_sec, record->time_nsec,
                record->reason, record->source_info, record->security,
                record->attributes);
    if (tsk_print_sanitized(stdout, record->fname) == 1)
        return TSK_WALK_ERROR;
    tsk_fprintf(stdout, "\n");

    return TSK_WALK_CONT;
}


/*
 * call back action function for usnjentry_walk
 */
static TSK_WALK_RET_ENUM
print_usnjent_act(TSK_USN_RECORD_HEADER *a_header, void *a_record, void *a_ptr)
{
    TSK_FS_USNJLS_FLAG_ENUM *flag = (TSK_FS_USNJLS_FLAG_ENUM*) a_ptr;

    switch(a_header->major_version) {
    case 2: {
        TSK_USN_RECORD_V2 *record = (TSK_USN_RECORD_V2 *) a_record;

        switch(*flag) {
        case TSK_FS_USNJLS_NONE:
            return print_v2_record(a_header, record);
        case TSK_FS_USNJLS_LONG:
            return print_v2_record_long(a_header, record);
        case TSK_FS_USNJLS_MAC:
            return print_v2_record_mac(a_header, record);
        }
    }
    default: return TSK_WALK_ERROR;
    }
}


/* Returns 0 on success and 1 on error */
uint8_t
tsk_fs_usnjls(TSK_FS_INFO * fs, TSK_INUM_T inode, TSK_FS_USNJLS_FLAG_ENUM flags)
{
    uint8_t ret = 0;

    tsk_error_reset();

    if (fs == NULL || fs->ftype != TSK_FS_TYPE_NTFS) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("Invalid FS type, valid types: NTFS");
        return 1;
    }

    ret = tsk_ntfs_usnjopen(fs, inode);
    if (ret == 1)
        return 1;

    return tsk_ntfs_usnjentry_walk(fs, print_usnjent_act, &flags);
}
