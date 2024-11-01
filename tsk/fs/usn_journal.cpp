/*
** usn_journal
** The Sleuth Kit
**
** Update Sequence Number Journal parsing logic.
**
** Matteo Cafasso [noxdafox <at> gmail [dot] com]
**
** This software is distributed under the Common Public License 1.0
**
*/

/** \file usn_journal.c
 * Contains the TSK Update Sequence Number journal walking code.
 */

#include "tsk_fs_i.h"
#include "tsk_ntfs.h"


/*
 * Search the next record in the buffer skipping null bytes.
 * Records are alway aligned at 8 bytes.
 * Returns the offset of the next record.
 */
static TSK_OFF_T
search_record(const unsigned char *buf, TSK_OFF_T offset, ssize_t bufsize)
{
    for ( ; offset < bufsize; offset++)
        if (buf[offset] != '\0')
            return offset - (offset % 8);

    return offset;
}


/*
 * Convert the record file name from UTF16 to UTF8.
 * Returns 0 on success, 1 otherwise
 */
static uint8_t
parse_fname(const unsigned char *buf, uint16_t nlen,
            TSK_USN_RECORD_V2 *record, TSK_ENDIAN_ENUM endian)
{
    int ret = 0;
    UTF8 *temp_name = NULL;
    size_t src_len = (size_t) nlen, dst_len = (size_t) nlen * 2;

    record->fname = tsk_malloc(dst_len + 1);
    if (record->fname == NULL)
        return 1;

    temp_name = (UTF8*)record->fname;

    ret = tsk_UTF16toUTF8(endian,
                          (const UTF16**)&buf, (UTF16*)&buf[src_len],
                          (UTF8**)&temp_name, (UTF8*)&temp_name[dst_len],
                          TSKlenientConversion);

    if (ret != TSKconversionOK) {
        if (tsk_verbose)
            tsk_fprintf(
                stderr, "parse_v2_record: USN name to UTF8 conversion error.");

        record->fname[0] = '\0';
    }
    else
        record->fname[dst_len] = '\0';

    return 0;
}


static void
parse_record_header(const unsigned char *buf, TSK_USN_RECORD_HEADER *header,
                    TSK_ENDIAN_ENUM endian)
{
    header->length = tsk_getu32(endian, &buf[0]);
    header->major_version = tsk_getu16(endian, &buf[4]);
    header->minor_version = tsk_getu16(endian, &buf[6]);
}


/*
 * Parse a V 2.0 USN record.
 * Returns 0 on success, 1 otherwise
 */
static uint8_t
parse_v2_record(const unsigned char *buf, TSK_USN_RECORD_HEADER *header,
                TSK_USN_RECORD_V2 *record, TSK_ENDIAN_ENUM endian)
{
    uint64_t timestamp = 0;
    uint16_t name_offset = 0, name_length = 0;

    record->refnum = tsk_getu48(endian, &buf[8]);
    record->refnum_seq = tsk_getu16(endian, &buf[14]);
    record->parent_refnum = tsk_getu48(endian, &buf[16]);
    record->parent_refnum_seq = tsk_getu16(endian, &buf[22]);
    record->usn = tsk_getu64(endian, &buf[24]);

    /* Convert NT timestamp into Unix */
    timestamp = tsk_getu64(endian, &buf[32]);
    record->time_sec = nt2unixtime(timestamp);
    record->time_nsec = nt2nano(timestamp);

    record->reason = tsk_getu32(endian, &buf[40]);
    record->source_info = tsk_getu32(endian, &buf[44]);
    record->security = tsk_getu32(endian, &buf[48]);
    record->attributes = tsk_getu32(endian, &buf[52]);

    /* Extract file name */
    name_length = tsk_getu16(endian, &buf[56]);
    name_offset = tsk_getu16(endian, &buf[58]);

    return parse_fname(&buf[name_offset], name_length, record, endian);
}


/*
 * Parse the UsnJrnl record.
 * Calls the action callback.
 * Returns TSK_WALK_CONT on success, TSK_WALK_ERROR on error.
 */
static TSK_WALK_RET_ENUM
parse_record(const unsigned char *buf, TSK_USN_RECORD_HEADER *header,
             TSK_ENDIAN_ENUM endian, TSK_FS_USNJENTRY_WALK_CB action, void *ptr)
{
    TSK_WALK_RET_ENUM ret;

    switch (header->major_version) {
    case 2: {
        TSK_USN_RECORD_V2 record;

        ret = parse_v2_record(buf, header, &record, endian);
        if (ret == 1)
            return TSK_WALK_ERROR;

        ret = (*action)(header, &record, ptr);

        free(record.fname);

        return ret;
    }
    case 3: {
        if (tsk_verbose)
            tsk_fprintf(stderr,
                        "parse_record: USN records V 3 not supported yet.");

        return TSK_WALK_CONT;
    }
    case 4: {
        if (tsk_verbose)
            tsk_fprintf(stderr,
                        "parse_record: USN records V 4 not supported yet.");

        return TSK_WALK_CONT;
    }
    default: return TSK_WALK_ERROR;
    }
}


/*
 * Parse the UsnJrnl block buffer.
 *
 * Recover the record size from the header.
 *
 * If the record does not fit in the entire buffer, returns to the callee
 * its offset for alignment.
 *
 * If the buffer is big enough, parses the USN record.
 *
 * Returns -1 on error, 0 in case the action callback decided to stop,
 * a number greater than 0 if the buffer is not big enough.
 */
static int
parse_buffer(const unsigned char *buf, ssize_t bufsize,
             TSK_ENDIAN_ENUM endian, TSK_FS_USNJENTRY_WALK_CB action, void *ptr)
{
    TSK_OFF_T offset = 0;
    TSK_WALK_RET_ENUM ret = 0;
    TSK_USN_RECORD_HEADER header;

    while ((offset = search_record(buf, offset, bufsize)) < bufsize) {
        parse_record_header(&buf[offset], &header, endian);

        /* The buffer does not contain the entire record */
        if (offset + header.length > bufsize)
            return bufsize - offset;

        ret = parse_record(&buf[offset], &header, endian, action, ptr);
        if (ret == TSK_WALK_ERROR)
            return -1;
        else if (ret == TSK_WALK_STOP)
            return 0;

        offset += header.length;
    }

    return offset;
}


/*
 * Parse the UsnJrnl file.
 * Iterates through the file in blocks.
 * Returns 0 on success, 1 otherwise
 */
static uint8_t
parse_file(NTFS_INFO * ntfs, unsigned char *buf,
           TSK_FS_USNJENTRY_WALK_CB action, void *ptr)
{
    ssize_t size = 0;
    TSK_OFF_T offset = 0, ret = 0;

    while ((size = tsk_fs_file_read(ntfs->usnjinfo->fs_file, offset,
                                    (char*)buf, ntfs->usnjinfo->bsize,
                                    TSK_FS_FILE_READ_FLAG_NONE)) > 0)
    {
        ret = parse_buffer(buf, size, ntfs->fs_info.endian, action, ptr);

        if (ret < 0)
            return 1;
        else if (ret == 0)
            return 0;

        offset += ret;
    }

    return 0;
}


/**
 * Open the Update Sequence Number Journal stored at the inode inum.
 *
 * @param ntfs File system where the journal is stored
 * @param inum file reference number where the USN journal is located
 * @returns 0 on success, 1 otherwise
 */
uint8_t
tsk_ntfs_usnjopen(TSK_FS_INFO *fs, TSK_INUM_T inum)
{
    NTFS_INFO *ntfs = (NTFS_INFO*)fs;

    tsk_error_reset();

    if (ntfs == NULL || ntfs->fs_info.ftype != TSK_FS_TYPE_NTFS) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("Invalid FS type in tsk_ntfs_usnjopen");
        return 1;
    }

    /* Initialize usnjinfo support structure */
    ntfs->usnjinfo = tsk_malloc(sizeof *ntfs->usnjinfo);
    if (ntfs->usnjinfo == NULL)
        return 1;

    ntfs->usnjinfo->usnj_inum = inum;
    ntfs->usnjinfo->bsize = ntfs->fs_info.block_size;

    ntfs->usnjinfo->fs_file = tsk_fs_file_open_meta(&ntfs->fs_info, NULL, inum);
    if (ntfs->usnjinfo->fs_file == NULL) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("ntfs_usnjopen: tsk_fs_file_open_meta");
        free(ntfs->usnjinfo);
        return 1;
    }

    if (tsk_verbose)
        tsk_fprintf(stderr, "usn journal opened at inode %" PRIuINUM
                    " bsize: %" PRIu32 "\n",
                    ntfs->usnjinfo->usnj_inum, ntfs->usnjinfo->bsize);

    return 0;
}


/**
 * Walk through the Update Sequence Number journal file
 * opened with ntfs_usnjopen.
 *
 * For each USN record, calls the callback action passing the USN record header,
 * the USN record and the pointer ptr.
 *
 * @param ntfs File system where the journal is stored
 * @param action action to be called per each USN entry
 * @param ptr pointer to data passed to the action callback
 * @returns 0 on success, 1 otherwise
 */
uint8_t
tsk_ntfs_usnjentry_walk(TSK_FS_INFO *fs, TSK_FS_USNJENTRY_WALK_CB action,
                        void *ptr)
{
    uint8_t ret = 0;
    unsigned char *buf = NULL;
    NTFS_INFO *ntfs = (NTFS_INFO*)fs;

    tsk_error_reset();

    if (ntfs == NULL || ntfs->fs_info.ftype != TSK_FS_TYPE_NTFS) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("Invalid FS type in ntfs_usnjentry_walk");
        return 1;
    }

    if (ntfs->usnjinfo == NULL) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("Must call tsk_ntfs_usnjopen first");
        return 1;
    }

    buf = tsk_malloc(ntfs->usnjinfo->bsize);
    if (buf == NULL)
        return 1;

    ret = parse_file(ntfs, buf, action, ptr);

    tsk_fs_file_close(ntfs->usnjinfo->fs_file);
    free(ntfs->usnjinfo);
    free(buf);

    return ret;
}
