/*
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
**
*/

/**
 * \file dls_lib.c
 * Contains the library API functions used by the TSK blkls command
 * line tool.
 */

/* TCT:
 *
 * LICENSE
 *	This software is distributed under the IBM Public License.
 * AUTHOR(S)
 *	Wietse Venema
 *	IBM T.J. Watson Research
 *	P.O. Box 704
 *	Yorktown Heights, NY 10598, USA
 */

#include "tsk_fs_i.h"

#ifdef TSK_WIN32
#include <winsock2.h>
#endif

/* call backs for listing details 
 *
 * return 1 on error
 * */
static uint8_t
print_list_head(TSK_FS_INFO * fs)
{
    char hostnamebuf[BUFSIZ];

#ifndef TSK_WIN32
    if (gethostname(hostnamebuf, sizeof(hostnamebuf) - 1) < 0) {
        if (tsk_verbose)
            tsk_fprintf(stderr, "blkls_lib: error getting hostname: %s\n",
                strerror(errno));
        strcpy(hostnamebuf, "unknown");
    }
    hostnamebuf[sizeof(hostnamebuf) - 1] = 0;
#else
    strcpy(hostnamebuf, "unknown");
#endif

    /*
     * Identify table type and table origin.
     */
    tsk_printf("class|host|image|first_time|unit\n");
    tsk_printf("blkls|%s||%" PRIu64 "|%s\n", hostnamebuf,
        (uint64_t) time(NULL), fs->duname);

    tsk_printf("addr|alloc\n");
    return 0;
}

static TSK_WALK_RET_ENUM
print_list(const TSK_FS_BLOCK * fs_block, void *ptr)
{
    tsk_printf("%" PRIuDADDR "|%s\n", fs_block->addr,
        (fs_block->flags & TSK_FS_BLOCK_FLAG_ALLOC) ? "a" : "f");
    return TSK_WALK_CONT;
}



/* print_block - write data block to stdout */
static TSK_WALK_RET_ENUM
print_block(const TSK_FS_BLOCK * fs_block, void *ptr)
{
    if (tsk_verbose)
        tsk_fprintf(stderr, "write block %" PRIuDADDR "\n",
            fs_block->addr);

    if (fwrite(fs_block->buf, fs_block->fs_info->block_size, 1,
            stdout) != 1) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WRITE);
        tsk_error_set_errstr("blkls_lib: error writing to stdout: %s",
            strerror(errno));
        return TSK_WALK_ERROR;
    }

    return TSK_WALK_CONT;
}


/** \internal 
* Structure to store data for callbacks.
*/
typedef struct {
    TSK_OFF_T flen;
} BLKLS_DATA;


/* SLACK SPACE  call backs */

static TSK_WALK_RET_ENUM
slack_file_act(TSK_FS_FILE * fs_file, TSK_OFF_T a_off, TSK_DADDR_T addr,
    char *buf, size_t size, TSK_FS_BLOCK_FLAG_ENUM flags, void *ptr)
{
    BLKLS_DATA *data = (BLKLS_DATA *) ptr;

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "slack_file_act: File: %" PRIuINUM " Remaining File:  %"
            PRIuOFF "  Buffer: %u\n", fs_file->meta->addr, data->flen,
            size);

    /* This is not the last data unit */
    if (data->flen >= size) {
        data->flen -= size;
    }
    /* We have passed the end of the allocated space */
    else if (data->flen == 0) {
        if (fwrite(buf, size, 1, stdout) != 1) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_WRITE);
            tsk_error_set_errstr("blkls_lib: error writing to stdout: %s",
                strerror(errno));
            return TSK_WALK_ERROR;
        }
    }
    /* This is the last data unit and there is unused space */
    else if (data->flen < size) {
        /* Clear the used space and print it */
        memset(buf, 0, (size_t) data->flen);
        if (fwrite(buf, size, 1, stdout) != 1) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_WRITE);
            tsk_error_set_errstr("blkls_lib: error writing to stdout: %s",
                strerror(errno));
            return TSK_WALK_ERROR;
        }
        data->flen = 0;
    }

    return TSK_WALK_CONT;
}

/* Call back for inode_walk */
static TSK_WALK_RET_ENUM
slack_inode_act(TSK_FS_FILE * fs_file, void *ptr)
{
    BLKLS_DATA *data = (BLKLS_DATA *) ptr;

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "slack_inode_act: Processing meta data: %" PRIuINUM "\n",
            fs_file->meta->addr);

    /* We will now do a file walk on the content and print the
     * data after the specified size of the file */
    if (TSK_FS_TYPE_ISNTFS(fs_file->fs_info->ftype) == 0) {
        data->flen = fs_file->meta->size;
        if (tsk_fs_file_walk(fs_file,
                TSK_FS_FILE_WALK_FLAG_SLACK, slack_file_act, ptr)) {
            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "slack_inode_act: error walking file: %" PRIuINUM,
                    fs_file->meta->addr);
            tsk_error_reset();
        }
    }

    /* For NTFS we go through each non-resident attribute */
    else {
        int i, cnt;

        cnt = tsk_fs_file_attr_getsize(fs_file);
        for (i = 0; i < cnt; i++) {
            const TSK_FS_ATTR *fs_attr =
                tsk_fs_file_attr_get_idx(fs_file, i);
            if (!fs_attr)
                continue;

            if (fs_attr->flags & TSK_FS_ATTR_NONRES) {
                data->flen = fs_attr->size;
                if (tsk_fs_file_walk_type(fs_file, fs_attr->type,
                        fs_attr->id, TSK_FS_FILE_WALK_FLAG_SLACK,
                        slack_file_act, ptr)) {
                    if (tsk_verbose)
                        tsk_fprintf(stderr,
                            "slack_inode_act: error walking file: %"
                            PRIuINUM, fs_file->meta->addr);
                    tsk_error_reset();
                }
            }
        }
    }

    return TSK_WALK_CONT;
}



/* Return 1 on error and 0 on success */
uint8_t
tsk_fs_blkls(TSK_FS_INFO * fs, TSK_FS_BLKLS_FLAG_ENUM a_blklsflags,
    TSK_DADDR_T bstart, TSK_DADDR_T blast,
    TSK_FS_BLOCK_WALK_FLAG_ENUM a_block_flags)
{
    BLKLS_DATA data;

    if (a_blklsflags & TSK_FS_BLKLS_SLACK) {
        /* get the info on each allocated inode */
        if (fs->inode_walk(fs, fs->first_inum, fs->last_inum,
                TSK_FS_META_FLAG_ALLOC, slack_inode_act, &data))
            return 1;
    }
    else if (a_blklsflags & TSK_FS_BLKLS_LIST) {
        if (print_list_head(fs))
            return 1;

        a_block_flags |= TSK_FS_BLOCK_WALK_FLAG_AONLY;
        if (tsk_fs_block_walk(fs, bstart, blast, a_block_flags, print_list,
                &data))
            return 1;
    }
    else {
#ifdef TSK_WIN32
        if (-1 == _setmode(_fileno(stdout), _O_BINARY)) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_WRITE);
            tsk_error_set_errstr
                ("blkls_lib: error setting stdout to binary: %s",
                strerror(errno));
            return 1;
        }
#endif
        if (tsk_fs_block_walk(fs, bstart, blast, a_block_flags,
                print_block, &data))
            return 1;
    }

    return 0;
}
