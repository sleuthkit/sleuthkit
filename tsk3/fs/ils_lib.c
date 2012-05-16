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
*/

/**
 * \file ils_lib.c
 * Library functionality of the TSK ils tool.
 */

/* TCT */
/*++
 * LICENSE
 *	This software is distributed under the IBM Public License.
 * AUTHOR(S)
 *	Wietse Venema
 *	IBM T.J. Watson Research
 *	P.O. Box 704
 *	Yorktown Heights, NY 10598, USA
 --*/

#include "tsk_fs_i.h"

#ifdef TSK_WIN32
#include <winsock2.h>
#endif


typedef struct {
    const TSK_TCHAR *image;

/* number of seconds time skew of system 
 * if the system was 100 seconds fast, the value should be +100 
 */
    int32_t sec_skew;

    TSK_FS_ILS_FLAG_ENUM flags;
} ILS_DATA;


/* print_header - print time machine header */

static void
print_header(TSK_FS_INFO * fs)
{
    char hostnamebuf[BUFSIZ];
    time_t now;

#ifndef TSK_WIN32
    if (gethostname(hostnamebuf, sizeof(hostnamebuf) - 1) < 0) {
        if (tsk_verbose)
            tsk_fprintf(stderr, "error getting host by name\n");

        strcpy(hostnamebuf, "unknown");
    }
    hostnamebuf[sizeof(hostnamebuf) - 1] = 0;
#else
    strcpy(hostnamebuf, "unknown");
#endif
    now = time((time_t *) 0);

    /*
     * Identify table type and table origin.
     */
    tsk_printf("class|host|device|start_time\n");
    tsk_printf("ils|%s||%" PRIu64 "\n", hostnamebuf, (uint64_t) now);

    /*
     * Identify the fields in the data that follow.
     */
    tsk_printf
        ("st_ino|st_alloc|st_uid|st_gid|st_mtime|st_atime|st_ctime|st_crtime");

    tsk_printf("|st_mode|st_nlink|st_size\n");
}

static void
print_header_mac()
{
    char hostnamebuf[BUFSIZ];

#ifndef TSK_WIN32
    if (gethostname(hostnamebuf, sizeof(hostnamebuf) - 1) < 0) {
        if (tsk_verbose)
            tsk_fprintf(stderr, "Error getting host by name\n");
        strcpy(hostnamebuf, "unknown");
    }
    hostnamebuf[sizeof(hostnamebuf) - 1] = 0;
#else
    strcpy(hostnamebuf, "unknown");
#endif

    /*
     * Identify the fields in the data that follow.
     */
    tsk_printf
        ("md5|file|st_ino|st_ls|st_uid|st_gid|st_size|st_atime|st_mtime|st_ctime|st_crtime\n");

    return;
}


/* print_inode - list generic inode */

static TSK_WALK_RET_ENUM
ils_act(TSK_FS_FILE * fs_file, void *ptr)
{
    ILS_DATA *data = (ILS_DATA *) ptr;

    // if we have no link count and want open files -- exit
    if ((fs_file->meta->nlink == 0)
        && ((data->flags & TSK_FS_ILS_OPEN) != 0)) {
        return TSK_WALK_CONT;
    }

    // verify link flags
    if ((fs_file->meta->nlink == 0)
        && ((data->flags & TSK_FS_ILS_UNLINK) == 0)) {
        return TSK_WALK_CONT;
    }
    else if ((fs_file->meta->nlink > 0)
        && ((data->flags & TSK_FS_ILS_LINK) == 0)) {
        return TSK_WALK_CONT;
    }

    if (data->sec_skew != 0) {
        fs_file->meta->mtime -= data->sec_skew;
        fs_file->meta->atime -= data->sec_skew;
        fs_file->meta->ctime -= data->sec_skew;
        fs_file->meta->crtime -= data->sec_skew;
    }
    tsk_printf("%" PRIuINUM "|%c|%" PRIuUID "|%" PRIuGID "|%" PRIu32 "|%"
        PRIu32 "|%" PRIu32 "|%" PRIu32,
        fs_file->meta->addr,
        (fs_file->meta->flags & TSK_FS_META_FLAG_ALLOC) ? 'a' : 'f',
        fs_file->meta->uid, fs_file->meta->gid,
        (uint32_t) fs_file->meta->mtime, (uint32_t) fs_file->meta->atime,
        (uint32_t) fs_file->meta->ctime, (uint32_t) fs_file->meta->crtime);

    if (data->sec_skew != 0) {
        fs_file->meta->mtime += data->sec_skew;
        fs_file->meta->atime += data->sec_skew;
        fs_file->meta->ctime += data->sec_skew;
        fs_file->meta->crtime += data->sec_skew;
    }

    tsk_printf("|%lo|%d|%" PRIuOFF "\n",
        (unsigned long) fs_file->meta->mode, fs_file->meta->nlink,
        fs_file->meta->size);

    return TSK_WALK_CONT;
}


/*
 * Print the inode information in the format that the mactimes program expects
 */

static TSK_WALK_RET_ENUM
ils_mac_act(TSK_FS_FILE * fs_file, void *ptr)
{
    char ls[12];
    ILS_DATA *data = (ILS_DATA *) ptr;

    if ((fs_file->meta->nlink == 0)
        && ((data->flags & TSK_FS_ILS_UNLINK) == 0)) {
        return TSK_WALK_CONT;
    }
    else if ((fs_file->meta->nlink > 0)
        && ((data->flags & TSK_FS_ILS_LINK) == 0)) {
        return TSK_WALK_CONT;
    }

    /* ADD image and file name (if we have one) */
    TFPRINTF(stdout, _TSK_T("0|<%s-"), data->image);
    tsk_printf("%s%s%s-%" PRIuINUM ">|%" PRIuINUM "|",
        (fs_file->meta->name2) ? fs_file->meta->name2->name : "",
        (fs_file->meta->name2) ? "-" : "",
        (fs_file->meta->flags & TSK_FS_META_FLAG_ALLOC) ? "alive" : "dead",
        fs_file->meta->addr, fs_file->meta->addr);

    /* Print the "ls" mode in ascii format */
    tsk_fs_meta_make_ls(fs_file->meta, ls, sizeof(ls));

    if (data->sec_skew != 0) {
        fs_file->meta->mtime -= data->sec_skew;
        fs_file->meta->atime -= data->sec_skew;
        fs_file->meta->ctime -= data->sec_skew;
        fs_file->meta->crtime -= data->sec_skew;
    }

    tsk_printf("-/%s|%" PRIuUID "|%" PRIuGID "|%" PRIuOFF "|%" PRIu32
        "|%" PRIu32 "|%" PRIu32 "|%" PRIu32 "\n",
        ls,
        fs_file->meta->uid, fs_file->meta->gid, fs_file->meta->size,
        (uint32_t) fs_file->meta->atime, (uint32_t) fs_file->meta->mtime,
        (uint32_t) fs_file->meta->ctime, (uint32_t) fs_file->meta->crtime);

    if (data->sec_skew != 0) {
        fs_file->meta->mtime -= data->sec_skew;
        fs_file->meta->atime -= data->sec_skew;
        fs_file->meta->ctime -= data->sec_skew;
        fs_file->meta->crtime -= data->sec_skew;
    }

    return TSK_WALK_CONT;
}



/**
 * Library API for inode walking.
 *
 * @param fs File system to analyze
 * @param lclflags TSK_FS_ILS_XXX flag settings
 * @param istart Starting inode address
 * @param ilast Ending inode address
 * @param flags Inode walk flags
 * @param skew clock skew in seconds
 * @param img Path to disk image name for header
 *
 * @returns 1 on error and 0 on success 
 */
uint8_t
tsk_fs_ils(TSK_FS_INFO * fs, TSK_FS_ILS_FLAG_ENUM lclflags,
    TSK_INUM_T istart, TSK_INUM_T ilast, TSK_FS_META_FLAG_ENUM flags,
    int32_t skew, const TSK_TCHAR * img)
{
    ILS_DATA data;

    /* If orphan is desired, then make sure LINK flags are set */
    if (flags & TSK_FS_META_FLAG_ORPHAN) {
        lclflags |= (TSK_FS_ILS_LINK | TSK_FS_ILS_UNLINK);
    }
    /* if OPEN lcl flag is given, then make sure ALLOC is not and UNALLOC is */
    if (lclflags & TSK_FS_ILS_OPEN) {
        flags |= TSK_FS_META_FLAG_UNALLOC;
        flags &= ~TSK_FS_META_FLAG_ALLOC;
        lclflags |= TSK_FS_ILS_LINK;
        lclflags &= ~TSK_FS_ILS_UNLINK;
    }
    else {
        /* If LINK is not set at all, then set them */
        if (((lclflags & TSK_FS_ILS_LINK) == 0)
            && ((lclflags & TSK_FS_ILS_UNLINK) == 0))
            lclflags |= (TSK_FS_ILS_LINK | TSK_FS_ILS_UNLINK);
    }

    data.flags = lclflags;
    data.sec_skew = skew;

    /* Print the data */
    if (lclflags & TSK_FS_ILS_MAC) {
        TSK_TCHAR *tmpptr;
        data.image = img;

#ifdef TSK_WIN32
        tmpptr = TSTRCHR(data.image, '\\');
#else
        tmpptr = strrchr(data.image, '/');
#endif

        if (tmpptr)
            data.image = ++tmpptr;

        print_header_mac();

        if (fs->inode_walk(fs, istart, ilast, flags, ils_mac_act, &data))
            return 1;
    }
    else {
        print_header(fs);
        if (fs->inode_walk(fs, istart, ilast, flags, ils_act, &data))
            return 1;
    }

    return 0;
}
