/*
** fatfs
** The Sleuth Kit
**
** Content and meta data layer support for the FAT file system
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2006-2011 Brian Carrier, Basis Technology.  All Rights reserved
** Copyright (c) 2003-2005 Brian Carrier.  All rights reserved
**
** TASK
** Copyright (c) 2002 Brian Carrier, @stake Inc.  All rights reserved
**
**
** This software is distributed under the Common Public License 1.0
**
** Unicode added with support from I.D.E.A.L. Technology Corp (Aug '05)
**
*/

/**
 * \file fatfs_meta.c
 * Contains the internal TSK FAT file system code to handle metadata structures.
 */

#include "tsk_fatfs.h"
#include "tsk_fatxxfs.h"
#include "tsk_exfatfs.h"

/*
 * Identify if the dentry is a valid 8.3 name
 *
 * returns 1 if it is, 0 if it does not
 */
uint8_t
is_83_name(FATXXFS_DENTRY * de)
{
    if (!de)
        return 0;

    /* The IS_NAME macro will fail if the value is 0x05, which is only
     * valid in name[0], similarly with '.' */
    if ((de->name[0] != FATFS_SLOT_E5) && (de->name[0] != '.') &&
        (FATFS_IS_83_NAME(de->name[0]) == 0)) {
        if (tsk_verbose)
            fprintf(stderr, "fatfs_is_83_name: name[0] is invalid\n");
        return 0;
    }

    // the name cannot start with 0x20
    else if (de->name[0] == 0x20) {
        if (tsk_verbose)
            fprintf(stderr, "fatfs_is_83_name: name[0] has 0x20\n");
        return 0;
    }

    /* the second name field can only be . if the first one is a . */
    if (de->name[1] == '.') {
        if (de->name[0] != '.') {
            if (tsk_verbose)
                fprintf(stderr, "fatfs_is_83_name: name[1] is .\n");
            return 0;
        }
    }
    else if (FATFS_IS_83_NAME(de->name[1]) == 0) {
        if (tsk_verbose)
            fprintf(stderr, "fatfs_is_83_name: name[1] is invalid\n");
        return 0;
    }

    if (FATFS_IS_83_NAME(de->name[2]) == 0) {
        if (tsk_verbose)
            fprintf(stderr, "fatfs_is_83_name: name[2] is invalid\n");
        return 0;
    }
    else if (FATFS_IS_83_NAME(de->name[3]) == 0) {
        if (tsk_verbose)
            fprintf(stderr, "fatfs_is_83_name: name[3] is invalid\n");
        return 0;
    }
    else if (FATFS_IS_83_NAME(de->name[4]) == 0) {
        if (tsk_verbose)
            fprintf(stderr, "fatfs_is_83_name: name[4] is invalid\n");
        return 0;
    }
    else if (FATFS_IS_83_NAME(de->name[5]) == 0) {
        if (tsk_verbose)
            fprintf(stderr, "fatfs_is_83_name: name[5] is invalid\n");
        return 0;
    }
    else if (FATFS_IS_83_NAME(de->name[6]) == 0) {
        if (tsk_verbose)
            fprintf(stderr, "fatfs_is_83_name: name[6] is invalid\n");
        return 0;
    }
    else if (FATFS_IS_83_NAME(de->name[7]) == 0) {
        if (tsk_verbose)
            fprintf(stderr, "fatfs_is_83_name: name[7] is invalid\n");
        return 0;
    }
    else if (FATFS_IS_83_NAME(de->ext[0]) == 0) {
        if (tsk_verbose)
            fprintf(stderr, "fatfs_is_83_name: ext[0] is invalid\n");
        return 0;
    }
    else if (FATFS_IS_83_NAME(de->ext[1]) == 0) {
        if (tsk_verbose)
            fprintf(stderr, "fatfs_is_83_name: ext[1] is invalid\n");
        return 0;
    }
    else if (FATFS_IS_83_NAME(de->ext[2]) == 0) {
        if (tsk_verbose)
            fprintf(stderr, "fatfs_is_83_name: ext[2] is invalid\n");
        return 0;
    }

    /* Ensure that if we get a "space", that the rest of the
     * name is spaces.  This is not in the spec, but is how
     * windows operates and serves as a good check to remove
     * false positives.  We do not do this check for the
     * volume label though. */
    if ((de->attrib & FATFS_ATTR_VOLUME) != FATFS_ATTR_VOLUME) {
        if (((de->name[1] == 0x20) && (de->name[2] != 0x20)) ||
            ((de->name[2] == 0x20) && (de->name[3] != 0x20)) ||
            ((de->name[3] == 0x20) && (de->name[4] != 0x20)) ||
            ((de->name[4] == 0x20) && (de->name[5] != 0x20)) ||
            ((de->name[5] == 0x20) && (de->name[6] != 0x20)) ||
            ((de->name[6] == 0x20) && (de->name[7] != 0x20)) ||
            ((de->ext[1] == 0x20) && (de->ext[2] != 0x20))) {
            if (tsk_verbose)
                fprintf(stderr,
                    "fatfs_is_83_name: space before non-space\n");
            return 0;
        }
    }

    return 1;
}

/*
** Convert the DOS time to the UNIX version
**
** UNIX stores the time in seconds from 1970 in UTC
** FAT dates are the actual date with the year relative to 1980
**
*/
time_t
dos2unixtime(uint16_t date, uint16_t time, uint8_t timetens)
{
    struct tm tm1;
    time_t ret;

    if (date == 0)
        return 0;

    memset(&tm1, 0, sizeof(struct tm));

    tm1.tm_sec = ((time & FATFS_SEC_MASK) >> FATFS_SEC_SHIFT) * 2;
    if ((tm1.tm_sec < 0) || (tm1.tm_sec > 60))
        tm1.tm_sec = 0;
    // the ctimetens value has a range of 0 to 199
    if (timetens > 100)
        tm1.tm_sec++;

    tm1.tm_min = ((time & FATFS_MIN_MASK) >> FATFS_MIN_SHIFT);
    if ((tm1.tm_min < 0) || (tm1.tm_min > 59))
        tm1.tm_min = 0;

    tm1.tm_hour = ((time & FATFS_HOUR_MASK) >> FATFS_HOUR_SHIFT);
    if ((tm1.tm_hour < 0) || (tm1.tm_hour > 23))
        tm1.tm_hour = 0;

    tm1.tm_mday = ((date & FATFS_DAY_MASK) >> FATFS_DAY_SHIFT);
    if ((tm1.tm_mday < 1) || (tm1.tm_mday > 31))
        tm1.tm_mday = 0;

    tm1.tm_mon = ((date & FATFS_MON_MASK) >> FATFS_MON_SHIFT) - 1;
    if ((tm1.tm_mon < 0) || (tm1.tm_mon > 11))
        tm1.tm_mon = 0;

    /* There is a limit to the year because the UNIX time value is
     * a 32-bit value
     * the maximum UNIX time is Tue Jan 19 03:14:07 2038
     */
    tm1.tm_year = ((date & FATFS_YEAR_MASK) >> FATFS_YEAR_SHIFT) + 80;
    if ((tm1.tm_year < 0) || (tm1.tm_year > 137))
        tm1.tm_year = 0;

    /* set the daylight savings variable to -1 so that mktime() figures
     * it out */
    tm1.tm_isdst = -1;

    ret = mktime(&tm1);

    if (ret < 0) {
        if (tsk_verbose)
            tsk_fprintf(stderr,
                "dos2unixtime: Error running mktime() on: %d:%d:%d %d/%d/%d\n",
                ((time & FATFS_HOUR_MASK) >> FATFS_HOUR_SHIFT),
                ((time & FATFS_MIN_MASK) >> FATFS_MIN_SHIFT),
                ((time & FATFS_SEC_MASK) >> FATFS_SEC_SHIFT) * 2,
                ((date & FATFS_MON_MASK) >> FATFS_MON_SHIFT) - 1,
                ((date & FATFS_DAY_MASK) >> FATFS_DAY_SHIFT),
                ((date & FATFS_YEAR_MASK) >> FATFS_YEAR_SHIFT) + 80);
        return 0;
    }

    return ret;
}


/** 
 * Cleans up a char string so that it is only ASCII. We do this
 * before we copy something into a TSK buffer that is supposed 
 * to be UTF-8.  If it is not ASCII and it is from a single-byte
 * data structure, then we we clean it up because we dont' know
 * what the actual encoding is (or if it is corrupt). 
 * @param name Name to cleanup
 */
void
fatfs_cleanup_ascii(char *name)
{
    int i;
    for (i = 0; name[i] != '\0'; i++) {
        if ((unsigned char) (name[i]) > 0x7e) {
            name[i] = '^';
        }
    }
}


/**
 * \internal
 * Create an FS_INODE structure for the root directory.  FAT does
 * not have a directory entry for the root directory, but this
 * function collects the needed data to make one.
 *
 * @param fatfs File system to analyze
 * @param fs_meta Inode structure to copy root directory information into.
 * @return 1 on error and 0 on success
 */
uint8_t
fatfs_make_root(FATFS_INFO * fatfs, TSK_FS_META * fs_meta)
{
//    TSK_FS_INFO *fs = (TSK_FS_INFO *) fatfs;
    TSK_DADDR_T *addr_ptr;

    fs_meta->type = (TSK_FS_META_TYPE_DIR);
    fs_meta->mode = 0;
    fs_meta->nlink = 1;
    fs_meta->addr = FATFS_ROOTINO;
    fs_meta->flags = (TSK_FS_META_FLAG_USED | TSK_FS_META_FLAG_ALLOC);
    fs_meta->uid = fs_meta->gid = 0;
    fs_meta->mtime = fs_meta->atime = fs_meta->ctime = fs_meta->crtime = 0;
    fs_meta->mtime_nano = fs_meta->atime_nano = fs_meta->ctime_nano =
        fs_meta->crtime_nano = 0;

    if (fs_meta->name2 == NULL) {
        if ((fs_meta->name2 = (TSK_FS_META_NAME_LIST *)
                tsk_malloc(sizeof(TSK_FS_META_NAME_LIST))) == NULL)
            return 1;
        fs_meta->name2->next = NULL;
    }
    fs_meta->name2->name[0] = '\0';

    fs_meta->attr_state = TSK_FS_META_ATTR_EMPTY;
    if (fs_meta->attr) {
        tsk_fs_attrlist_markunused(fs_meta->attr);
    }
    addr_ptr = (TSK_DADDR_T *) fs_meta->content_ptr;

    /* TSK_FS_TYPE_FAT12 and TSK_FS_TYPE_FAT16 don't use the FAT for root directory, so
     * we will have to fake it.
     */
    if (fatfs->fs_info.ftype != TSK_FS_TYPE_FAT32) {
        TSK_DADDR_T snum;

        /* Other code will have to check this as a special condition
         */
        addr_ptr[0] = 1;

        /* difference between end of FAT and start of clusters */
        snum = fatfs->firstclustsect - fatfs->firstdatasect;

        /* number of bytes */
        fs_meta->size = snum << fatfs->ssize_sh;
    }
    else {
        /* Get the number of allocated clusters */
        TSK_DADDR_T cnum;
        TSK_DADDR_T clust;
        TSK_LIST *list_seen = NULL;

        /* base cluster */
        clust = FATFS_SECT_2_CLUST(fatfs, fatfs->rootsect);
        addr_ptr[0] = clust;

        cnum = 0;
        while ((clust) && (0 == FATFS_ISEOF(clust, FATFS_32_MASK))) {
            TSK_DADDR_T nxt;

            /* Make sure we do not get into an infinite loop */
            if (tsk_list_find(list_seen, clust)) {
                if (tsk_verbose)
                    tsk_fprintf(stderr,
                        "Loop found while determining root directory size\n");
                break;
            }
            if (tsk_list_add(&list_seen, clust)) {
                tsk_list_free(list_seen);
                list_seen = NULL;
                return 1;
            }

            cnum++;
            if (fatfs_getFAT(fatfs, clust, &nxt))
                break;
            else
                clust = nxt;
        }
        tsk_list_free(list_seen);
        list_seen = NULL;
        fs_meta->size = (cnum * fatfs->csize) << fatfs->ssize_sh;
    }
    return 0;
}


/**
* \internal
 * Create an FS_INODE structure for the master boot record.
 *
 * @param fatfs File system to analyze
 * @param fs_meta Inode structure to copy file information into.
 * @return 1 on error and 0 on success
 */
uint8_t
fatfs_make_mbr(FATFS_INFO * fatfs, TSK_FS_META * fs_meta)
{
    TSK_DADDR_T *addr_ptr;
    TSK_FS_INFO *fs = (TSK_FS_INFO *) fatfs;

    fs_meta->type = TSK_FS_META_TYPE_VIRT;
    fs_meta->mode = 0;
    fs_meta->nlink = 1;
    fs_meta->addr = FATFS_MBRINO(fs);
    fs_meta->flags = (TSK_FS_META_FLAG_USED | TSK_FS_META_FLAG_ALLOC);
    fs_meta->uid = fs_meta->gid = 0;
    fs_meta->mtime = fs_meta->atime = fs_meta->ctime = fs_meta->crtime = 0;
    fs_meta->mtime_nano = fs_meta->atime_nano = fs_meta->ctime_nano =
        fs_meta->crtime_nano = 0;

    if (fs_meta->name2 == NULL) {
        if ((fs_meta->name2 = (TSK_FS_META_NAME_LIST *)
                tsk_malloc(sizeof(TSK_FS_META_NAME_LIST))) == NULL)
            return 1;
        fs_meta->name2->next = NULL;
    }
    strncpy(fs_meta->name2->name, FATFS_MBRNAME,
        TSK_FS_META_NAME_LIST_NSIZE);

    fs_meta->attr_state = TSK_FS_META_ATTR_EMPTY;
    if (fs_meta->attr) {
        tsk_fs_attrlist_markunused(fs_meta->attr);
    }

    addr_ptr = (TSK_DADDR_T *) fs_meta->content_ptr;
    addr_ptr[0] = 0;
    fs_meta->size = 512;

    return 0;
}

/**
* \internal
 * Create an FS_INODE structure for the FAT tables.
 *
 * @param fatfs File system to analyze
 * @param a_which 1 or 2 to choose between defining FAT1 or FAT2
 * @param fs_meta Inode structure to copy file information into.
 * @return 1 on error and 0 on success
 */
uint8_t
fatfs_make_fat(FATFS_INFO * fatfs, uint8_t a_which, TSK_FS_META * fs_meta)
{
    TSK_FS_INFO *fs = (TSK_FS_INFO *) fatfs;
    TSK_DADDR_T *addr_ptr;

    fs_meta->type = TSK_FS_META_TYPE_VIRT;
    fs_meta->mode = 0;
    fs_meta->nlink = 1;

    fs_meta->flags = (TSK_FS_META_FLAG_USED | TSK_FS_META_FLAG_ALLOC);
    fs_meta->uid = fs_meta->gid = 0;
    fs_meta->mtime = fs_meta->atime = fs_meta->ctime = fs_meta->crtime = 0;
    fs_meta->mtime_nano = fs_meta->atime_nano = fs_meta->ctime_nano =
        fs_meta->crtime_nano = 0;

    if (fs_meta->name2 == NULL) {
        if ((fs_meta->name2 = (TSK_FS_META_NAME_LIST *)
                tsk_malloc(sizeof(TSK_FS_META_NAME_LIST))) == NULL)
            return 1;
        fs_meta->name2->next = NULL;
    }

    if (a_which == 1) {
        fs_meta->addr = FATFS_FAT1INO(fs);
        strncpy(fs_meta->name2->name, FATFS_FAT1NAME,
            TSK_FS_META_NAME_LIST_NSIZE);
        addr_ptr = (TSK_DADDR_T *) fs_meta->content_ptr;
        addr_ptr[0] = fatfs->firstfatsect;
    }
    else if (a_which == 2) {
        fs_meta->addr = FATFS_FAT2INO(fs);
        strncpy(fs_meta->name2->name, FATFS_FAT2NAME,
            TSK_FS_META_NAME_LIST_NSIZE);
        addr_ptr = (TSK_DADDR_T *) fs_meta->content_ptr;
        addr_ptr[0] = fatfs->firstfatsect + fatfs->sectperfat;
    }
    else {
        ////@@@
    }

    fs_meta->attr_state = TSK_FS_META_ATTR_EMPTY;
    if (fs_meta->attr) {
        tsk_fs_attrlist_markunused(fs_meta->attr);
    }

    fs_meta->size = fatfs->sectperfat * fs->block_size;

    return 0;
}

/**************************************************************************
 *
 * INODE WALKING
 *
 *************************************************************************/
/* Mark the sector used in the bitmap */
static TSK_WALK_RET_ENUM
inode_walk_file_act(TSK_FS_FILE * fs_file, TSK_OFF_T a_off,
    TSK_DADDR_T addr, char *buf, size_t size,
    TSK_FS_BLOCK_FLAG_ENUM a_flags, void *a_ptr)
{
    setbit((uint8_t *) a_ptr, addr);
    return TSK_WALK_CONT;
}

/* The inode_walk call back for each file.  we want only the directories */
static TSK_WALK_RET_ENUM
inode_walk_dent_act(TSK_FS_FILE * fs_file, const char *a_path, void *a_ptr)
{
    if ((fs_file->meta == NULL)
        || (fs_file->meta->type != TSK_FS_META_TYPE_DIR))
        return TSK_WALK_CONT;

    /* Get the sector addresses & ignore any errors */
    if (tsk_fs_file_walk(fs_file,
            TSK_FS_FILE_WALK_FLAG_SLACK | TSK_FS_FILE_WALK_FLAG_AONLY,
            inode_walk_file_act, a_ptr)) {
        tsk_error_reset();
    }

    return TSK_WALK_CONT;
}

/*
 * walk the inodes
 *
 * Flags that are used: TSK_FS_META_FLAG_ALLOC, TSK_FS_META_FLAG_UNALLOC,
 * TSK_FS_META_FLAG_USED, TSK_FS_META_FLAG_UNUSED, TSK_FS_META_FLAG_ORPHAN
 *
 */
uint8_t
fatfs_inode_walk(TSK_FS_INFO * fs, TSK_INUM_T start_inum,
    TSK_INUM_T end_inum, TSK_FS_META_FLAG_ENUM a_flags,
    TSK_FS_META_WALK_CB a_action, void *a_ptr)
{
    char *myname = "fatfs_inode_walk";
    FATFS_INFO *fatfs = (FATFS_INFO *) fs;
    TSK_INUM_T end_inum_tmp;
    TSK_FS_FILE *fs_file;
    TSK_DADDR_T sect, ssect, lsect;
    char *dino_buf;
    FATFS_DENTRY *dep;
    unsigned int myflags, didx;
    uint8_t *sect_alloc;
    ssize_t cnt;
    uint8_t done = 0;
    uint8_t(*is_dentry)(FATFS_INFO*, FATFS_DENTRY*, uint8_t) = NULL;
    TSK_RETVAL_ENUM(*dinode_copy)(FATFS_INFO*, TSK_FS_META*, FATFS_DENTRY*, TSK_DADDR_T, TSK_INUM_T) = NULL;

    // clean up any error messages that are lying around
    tsk_error_reset();

    /*
     * Sanity checks.
     */
    if (start_inum < fs->first_inum || start_inum > fs->last_inum) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("%s: Start inode:  %" PRIuINUM "", myname,
            start_inum);
        return 1;
    }
    else if (end_inum < fs->first_inum || end_inum > fs->last_inum
        || end_inum < start_inum) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("%s: End inode: %" PRIuINUM "", myname,
            end_inum);
        return 1;
    }

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "fatfs_inode_walk: Inode Walking %" PRIuINUM " to %"
            PRIuINUM "\n", start_inum, end_inum);

    /* If ORPHAN is wanted, then make sure that the a_flags are correct */
    if (a_flags & TSK_FS_META_FLAG_ORPHAN) {
        a_flags |= TSK_FS_META_FLAG_UNALLOC;
        a_flags &= ~TSK_FS_META_FLAG_ALLOC;
        a_flags |= TSK_FS_META_FLAG_USED;
        a_flags &= ~TSK_FS_META_FLAG_UNUSED;
    }

    else {
        if (((a_flags & TSK_FS_META_FLAG_ALLOC) == 0) &&
            ((a_flags & TSK_FS_META_FLAG_UNALLOC) == 0)) {
            a_flags |= (TSK_FS_META_FLAG_ALLOC | TSK_FS_META_FLAG_UNALLOC);
        }

        /* If neither of the USED or UNUSED a_flags are set, then set them
         * both
         */
        if (((a_flags & TSK_FS_META_FLAG_USED) == 0) &&
            ((a_flags & TSK_FS_META_FLAG_UNUSED) == 0)) {
            a_flags |= (TSK_FS_META_FLAG_USED | TSK_FS_META_FLAG_UNUSED);
        }
    }


    /* If we are looking for orphan files and have not yet filled
     * in the list of unalloc inodes that are pointed to, then fill
     * in the list
     */
    if ((a_flags & TSK_FS_META_FLAG_ORPHAN)) {
        if (tsk_fs_dir_load_inum_named(fs) != TSK_OK) {
            tsk_error_errstr2_concat
                ("- fatfs_inode_walk: identifying inodes allocated by file names");
            return 1;
        }
    }

    if ((fs_file = tsk_fs_file_alloc(fs)) == NULL)
        return 1;

    if ((fs_file->meta =
            tsk_fs_meta_alloc(FATFS_FILE_CONTENT_LEN)) == NULL)
        return 1;


    // handle the root directory
    if (start_inum == FATFS_ROOTINO) {

        if (((TSK_FS_META_FLAG_ALLOC & a_flags) == TSK_FS_META_FLAG_ALLOC)
            && ((TSK_FS_META_FLAG_USED & a_flags) == TSK_FS_META_FLAG_USED)
            && ((TSK_FS_META_FLAG_ORPHAN & a_flags) == 0)) {
            int retval;

            if (fatfs_make_root(fatfs, fs_file->meta)) {
                tsk_fs_file_close(fs_file);
                return 1;
            }

            retval = a_action(fs_file, a_ptr);
            if (retval == TSK_WALK_STOP) {
                tsk_fs_file_close(fs_file);
                return 0;
            }
            else if (retval == TSK_WALK_ERROR) {
                tsk_fs_file_close(fs_file);
                return 1;
            }
        }
        /* advance it so that it is a valid starting point */
        start_inum++;

        // exit if that is all that was requested
        if (start_inum == end_inum) {
            tsk_fs_file_close(fs_file);
            return 0;
        }
    }

    /* We will be looking at each sector to see if it contains directory
     * entries.  We can make mistakes and ignore sectors that have valid
     * entries in them.  To make sure we at least get all sectors that
     * are allocated by directories in the directory tree, we will
     * run name_walk and then a file walk on each dir.
     * We'll be make sure to print those.  We skip this for ORPHAN hunting
     * because it doesn't help and can introduce infinite loop situations
     * inode_walk was called by the function that determines which inodes
     * are orphans. */
    if ((sect_alloc =
            (uint8_t *) tsk_malloc((size_t) ((fs->block_count +
                        7) / 8))) == NULL) {
        tsk_fs_file_close(fs_file);
        return 1;
    }
    if ((a_flags & TSK_FS_META_FLAG_ORPHAN) == 0) {

        if (tsk_verbose)
            tsk_fprintf(stderr,
                "fatfs_inode_walk: Walking directories to collect sector info\n");

        // Do a file_walk on the root directory to get its layout
        if (fatfs_make_root(fatfs, fs_file->meta)) {
            tsk_fs_file_close(fs_file);
            free(sect_alloc);
            return 1;
        }

        if (tsk_fs_file_walk(fs_file,
                TSK_FS_FILE_WALK_FLAG_SLACK | TSK_FS_FILE_WALK_FLAG_AONLY,
                inode_walk_file_act, (void *) sect_alloc)) {
            tsk_fs_file_close(fs_file);
            free(sect_alloc);
            return 1;
        }

        // now get the rest of the directories.
        if (tsk_fs_dir_walk(fs, fs->root_inum,
                TSK_FS_DIR_WALK_FLAG_ALLOC | TSK_FS_DIR_WALK_FLAG_RECURSE |
                TSK_FS_DIR_WALK_FLAG_NOORPHAN, inode_walk_dent_act,
                (void *) sect_alloc)) {
            tsk_error_errstr2_concat
                ("- fatfs_inode_walk: mapping directories");
            tsk_fs_file_close(fs_file);
            free(sect_alloc);
            return 1;
        }
    }

    /* start analyzing each sector
     *
     * Perform a test on the first 32 bytes of each sector to identify if
     * the sector contains directory entries.  If it does, then continue
     * to analyze it.  If not, then read the next sector
     */

    /* identify the starting and ending inodes sector addrs */

    /* we need to handle end_inum specially if it is for the
     * virtual ORPHANS directory or virtual FAT files.
     * Handle these outside of the loop. */
    if (end_inum > fs->last_inum - FATFS_NUM_SPECFILE)
        end_inum_tmp = fs->last_inum - FATFS_NUM_SPECFILE;
    else
        end_inum_tmp = end_inum;

    ssect = FATFS_INODE_2_SECT(fatfs, start_inum);
    lsect = FATFS_INODE_2_SECT(fatfs, end_inum_tmp);

    if (ssect > fs->last_block) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr
            ("fatfs_inode_walk: Starting inode in sector too big for image: %"
            PRIuDADDR, ssect);
        tsk_fs_file_close(fs_file);
        free(sect_alloc);
        return 1;
    }
    else if (lsect > fs->last_block) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr
            ("fatfs_inode_walk: Ending inode in sector too big for image: %"
            PRIuDADDR, lsect);
        tsk_fs_file_close(fs_file);
        free(sect_alloc);
        return 1;
    }

    sect = ssect;
    if ((dino_buf =
            (char *) tsk_malloc(fatfs->csize << fatfs->ssize_sh)) ==
        NULL) {
        tsk_fs_file_close(fs_file);
        free(sect_alloc);
        return 1;
    }
    while (sect <= lsect) {
        int clustalloc;         // 1 if current sector / cluster is allocated
        size_t sect_proc;       // number of sectors read for this loop
        size_t sidx;            // sector index for loop
        uint8_t basicTest;      // 1 if only a basic dentry test is needed

        /* This occurs for the root directory of TSK_FS_TYPE_FAT12/16
         *
         * We are going to process the image in clusters, so take care of the root
         * directory seperately.
         */
        if (sect < fatfs->firstclustsect) {

            // there are no orphans in the root directory
            if ((a_flags & TSK_FS_META_FLAG_ORPHAN) != 0) {
                sect = fatfs->firstclustsect;
                continue;
            }

            clustalloc = 1;

            /* read the sector */
            cnt = tsk_fs_read_block(fs, sect, dino_buf, fatfs->ssize);
            if (cnt != fatfs->ssize) {
                if (cnt >= 0) {
                    tsk_error_reset();
                    tsk_error_set_errno(TSK_ERR_FS_READ);
                }
                tsk_error_set_errstr2
                    ("fatfs_inode_walk (root dir): sector: %" PRIuDADDR,
                    sect);
                tsk_fs_file_close(fs_file);
                free(sect_alloc);
                free(dino_buf);
                return 1;
            }
            sect_proc = 1;
        }

        /* For the data area, we will read in cluster-sized chunks */
        else {

            /* get the base sector for the cluster in which the first inode exists */
            sect =
                FATFS_CLUST_2_SECT(fatfs, (FATFS_SECT_2_CLUST(fatfs,
                        sect)));

            /* if the cluster is not allocated, then do not go into it if we
             * only want allocated/link entries
             * If it is allocated, then go into it no matter what
             */
            clustalloc = fatfs_is_sectalloc(fatfs, sect);
            if (clustalloc == -1) {
                tsk_fs_file_close(fs_file);
                free(sect_alloc);
                free(dino_buf);
                return 1;
            }
            else if ((clustalloc == 0)
                && ((a_flags & TSK_FS_META_FLAG_UNALLOC) == 0)) {
                sect += fatfs->csize;
                continue;
            }


            /* If it is allocated, but we know it is not allocated to a
             * directory then skip it.  NOTE: This will miss unallocated
             * entries in slack space of the file...
             */
            if ((clustalloc == 1) && (isset(sect_alloc, sect) == 0)) {
                sect += fatfs->csize;
                continue;
            }

            /* The final cluster may not be full */
            if (lsect - sect + 1 < fatfs->csize)
                sect_proc = (size_t) (lsect - sect + 1);
            else
                sect_proc = fatfs->csize;

            /* read the full cluster */
            cnt = tsk_fs_read_block
                (fs, sect, dino_buf, sect_proc << fatfs->ssize_sh);
            if (cnt != (sect_proc << fatfs->ssize_sh)) {
                if (cnt >= 0) {
                    tsk_error_reset();
                    tsk_error_set_errno(TSK_ERR_FS_READ);
                }
                tsk_error_set_errstr2("fatfs_inode_walk: sector: %"
                    PRIuDADDR, sect);
                tsk_fs_file_close(fs_file);
                free(sect_alloc);
                free(dino_buf);
                return 1;
            }
        }

        /* do an in-depth test if we are in an unallocted cluster
         * or if we are not in a known directory. */
        basicTest = 1;
        if ((isset(sect_alloc, sect) == 0) || (clustalloc == 0))
            basicTest = 0;

        // cycle through the sectors read
        for (sidx = 0; sidx < sect_proc; sidx++) {
            TSK_INUM_T inum;
            uint8_t isInDir;

            dep = (FATFS_DENTRY *) & dino_buf[sidx << fatfs->ssize_sh];

            /* if we know it is not part of a directory and it is not valid dentires,
             * then skip it */
            isInDir = isset(sect_alloc, sect);
            if ((isInDir == 0) && (fatxxfs_is_dentry(fatfs, (FATFS_DENTRY*)dep, 0) == 0)) {
                sect++;
                continue;
            }

            /* See if the last inode in this sector is smaller than the starting one */
            if (FATFS_SECT_2_INODE(fatfs, sect + 1) < start_inum) {
                sect++;
                continue;
            }

            /* get the base inode address of this sector */
            inum = FATFS_SECT_2_INODE(fatfs, sect);

            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "fatfs_inode_walk: Processing sector %" PRIuDADDR
                    " starting at inode %" PRIuINUM "\n", sect, inum);

            /* cycle through the directory entries */

            for (didx = 0; didx < fatfs->dentry_cnt_se;
                didx++, inum++, dep++) {
                int retval;
                TSK_RETVAL_ENUM retval2;

                /* If less, then move on */
                if (inum < start_inum)
                    continue;

                /* If we are done, then exit from the loops  */
                if (inum > end_inum_tmp) {
                    done = 1;
                    break;
                }


                /* if this is a long file name entry, then skip it and
                 * wait for the short name */
                if ((fs->ftype != TSK_FS_TYPE_EXFAT) && 
                    ((((FATXXFS_DENTRY*)dep)->attrib & FATFS_ATTR_LFN) == FATFS_ATTR_LFN)) // RJCTODO: Fix
                    continue;


                /* we don't care about . and .. entries because they
                 * are redundant of other 'inode' entries */
                if ((fs->ftype != TSK_FS_TYPE_EXFAT) && 
                    ((((FATXXFS_DENTRY*)dep)->attrib & FATFS_ATTR_DIRECTORY) == FATFS_ATTR_DIRECTORY) &&
                    (((FATXXFS_DENTRY*)dep)->name[0] == '.')) // RJCTODO: Fix
                    continue;


                /* Allocation status
                 * This is determined first by the sector allocation status
                 * an then the dentry flag.  When a directory is deleted, the
                 * contents are not always set to unallocated
                 */
                if ((fs->ftype != TSK_FS_TYPE_EXFAT) && (clustalloc == 1)) { // RJCTODO: Fix
                    myflags =
                        ((((FATXXFS_DENTRY*)dep)->name[0] ==
                            FATFS_SLOT_DELETED) ? TSK_FS_META_FLAG_UNALLOC
                        : TSK_FS_META_FLAG_ALLOC);
                }
                else {
                    myflags = TSK_FS_META_FLAG_UNALLOC;
                }

                if ((a_flags & myflags) != myflags)
                    continue;

                /* Slot has not been used yet */
                myflags |= ((((FATXXFS_DENTRY*)dep)->name[0] == FATFS_SLOT_EMPTY) ?
                    TSK_FS_META_FLAG_UNUSED : TSK_FS_META_FLAG_USED);

                if ((a_flags & myflags) != myflags)
                    continue;

                /* If we want only orphans, then check if this
                 * inode is in the seen list
                 */
                if ((myflags & TSK_FS_META_FLAG_UNALLOC) &&
                    (a_flags & TSK_FS_META_FLAG_ORPHAN) &&
                    (tsk_fs_dir_find_inum_named(fs, inum))) {
                    continue;
                }

                if (fs->ftype == TSK_FS_TYPE_EXFAT) {
                    is_dentry = exfatfs_is_dentry;
                    dinode_copy = exfatfs_dinode_copy;
                }
                else {
                    is_dentry = fatxxfs_is_dentry;
                    dinode_copy = fatxxfs_dinode_copy; 
                }

                /* Do a final sanity check */
                if (0 == is_dentry(fatfs, dep, basicTest))
                    continue;

                if ((retval2 =
                        dinode_copy(fatfs, fs_file->meta, dep, sect,
                            inum)) != TSK_OK) {
                    /* Ignore this error and continue */
                    if (retval2 == TSK_COR) {
                        if (tsk_verbose)
                            tsk_error_print(stderr);
                        tsk_error_reset();
                        continue;
                    }
                    else {
                        tsk_fs_file_close(fs_file);
                        free(sect_alloc);
                        free(dino_buf);
                        return 1;
                    }
                }

                if (tsk_verbose)
                    tsk_fprintf(stderr,
                        "fatfs_inode_walk: Directory Entry %" PRIuINUM
                        " (%u) at sector %" PRIuDADDR "\n", inum, didx,
                        sect);

                retval = a_action(fs_file, a_ptr);
                if (retval == TSK_WALK_STOP) {
                    tsk_fs_file_close(fs_file);
                    free(sect_alloc);
                    free(dino_buf);
                    return 0;
                }
                else if (retval == TSK_WALK_ERROR) {
                    tsk_fs_file_close(fs_file);
                    free(sect_alloc);
                    free(dino_buf);
                    return 1;
                }
            }                   /* dentries */
            sect++;
            if (done)
                break;
        }
        if (done)
            break;
    }


    free(sect_alloc);
    free(dino_buf);


    // handle the virtual orphans folder and FAT files if they asked for them
    if ((end_inum > fs->last_inum - FATFS_NUM_SPECFILE)
        && (a_flags & TSK_FS_META_FLAG_ALLOC)
        && (a_flags & TSK_FS_META_FLAG_USED)
        && ((a_flags & TSK_FS_META_FLAG_ORPHAN) == 0)) {
        TSK_INUM_T inum;

        // cycle through the special files
        for (inum = fs->last_inum - FATFS_NUM_SPECFILE + 1;
            inum <= end_inum; inum++) {
            int retval;

            tsk_fs_meta_reset(fs_file->meta);

            if (inum == FATFS_MBRINO(fs)) {
                if (fatfs_make_mbr(fatfs, fs_file->meta)) {
                    tsk_fs_file_close(fs_file);
                    return 1;
                }
            }
            else if (inum == FATFS_FAT1INO(fs)) {
                if (fatfs_make_fat(fatfs, 1, fs_file->meta)) {
                    tsk_fs_file_close(fs_file);
                    return 1;
                }
            }
            else if (inum == FATFS_FAT2INO(fs)) {
                if (fatfs_make_fat(fatfs, 2, fs_file->meta)) {
                    tsk_fs_file_close(fs_file);
                    return 1;
                }
            }
            else if (inum == TSK_FS_ORPHANDIR_INUM(fs)) {
                if (tsk_fs_dir_make_orphan_dir_meta(fs, fs_file->meta)) {
                    tsk_fs_file_close(fs_file);
                    return 1;
                }
            }

            retval = a_action(fs_file, a_ptr);
            if (retval == TSK_WALK_STOP) {
                tsk_fs_file_close(fs_file);
                return 0;
            }
            else if (retval == TSK_WALK_ERROR) {
                tsk_fs_file_close(fs_file);
                return 1;
            }
        }
    }

    tsk_fs_file_close(fs_file);
    return 0;
}                               /* end of inode_walk */


/*
 * return the contents of a specific inode
 *
 * 1 is returned if an error occurs or if the entry is not
 * a valid inode
 */
uint8_t
fatfs_inode_lookup(TSK_FS_INFO * fs, TSK_FS_FILE * a_fs_file,
    TSK_INUM_T inum)
{
    FATFS_INFO *fatfs = (FATFS_INFO *) fs;
    TSK_DADDR_T sect;
    TSK_RETVAL_ENUM retval;
    FATFS_DENTRY dep;
    uint8_t(*is_dentry)(FATFS_INFO*, FATFS_DENTRY*, uint8_t) = NULL;
    TSK_RETVAL_ENUM(*dinode_copy)(FATFS_INFO*, TSK_FS_META*, FATFS_DENTRY*, TSK_DADDR_T, TSK_INUM_T) = NULL;

    // clean up any error messages that are lying around
    tsk_error_reset();

    /*
     * Sanity check.
     */
    if (inum < fs->first_inum || inum > fs->last_inum) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_INODE_NUM);
        tsk_error_set_errstr("fatfs_inode_lookup: %" PRIuINUM
            " too large/small", inum);
        return 1;
    }

    if (a_fs_file == NULL) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("fatfs_inode_lookup: fs_file is NULL");
        return 1;
    }
    if (a_fs_file->meta == NULL) {
        if ((a_fs_file->meta =
                tsk_fs_meta_alloc(FATFS_FILE_CONTENT_LEN)) == NULL)
            return 1;
    }
    else {
        tsk_fs_meta_reset(a_fs_file->meta);
    }

    /* As there is no real root inode in FAT, use the made up one */
    if (fs->ftype != TSK_FS_TYPE_EXFAT) //RJCTODO: Fix later
    {
        if (inum == FATFS_ROOTINO) {
            if (fatfs_make_root(fatfs, a_fs_file->meta))
                return 1;
            else
                return 0;
        }
        else if (inum == FATFS_MBRINO(fs)) {
            if (fatfs_make_mbr(fatfs, a_fs_file->meta))
                return 1;
            else
                return 0;
        }
        else if (inum == FATFS_FAT1INO(fs)) {
            if (fatfs_make_fat(fatfs, 1, a_fs_file->meta))
                return 1;
            else
                return 0;
        }
        else if (inum == FATFS_FAT2INO(fs)) {
            if (fatfs_make_fat(fatfs, 2, a_fs_file->meta))
                return 1;
            else
                return 0;
        }
        else if (inum == TSK_FS_ORPHANDIR_INUM(fs)) {
            if (tsk_fs_dir_make_orphan_dir_meta(fs, a_fs_file->meta))
                return 1;
            else
                return 0;
        }
    }

    /* Get the sector that this inode would be in and its offset */ 
    sect = FATFS_INODE_2_SECT(fatfs, inum);
    if (sect > fs->last_block) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_INODE_NUM);
        tsk_error_set_errstr("fatfs_inode_lookup Inode %" PRIuINUM
            " in sector too big for image: %" PRIuDADDR, inum, sect);
        return 1;
    }

    if (fatfs_dinode_load(fs, &dep, inum)) {
        return 1;
    }

    if (fs->ftype == TSK_FS_TYPE_EXFAT) {
        is_dentry = exfatfs_is_dentry;
        dinode_copy = exfatfs_dinode_copy;
    }
    else {
        is_dentry = fatxxfs_is_dentry;
        dinode_copy = fatxxfs_dinode_copy; 
    }

    /* We use only the sector allocation status for the basic/adv test.
     * Other places use information about if the sector is part of a folder
     * or not, but we don't have that...  so we could let some corrupt things
     * pass in here that get caught else where. */
    if (is_dentry(fatfs, &dep, fatfs_is_sectalloc(fatfs, sect))) {
        if ((retval =
                dinode_copy(fatfs, a_fs_file->meta, &dep, sect,
                    inum)) != TSK_OK) {
            /* If there was a unicode conversion error,
             * then still return the inode */
            if (retval == TSK_ERR) {
                return 1;
            }
            else {
                if (tsk_verbose)
                    tsk_error_print(stderr);
                tsk_error_reset();
            }
        }
        return 0;
    }
    else {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_INODE_NUM);
        tsk_error_set_errstr("fatfs_inode_lookup: %" PRIuINUM
            " is not an inode", inum);
        return 1;
    }
}

/** \internal
 * Process the file and load up the clusters into the FS_DATA attribute
 * in fs_meta. The run will list the starting sector and length in sectors
 *
 * @param a_fs_file File to process and structore to store results in
 *
 * @returns 1 on error and 0 on success
 */
uint8_t
fatfs_make_data_run(TSK_FS_FILE * a_fs_file)
{
    TSK_FS_INFO *fs;
    TSK_DADDR_T clust;
    TSK_OFF_T size_remain;
    TSK_FS_ATTR *fs_attr = NULL;
    TSK_FS_META *fs_meta;
    FATFS_INFO *fatfs;

    if ((a_fs_file == NULL) || (a_fs_file->meta == NULL)
        || (a_fs_file->fs_info == NULL)) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr
            ("fatfs_make_data_run: called with NULL pointers");
        return 1;
    }
    fs_meta = a_fs_file->meta;
    fs = a_fs_file->fs_info;
    fatfs = (FATFS_INFO *) fs;

    clust = ((TSK_DADDR_T *) fs_meta->content_ptr)[0];
    size_remain = roundup(fs_meta->size, fatfs->csize * fs->block_size);

    // see if we have already loaded the runs
    if ((fs_meta->attr != NULL)
        && (fs_meta->attr_state == TSK_FS_META_ATTR_STUDIED)) {
        return 0;
    }
    else if (fs_meta->attr_state == TSK_FS_META_ATTR_ERROR) {
        return 1;
    }
    // not sure why this would ever happen, but...
    else if (fs_meta->attr != NULL) {
        tsk_fs_attrlist_markunused(fs_meta->attr);
    }
    else if (fs_meta->attr == NULL) {
        fs_meta->attr = tsk_fs_attrlist_alloc();
    }

    // sanity check on input
    if ((clust > (fatfs->lastclust)) &&
        (FATFS_ISEOF(clust, fatfs->mask) == 0)) {
        fs_meta->attr_state = TSK_FS_META_ATTR_ERROR;
        tsk_error_reset();
        if (a_fs_file->meta->flags & TSK_FS_META_FLAG_UNALLOC)
            tsk_error_set_errno(TSK_ERR_FS_RECOVER);
        else
            tsk_error_set_errno(TSK_ERR_FS_INODE_COR);
        tsk_error_set_errstr
            ("fatfs_make_data_run: Starting cluster address too large: %"
            PRIuDADDR, clust);
        return 1;
    }


    /* We need to handle the special files specially because they
     * are not in the FAT.  Except for FAT32 root dirs, those are normal.
     */
    if ((a_fs_file->meta->addr == FATFS_ROOTINO)
        && (fs->ftype != TSK_FS_TYPE_FAT32) && (clust == 1)) {
        TSK_FS_ATTR_RUN *data_run;

        if (tsk_verbose)
            tsk_fprintf(stderr,
                "fatfs_make_data_run: Loading root directory\n");

        // make a non-resident run
        data_run = tsk_fs_attr_run_alloc();
        if (data_run == NULL) {
            return 1;
        }
        data_run->addr = fatfs->rootsect;
        data_run->len = fatfs->firstclustsect - fatfs->firstdatasect;

        if ((fs_attr =
                tsk_fs_attrlist_getnew(fs_meta->attr,
                    TSK_FS_ATTR_NONRES)) == NULL) {
            return 1;
        }

        // initialize the data run
        if (tsk_fs_attr_set_run(a_fs_file, fs_attr, data_run, NULL,
                TSK_FS_ATTR_TYPE_DEFAULT, TSK_FS_ATTR_ID_DEFAULT,
                data_run->len * fs->block_size,
                data_run->len * fs->block_size,
                data_run->len * fs->block_size, 0, 0)) {
            return 1;
        }

        fs_meta->attr_state = TSK_FS_META_ATTR_STUDIED;
        return 0;
    }

    // see if it is one of the special files
    else if ((a_fs_file->meta->addr > fs->last_inum - FATFS_NUM_SPECFILE)
        && (a_fs_file->meta->addr != TSK_FS_ORPHANDIR_INUM(fs))) {
        TSK_FS_ATTR_RUN *data_run;

        if (tsk_verbose)
            tsk_fprintf(stderr,
                "fatfs_make_data_run: Loading special file: %" PRIuINUM
                "\n", a_fs_file->meta->addr);

        // make a non-resident run
        data_run = tsk_fs_attr_run_alloc();
        if (data_run == NULL) {
            return 1;
        }
        data_run->addr = clust;
        data_run->len = a_fs_file->meta->size / fs->block_size;

        if ((fs_attr =
                tsk_fs_attrlist_getnew(fs_meta->attr,
                    TSK_FS_ATTR_NONRES)) == NULL) {
            return 1;
        }

        // initialize the data run
        if (tsk_fs_attr_set_run(a_fs_file, fs_attr, data_run, NULL,
                TSK_FS_ATTR_TYPE_DEFAULT, TSK_FS_ATTR_ID_DEFAULT,
                data_run->len * fs->block_size,
                data_run->len * fs->block_size,
                data_run->len * fs->block_size, 0, 0)) {
            return 1;
        }

        fs_meta->attr_state = TSK_FS_META_ATTR_STUDIED;
        return 0;
    }


    /* A deleted file that we want to recover
     * In this case, we could get a lot of errors because of inconsistent
     * data.  TO make it clear that these are from a recovery, we set most
     * error codes to _RECOVER so that they can be more easily suppressed.
     */
    else if (fs_meta->flags & TSK_FS_META_FLAG_UNALLOC) {
        TSK_DADDR_T sbase;
        TSK_DADDR_T startclust = clust;
        TSK_OFF_T recoversize = fs_meta->size;
        int retval;
        TSK_FS_ATTR_RUN *data_run = NULL;
        TSK_FS_ATTR_RUN *data_run_head = NULL;
        TSK_OFF_T full_len_s = 0;
        uint8_t canRecover = 1; // set to 0 if recovery is not possible

        if (tsk_verbose)
            tsk_fprintf(stderr,
                "fatfs_make_data_run: Processing deleted file %" PRIuINUM
                " in recovery mode\n", fs_meta->addr);

        /* We know the size and the starting cluster
         *
         * We are going to take the clusters from the starting cluster
         * onwards and skip the clusters that are current allocated
         */

        /* Sanity checks on the starting cluster */
        /* Convert the cluster addr to a sector addr */
        sbase = FATFS_CLUST_2_SECT(fatfs, startclust);

        if (sbase > fs->last_block) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_RECOVER);
            tsk_error_set_errstr
                ("fatfs_make_data_run: Starting cluster address too large (recovery): %"
                PRIuDADDR, sbase);
            fs_meta->attr_state = TSK_FS_META_ATTR_ERROR;
            return 1;
        }
        else {

            /* If the starting cluster is already allocated then we can't
             * recover it */
            retval = fatfs_is_clustalloc(fatfs, startclust);
            if (retval != 0) {
                canRecover = 0;
            }
        }


        /* Part 1 is to make sure there are enough unallocated clusters
         * for the size of the file
         */
        clust = startclust;
        size_remain = recoversize;

        // we could make this negative so sign it for the comparison
        while (((int64_t) size_remain > 0) && (canRecover)) {
            int retval;
            sbase = FATFS_CLUST_2_SECT(fatfs, clust);

            /* Are we past the end of the FS?
             * that means we could not find enough unallocated clusters
             * for the file size */
            if (sbase + fatfs->csize - 1 > fs->last_block) {
                canRecover = 0;

                if (tsk_verbose)
                    tsk_fprintf(stderr,
                        "Could not find enough unallocated sectors to recover with - aborting\n");
                break;
            }

            /* Skip allocated clusters */
            retval = fatfs_is_clustalloc(fatfs, clust);
            if (retval == -1) {
                canRecover = 0;
                break;
            }
            else if (retval == 1) {
                clust++;
                continue;
            }

            /* We can use this sector */
            // see if we need a new run
            if ((data_run == NULL)
                || (data_run->addr + data_run->len != sbase)) {

                TSK_FS_ATTR_RUN *data_run_tmp = tsk_fs_attr_run_alloc();
                if (data_run_tmp == NULL) {
                    fs_meta->attr_state = TSK_FS_META_ATTR_ERROR;
                    tsk_fs_attr_run_free(data_run_head);
                    return 1;
                }

                if (data_run_head == NULL) {
                    data_run_head = data_run_tmp;
                    data_run_tmp->offset = 0;
                }
                else if (data_run != NULL) {
                    data_run->next = data_run_tmp;
                    data_run_tmp->offset =
                        data_run->offset + data_run->len;
                }
                data_run = data_run_tmp;
                data_run->len = 0;
                data_run->addr = sbase;
            }
            data_run->len += fatfs->csize;
            full_len_s += fatfs->csize;

            size_remain -= (fatfs->csize << fatfs->ssize_sh);
            clust++;
        }

        // Get a FS_DATA structure and add the runlist to it
        if ((fs_attr =
                tsk_fs_attrlist_getnew(fs_meta->attr,
                    TSK_FS_ATTR_NONRES)) == NULL) {
            fs_meta->attr_state = TSK_FS_META_ATTR_ERROR;
            return 1;
        }

        if (canRecover) {
            /* We can recover the file */

            // initialize the data run
            if (tsk_fs_attr_set_run(a_fs_file, fs_attr, data_run_head,
                    NULL, TSK_FS_ATTR_TYPE_DEFAULT, TSK_FS_ATTR_ID_DEFAULT,
                    fs_meta->size, fs_meta->size, roundup(fs_meta->size,
                        fatfs->csize * fs->block_size), 0, 0)) {
                fs_meta->attr_state = TSK_FS_META_ATTR_ERROR;
                return 1;
            }

            fs_meta->attr_state = TSK_FS_META_ATTR_STUDIED;
        }
        // create a one cluster run
        else {
            TSK_FS_ATTR_RUN *data_run_tmp = tsk_fs_attr_run_alloc();
            if (data_run_tmp == NULL) {
                fs_meta->attr_state = TSK_FS_META_ATTR_ERROR;
                return 1;
            }
            data_run_tmp->addr = sbase;
            data_run_tmp->len = fatfs->csize;

            // initialize the data run
            if (tsk_fs_attr_set_run(a_fs_file, fs_attr, data_run_tmp, NULL,
                    TSK_FS_ATTR_TYPE_DEFAULT, TSK_FS_ATTR_ID_DEFAULT,
                    fs_meta->size, fs_meta->size, roundup(fs_meta->size,
                        fatfs->csize * fs->block_size), 0, 0)) {
                fs_meta->attr_state = TSK_FS_META_ATTR_ERROR;
                return 1;
            }

            fs_meta->attr_state = TSK_FS_META_ATTR_STUDIED;
        }

        return 0;
    }

    /* Normal cluster chain walking */
    else {
        TSK_LIST *list_seen = NULL;
        TSK_FS_ATTR_RUN *data_run = NULL;
        TSK_FS_ATTR_RUN *data_run_head = NULL;
        TSK_OFF_T full_len_s = 0;
        TSK_DADDR_T sbase;

        if (tsk_verbose)
            tsk_fprintf(stderr,
                "fatfs_make_data_run: Processing file %" PRIuINUM
                " in normal mode\n", fs_meta->addr);

        /* Cycle through the cluster chain */
        while ((clust & fatfs->mask) > 0 && (int64_t) size_remain > 0 &&
            (0 == FATFS_ISEOF(clust, fatfs->mask))) {

            /* Convert the cluster addr to a sector addr */
            sbase = FATFS_CLUST_2_SECT(fatfs, clust);

            if (sbase + fatfs->csize - 1 > fs->last_block) {
                fs_meta->attr_state = TSK_FS_META_ATTR_ERROR;
                tsk_error_reset();

                tsk_error_set_errno(TSK_ERR_FS_INODE_COR);
                tsk_error_set_errstr
                    ("fatfs_make_data_run: Invalid sector address in FAT (too large): %"
                    PRIuDADDR " (plus %d sectors)", sbase, fatfs->csize);
                return 1;
            }


            // see if we need a new run
            if ((data_run == NULL)
                || (data_run->addr + data_run->len != sbase)) {

                TSK_FS_ATTR_RUN *data_run_tmp = tsk_fs_attr_run_alloc();
                if (data_run_tmp == NULL) {
                    tsk_fs_attr_run_free(data_run_head);
                    fs_meta->attr_state = TSK_FS_META_ATTR_ERROR;
                    return 1;
                }

                if (data_run_head == NULL) {
                    data_run_head = data_run_tmp;
                    data_run_tmp->offset = 0;
                }
                else if (data_run != NULL) {
                    data_run->next = data_run_tmp;
                    data_run_tmp->offset =
                        data_run->offset + data_run->len;
                }
                data_run = data_run_tmp;
                data_run->len = 0;
                data_run->addr = sbase;
            }

            data_run->len += fatfs->csize;
            full_len_s += fatfs->csize;
            size_remain -= (fatfs->csize * fs->block_size);

            if ((int64_t) size_remain > 0) {
                TSK_DADDR_T nxt;
                if (fatfs_getFAT(fatfs, clust, &nxt)) {
                    tsk_error_set_errstr2("file walk: Inode: %" PRIuINUM
                        "  cluster: %" PRIuDADDR, fs_meta->addr, clust);
                    fs_meta->attr_state = TSK_FS_META_ATTR_ERROR;
                    tsk_fs_attr_run_free(data_run_head);
                    tsk_list_free(list_seen);
                    list_seen = NULL;
                    return 1;
                }
                clust = nxt;

                /* Make sure we do not get into an infinite loop */
                if (tsk_list_find(list_seen, clust)) {
                    if (tsk_verbose)
                        tsk_fprintf(stderr,
                            "Loop found while processing file\n");
                    break;
                }

                if (tsk_list_add(&list_seen, clust)) {
                    fs_meta->attr_state = TSK_FS_META_ATTR_ERROR;
                    tsk_list_free(list_seen);
                    list_seen = NULL;
                    return 1;
                }
            }
        }

        // add the run list to the inode structure
        if ((fs_attr =
                tsk_fs_attrlist_getnew(fs_meta->attr,
                    TSK_FS_ATTR_NONRES)) == NULL) {
            fs_meta->attr_state = TSK_FS_META_ATTR_ERROR;
            return 1;
        }
        // initialize the data run
        if (tsk_fs_attr_set_run(a_fs_file, fs_attr, data_run_head, NULL,
                TSK_FS_ATTR_TYPE_DEFAULT, TSK_FS_ATTR_ID_DEFAULT,
                fs_meta->size, fs_meta->size, roundup(fs_meta->size,
                    fatfs->csize * fs->block_size), 0, 0)) {
            fs_meta->attr_state = TSK_FS_META_ATTR_ERROR;
            return 1;
        }

        tsk_list_free(list_seen);
        list_seen = NULL;

        fs_meta->attr_state = TSK_FS_META_ATTR_STUDIED;
        return 0;
    }
}
