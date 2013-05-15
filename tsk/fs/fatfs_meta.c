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
#include <assert.h>

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
    const char *func_name = "fatfs_make_data_run";
    TSK_FS_INFO *fs;
    TSK_DADDR_T clust;
    TSK_OFF_T size_remain;
    TSK_FS_ATTR *fs_attr = NULL;
    TSK_FS_META *fs_meta;
    FATFS_INFO *fatfs;

    if ((a_fs_file == NULL) || (a_fs_file->meta == NULL)
        || (a_fs_file->fs_info == NULL)) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("%s: called with NULL pointers", func_name);
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
            ("%s: Starting cluster address too large: %"
            PRIuDADDR, func_name, clust);
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
                "%s: Loading root directory\n", func_name);

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
                "%s: Loading special file: %" PRIuINUM
                "\n", func_name, a_fs_file->meta->addr);

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
                "%s: Processing deleted file %" PRIuINUM
                " in recovery mode\n", func_name, fs_meta->addr);

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
                ("%s: Starting cluster address too large (recovery): %"
                PRIuDADDR, func_name, sbase);
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
                        "%s: Could not find enough unallocated sectors to recover with - aborting\n", func_name);
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
                "%s: Processing file %" PRIuINUM
                " in normal mode\n", func_name, fs_meta->addr);

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
                    ("%s: Invalid sector address in FAT (too large): %"
                    PRIuDADDR " (plus %d sectors)", func_name, sbase, fatfs->csize);
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
                    tsk_error_set_errstr2("%s: Inode: %" PRIuINUM
                        "  cluster: %" PRIuDADDR, func_name, fs_meta->addr, clust);
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

uint8_t
fatfs_dinode_load(TSK_FS_INFO *a_fs, char *a_buf, size_t a_inode_size, TSK_INUM_T a_inum) // RJCTODO: Consider making the buffer uint8_t
{
    const char *func_name = "fatfs_dinode_load";
    FATFS_INFO *fatfs = (FATFS_INFO*)a_fs;
    TSK_DADDR_T sect = 0;
    size_t off = 0;
    ssize_t cnt = 0;

    /*
     * Sanity check.
     * Account for virtual orphan directory and virtual files added to the
     * inode address range (FATFS_NUM_SPECFILE).
     */
    if ((a_inum < a_fs->first_inum)
        || (a_inum > a_fs->last_inum - FATFS_NUM_SPECFILE)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_INODE_NUM);
        tsk_error_set_errstr("%s: address: %" PRIuINUM,
            func_name, a_inum);
        return 1;
    }              
    
    /* Get the sector that this inode would be. */
    sect = FATFS_INODE_2_SECT(fatfs, a_inum);
    if (sect > a_fs->last_block) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_INODE_NUM);
        tsk_error_set_errstr("%s: Inode %" PRIuINUM
            " in sector too big for image: %" PRIuDADDR, func_name, a_inum, sect);
        return 1;
    }

    /* Get the byte offset of the inode within the sector and read it in. */
    off = FATFS_INODE_2_OFF(fatfs, a_inum);
    cnt = tsk_fs_read(a_fs, sect * a_fs->block_size + off, a_buf, a_inode_size);
    if (cnt != a_inode_size) {
        if (cnt >= 0) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_READ);
        }
        tsk_error_set_errstr2("%s: block: %" PRIuDADDR,
            func_name, sect);
        return 1;
    }

    return 0;
}

/**
 * \internal
 * Create an TSK_FS_META structure for the root directory.  FAT does
 * not have a directory entry for the root directory, but this
 * function collects the needed data to make one.
 *
 * @param fatfs File system to analyze
 * @param fs_meta Inode structure to copy root directory information into.
 * @return 1 on error and 0 on success
 */
static uint8_t
fatfs_make_root(FATFS_INFO * fatfs, TSK_FS_META * fs_meta)
{
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
 * Create an TSK_FS_META structure for the master boot record.
 *
 * @param fatfs File system to analyze
 * @param fs_meta Inode structure to copy file information into.
 * @return 1 on error and 0 on success
 */
static uint8_t
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
 * Create an TSK_FS_META structure for the FAT tables.
 *
 * @param fatfs File system to analyze
 * @param a_which 1 or 2 to choose between defining FAT1 or FAT2
 * @param fs_meta Inode structure to copy file information into.
 * @return 1 on error and 0 on success
 */
static uint8_t
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

uint8_t
fatfs_inode_lookup(TSK_FS_INFO *a_fs, TSK_FS_FILE *a_fs_file,
    TSK_INUM_T a_inum)
{
    const char *func_name = "fatfs_inode_lookup";
    FATFS_INFO *fatfs = (FATFS_INFO*)a_fs;
    TSK_DADDR_T sect;
    TSK_RETVAL_ENUM retval;
    char *buf = NULL; //RJCTODO: Free memory or do differntly
    size_t inode_size = (a_fs->ftype == TSK_FS_TYPE_EXFAT ? 64 : 32); // RJCTODO: Deal with magic numbers 
    uint8_t(*is_dentry)(FATFS_INFO*, char*, uint8_t) = (a_fs->ftype == TSK_FS_TYPE_EXFAT ? exfatfs_is_dentry : fatxxfs_is_dentry);
    TSK_RETVAL_ENUM(*dinode_copy)(FATFS_INFO*, TSK_FS_META*, char*, TSK_DADDR_T, TSK_INUM_T) = (a_fs->ftype == TSK_FS_TYPE_EXFAT ? exfatfs_dinode_copy : fatxxfs_dinode_copy);

    /* Clean up any error messages that are lying around. */
    tsk_error_reset();

    /* Validate the function arguments. */
    if (a_fs == NULL)
    {
        assert(a_fs != NULL);
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("%s: a_fs argument is NULL", func_name);
        return 1;
    }

    if (a_fs_file == NULL) {
        assert(a_fs_file != NULL);
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("%s: a_fs_file argument is NULL", func_name);
        return 1;
    }

    if (a_inum < a_fs->first_inum || a_inum > a_fs->last_inum) {
        tsk_error_set_errno(TSK_ERR_FS_INODE_NUM);
        tsk_error_set_errstr("%s: inode number %" PRIuINUM
            " too large/small", func_name, a_inum);
        return 1;
    }

    /* Reset or allocate the TSK_FS_META struct this function populates. */
    if (a_fs_file->meta == NULL) {
        if ((a_fs_file->meta =
                tsk_fs_meta_alloc(FATFS_FILE_CONTENT_LEN)) == NULL) {
            return 1;
        }
    }
    else {
        tsk_fs_meta_reset(a_fs_file->meta);
    }

    /* Manufacture a root inode and other special inodes as required to fit 
     * the SleuthKit file system model. */
    if (a_fs->ftype != TSK_FS_TYPE_EXFAT) //RJCTODO: Fix for exFAT
    {
        if (a_inum == FATFS_ROOTINO) {
            if (fatfs_make_root(fatfs, a_fs_file->meta))
                return 1;
            else
                return 0;
        }
        else if (a_inum == FATFS_MBRINO(a_fs)) {
            if (fatfs_make_mbr(fatfs, a_fs_file->meta))
                return 1;
            else
                return 0;
        }
        else if (a_inum == FATFS_FAT1INO(a_fs)) {
            if (fatfs_make_fat(fatfs, 1, a_fs_file->meta))
                return 1;
            else
                return 0;
        }
        else if (a_inum == FATFS_FAT2INO(a_fs)) {
            if (fatfs_make_fat(fatfs, 2, a_fs_file->meta))
                return 1;
            else
                return 0;
        }
        else if (a_inum == TSK_FS_ORPHANDIR_INUM(a_fs)) {
            if (tsk_fs_dir_make_orphan_dir_meta(a_fs, a_fs_file->meta))
                return 1;
            else
                return 0;
        }
    }

    /* Get the sector that this inode would be in. */ 
    sect = FATFS_INODE_2_SECT(fatfs, a_inum);
    if (sect > a_fs->last_block) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_INODE_NUM);
        tsk_error_set_errstr("%s: Inode %" PRIuINUM
            " in sector too big for image: %" PRIuDADDR, func_name, a_inum, sect);
        return 1;
    }

    /* Fill the directory entry buffer with the bytes corresponding to 
     * the inode. */
    buf = (char*)tsk_malloc(inode_size);
    if (fatfs_dinode_load(a_fs, buf, inode_size, a_inum)) {
        free(buf);
        return 1;
    }

    /* 
     * Use the directory entry check function to see if the bytes in the 
     * buffer appear to be a valid inode. If so, call the copy function to 
     * populate the TSK_FS_META struct with data parsed from the buffer.
     * Note that only the sector allocation status is used to select the basic
     * or in-depth version of the directory entry check, while other places in
     * the code use information about whether or not the sector is part of a 
     * folder, information that is not availble here. Thus, the check here is
     * less reliable and may allow some false positives through its filter. 
     */
    if (is_dentry(fatfs, buf, fatfs_is_sectalloc(fatfs, sect))) {
        if ((retval =
                dinode_copy(fatfs, a_fs_file->meta, buf, sect,
                    a_inum)) != TSK_OK) {
            /* If there was a unicode conversion error,
             * then still return the inode */
            if (retval == TSK_ERR) {
                free(buf);
                return 1;
            }
            else {
                if (tsk_verbose) {
                    tsk_error_print(stderr);
                }
                tsk_error_reset();
            }
        }
        free(buf);
        return 0;
    }
    else {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_INODE_NUM);
        tsk_error_set_errstr("%s: %" PRIuINUM
            " is not an inode", func_name, a_inum);
        free(buf);
        return 1;
    }
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
    unsigned int flags = TSK_FS_FILE_WALK_FLAG_SLACK | TSK_FS_FILE_WALK_FLAG_AONLY;

    if ((fs_file->meta == NULL)
        || (fs_file->meta->type != TSK_FS_META_TYPE_DIR))
        return TSK_WALK_CONT;

    /* Get the sector addresses & ignore any errors */
    if (tsk_fs_file_walk(fs_file,
            (TSK_FS_FILE_WALK_FLAG_ENUM)flags,
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
    char *func_name = "fatfs_inode_walk";
    FATFS_INFO *fatfs = (FATFS_INFO*)fs;
    unsigned int flags = a_flags;
    TSK_INUM_T end_inum_tmp = 0;
    TSK_FS_FILE *fs_file =  NULL;
    TSK_DADDR_T ssect = 0; 
    TSK_DADDR_T lsect = 0; 
    TSK_DADDR_T sect = 0; 
    char *dino_buf = NULL;
    char *dep = NULL;
    unsigned int myflags = 0;
    unsigned int dentry_idx = 0;
    uint8_t *dir_sectors_bitmap = NULL;
    ssize_t cnt = 0;
    uint8_t done = 0;
    uint8_t(*is_dentry)(FATFS_INFO*, char*, uint8_t) = NULL;
    TSK_RETVAL_ENUM(*dinode_copy)(FATFS_INFO*, TSK_FS_META*, char*, TSK_DADDR_T, TSK_INUM_T) = NULL;

    /* Clean up any error messages that may be lying around. */
    tsk_error_reset();

     /* Do a range check on the start and end inode numbers. */
    if (start_inum < fs->first_inum || start_inum > fs->last_inum) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("%s: Start inode:  %" PRIuINUM "", func_name,
            start_inum);
        return 1;
    }
    else if (end_inum < fs->first_inum || 
             end_inum > fs->last_inum ||
             end_inum < start_inum) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("%s: End inode: %" PRIuINUM "", func_name,
            end_inum);
        return 1;
    }

    if (tsk_verbose) {
        tsk_fprintf(stderr,
            "%s: Inode Walking %" PRIuINUM " to %"
            PRIuINUM "\n", func_name, start_inum, end_inum);
    }

    /* Plug in functions that handle differences in FATXX vs. exFAT file 
     * systems. */
    if (fs->ftype == TSK_FS_TYPE_EXFAT) {
        is_dentry = exfatfs_is_dentry;
        dinode_copy = exfatfs_dinode_copy;
    }
    else {
        is_dentry = fatxxfs_is_dentry;
        dinode_copy = fatxxfs_dinode_copy; 
    }

    /* Make sure the flags are set correctly. */
    if (flags & TSK_FS_META_FLAG_ORPHAN) {
        /* If ORPHAN is wanted, then make sure that the UNALLOCATED and USED flags
         * are set. */
        flags |= TSK_FS_META_FLAG_UNALLOC;
        flags &= ~TSK_FS_META_FLAG_ALLOC;
        flags |= TSK_FS_META_FLAG_USED;
        flags &= ~TSK_FS_META_FLAG_UNUSED;
    }
    else {
        /* If neither of the ALLOCATED or UNALOCATED flags are set, then set
         * them both. */
        if (((flags & TSK_FS_META_FLAG_ALLOC) == 0) &&
            ((flags & TSK_FS_META_FLAG_UNALLOC) == 0)) {
            flags |= (TSK_FS_META_FLAG_ALLOC | TSK_FS_META_FLAG_UNALLOC);
        }

        /* If neither of the USED or UNUSED flags are set, then set them
         * both. */
        if (((flags & TSK_FS_META_FLAG_USED) == 0) &&
            ((flags & TSK_FS_META_FLAG_UNUSED) == 0)) {
            flags |= (TSK_FS_META_FLAG_USED | TSK_FS_META_FLAG_UNUSED);
        }
    }

    /* If we are looking for orphan files and have not yet filled
     * in the list of unalloc inodes that are pointed to, then fill
     * in the list.
     */
    if ((flags & TSK_FS_META_FLAG_ORPHAN)) {
        if (tsk_fs_dir_load_inum_named(fs) != TSK_OK) {
            tsk_error_errstr2_concat
                ("- fatfs_inode_walk: identifying inodes allocated by file names"); //RJCTODO: Use func_name here
            return 1;
        }
    }

    /* Allocate a TSK_FS_FILE with a TSK_FS_META to populate and pass to
     * the callback supplied by the caller whenever an inode that fits the
     * caller's criteris is found. */
    if ((fs_file = tsk_fs_file_alloc(fs)) == NULL)
        return 1;

    if ((fs_file->meta =
            tsk_fs_meta_alloc(FATFS_FILE_CONTENT_LEN)) == NULL)
        return 1;

    /* Handle the root directory, if it's included in the walk. */
    if (start_inum == FATFS_ROOTINO) {
        if (((TSK_FS_META_FLAG_ALLOC & flags) == TSK_FS_META_FLAG_ALLOC)
            && ((TSK_FS_META_FLAG_USED & flags) == TSK_FS_META_FLAG_USED)
            && ((TSK_FS_META_FLAG_ORPHAN & flags) == 0)) {
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

        /* Move on to the next inode, if there is one. */
        start_inum++;
        if (start_inum == end_inum) {
            tsk_fs_file_close(fs_file);
            return 0;
        }
    }

    // RJCTODO: Clarify the comments that follow.
    /* We will be looking at each sector to see if it contains directory
     * entries.  We can make mistakes and ignore sectors that have valid
     * entries in them.  To make sure we at least get all sectors that
     * are allocated by directories in the directory tree, we will
     * run name_walk and then a file walk on each dir.
     * We'll be make sure to print those.  We skip this for ORPHAN hunting
     * because it doesn't help and can introduce infinite loop situations
     * inode_walk was called by the function that determines which inodes
     * are orphans. */
    if ((dir_sectors_bitmap =
            (uint8_t *) tsk_malloc((size_t) ((fs->block_count +
                        7) / 8))) == NULL) {
        tsk_fs_file_close(fs_file);
        return 1;
    }

    if ((flags & TSK_FS_META_FLAG_ORPHAN) == 0) {
        if (tsk_verbose) {
            tsk_fprintf(stderr,
                "fatfs_inode_walk: Walking directories to collect sector info\n");
        }

        /* Do a file_walk on the root directory to get its layout. */
        if (fatfs_make_root(fatfs, fs_file->meta)) {
            tsk_fs_file_close(fs_file);
            free(dir_sectors_bitmap);
            return 1;
        }

        if (tsk_fs_file_walk(fs_file,
                TSK_FS_FILE_WALK_FLAG_SLACK | TSK_FS_FILE_WALK_FLAG_AONLY,
                inode_walk_file_act, (void *) dir_sectors_bitmap)) {
            tsk_fs_file_close(fs_file);
            free(dir_sectors_bitmap);
            return 1;
        }

        /* Now do a directory walk to get the rest of the directories. */
        if (tsk_fs_dir_walk(fs, fs->root_inum,
                TSK_FS_DIR_WALK_FLAG_ALLOC | TSK_FS_DIR_WALK_FLAG_RECURSE |
                TSK_FS_DIR_WALK_FLAG_NOORPHAN, inode_walk_dent_act,
                (void *) dir_sectors_bitmap)) {
            tsk_error_errstr2_concat
                ("- fatfs_inode_walk: mapping directories");
            tsk_fs_file_close(fs_file);
            free(dir_sectors_bitmap);
            return 1;
        }
    }

    // RJCTODO: This comment is not helpful because so much follows, it would be really great to break this function 
    // up into more easily comprehensible parts. 
    /* start analyzing each sector
     *
     * Perform a test on the first 32 bytes of each sector to identify if
     * the sector contains directory entries.  If it does, then continue
     * to analyze it.  If not, then read the next sector
     */

    /* If the end inode is the one of the virtual ORPHANS directory or the 
     * virtual FAT files, adjust the end point and handle them outside of the 
     * inode walking loop. */
    if (end_inum > fs->last_inum - FATFS_NUM_SPECFILE) {
        end_inum_tmp = fs->last_inum - FATFS_NUM_SPECFILE;
    }
    else {
        end_inum_tmp = end_inum;
    }

    /* Map the starting and ending inodes to the sectors that contain them. */
    ssect = FATFS_INODE_2_SECT(fatfs, start_inum);
    lsect = FATFS_INODE_2_SECT(fatfs, end_inum_tmp);
    if (ssect > fs->last_block) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr
            ("%s: Starting inode in sector too big for image: %"
            PRIuDADDR, func_name, ssect);
        tsk_fs_file_close(fs_file);
        free(dir_sectors_bitmap);
        return 1;
    }
    else if (lsect > fs->last_block) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr
            ("%s: Ending inode in sector too big for image: %"
            PRIuDADDR, func_name, lsect);
        tsk_fs_file_close(fs_file);
        free(dir_sectors_bitmap);
        return 1;
    }

    /* Allocate a buffer big enough to read in a cluster at a time. */
    if ((dino_buf =
            (char *) tsk_malloc(fatfs->csize << fatfs->ssize_sh)) ==
        NULL) {
        tsk_fs_file_close(fs_file);
        free(dir_sectors_bitmap);
        return 1;
    }

    /* Walk the virtual inodes. */
    sect = ssect;
    while (sect <= lsect) {
        int cluster_is_alloc = 0;
        size_t num_sectors_to_process = 0;       
        size_t sector_idx = 0;            
        uint8_t do_basic_dentry_test = 0; 

        /* Read a chunk of the image to process on this iteration of the inode
         * walk. The read size for the data area (exFAT cluster heap) will be
         * the size of a cluster. However, the root directory for a FAT12 or 
         * FAT16 file system precedes the data area and the read size for it
         * should be a sector, not a cluster. */
        if (sect < fatfs->firstclustsect) {
            if ((flags & TSK_FS_META_FLAG_ORPHAN) != 0) {
                /* Orpahn hunting, and there are no orphans in the root 
                 * directory, so skip ahead to the data area. */
                sect = fatfs->firstclustsect;
                continue;
            }

            /* Read in a sector. */
            cnt = tsk_fs_read_block(fs, sect, dino_buf, fatfs->ssize);
            if (cnt != fatfs->ssize) {
                if (cnt >= 0) {
                    tsk_error_reset();
                    tsk_error_set_errno(TSK_ERR_FS_READ);
                }
                tsk_error_set_errstr2
                    ("&s (root dir): sector: %" PRIuDADDR,
                    func_name, sect);
                tsk_fs_file_close(fs_file);
                free(dir_sectors_bitmap);
                free(dino_buf);
                return 1;
            }
            cluster_is_alloc = 1;
            num_sectors_to_process = 1;
        }
        else {
            /* Get the base sector for the cluster that contains the current 
             * sector. The first time through the loop, the current sector is
             * the sector that conatins the start virtual inode. */
            sect =
                FATFS_CLUST_2_SECT(fatfs, (FATFS_SECT_2_CLUST(fatfs,
                        sect)));

            /* Determine whether the cluster is allocated. Skip it if it is
             * not allocated and the UNALLOCATED flag is not set. */
            cluster_is_alloc = fatfs_is_sectalloc(fatfs, sect);
            if ((cluster_is_alloc == 0)
                && ((flags & TSK_FS_META_FLAG_UNALLOC) == 0)) {
                sect += fatfs->csize;
                continue;
            }
            else if (cluster_is_alloc == -1) {
                tsk_fs_file_close(fs_file);
                free(dir_sectors_bitmap);
                free(dino_buf);
                return 1;
            }

            /* If the cluster is allocated but is not allocated to a
             * directory, then skip it.  NOTE: This will miss unallocated
             * entries in the slack space of files.
             */
            if ((cluster_is_alloc == 1) && (isset(dir_sectors_bitmap, sect) == 0)) {
                sect += fatfs->csize;
                continue;
            }

            /* The final cluster may not be full */
            if (lsect - sect + 1 < fatfs->csize) {
                num_sectors_to_process = (size_t) (lsect - sect + 1);
            }
            else {
                num_sectors_to_process = fatfs->csize;
            }

            /* Read in a cluster's worth of sectors. */
            cnt = tsk_fs_read_block
                (fs, sect, dino_buf, num_sectors_to_process << fatfs->ssize_sh);
            if (cnt != (num_sectors_to_process << fatfs->ssize_sh)) {
                if (cnt >= 0) {
                    tsk_error_reset();
                    tsk_error_set_errno(TSK_ERR_FS_READ);
                }
                tsk_error_set_errstr2("%s: sector: %"
                    PRIuDADDR, func_name, sect);
                tsk_fs_file_close(fs_file);
                free(dir_sectors_bitmap);
                free(dino_buf);
                return 1;
            }
        }

        /* Now that the sectors are read in, prepare to step through them in 
         * directory entry size chunks. Only do a basic test to confirm the 
         * contents of each chunk is a directory entry unless the sector that
         * contains it is not allocated to a directory or is unallocated.*/
        do_basic_dentry_test = 1;
        if ((isset(dir_sectors_bitmap, sect) == 0) || (cluster_is_alloc == 0)) {
            do_basic_dentry_test = 0;
        }

        /* Work through the the sectors. */
        for (sector_idx = 0; sector_idx < num_sectors_to_process; sector_idx++) {
            TSK_INUM_T inum = 0;

            /* If the last virtual inode in this sector is before the start 
             * inode, skip the sector. */
            if (FATFS_SECT_2_INODE(fatfs, sect + 1) < start_inum) {
                sect++;
                continue;
            }

            dep = &dino_buf[sector_idx << fatfs->ssize_sh];

            /* If the sector is not allocated to a directory and the first 
             * chunk is not a directory entry, skip the sector. */
            if ((!isset(dir_sectors_bitmap, sect)) &&
                ((fs->ftype != TSK_FS_TYPE_EXFAT) && (!fatxxfs_is_dentry(fatfs, dep, 0)) ||
                 (exfatfs_is_dentry(fatfs, dep, 0) == 0))) {
                sect++;
                continue;
            }

            /* Get the base inode address of this sector. */
            inum = FATFS_SECT_2_INODE(fatfs, sect);
            if (tsk_verbose) {
                tsk_fprintf(stderr,
                    "%s: Processing sector %" PRIuDADDR
                    " starting at inode %" PRIuINUM "\n", func_name, sect, inum);
            }

            /* Work through the directory entry size chunks of the sectors. */
            for (dentry_idx = 0; dentry_idx < fatfs->dentry_cnt_se;
                dentry_idx++, inum++, dep++) {
                int retval;
                TSK_RETVAL_ENUM retval2;

                /* If less than the start inode, skip it. */
                if (inum < start_inum) {
                    continue;
                }

                /* If greater than the end inode, break out of the walk loops. */
                if (inum > end_inum_tmp) {
                    done = 1;
                    break;
                }

                // RJCTODO: Fix this up for exFAT, looks like a good place for template method
                if (fs->ftype != TSK_FS_TYPE_EXFAT) { 
                    /* If this is a long file name entry, then skip it and
                     * wait for the short name. */
                    if ((fs->ftype != TSK_FS_TYPE_EXFAT) && 
                        ((((FATXXFS_DENTRY*)dep)->attrib & FATFS_ATTR_LFN) == FATFS_ATTR_LFN)) {
                        continue;
                    }

                    /* Skip the "." and ".." entries because they are redundant. */
                    if ((fs->ftype != TSK_FS_TYPE_EXFAT) && 
                        ((((FATXXFS_DENTRY*)dep)->attrib & FATFS_ATTR_DIRECTORY) == FATFS_ATTR_DIRECTORY) &&
                        (((FATXXFS_DENTRY*)dep)->name[0] == '.')) {
                        continue;
                    }

                    /* Allocation status
                     * This is determined first by the sector allocation status
                     * an then the dentry flag.  When a directory is deleted, the
                     * contents are not always set to unallocated
                     */
                    if ((fs->ftype != TSK_FS_TYPE_EXFAT) && (cluster_is_alloc == 1)) {
                        myflags =
                            ((((FATXXFS_DENTRY*)dep)->name[0] ==
                                FATFS_SLOT_DELETED) ? TSK_FS_META_FLAG_UNALLOC
                            : TSK_FS_META_FLAG_ALLOC);
                    }
                    else {
                        myflags = TSK_FS_META_FLAG_UNALLOC;
                    }

                    if ((flags & myflags) != myflags) {
                        continue;
                    }

                    /* Slot has not been used yet */
                    myflags |= ((((FATXXFS_DENTRY*)dep)->name[0] == FATFS_SLOT_EMPTY) ?
                        TSK_FS_META_FLAG_UNUSED : TSK_FS_META_FLAG_USED);

                    if ((flags & myflags) != myflags) {
                        continue;
                    }
                }

                /* If we want only orphans, then check if this
                 * inode is in the seen list.*/
                if ((myflags & TSK_FS_META_FLAG_UNALLOC) &&
                    (flags & TSK_FS_META_FLAG_ORPHAN) &&
                    (tsk_fs_dir_find_inum_named(fs, inum))) {
                    continue;
                }

                // RJCTODO: Improve this comment.
                /* Do a final sanity check */
                if (0 == is_dentry(fatfs, dep, do_basic_dentry_test)) {
                    continue;
                }

                if ((retval2 =
                        dinode_copy(fatfs, fs_file->meta, dep, sect,
                            inum)) != TSK_OK) {

                    if (retval2 == TSK_COR) {
                        /* Corrupted, move on to the next chunk. */ // RJCTODO: Check out this logic/return code
                        if (tsk_verbose) {
                            tsk_error_print(stderr);
                        }
                        tsk_error_reset();
                        continue;
                    }
                    else {
                        tsk_fs_file_close(fs_file);
                        free(dir_sectors_bitmap);
                        free(dino_buf);
                        return 1;
                    }
                }

                if (tsk_verbose) {
                    tsk_fprintf(stderr,
                        "%s: Directory Entry %" PRIuINUM
                        " (%u) at sector %" PRIuDADDR "\n", func_name, inum, dentry_idx,
                        sect);
                }

                retval = a_action(fs_file, a_ptr);
                if (retval == TSK_WALK_STOP) {
                    tsk_fs_file_close(fs_file);
                    free(dir_sectors_bitmap);
                    free(dino_buf);
                    return 0;
                }
                else if (retval == TSK_WALK_ERROR) {
                    tsk_fs_file_close(fs_file);
                    free(dir_sectors_bitmap);
                    free(dino_buf);
                    return 1;
                }
            }                   /* dentries */
            sect++;
            if (done) {
                break;
            }
        }
        if (done) {
            break;
        }
    }


    free(dir_sectors_bitmap);
    free(dino_buf);


    // handle the virtual orphans folder and FAT files if they asked for them
    if ((end_inum > fs->last_inum - FATFS_NUM_SPECFILE)
        && (flags & TSK_FS_META_FLAG_ALLOC)
        && (flags & TSK_FS_META_FLAG_USED)
        && ((flags & TSK_FS_META_FLAG_ORPHAN) == 0)) {
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