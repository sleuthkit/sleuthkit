/*
** fatfs
** The Sleuth Kit
**
** Meta data layer support for the FAT file system.
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
 * Meta data layer support for FAT file systems.
 */

#include "tsk_fatfs.h"
#include "tsk_fatxxfs.h"
#include "tsk_exfatfs.h"

TSK_FS_ATTR_TYPE_ENUM
fatfs_get_default_attr_type(const TSK_FS_FILE * a_file)
{
    return TSK_FS_ATTR_TYPE_DEFAULT;
}

/**
 * \internal
 * Create an TSK_FS_META structure for the root directory.  FAT does
 * not have a directory entry for the root directory, but this
 * function collects the data needed to make one.
 *
 * @param fatfs File system to analyze.
 * @param fs_meta Inode structure to copy root directory information into.
 * @return 1 on error and 0 on success
 */
static uint8_t
fatfs_make_root(FATFS_INFO *a_fatfs, TSK_FS_META *a_fs_meta)
{
    const char *func_name = "fatfs_make_root";
    TSK_DADDR_T *first_clust_addr_ptr = NULL;

    tsk_error_reset();
    if (fatfs_is_ptr_arg_null(a_fatfs, "a_fatfs", func_name) ||
        fatfs_is_ptr_arg_null(a_fs_meta, "a_fs_meta", func_name)) {
        return 1;
    }

    /* Manufacture some metadata. */
    a_fs_meta->type = TSK_FS_META_TYPE_DIR;
    a_fs_meta->mode = TSK_FS_META_MODE_UNSPECIFIED; //RJCTODO: This is where it was zero, why I made UNSPEC
    a_fs_meta->nlink = 1;
    a_fs_meta->addr = FATFS_ROOTINO;
    a_fs_meta->flags = (TSK_FS_META_FLAG_ENUM)(TSK_FS_META_FLAG_USED | TSK_FS_META_FLAG_ALLOC);
    a_fs_meta->uid = a_fs_meta->gid = 0;
    a_fs_meta->mtime = a_fs_meta->atime = a_fs_meta->ctime = a_fs_meta->crtime = 0;
    a_fs_meta->mtime_nano = a_fs_meta->atime_nano = a_fs_meta->ctime_nano =
        a_fs_meta->crtime_nano = 0;

    /* Give the root directory an empty name. */
    if (a_fs_meta->name2 == NULL) {
        if ((a_fs_meta->name2 = (TSK_FS_META_NAME_LIST *)
                tsk_malloc(sizeof(TSK_FS_META_NAME_LIST))) == NULL) {
            return 1;
        }
        a_fs_meta->name2->next = NULL;
    }
    a_fs_meta->name2->name[0] = '\0';

    /* Mark the generic attribute list as not in use (in the generic file model
     * attributes are containers for data or metadata). Population of this 
     * stuff is done on demand (lazy look up). */
    a_fs_meta->attr_state = TSK_FS_META_ATTR_EMPTY;
    if (a_fs_meta->attr) {
        tsk_fs_attrlist_markunused(a_fs_meta->attr);
    }

    /* Determine the size of the root directory and the address of its 
     * first cluster. */
    first_clust_addr_ptr = (TSK_DADDR_T*)a_fs_meta->content_ptr;
    if (a_fatfs->fs_info.ftype == TSK_FS_TYPE_FAT32 ||
        a_fatfs->fs_info.ftype == TSK_FS_TYPE_EXFAT) {
        TSK_DADDR_T cnum = 0;
        TSK_DADDR_T clust = 0;
        TSK_LIST *list_seen = NULL;

        /* Convert the address of the first sector of the root directory into
         * the address of its first cluster. */
        clust = FATFS_SECT_2_CLUST(a_fatfs, a_fatfs->rootsect);
        first_clust_addr_ptr[0] = clust;

        /* Walk the FAT and count the clusters allocated to the root directory. */
        cnum = 0;
        while ((clust) && (0 == FATFS_ISEOF(clust, FATFS_32_MASK))) {
            TSK_DADDR_T nxt = 0;

            /* Make sure we do not get into an infinite loop */
            if (tsk_list_find(list_seen, clust)) {
                if (tsk_verbose) {
                    tsk_fprintf(stderr,
                        "Loop found while determining root directory size\n");
                }
                break;
            }
            if (tsk_list_add(&list_seen, clust)) {
                tsk_list_free(list_seen);
                list_seen = NULL;
                return 1;
            }

            cnum++;
            if (fatfs_getFAT(a_fatfs, clust, &nxt)) {
                break;
            }
            else {
                clust = nxt;
            }
        }
        tsk_list_free(list_seen);
        list_seen = NULL;

        /* Calculate the size of the root directory. */
        a_fs_meta->size = (cnum * a_fatfs->csize) << a_fatfs->ssize_sh;
    }
    else {
        /* FAT12 and FAT16 don't use the FAT for the root directory, so set 
         * the first cluster address to a distinguished value that other code
         * will have to check as a special condition. */ 
        first_clust_addr_ptr[0] = 1;

        /* Set the size equal to the number of bytes between the end of the 
         * FATs and the start of the clusters. */
        a_fs_meta->size = (a_fatfs->firstclustsect - a_fatfs->firstdatasect) << a_fatfs->ssize_sh;
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
fatfs_make_mbr(FATFS_INFO *fatfs, TSK_FS_META *fs_meta)
{
    TSK_DADDR_T *addr_ptr;
    TSK_FS_INFO *fs = (TSK_FS_INFO *) fatfs;

    fs_meta->type = TSK_FS_META_TYPE_VIRT;
    fs_meta->mode = TSK_FS_META_MODE_UNSPECIFIED;
    fs_meta->nlink = 1;
    fs_meta->addr = FATFS_MBRINO(fs);
    fs_meta->flags = (TSK_FS_META_FLAG_ENUM)
        (TSK_FS_META_FLAG_USED | TSK_FS_META_FLAG_ALLOC);
    fs_meta->uid = fs_meta->gid = 0;
    fs_meta->mtime = fs_meta->atime = fs_meta->ctime = fs_meta->crtime = 0;
    fs_meta->mtime_nano = fs_meta->atime_nano = fs_meta->ctime_nano =
        fs_meta->crtime_nano = 0;

    if (fs_meta->name2 == NULL) {
        if ((fs_meta->name2 = (TSK_FS_META_NAME_LIST *)
                tsk_malloc(sizeof(TSK_FS_META_NAME_LIST))) == NULL) {
            return 1;
        }
        fs_meta->name2->next = NULL;
    }
    strncpy(fs_meta->name2->name, FATFS_MBRNAME,
        TSK_FS_META_NAME_LIST_NSIZE);

    fs_meta->attr_state = TSK_FS_META_ATTR_EMPTY;
    if (fs_meta->attr) {
        tsk_fs_attrlist_markunused(fs_meta->attr);
    }

    addr_ptr = (TSK_DADDR_T*)fs_meta->content_ptr;
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
fatfs_make_fat(FATFS_INFO *fatfs, uint8_t a_which, TSK_FS_META *fs_meta)
{
    TSK_FS_INFO *fs = (TSK_FS_INFO*)fatfs;
    TSK_DADDR_T *addr_ptr = (TSK_DADDR_T *)fs_meta->content_ptr;

    // RJCTODO: Can macros be used instead of hard coded numbers?
    if ((a_which != 1) && (a_which != 2)) {
        return 1;
    }

    fs_meta->type = TSK_FS_META_TYPE_VIRT;
    fs_meta->mode = TSK_FS_META_MODE_UNSPECIFIED;
    fs_meta->nlink = 1;

    fs_meta->flags = (TSK_FS_META_FLAG_ENUM)
        (TSK_FS_META_FLAG_USED | TSK_FS_META_FLAG_ALLOC);
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
        addr_ptr[0] = fatfs->firstfatsect;
    }
    else {
        if ((fs->ftype == TSK_FS_TYPE_EXFAT) && (fatfs->numfat != 2)) {
            return 1; // RJCTODO: Not sure this is the right way to go. 
        }
        fs_meta->addr = FATFS_FAT2INO(fs);
        strncpy(fs_meta->name2->name, FATFS_FAT2NAME,
            TSK_FS_META_NAME_LIST_NSIZE);
        addr_ptr[0] = fatfs->firstfatsect + fatfs->sectperfat;
    }

    fs_meta->attr_state = TSK_FS_META_ATTR_EMPTY;
    if (fs_meta->attr) {
        tsk_fs_attrlist_markunused(fs_meta->attr);
    }

    fs_meta->size = fatfs->sectperfat * fs->block_size;

    return 0;
}

/**
 * \internal
 * Load a FATFS_DENTRY structure with the bytes at a given inode address.
 *
 * @param [in] a_fs The file system from which to read the bytes.
 * @param [out] a_de The FATFS_DENTRY.
 * @param [in] a_inum An inode address.
 * @return 0 on success, 1 on failure 
 */
uint8_t
fatfs_dentry_load(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_dentry, TSK_INUM_T a_inum)
{
    const char *func_name = "fatfs_dentry_load";
    TSK_FS_INFO *fs = (TSK_FS_INFO*)a_fatfs;
    TSK_DADDR_T sect = 0;
    size_t off = 0;
    ssize_t cnt = 0;

    tsk_error_reset();
    if (fatfs_is_ptr_arg_null(a_fatfs, "a_fatfs", func_name) ||
        fatfs_is_ptr_arg_null(a_dentry, "a_dentry", func_name) ||
        !fatfs_is_inum_in_range(a_fatfs, a_inum, func_name)) {
        return 1;
    }
    
    /* Map the inode address to a sector. */
    sect = FATFS_INODE_2_SECT(a_fatfs, a_inum);
    if (sect > fs->last_block) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_INODE_NUM);
        tsk_error_set_errstr("%s: Inode %" PRIuINUM
            " in sector too big for image: %" PRIuDADDR, func_name, a_inum, sect);
        return 1;
    }

    /* Get the byte offset of the inode address within the sector. */
    off = FATFS_INODE_2_OFF(a_fatfs, a_inum);

    /* Read in the bytes. */
    cnt = tsk_fs_read(fs, sect * fs->block_size + off, (char*)a_dentry, sizeof(FATFS_DENTRY));
    if (cnt != sizeof(FATFS_DENTRY)) {
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

uint8_t
fatfs_is_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_dentry, uint8_t a_basic)
{
    TSK_FS_INFO *fs = (TSK_FS_INFO*)a_fatfs;

    if (fs->ftype == TSK_FS_TYPE_EXFAT) {
        return exfatfs_is_dentry(a_fatfs, a_dentry, a_basic);
    }
    else {
        return fatxxfs_is_dentry(a_fatfs, a_dentry, a_basic);
    }
}

/**
 * \internal
 * Populate the TSK_FS_META structure of a TSK_FS_FILE structure for a 
 * given inode address.
 *
 * @param [in] a_fs File system that contains the inode.
 * @param [out] a_fs_file The file corresponding to the inode.
 * @param [in] a_inum The inode address.
 * @returns 1 if an error occurs or if the inode address is not
 * for a valid inode, 0 otherwise.
 */
uint8_t
fatfs_inode_lookup(TSK_FS_INFO *a_fs, TSK_FS_FILE *a_fs_file,
    TSK_INUM_T a_inum)
{
    const char *func_name = "fatfs_inode_lookup";
    FATFS_INFO *fatfs = (FATFS_INFO*)a_fs;

    tsk_error_reset();
    if (fatfs_is_ptr_arg_null(a_fs, "a_fs", func_name) ||
        fatfs_is_ptr_arg_null(a_fs_file, "a_fs_file", func_name) ||
        !fatfs_is_inum_in_range(fatfs, a_inum, func_name)) {
        return 1;
    }

    /* Allocate or reset the TSK_FS_META struct. */
    if (a_fs_file->meta == NULL) {
        if ((a_fs_file->meta =
                tsk_fs_meta_alloc(FATFS_FILE_CONTENT_LEN)) == NULL) {
            return 1;
        }
    }
    else {
        tsk_fs_meta_reset(a_fs_file->meta);
    }

    /* Manufacture an inode for the root directory or a FAT virtual file,
     * or do a look up. */
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
    else {
        if (a_fs->ftype == TSK_FS_TYPE_EXFAT) {
            return exfatfs_inode_lookup(fatfs, a_fs_file, a_inum);
        } 
        else {
            return fatxxfs_inode_lookup(fatfs, a_fs_file, a_inum);
        }
    }
}

/** \internal
 * Make data runs out of the clusters allocated to a file represented by a 
 * TSK_FS_FILE structure. Each data run will have a starting sector and a 
 * length in sectors. The runs will be stored as a non-resident attribute in 
 * the TSK_FS_ATTRLIST of the TSK_FS_META structure of the TSK_FS_FILE. 
 *
 * @param a_fs_file A representation of a file.
 * @return 1 on error and 0 on success
 */
uint8_t
fatfs_make_data_runs(TSK_FS_FILE * a_fs_file)
{
    const char *func_name = "fatfs_make_data_runs";
    TSK_FS_INFO *fs = NULL;
    TSK_FS_META *fs_meta = NULL;
    FATFS_INFO *fatfs = NULL;
    TSK_DADDR_T clust = 0;
    TSK_OFF_T size_remain = 0;
    TSK_FS_ATTR *fs_attr = NULL;

    if ((fatfs_is_ptr_arg_null(a_fs_file, "a_fs_file", func_name)) ||
        (fatfs_is_ptr_arg_null(a_fs_file->meta, "a_fs_file->meta", func_name)) ||
        (fatfs_is_ptr_arg_null(a_fs_file->fs_info, "a_fs_file->fs_info", func_name))) {
        return TSK_ERR;
    }
    
    fs_meta = a_fs_file->meta;
    fs = a_fs_file->fs_info;
    fatfs = (FATFS_INFO*)fs;

    /* Check for an already populated attribute list, since a lazy strategy
     * is used to fill in attributes. If the attribute list is not yet 
     * allocated, do so now. */  
    if ((fs_meta->attr != NULL)
        && (fs_meta->attr_state == TSK_FS_META_ATTR_STUDIED)) {
        return 0;
    }
    else if (fs_meta->attr_state == TSK_FS_META_ATTR_ERROR) {
        return 1;
    }
    else if (fs_meta->attr != NULL) {
        tsk_fs_attrlist_markunused(fs_meta->attr);
    }
    else if (fs_meta->attr == NULL) {
        fs_meta->attr = tsk_fs_attrlist_alloc();
    }

    /* Get the stashed first cluster address of the file. */
    clust = ((TSK_DADDR_T*)fs_meta->content_ptr)[0];
    if ((clust > (fatfs->lastclust)) &&
        (FATFS_ISEOF(clust, fatfs->mask) == 0)) {
        fs_meta->attr_state = TSK_FS_META_ATTR_ERROR;
        tsk_error_reset();
        if (a_fs_file->meta->flags & TSK_FS_META_FLAG_UNALLOC) {
            tsk_error_set_errno(TSK_ERR_FS_RECOVER);
        }
        else {
            tsk_error_set_errno(TSK_ERR_FS_INODE_COR);
        }
        tsk_error_set_errstr
            ("%s: Starting cluster address too large: %"
            PRIuDADDR, func_name, clust);
        return 1;
    }

    /* Figure out the allocated length of the file in bytes. Because the
     * allocation unit for FAT file systems is the cluster, round the
     * size up to a multiple of cluster size. */
    size_remain = roundup(fs_meta->size, fatfs->csize * fs->block_size);

    // RJCTODO: Consider addressing the code duplication below.
    if ((a_fs_file->meta->addr == FATFS_ROOTINO) && 
        (fs->ftype != TSK_FS_TYPE_FAT32) &&
        (fs->ftype != TSK_FS_TYPE_EXFAT) &&
        (clust == 1)) {
        /* Make a single contiguous data run for a FAT12 or FAT16 root 
         * directory. The root directory for these file systems is not 
         * tracked in the FAT. */
        TSK_FS_ATTR_RUN *data_run;

        if (tsk_verbose) {
            tsk_fprintf(stderr,
                "%s: Loading root directory\n", func_name);
        }

        /* Allocate the run. */
        data_run = tsk_fs_attr_run_alloc();
        if (data_run == NULL) {
            return 1;
        }

        /* Set the starting sector address and run length. The run begins with 
         * the first sector of the data area. */
        data_run->addr = fatfs->rootsect;
        data_run->len = fatfs->firstclustsect - fatfs->firstdatasect;

        /* Allocate a non-resident attribute to hold the run and add it
         to the attribute list. */
        if ((fs_attr =
                tsk_fs_attrlist_getnew(fs_meta->attr,
                    TSK_FS_ATTR_NONRES)) == NULL) {
            return 1;
        }

        /* Tie everything together. */
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
    else if ((a_fs_file->meta->addr > fs->last_inum - FATFS_NUM_SPECFILE) &&
             (a_fs_file->meta->addr != TSK_FS_ORPHANDIR_INUM(fs))) {
        /* Make a single contiguous data run for a virtual directory or 
         * virtual file (MBR, FAT). */
        TSK_FS_ATTR_RUN *data_run;

        if (tsk_verbose) {
            tsk_fprintf(stderr,
                "%s: Loading virtual file: %" PRIuINUM
                "\n", func_name, a_fs_file->meta->addr);
        }

        /* Allocate the run. */
        data_run = tsk_fs_attr_run_alloc();
        if (data_run == NULL) {
            return 1;
        }

        /* Set the starting sector address and run length. */
        data_run->addr = clust;
        data_run->len = a_fs_file->meta->size / fs->block_size;

        /* Allocate a non-resident attribute to hold the run and add it
         to the attribute list. */
        if ((fs_attr =
                tsk_fs_attrlist_getnew(fs_meta->attr,
                    TSK_FS_ATTR_NONRES)) == NULL) {
            return 1;
        }

        /* Tie everything together. */
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
    else if (fs_meta->flags & TSK_FS_META_FLAG_UNALLOC) {
        /* Make data runs for a deleted file that we want to recover.
         * In this case, we could get a lot of errors because of inconsistent
         * data.  To make it clear that these are from a recovery, we set most
         * error codes to _RECOVER so that they can be more easily suppressed.
         */
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
    else {
        // RJCTODO: Find and fix the bug that causes sectors to be printed incorrectly.
        TSK_LIST *list_seen = NULL;
        TSK_FS_ATTR_RUN *data_run = NULL;
        TSK_FS_ATTR_RUN *data_run_head = NULL;
        TSK_OFF_T full_len_s = 0;
        TSK_DADDR_T sbase;
        /* Do normal cluster chain walking for a file or directory, including
         * FAT32 and exFAT root directories. */

        if (tsk_verbose) {
            tsk_fprintf(stderr,
                "%s: Processing file %" PRIuINUM
                " in normal mode\n", func_name, fs_meta->addr);
        }

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

/* Used for istat callback */
typedef struct {
    FILE *hFile;
    int idx;
    int istat_seen;
} FATFS_PRINT_ADDR;

/* Callback a_action for file_walk to print the sector addresses
 * of a file, used for istat
 */
static TSK_WALK_RET_ENUM
print_addr_act(TSK_FS_FILE * fs_file, TSK_OFF_T a_off, TSK_DADDR_T addr,
    char *buf, size_t size, TSK_FS_BLOCK_FLAG_ENUM a_flags, void *a_ptr)
{
    FATFS_PRINT_ADDR *print = (FATFS_PRINT_ADDR *) a_ptr;

    tsk_fprintf(print->hFile, "%" PRIuDADDR " ", addr);

    if (++(print->idx) == 8) {
        tsk_fprintf(print->hFile, "\n");
        print->idx = 0;
    }
    print->istat_seen = 1;

    return TSK_WALK_CONT;
}

/**
 * Print details on a specific file to a file handle. 
 *
 * @param a_fs File system file is located in.
 * @param a_hFile File handle to print text to.
 * @param a_inum Address of file in file system.
 * @param a_numblock The number of blocks in file to force print (can go beyond file size).
 * @param a_sec_skew Clock skew in seconds to also print times in.
 * 
 * @returns 1 on error and 0 on success.
 */
uint8_t
fatfs_istat(TSK_FS_INFO *a_fs, FILE *a_hFile, TSK_INUM_T a_inum,
    TSK_DADDR_T a_numblock, int32_t a_sec_skew)
{
    const char* func_name = "fatfs_istat";
    FATFS_INFO *fatfs = (FATFS_INFO*)a_fs;
    TSK_FS_META *fs_meta = NULL; 
    TSK_FS_FILE *fs_file =  NULL;
    TSK_FS_META_NAME_LIST *fs_name_list = NULL;
    FATFS_PRINT_ADDR print;
    char timeBuf[128];
 
    tsk_error_reset();
    if (fatfs_is_ptr_arg_null(a_fs, "a_fs", func_name) ||
        fatfs_is_ptr_arg_null(a_hFile, "a_hFile", func_name) ||
        !fatfs_is_inum_in_range(fatfs, a_inum, func_name)) {
        return 1;
    }

    /* Create a TSK_FS_FILE corresponding to the specified inode. */
    if ((fs_file = tsk_fs_file_open_meta(a_fs, NULL, a_inum)) == NULL) {
        return 1;
    }
    fs_meta = fs_file->meta;

    /* Print the inode address. */
    tsk_fprintf(a_hFile, "Directory Entry: %" PRIuINUM "\n", a_inum);

    /* Print the allocation status. */
    tsk_fprintf(a_hFile, "%sAllocated\n",
        (fs_meta->flags & TSK_FS_META_FLAG_UNALLOC) ? "Not " : "");

    /* Print the attributes. */
    tsk_fprintf(a_hFile, "File Attributes: ");

    if (a_inum == FATFS_ROOTINO) {
        tsk_fprintf(a_hFile, "Root Directory\n");
    }
    else if (fs_meta->type == TSK_FS_META_TYPE_VIRT) {
        tsk_fprintf(a_hFile, "Virtual\n");
    }
    else if (a_fs->ftype == TSK_FS_TYPE_EXFAT) {
        if (exfatfs_istat_attr_flags(fatfs, a_inum, a_hFile)) {
            return 1;
        }
    }
    else {
        if (fatxxfs_istat_attr_flags(fatfs, a_inum, a_hFile)) {
            return 1;
        }
    }

    /* Print the file size. */
    tsk_fprintf(a_hFile, "Size: %" PRIuOFF "\n", fs_meta->size);

    /* Print the name. */
    if (fs_meta->name2) {
        fs_name_list = fs_meta->name2;
        tsk_fprintf(a_hFile, "Name: %s\n", fs_name_list->name);
    }

    /* Print the times. */
    if (a_sec_skew != 0) {
        tsk_fprintf(a_hFile, "\nAdjusted Directory Entry Times:\n");

        if (fs_meta->mtime)
            fs_meta->mtime -= a_sec_skew;
        if (fs_meta->atime)
            fs_meta->atime -= a_sec_skew;
        if (fs_meta->crtime)
            fs_meta->crtime -= a_sec_skew;

        tsk_fprintf(a_hFile, "Written:\t%s\n",
            tsk_fs_time_to_str(fs_meta->mtime, timeBuf));
        tsk_fprintf(a_hFile, "Accessed:\t%s\n",
            tsk_fs_time_to_str(fs_meta->atime, timeBuf));
        tsk_fprintf(a_hFile, "Created:\t%s\n",
            tsk_fs_time_to_str(fs_meta->crtime, timeBuf));

        if (fs_meta->mtime == 0)
            fs_meta->mtime += a_sec_skew;
        if (fs_meta->atime == 0)
            fs_meta->atime += a_sec_skew;
        if (fs_meta->crtime == 0)
            fs_meta->crtime += a_sec_skew;

        tsk_fprintf(a_hFile, "\nOriginal Directory Entry Times:\n");
    }
    else {
        tsk_fprintf(a_hFile, "\nDirectory Entry Times:\n");
    }

    tsk_fprintf(a_hFile, "Written:\t%s\n", tsk_fs_time_to_str(fs_meta->mtime,
            timeBuf));
    tsk_fprintf(a_hFile, "Accessed:\t%s\n",
        tsk_fs_time_to_str(fs_meta->atime, timeBuf));
    tsk_fprintf(a_hFile, "Created:\t%s\n",
        tsk_fs_time_to_str(fs_meta->crtime, timeBuf));

    /* Print the specified number of sector addresses. */
    tsk_fprintf(a_hFile, "\nSectors:\n");
    if (a_numblock > 0) {
        /* A bad hack to force a specified number of blocks */
        fs_meta->size = a_numblock * a_fs->block_size;
    }
    print.istat_seen = 0;
    print.idx = 0;
    print.hFile = a_hFile;
    if (tsk_fs_file_walk(fs_file,
            (TSK_FS_FILE_WALK_FLAG_ENUM)(TSK_FS_FILE_WALK_FLAG_AONLY | TSK_FS_FILE_WALK_FLAG_SLACK),
            print_addr_act, (void *) &print)) {
        tsk_fprintf(a_hFile, "\nError reading file\n");
        tsk_error_print(a_hFile);
        tsk_error_reset();
    }
    else if (print.idx != 0) {
        tsk_fprintf(a_hFile, "\n");
    }

    tsk_fs_file_close(fs_file);
    return 0;
}

static TSK_RETVAL_ENUM
fatfs_dinode_copy(FATFS_INFO *a_fatfs, TSK_FS_META *a_fs_meta,
    FATFS_DENTRY *a_dentry, TSK_DADDR_T a_sect, TSK_INUM_T a_inum)
{
    TSK_FS_INFO *fs = (TSK_FS_INFO*)a_fatfs;

    if (fs->ftype == TSK_FS_TYPE_EXFAT) {
        return exfatfs_dinode_copy_stub(a_fatfs, a_fs_meta, a_dentry, a_sect, a_inum);
    }
    else {
        return fatxxfs_dinode_copy(a_fatfs, a_fs_meta, a_dentry, a_sect, a_inum);
    }
}

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
    FATFS_DENTRY *dep = NULL;
    unsigned int myflags = 0;
    unsigned int dentry_idx = 0;
    uint8_t *dir_sectors_bitmap = NULL;
    ssize_t cnt = 0;
    uint8_t done = 0;

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

    /* Handle the root directory inode, if it's included in the walk. */
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
                (TSK_FS_FILE_WALK_FLAG_ENUM)(TSK_FS_FILE_WALK_FLAG_SLACK | TSK_FS_FILE_WALK_FLAG_AONLY),
                inode_walk_file_act, (void *) dir_sectors_bitmap)) {
            tsk_fs_file_close(fs_file);
            free(dir_sectors_bitmap);
            return 1;
        }

        /* Now do a directory walk to get the rest of the directories. */
        if (tsk_fs_dir_walk(fs, fs->root_inum,
                (TSK_FS_DIR_WALK_FLAG_ENUM)(TSK_FS_DIR_WALK_FLAG_ALLOC | TSK_FS_DIR_WALK_FLAG_RECURSE |
                TSK_FS_DIR_WALK_FLAG_NOORPHAN), inode_walk_dent_act,
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

            dep = (FATFS_DENTRY*)(&dino_buf[sector_idx << fatfs->ssize_sh]);

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
                if (0 == fatfs_is_dentry(fatfs, dep, do_basic_dentry_test)) {
                    continue;
                }

                if ((retval2 =
                        fatfs_dinode_copy(fatfs, fs_file->meta, dep, sect,
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