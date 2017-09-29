/*
** fatfs
** The Sleuth Kit
**
** Meta data layer support for the FAT file system.
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2006-2013 Brian Carrier, Basis Technology.  All Rights reserved
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
    if (fatfs_ptr_arg_is_null(a_fatfs, "a_fatfs", func_name) ||
        fatfs_ptr_arg_is_null(a_fs_meta, "a_fs_meta", func_name)) {
        return 1;
    }

    /* Manufacture some metadata. */
    a_fs_meta->type = TSK_FS_META_TYPE_DIR;
    a_fs_meta->mode = TSK_FS_META_MODE_UNSPECIFIED;
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
     * list is done by lazy look up. */
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

    fs_meta->type = TSK_FS_META_TYPE_VIRT;
    fs_meta->mode = TSK_FS_META_MODE_UNSPECIFIED;
    fs_meta->nlink = 1;
    fs_meta->addr = fatfs->mbr_virt_inum;
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

    if ((a_which != 1) && (a_which != 2)) {
        return 1;
    }

    if (a_which > fatfs->numfat) {
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
        fs_meta->addr = fatfs->fat1_virt_inum;
        strncpy(fs_meta->name2->name, FATFS_FAT1NAME,
            TSK_FS_META_NAME_LIST_NSIZE);
        addr_ptr[0] = fatfs->firstfatsect;
    }
    else {
        fs_meta->addr = fatfs->fat2_virt_inum;
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
 * @return 0 on success, 1 on failure. 
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
    if (fatfs_ptr_arg_is_null(a_fatfs, "a_fatfs", func_name) ||
        fatfs_ptr_arg_is_null(a_dentry, "a_dentry", func_name) ||
        !fatfs_inum_arg_is_in_range(a_fatfs, a_inum, func_name)) {
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
    if (fatfs_ptr_arg_is_null(a_fs, "a_fs", func_name) ||
        fatfs_ptr_arg_is_null(a_fs_file, "a_fs_file", func_name) ||
        !fatfs_inum_arg_is_in_range(fatfs, a_inum, func_name)) {
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
    if (a_inum == a_fs->root_inum) {
        if (fatfs_make_root(fatfs, a_fs_file->meta))
            return 1;
        else
            return 0;
    }
    else if (a_inum == fatfs->mbr_virt_inum) {
        if (fatfs_make_mbr(fatfs, a_fs_file->meta))
            return 1;
        else
            return 0;
    }
    else if (a_inum == fatfs->fat1_virt_inum) {
        if (fatfs_make_fat(fatfs, 1, a_fs_file->meta))
            return 1;
        else
            return 0;
    }
    else if (a_inum == fatfs->fat2_virt_inum && fatfs->numfat == 2) {
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
        return fatfs->inode_lookup(fatfs, a_fs_file, a_inum);
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

    if ((fatfs_ptr_arg_is_null(a_fs_file, "a_fs_file", func_name)) ||
        (fatfs_ptr_arg_is_null(a_fs_file->meta, "a_fs_file->meta", func_name)) ||
        (fatfs_ptr_arg_is_null(a_fs_file->fs_info, "a_fs_file->fs_info", func_name))) {
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

    if (fs_meta->attr != NULL) {
        tsk_fs_attrlist_markunused(fs_meta->attr);
    }
    else  {
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

    if ((a_fs_file->meta->addr == fs->root_inum) && 
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
    else if ((a_fs_file->meta->addr >= fatfs->mbr_virt_inum) &&
             (a_fs_file->meta->addr <= fatfs->mbr_virt_inum + fatfs->numfat)) {
        /* Make a single contiguous data run for a virtual file (MBR, FAT). */ 
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
        TSK_FS_ATTR_RUN *data_run = NULL;
        TSK_FS_ATTR_RUN *data_run_tmp = NULL;
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

		/* Quick check for exFAT only
		 * Empty deleted files have a starting cluster of zero, which
		 * causes problems in the exFAT functions since the first data
		 * cluster should be 2. Since a starting cluster of zero indicates
		 * no data, make an empty data run and skip any further processing
		 */
		if((fs->ftype == TSK_FS_TYPE_EXFAT) && (startclust == 0)){
            // initialize the data run
			fs_attr = tsk_fs_attrlist_getnew(a_fs_file->meta->attr, TSK_FS_ATTR_NONRES);
			if (fs_attr == NULL) {
				a_fs_file->meta->attr_state = TSK_FS_META_ATTR_ERROR;
				return 1;
			}

			// Add the empty data run
            if (tsk_fs_attr_set_run(a_fs_file, fs_attr, NULL, NULL,
                    TSK_FS_ATTR_TYPE_DEFAULT, TSK_FS_ATTR_ID_DEFAULT,
                    0, 0, 0, (TSK_FS_ATTR_FLAG_ENUM)0, 0)) {
                fs_meta->attr_state = TSK_FS_META_ATTR_ERROR;
                return 1;
            }
			fs_meta->attr_state = TSK_FS_META_ATTR_STUDIED;
			return 0;
		}

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
            int retval;

            /* If the starting cluster is already allocated then we can't
             * recover it */
            retval = fatfs->is_cluster_alloc(fatfs, startclust);
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
            retval = fatfs->is_cluster_alloc(fatfs, clust);
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
            tsk_fs_attr_run_free(data_run_head);
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
            tsk_fs_attr_run_free(data_run_head);

            data_run_tmp = tsk_fs_attr_run_alloc();
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
fatfs_istat(TSK_FS_INFO *a_fs, TSK_FS_ISTAT_FLAG_ENUM istat_flags, FILE *a_hFile, TSK_INUM_T a_inum,
    TSK_DADDR_T a_numblock, int32_t a_sec_skew)
{
    const char* func_name = "fatfs_istat";
    FATFS_INFO *fatfs = (FATFS_INFO*)a_fs;
    TSK_FS_META *fs_meta = NULL;
    TSK_FS_FILE *fs_file = NULL;
    TSK_FS_META_NAME_LIST *fs_name_list = NULL;
    FATFS_PRINT_ADDR print;
    char timeBuf[128];

    tsk_error_reset();
    if (fatfs_ptr_arg_is_null(a_fs, "a_fs", func_name) ||
        fatfs_ptr_arg_is_null(a_hFile, "a_hFile", func_name) ||
        !fatfs_inum_arg_is_in_range(fatfs, a_inum, func_name)) {
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

    if (a_inum == a_fs->root_inum) {
        tsk_fprintf(a_hFile, "Root Directory\n");
    }
    else if (fs_meta->type == TSK_FS_META_TYPE_VIRT) {
        tsk_fprintf(a_hFile, "Virtual File\n");
    }
    else if (fs_meta->addr == TSK_FS_ORPHANDIR_INUM(a_fs)) {
        tsk_fprintf(a_hFile, "Virtual Directory\n");
    }
    else {
        if (fatfs->istat_attr_flags(fatfs, a_inum, a_hFile)) {
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

        if (fs_meta->mtime)
            fs_meta->mtime += a_sec_skew;
        if (fs_meta->atime)
            fs_meta->atime += a_sec_skew;
        if (fs_meta->crtime)
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
    if (istat_flags & TSK_FS_ISTAT_RUNLIST) {
        const TSK_FS_ATTR *fs_attr_default =
            tsk_fs_file_attr_get_type(fs_file,
                TSK_FS_ATTR_TYPE_DEFAULT, 0, 0);
        if (fs_attr_default && (fs_attr_default->flags & TSK_FS_ATTR_NONRES)) {
            if (tsk_fs_attr_print(fs_attr_default, a_hFile)) {
                tsk_fprintf(a_hFile, "\nError creating run lists\n");
                tsk_error_print(a_hFile);
                tsk_error_reset();
            }
        }
    }
    else {

        if (a_numblock > 0) {
            /* A bad hack to force a specified number of blocks */
            fs_meta->size = a_numblock * a_fs->block_size;
        }
        print.istat_seen = 0;
        print.idx = 0;
        print.hFile = a_hFile;
        if (tsk_fs_file_walk(fs_file,
            (TSK_FS_FILE_WALK_FLAG_ENUM)(TSK_FS_FILE_WALK_FLAG_AONLY | TSK_FS_FILE_WALK_FLAG_SLACK),
            print_addr_act, (void *)&print)) {
            tsk_fprintf(a_hFile, "\nError reading file\n");
            tsk_error_print(a_hFile);
            tsk_error_reset();
        }
        else if (print.idx != 0) {
            tsk_fprintf(a_hFile, "\n");
        }
    }

    tsk_fs_file_close(fs_file);
    return 0;
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
        || ( ! TSK_FS_IS_DIR_META(fs_file->meta->type)))
        return TSK_WALK_CONT;

    /* Get the sector addresses & ignore any errors */
    if (tsk_fs_file_walk(fs_file,
            (TSK_FS_FILE_WALK_FLAG_ENUM)flags,
            inode_walk_file_act, a_ptr)) {
        tsk_error_reset();
    }

    return TSK_WALK_CONT;
}

/**
 * Walk the inodes in a specified range and do a TSK_FS_META_WALK_CB callback
 * for each inode that satisfies criteria specified by a set of 
 * TSK_FS_META_FLAG_ENUM flags. The following flags are supported: 
 * TSK_FS_META_FLAG_ALLOC, TSK_FS_META_FLAG_UNALLOC, TSK_FS_META_FLAG_ORPHAN,
 * TSK_FS_META_FLAG_USED (FATXX only), and TSK_FS_META_FLAG_UNUSED 
 * (FATXX only).
 *
 * @param [in] a_fs File system that contains the inodes.
 * @param [in] a_start_inum Inclusive lower bound of inode range.
 * @param [in] a_end_inum Inclusive upper bound of inode range.
 * @param [in] a_selection_flags Inode selection criteria.
 * @param [in] a_action Callback function for selected inodes.
 * @param [in] a_ptr Private data pointer passed through to callback function.
 * @return 0 on success, 1 on failure, per TSK convention
 */
uint8_t
fatfs_inode_walk(TSK_FS_INFO *a_fs, TSK_INUM_T a_start_inum,
    TSK_INUM_T a_end_inum, TSK_FS_META_FLAG_ENUM a_selection_flags,
    TSK_FS_META_WALK_CB a_action, void *a_ptr)
{
    char *func_name = "fatfs_inode_walk";
    FATFS_INFO *fatfs = (FATFS_INFO*)a_fs;
    unsigned int flags = a_selection_flags;
    TSK_INUM_T end_inum_tmp = 0;
    TSK_FS_FILE *fs_file =  NULL;
    TSK_DADDR_T ssect = 0; 
    TSK_DADDR_T lsect = 0; 
    TSK_DADDR_T sect = 0; 
    char *dino_buf = NULL;
    FATFS_DENTRY *dep = NULL;
    unsigned int dentry_idx = 0;
    uint8_t *dir_sectors_bitmap = NULL;
    ssize_t cnt = 0;
    uint8_t done = 0;

    tsk_error_reset();
    if (fatfs_ptr_arg_is_null(a_fs, "a_fs", func_name) ||
        fatfs_ptr_arg_is_null(a_action, "a_action", func_name)) {
        return 1;
    }

    if (a_start_inum < a_fs->first_inum || a_start_inum > a_fs->last_inum) {
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("%s: Begin inode out of range:  %" PRIuINUM "", 
            func_name, a_start_inum);
        return 1;
    }
    else if (a_end_inum < a_fs->first_inum || 
             a_end_inum > a_fs->last_inum ||
             a_end_inum < a_start_inum) {
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("%s: End inode out of range: %" PRIuINUM "", 
            func_name, a_end_inum);
        return 1;
    }

    /* FAT file systems do not really have the concept of unused inodes. */
    if ((flags & TSK_FS_META_FLAG_UNUSED) && !(flags & TSK_FS_META_FLAG_USED)) {
        return 0;
    }
    flags |= TSK_FS_META_FLAG_USED;
    flags &= ~TSK_FS_META_FLAG_UNUSED;

    /* Make sure the inode selection flags are set correctly. */
    if (flags & TSK_FS_META_FLAG_ORPHAN) {
        /* If ORPHAN file inodes are wanted, make sure that the UNALLOC
         * selection flag is set. */
        flags |= TSK_FS_META_FLAG_UNALLOC;
        flags &= ~TSK_FS_META_FLAG_ALLOC;
    }
    else {
        /* If neither of the ALLOC or UNALLOC inode selection flags are set,
        *  then set them both. */
        if (((flags & TSK_FS_META_FLAG_ALLOC) == 0) &&
            ((flags & TSK_FS_META_FLAG_UNALLOC) == 0)) {
            flags |= (TSK_FS_META_FLAG_ALLOC | TSK_FS_META_FLAG_UNALLOC);
        }
    }

    if (tsk_verbose) {
        tsk_fprintf(stderr,
            "%s: Inode walking %" PRIuINUM " to %"
            PRIuINUM "\n", func_name, a_start_inum, a_end_inum);
    }

    /* If we are looking for orphan files and have not yet populated
     * the list of files reachable by name for this file system, do so now.
     */
    if ((flags & TSK_FS_META_FLAG_ORPHAN)) {
        if (tsk_fs_dir_load_inum_named(a_fs) != TSK_OK) {
            tsk_error_errstr2_concat(
                "%s: Identifying orphan inodes", func_name);
            return 1;
        }
    }

    /* Allocate a TSK_FS_FILE object with a TSK_FS_META object to populate and 
     * pass to the callback function when an inode that fits the inode 
     * selection criteria is found. */
    if ((fs_file = tsk_fs_file_alloc(a_fs)) == NULL) {
        return 1;
    }

    if ((fs_file->meta =
            tsk_fs_meta_alloc(FATFS_FILE_CONTENT_LEN)) == NULL) {
        return 1;
    }

    /* Process the root directory inode, if it's included in the walk. */
    if (a_start_inum == a_fs->root_inum) {
        if (((TSK_FS_META_FLAG_ALLOC & flags) == TSK_FS_META_FLAG_ALLOC)
            && ((TSK_FS_META_FLAG_ORPHAN & flags) == 0)) {
            TSK_WALK_RET_ENUM retval = TSK_WALK_CONT;

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

        a_start_inum++;
        if (a_start_inum == a_end_inum) {
            tsk_fs_file_close(fs_file);
            return 0;
        }
    }

    /* Allocate a bitmap to keep track of which sectors are allocated to
     * directories. */
    if ((dir_sectors_bitmap =
            (uint8_t*)tsk_malloc((size_t) ((a_fs->block_count +
                        7) / 8))) == NULL) {
        tsk_fs_file_close(fs_file);
        return 1;
    }

    /* If not doing an orphan files search, populate the directory sectors 
     * bitmap. The bitmap will be used to make sure that no sector marked as
     * allocated to a directory is skipped when searching for directory 
     * entries to map to inodes. */
    if ((flags & TSK_FS_META_FLAG_ORPHAN) == 0) {
        if (tsk_verbose) {
            tsk_fprintf(stderr,
                "fatfs_inode_walk: Walking directories to collect sector info\n");
        }

        /* Manufacture an inode for the root directory. */
        if (fatfs_make_root(fatfs, fs_file->meta)) {
            tsk_fs_file_close(fs_file);
            free(dir_sectors_bitmap);
            return 1;
        }

        /* Do a file_walk on the root directory to set the bits in the 
         * directory sectors bitmap for each sector allocated to the root
         * directory. */
        if (tsk_fs_file_walk(fs_file,
                (TSK_FS_FILE_WALK_FLAG_ENUM)(TSK_FS_FILE_WALK_FLAG_SLACK | TSK_FS_FILE_WALK_FLAG_AONLY),
                inode_walk_file_act, (void*)dir_sectors_bitmap)) {
            tsk_fs_file_close(fs_file);
            free(dir_sectors_bitmap);
            return 1;
        }

        /* Now walk recursively through the entire directory tree to set the 
         * bits in the directory sectors bitmap for each sector allocated to 
         * the children of the root directory. */
        if (tsk_fs_dir_walk(a_fs, a_fs->root_inum,
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

    /* If the end inode is the one of the virtual virtual FAT files or the 
     * virtual orphan files directory, adjust the end inum and handle the 
     * virtual inodes after the main inode walking loop below completes. */
    if (a_end_inum > a_fs->last_inum - FATFS_NUM_VIRT_FILES(fatfs)) {
        end_inum_tmp = a_fs->last_inum - FATFS_NUM_VIRT_FILES(fatfs);
    }
    else {
        end_inum_tmp = a_end_inum;
    }

    /* Map the begin and end inodes to the sectors that contain them. 
     * This sets the image level boundaries for the inode walking loop. */
    ssect = FATFS_INODE_2_SECT(fatfs, a_start_inum);
    if (ssect > a_fs->last_block) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr
            ("%s: Begin inode in sector too big for image: %"
            PRIuDADDR, func_name, ssect);
        tsk_fs_file_close(fs_file);
        free(dir_sectors_bitmap);
        return 1;
    }

    lsect = FATFS_INODE_2_SECT(fatfs, end_inum_tmp);
    if (lsect > a_fs->last_block) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr
            ("%s: End inode in sector too big for image: %"
            PRIuDADDR, func_name, lsect);
        tsk_fs_file_close(fs_file);
        free(dir_sectors_bitmap);
        return 1;
    }

    /* Allocate a buffer big enough to read in a cluster at a time. */
    if ((dino_buf = (char*)tsk_malloc(fatfs->csize << fatfs->ssize_sh)) ==
        NULL) {
        tsk_fs_file_close(fs_file);
        free(dir_sectors_bitmap);
        return 1;
    }

    /* Walk the inodes. */
    sect = ssect;
    while (sect <= lsect) {
        int cluster_is_alloc = 0;
        size_t num_sectors_to_process = 0;       
        size_t sector_idx = 0;            
        uint8_t do_basic_dentry_test = 0; 

        /* Read in a chunk of the image to process on this iteration of the inode
         * walk. The actual size of the read will depend on whether or not it is 
         * coming from the root directory of a FAT12 or FAT16 file system. As 
         * indicated by the size of the buffer, the data area (exFAT cluster 
         * heap) will for the most part be read in a cluster at a time. 
         * However, the root directory for a FAT12/FAT16 file system precedes 
         * the data area and the read size for it should be a sector, not a 
         * cluster. */
        if (sect < fatfs->firstclustsect) {

            if ((flags & TSK_FS_META_FLAG_ORPHAN) != 0) {
                /* If orphan file hunting, there are no orphans in the root 
                 * directory, so skip ahead to the data area. */
                sect = fatfs->firstclustsect;
                continue;
            }

            /* Read in a FAT12/FAT16 root directory sector. */
            cnt = tsk_fs_read_block(a_fs, sect, dino_buf, fatfs->ssize);
            if (cnt != fatfs->ssize) {
                if (cnt >= 0) {
                    tsk_error_reset();
                    tsk_error_set_errno(TSK_ERR_FS_READ);
                }
                tsk_error_set_errstr2
                    ("%s (root dir): sector: %" PRIuDADDR,
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
            /* The walk has proceeded into the data area (exFAT cluster heap).
             * It's time to read in a cluster at a time. Get the base sector 
             * for the cluster that contains the current sector. */
            sect =
                FATFS_CLUST_2_SECT(fatfs, (FATFS_SECT_2_CLUST(fatfs,
                        sect)));

            /* Determine whether the cluster is allocated. Skip it if it is
             * not allocated and the UNALLOCATED inode selection flag is not 
             * set. */
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
             * directory, then skip it.  NOTE: This will miss orphan file 
             * entries in the slack space of files.
             */
            if ((cluster_is_alloc == 1) && (isset(dir_sectors_bitmap, sect) == 0)) {
                sect += fatfs->csize;
                continue;
            }

            /* The final cluster may not be full. */
            if (lsect - sect + 1 < fatfs->csize) {
                num_sectors_to_process = (size_t) (lsect - sect + 1);
            }
            else {
                num_sectors_to_process = fatfs->csize;
            }

            /* Read in a cluster. */
            cnt = tsk_fs_read_block
                (a_fs, sect, dino_buf, num_sectors_to_process << fatfs->ssize_sh);
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

        /* Walk through the sectors read in. */
        for (sector_idx = 0; sector_idx < num_sectors_to_process; sector_idx++) {
            TSK_INUM_T inum = 0;

            /* If the last inode in this sector is before the start 
             * inode, skip the sector. */
            if (FATFS_SECT_2_INODE(fatfs, sect + 1) < a_start_inum) {
                sect++;
                continue;
            }

            /* Advance the directory entry pointer to the start of the 
             * sector. */
            dep = (FATFS_DENTRY*)(&dino_buf[sector_idx << fatfs->ssize_sh]);

            /* If the sector is not allocated to a directory and the first 
             * chunk is not a directory entry, skip the sector. */
            if (!isset(dir_sectors_bitmap, sect) &&
                !fatfs->is_dentry(fatfs, dep, (FATFS_DATA_UNIT_ALLOC_STATUS_ENUM)cluster_is_alloc, do_basic_dentry_test)) {
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

            /* Walk through the potential directory entries in the sector. */
            for (dentry_idx = 0; dentry_idx < fatfs->dentry_cnt_se;
                dentry_idx++, inum++, dep++) {
                int retval;
                TSK_RETVAL_ENUM retval2 = TSK_OK;

                /* If the inode address of the potential entry is less than
                 * the beginning inode address for the inode walk, skip it. */
                if (inum < a_start_inum) {
                    continue;
                }

                /* If inode address of the potential entry is greater than the
                 * ending inode address for the walk, terminate the inode walk. */ 
                if (inum > end_inum_tmp) {
                    done = 1;
                    break;
                }

                /* If the potential entry is likely not an entry, or it is an  
                 * entry that is not reported in an inode walk, or it does not   
                 * satisfy the inode selection flags, then skip it. */
                if (!fatfs->is_dentry(fatfs, dep, (FATFS_DATA_UNIT_ALLOC_STATUS_ENUM)cluster_is_alloc, do_basic_dentry_test) ||
                    fatfs->inode_walk_should_skip_dentry(fatfs, inum, dep, flags, cluster_is_alloc)) {
                    continue;
                }

                retval2 = fatfs->dinode_copy(fatfs, inum, dep, cluster_is_alloc, fs_file);

                if (retval2 != TSK_OK) {
                    if (retval2 == TSK_COR) {
                        /* Corrupted, move on to the next chunk. */
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

                /* Do the callback. */
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
            }                  
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
    if ((a_end_inum > a_fs->last_inum - FATFS_NUM_VIRT_FILES(fatfs))
        && (flags & TSK_FS_META_FLAG_ALLOC)
        && ((flags & TSK_FS_META_FLAG_ORPHAN) == 0)) {
        TSK_INUM_T inum;

        // cycle through the special files
        for (inum = a_fs->last_inum - FATFS_NUM_VIRT_FILES(fatfs) + 1;
            inum <= a_end_inum; inum++) {
            int retval;

            tsk_fs_meta_reset(fs_file->meta);

            if (inum == fatfs->mbr_virt_inum) {
                if (fatfs_make_mbr(fatfs, fs_file->meta)) {
                    tsk_fs_file_close(fs_file);
                    return 1;
                }
            }
            else if (inum == fatfs->fat1_virt_inum) {
                if (fatfs_make_fat(fatfs, 1, fs_file->meta)) {
                    tsk_fs_file_close(fs_file);
                    return 1;
                }
            }
            else if (inum == fatfs->fat2_virt_inum && fatfs->numfat == 2) {
                if (fatfs_make_fat(fatfs, 2, fs_file->meta)) {
                    tsk_fs_file_close(fs_file);
                    return 1;
                }
            }
            else if (inum == TSK_FS_ORPHANDIR_INUM(a_fs)) {
                if (tsk_fs_dir_make_orphan_dir_meta(a_fs, fs_file->meta)) {
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
}
