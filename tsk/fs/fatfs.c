/*
** The Sleuth Kit
**
** Copyright (c) 2013 Basis Technology Corp.  All rights reserved
** Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
**
** This software is distributed under the Common Public License 1.0
**
*/

/**
 * \file fatfs.c
 * Contains the internal TSK FAT file system code to handle basic file system 
 * processing for opening file system, processing sectors, and directory entries. 
 */

#include "tsk_fs_i.h"
#include "tsk_fatfs.h"
#include "tsk_fatxxfs.h"
#include "tsk_exfatfs.h"

TSK_FS_INFO *
fatfs_open(TSK_IMG_INFO *a_img_info, TSK_OFF_T a_offset, TSK_FS_TYPE_ENUM a_ftype, uint8_t a_test)
{
    const char *func_name = "fatfs_open";
    FATFS_INFO *fatfs = NULL;
    TSK_FS_INFO *fs = NULL;
    TSK_OFF_T boot_sector_offset = 0;
	int find_boot_sector_attempt = 0;
    ssize_t bytes_read = 0;
    FAT_BOOT_SECTOR_RECORD *bootSector;

    tsk_error_reset();

    if (TSK_FS_TYPE_ISFAT(a_ftype) == 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("%s: Invalid FS Type", func_name);
        return NULL;
    }

	// RJCTODO: Add validation of other parameters?

	// Allocate an FATFS_INFO and initialize its generic TSK_FS_INFO members. 
    if ((fatfs = (FATFS_INFO*)tsk_fs_malloc(sizeof(FATFS_INFO))) == NULL) {
        return NULL;
	}
    fs = &(fatfs->fs_info);
    fs->ftype = a_ftype;
    fs->img_info = a_img_info;
    fs->offset = a_offset;
    fs->dev_bsize = a_img_info->sector_size;
    fs->journ_inum = 0;
    fs->tag = TSK_FS_INFO_TAG;

	// Look for a FAT boot sector. Try up to three times because FAT32 and exFAT file systems have backup boot sectors.
    for (find_boot_sector_attempt = 0; find_boot_sector_attempt < 3; ++find_boot_sector_attempt) {
        if (find_boot_sector_attempt == 1) {
			// The FATXX backup boot sector is located in sector 6, look there.
            boot_sector_offset = 6 * fs->img_info->sector_size; 
		}
        else if (find_boot_sector_attempt == 2) {
			// The exFAT backup boot sector is located in sector 12, look there.
            boot_sector_offset = 12 * fs->img_info->sector_size;
		}

        // Read in the prospective boot sector. 
        bytes_read = tsk_fs_read(fs, boot_sector_offset, fatfs->boot_sector_buffer, FAT_BOOT_SECTOR_SIZE);
        if (bytes_read != FAT_BOOT_SECTOR_SIZE) {
            if (bytes_read >= 0) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_FS_READ);
            }
            tsk_error_set_errstr2("%s: boot sector", func_name); // RJCTODO: Is this a helpful error message?
			free(fatfs);
			return NULL;
        }

        // Check it out...
        bootSector = (FAT_BOOT_SECTOR_RECORD*)fatfs->boot_sector_buffer;
        if (tsk_fs_guessu16(fs, bootSector->magic, FATFS_FS_MAGIC) != 0) {
            // No magic, look for a backup boot sector. 
            if ((tsk_getu16(TSK_LIT_ENDIAN, bootSector->magic) == 0) && (find_boot_sector_attempt < 3)) {
                continue;
            }
            else {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_FS_MAGIC);
                tsk_error_set_errstr("Not a FATFS file system (magic)");
                if (tsk_verbose) {
                    fprintf(stderr, "%s: Incorrect FATFS magic\n", func_name);
				}
				free(fatfs);
				return NULL;
            }
        }
        else {
            // Found the magic.
            fatfs->using_backup_boot_sector = boot_sector_offset > 0;
            if (fatfs->using_backup_boot_sector && tsk_verbose) {
				fprintf(stderr, "%s: Using backup boot sector\n", func_name);
            }
            break;
        }
    }

	// Attempt to open the file system as one of the FAT types.
	// RJCTODO: Should this return an error if not detecting and a specific type of FAT fs is specified?
    if ((a_ftype == TSK_FS_TYPE_FAT_DETECT && (fatxxfs_open(fatfs) || exfatfs_open(fatfs))) ||
		(a_ftype == TSK_FS_TYPE_EXFAT && exfatfs_open(fatfs)) ||
		(fatxxfs_open(fatfs))) {
    	return (TSK_FS_INFO*)fatfs;
	} else {
        free(fatfs);
		return NULL;
    }
}

/**************************************************************************
 *
 * BLOCK WALKING
 * 
 *************************************************************************/
/* 
** Walk the sectors of the partition. 
**
** NOTE: This is by SECTORS and not CLUSTERS
** _flags: TSK_FS_BLOCK_FLAG_ALLOC, TSK_FS_BLOCK_FLAG_UNALLOC, TSK_FS_BLOCK_FLAG_META
**  TSK_FS_BLOCK_FLAG_CONT
**
*/
uint8_t
fatfs_block_walk(TSK_FS_INFO * fs, TSK_DADDR_T a_start_blk,
    TSK_DADDR_T a_end_blk, TSK_FS_BLOCK_WALK_FLAG_ENUM a_flags,
    TSK_FS_BLOCK_WALK_CB a_action, void *a_ptr)
{
    char *myname = "fatfs_block_walk";
    FATFS_INFO *fatfs = (FATFS_INFO *) fs;
    char *data_buf = NULL;
    ssize_t cnt;
    TSK_FS_BLOCK *fs_block;

    TSK_DADDR_T addr;
    int myflags;
    unsigned int i;

    // clean up any error messages that are lying around
    tsk_error_reset();

    /*
     * Sanity checks.
     */
    if (a_start_blk < fs->first_block || a_start_blk > fs->last_block) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("%s: Start block: %" PRIuDADDR "", myname,
            a_start_blk);
        return 1;
    }
    if (a_end_blk < fs->first_block || a_end_blk > fs->last_block) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("%s: End block: %" PRIuDADDR "", myname,
            a_end_blk);
        return 1;
    }

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "fatfs_block_walk: Block Walking %" PRIuDADDR " to %"
            PRIuDADDR "\n", a_start_blk, a_end_blk);


    /* Sanity check on a_flags -- make sure at least one ALLOC is set */
    if (((a_flags & TSK_FS_BLOCK_WALK_FLAG_ALLOC) == 0) &&
        ((a_flags & TSK_FS_BLOCK_WALK_FLAG_UNALLOC) == 0)) {
        a_flags |=
            (TSK_FS_BLOCK_WALK_FLAG_ALLOC |
            TSK_FS_BLOCK_WALK_FLAG_UNALLOC);
    }
    if (((a_flags & TSK_FS_BLOCK_WALK_FLAG_META) == 0) &&
        ((a_flags & TSK_FS_BLOCK_WALK_FLAG_CONT) == 0)) {
        a_flags |=
            (TSK_FS_BLOCK_WALK_FLAG_CONT | TSK_FS_BLOCK_WALK_FLAG_META);
    }

    if ((fs_block = tsk_fs_block_alloc(fs)) == NULL) {
        return 1;
    }

    /* cycle through the sectors.  We do the sectors before the first
     * cluster seperate from the data area */
    addr = a_start_blk;

    /* Before the data area beings (FAT, root directory etc.) */
    if ((a_start_blk < fatfs->firstclustsect)
        && (a_flags & TSK_FS_BLOCK_WALK_FLAG_ALLOC)) {

        if (tsk_verbose)
            tsk_fprintf(stderr,
                "fatfs_block_walk: Walking non-data area (pre %"
                PRIuDADDR "\n", fatfs->firstclustsect);

        if ((data_buf = (char *) tsk_malloc(fs->block_size * 8)) == NULL) {
            tsk_fs_block_free(fs_block);
            return 1;
        }

        /* Read 8 sectors at a time to be faster */
        for (; addr < fatfs->firstclustsect && addr <= a_end_blk;) {

            if ((a_flags & TSK_FS_BLOCK_WALK_FLAG_AONLY) == 0) {
                cnt =
                    tsk_fs_read_block(fs, addr, data_buf, fs->block_size * 8);
                if (cnt != fs->block_size * 8) {
                    if (cnt >= 0) {
                        tsk_error_reset();
                        tsk_error_set_errno(TSK_ERR_FS_READ);
                    }
                    tsk_error_set_errstr2
                        ("fatfs_block_walk: pre-data area block: %" PRIuDADDR,
                        addr);
                    free(data_buf);
                    tsk_fs_block_free(fs_block);
                    return 1;
                }
            }

            /* Process the sectors until we get to the clusters, 
             * end of target, or end of buffer */
            for (i = 0;
                i < 8 && (addr) <= a_end_blk
                && (addr) < fatfs->firstclustsect; i++, addr++) {
                int retval;

                myflags = TSK_FS_BLOCK_FLAG_ALLOC;

                /* stuff before the first data sector is the 
                 * FAT and boot sector */
                if (addr < fatfs->firstdatasect)
                    myflags |= TSK_FS_BLOCK_FLAG_META;
                /* This must be the root directory for FAT12/16 */
                else
                    myflags |= TSK_FS_BLOCK_FLAG_CONT;

                // test this sector (we already tested ALLOC)
                if ((myflags & TSK_FS_BLOCK_FLAG_META)
                    && (!(a_flags & TSK_FS_BLOCK_WALK_FLAG_META)))
                    continue;
                else if ((myflags & TSK_FS_BLOCK_FLAG_CONT)
                    && (!(a_flags & TSK_FS_BLOCK_WALK_FLAG_CONT)))
                    continue;

                if (a_flags & TSK_FS_BLOCK_WALK_FLAG_AONLY)
                    myflags |= TSK_FS_BLOCK_FLAG_AONLY;

                tsk_fs_block_set(fs, fs_block, addr,
                    myflags | TSK_FS_BLOCK_FLAG_RAW,
                    &data_buf[i * fs->block_size]);

                retval = a_action(fs_block, a_ptr);
                if (retval == TSK_WALK_STOP) {
                    free(data_buf);
                    tsk_fs_block_free(fs_block);
                    return 0;
                }
                else if (retval == TSK_WALK_ERROR) {
                    free(data_buf);
                    tsk_fs_block_free(fs_block);
                    return 1;
                }
            }
        }

        free(data_buf);

        /* Was that it? */
        if (addr >= a_end_blk) {
            tsk_fs_block_free(fs_block);
            return 0;
        }
    }
    /* Reset the first sector to the start of the data area if we did
     * not examine it - the next calculation will screw up otherwise */
    else if (addr < fatfs->firstclustsect) {
        addr = fatfs->firstclustsect;
    }


    /* Now we read in the clusters in cluster-sized chunks,
     * sectors are too small
     */

    /* Determine the base sector of the cluster where the first 
     * sector is located */
    addr = FATFS_CLUST_2_SECT(fatfs, (FATFS_SECT_2_CLUST(fatfs, addr)));

    if ((data_buf = tsk_malloc(fs->block_size * fatfs->csize)) == NULL) {
        tsk_fs_block_free(fs_block);
        return 1;
    }

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "fatfs_block_walk: Walking data area blocks (%" PRIuDADDR
            " to %" PRIuDADDR ")\n", addr, a_end_blk);

    for (; addr <= a_end_blk; addr += fatfs->csize) {
        int retval;
        size_t read_size;

        /* Identify its allocation status */
        retval = fatfs_is_sectalloc(fatfs, addr);
        if (retval == -1) {
            free(data_buf);
            tsk_fs_block_free(fs_block);
            return 1;
        }
        else if (retval == 1) {
            myflags = TSK_FS_BLOCK_FLAG_ALLOC;
        }
        else {
            myflags = TSK_FS_BLOCK_FLAG_UNALLOC;
        }

        /* At this point, there should be no more meta - just content */
        myflags |= TSK_FS_BLOCK_FLAG_CONT;

        // test if we should call the callback with this one
        if ((myflags & TSK_FS_BLOCK_FLAG_CONT)
            && (!(a_flags & TSK_FS_BLOCK_WALK_FLAG_CONT)))
            continue;
        else if ((myflags & TSK_FS_BLOCK_FLAG_ALLOC)
            && (!(a_flags & TSK_FS_BLOCK_WALK_FLAG_ALLOC)))
            continue;
        else if ((myflags & TSK_FS_BLOCK_FLAG_UNALLOC)
            && (!(a_flags & TSK_FS_BLOCK_WALK_FLAG_UNALLOC)))
            continue;

        if (a_flags & TSK_FS_BLOCK_WALK_FLAG_AONLY)
            myflags |= TSK_FS_BLOCK_FLAG_AONLY;

        
        /* The final cluster may not be full */
        if (a_end_blk - addr + 1 < fatfs->csize)
            read_size = (size_t) (a_end_blk - addr + 1);
        else
            read_size = fatfs->csize;

        if ((a_flags & TSK_FS_BLOCK_WALK_FLAG_AONLY) == 0) {
            cnt = tsk_fs_read_block
                (fs, addr, data_buf, fs->block_size * read_size);
            if (cnt != fs->block_size * read_size) {
                if (cnt >= 0) {
                    tsk_error_reset();
                    tsk_error_set_errno(TSK_ERR_FS_READ);
                }
                tsk_error_set_errstr2("fatfs_block_walk: block: %" PRIuDADDR,
                    addr);
                free(data_buf);
                tsk_fs_block_free(fs_block);
                return 1;
            }
        }

        /* go through each sector in the cluster */
        for (i = 0; i < read_size; i++) {
            int retval;

            if (addr + i < a_start_blk)
                continue;
            else if (addr + i > a_end_blk)
                break;

            tsk_fs_block_set(fs, fs_block, addr + i,
                myflags | TSK_FS_BLOCK_FLAG_RAW,
                &data_buf[i * fs->block_size]);

            retval = a_action(fs_block, a_ptr);
            if (retval == TSK_WALK_STOP) {
                free(data_buf);
                tsk_fs_block_free(fs_block);
                return 0;
            }
            else if (retval == TSK_WALK_ERROR) {
                free(data_buf);
                tsk_fs_block_free(fs_block);
                return 1;
            }
        }
    }

    free(data_buf);
    tsk_fs_block_free(fs_block);
    return 0;
}

/* 
 * Identifies if a sector is allocated
 *
 * If it is less than the data area, then it is allocated
 * else the FAT table is consulted
 *
 * Return 1 if allocated, 0 if unallocated, and -1 if error 
 */
int8_t
fatfs_is_sectalloc(FATFS_INFO * fatfs, TSK_DADDR_T sect)
{
    TSK_FS_INFO *fs = (TSK_FS_INFO *) fatfs;
    /* If less than the first cluster sector, then it is allocated 
     * otherwise check the FAT
     */
    if (sect < fatfs->firstclustsect)
        return 1;

    /* If we are in the unused area, then we are "unalloc" */
    if ((sect <= fs->last_block) &&
        (sect >= (fatfs->firstclustsect + fatfs->csize * fatfs->clustcnt)))
        return 0;

    return fatfs_is_clustalloc(fatfs, FATFS_SECT_2_CLUST(fatfs, sect));
}

/* Return 1 if allocated, 0 if unallocated, and -1 if error */
int8_t
fatfs_is_clustalloc(FATFS_INFO *fatfs, TSK_DADDR_T clust)
{
    TSK_FS_INFO *fs = (TSK_FS_INFO*)fatfs;
    if (fs->ftype == TSK_FS_TYPE_EXFAT) {
        return exfatfs_is_clust_alloc(fatfs, clust);
    }
    else {
        return fatxxfs_is_clust_alloc(fatfs, clust);
    }
}

/* return 1 on error and 0 on success */
uint8_t
fatfs_jopen(TSK_FS_INFO * fs, TSK_INUM_T inum)
{
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_UNSUPFUNC);
    tsk_error_set_errstr("FAT does not have a journal\n");
    return 1;
}

/* return 1 on error and 0 on success */
uint8_t
fatfs_jentry_walk(TSK_FS_INFO * fs, int a_flags,
    TSK_FS_JENTRY_WALK_CB a_action, void *a_ptr)
{
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_UNSUPFUNC);
    tsk_error_set_errstr("FAT does not have a journal\n");
    return 1;
}

/* return 1 on error and 0 on success */
uint8_t
fatfs_jblk_walk(TSK_FS_INFO * fs, TSK_DADDR_T start, TSK_DADDR_T end,
    int a_flags, TSK_FS_JBLK_WALK_CB a_action, void *a_ptr)
{
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_UNSUPFUNC);
    tsk_error_set_errstr("FAT does not have a journal\n");
    return 1;
}

/* fatfs_close - close an fatfs file system */
void
fatfs_close(TSK_FS_INFO *fs)
{
    FATFS_INFO *fatfs = (FATFS_INFO *) fs;
 
    fatfs_dir_buf_free(fatfs);

    fs->tag = 0;
	memset(fatfs->boot_sector_buffer, 0, FAT_BOOT_SECTOR_SIZE);
    tsk_deinit_lock(&fatfs->cache_lock);
    tsk_deinit_lock(&fatfs->dir_lock);
	
    tsk_fs_free(fs);
}

/* fatfs_dinode_load - look up disk inode & load into FATFS_DENTRY structure
 *
 * return 1 on error and 0 on success
 * */

uint8_t
fatfs_dinode_load(TSK_FS_INFO * fs, FATFS_DENTRY * dep, TSK_INUM_T inum)
{
    const char *func_name = "fatfs_dinode_load";
    FATFS_INFO *fatfs = (FATFS_INFO *) fs;
    ssize_t cnt;
    size_t off;
    TSK_DADDR_T sect;

    /*
     * Sanity check.
     * Account for virtual Orphan directory and virtual files
     */
    if ((inum < fs->first_inum)
        || (inum > fs->last_inum - FATFS_NUM_SPECFILE)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_INODE_NUM);
        tsk_error_set_errstr("%s: address: %" PRIuINUM,
            func_name, inum);
        return 1;
    }              
    
    /* Get the sector that this inode would be in and its offset */
    sect = FATFS_INODE_2_SECT(fatfs, inum);
    off = FATFS_INODE_2_OFF(fatfs, inum);

    if (sect > fs->last_block) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_INODE_NUM);
        tsk_error_set_errstr("%s: Inode %" PRIuINUM
            " in sector too big for image: %" PRIuDADDR, func_name, inum, sect);
        return 1;
    }

    cnt = tsk_fs_read(fs, sect * fs->block_size + off, (char *) dep, sizeof(FATFS_DENTRY));
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

/************************* istat *******************************/

/* Callback a_action for file_walk to print the sector addresses
 * of a file
 */

typedef struct {
    FILE *hFile;
    int idx;
    int istat_seen;
} FATFS_PRINT_ADDR;

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
 * @param fs File system file is located in
 * @param hFile File handle to print text to
 * @param inum Address of file in file system
 * @param numblock The number of blocks in file to force print (can go beyond file size)
 * @param sec_skew Clock skew in seconds to also print times in
 * 
 * @returns 1 on error and 0 on success
 */
uint8_t
fatfs_istat(TSK_FS_INFO * fs, FILE * hFile, TSK_INUM_T inum,
    TSK_DADDR_T numblock, int32_t sec_skew)
{
    TSK_FS_META *fs_meta;
    TSK_FS_FILE *fs_file;
    TSK_FS_META_NAME_LIST *fs_name_list;
    FATFS_PRINT_ADDR print;
    FATFS_DENTRY dep;
    FATXXFS_DENTRY *fatxxdep = (FATXXFS_DENTRY*)&dep; //RJCTODO
    char timeBuf[128];

    // clean up any error messages that are lying around
    tsk_error_reset();

    if ((fs_file = tsk_fs_file_open_meta(fs, NULL, inum)) == NULL) {
        return 1;
    }
    fs_meta = fs_file->meta;

    tsk_fprintf(hFile, "Directory Entry: %" PRIuINUM "\n", inum);

    tsk_fprintf(hFile, "%sAllocated\n",
        (fs_meta->flags & TSK_FS_META_FLAG_UNALLOC) ? "Not " : "");

    tsk_fprintf(hFile, "File Attributes: ");

    /* This should only be null if we have the root directory or special file */
    if (fatfs_dinode_load(fs, &dep, inum)) {
        if (inum == FATFS_ROOTINO)
            tsk_fprintf(hFile, "Directory\n");
        else if (fs_file->meta->type == TSK_FS_META_TYPE_VIRT)
            tsk_fprintf(hFile, "Virtual\n");
        else
            tsk_fprintf(hFile, "File\n");
    }
    else if ((fatxxdep->attrib & FATFS_ATTR_LFN) == FATFS_ATTR_LFN) {
        tsk_fprintf(hFile, "Long File Name\n");
    }
    else {
        if (fatxxdep->attrib & FATFS_ATTR_DIRECTORY)
            tsk_fprintf(hFile, "Directory");
        else if (fatxxdep->attrib & FATFS_ATTR_VOLUME)
            tsk_fprintf(hFile, "Volume Label");
        else
            tsk_fprintf(hFile, "File");

        if (fatxxdep->attrib & FATFS_ATTR_READONLY)
            tsk_fprintf(hFile, ", Read Only");
        if (fatxxdep->attrib & FATFS_ATTR_HIDDEN)
            tsk_fprintf(hFile, ", Hidden");
        if (fatxxdep->attrib & FATFS_ATTR_SYSTEM)
            tsk_fprintf(hFile, ", System");
        if (fatxxdep->attrib & FATFS_ATTR_ARCHIVE)
            tsk_fprintf(hFile, ", Archive");

        tsk_fprintf(hFile, "\n");
    }

    tsk_fprintf(hFile, "Size: %" PRIuOFF "\n", fs_meta->size);

    if (fs_meta->name2) {
        fs_name_list = fs_meta->name2;
        tsk_fprintf(hFile, "Name: %s\n", fs_name_list->name);
    }

    if (sec_skew != 0) {
        tsk_fprintf(hFile, "\nAdjusted Directory Entry Times:\n");

        if (fs_meta->mtime)
            fs_meta->mtime -= sec_skew;
        if (fs_meta->atime)
            fs_meta->atime -= sec_skew;
        if (fs_meta->crtime)
            fs_meta->crtime -= sec_skew;

        tsk_fprintf(hFile, "Written:\t%s\n",
            tsk_fs_time_to_str(fs_meta->mtime, timeBuf));
        tsk_fprintf(hFile, "Accessed:\t%s\n",
            tsk_fs_time_to_str(fs_meta->atime, timeBuf));
        tsk_fprintf(hFile, "Created:\t%s\n",
            tsk_fs_time_to_str(fs_meta->crtime, timeBuf));

        if (fs_meta->mtime == 0)
            fs_meta->mtime += sec_skew;
        if (fs_meta->atime == 0)
            fs_meta->atime += sec_skew;
        if (fs_meta->crtime == 0)
            fs_meta->crtime += sec_skew;

        tsk_fprintf(hFile, "\nOriginal Directory Entry Times:\n");
    }
    else
        tsk_fprintf(hFile, "\nDirectory Entry Times:\n");

    tsk_fprintf(hFile, "Written:\t%s\n", tsk_fs_time_to_str(fs_meta->mtime,
            timeBuf));
    tsk_fprintf(hFile, "Accessed:\t%s\n",
        tsk_fs_time_to_str(fs_meta->atime, timeBuf));
    tsk_fprintf(hFile, "Created:\t%s\n",
        tsk_fs_time_to_str(fs_meta->crtime, timeBuf));

    tsk_fprintf(hFile, "\nSectors:\n");

    /* A bad hack to force a specified number of blocks */
    if (numblock > 0)
        fs_meta->size = numblock * fs->block_size;

    print.istat_seen = 0;
    print.idx = 0;
    print.hFile = hFile;

    if (tsk_fs_file_walk(fs_file,
            (TSK_FS_FILE_WALK_FLAG_AONLY | TSK_FS_FILE_WALK_FLAG_SLACK),
            print_addr_act, (void *) &print)) {
        tsk_fprintf(hFile, "\nError reading file\n");
        tsk_error_print(hFile);
        tsk_error_reset();
    }
    else if (print.idx != 0) {
        tsk_fprintf(hFile, "\n");
    }

    tsk_fs_file_close(fs_file);
    return 0;
}
