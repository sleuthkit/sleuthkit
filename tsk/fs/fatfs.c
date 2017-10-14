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

/**
 * \internal
 * Open part of a disk image as a FAT file system. 
 *
 * @param a_img_info Disk image to analyze
 * @param a_offset Byte offset where FAT file system starts
 * @param a_ftype Specific type of FAT file system
 * @param a_test NOT USED
 * @returns NULL on error or if data is not a FAT file system
 */
TSK_FS_INFO *
fatfs_open(TSK_IMG_INFO *a_img_info, TSK_OFF_T a_offset, TSK_FS_TYPE_ENUM a_ftype, uint8_t a_test)
{
    const char *func_name = "fatfs_open";
    FATFS_INFO *fatfs = NULL;
    TSK_FS_INFO *fs = NULL;
	int find_boot_sector_attempt = 0;
    ssize_t bytes_read = 0;
    FATFS_MASTER_BOOT_RECORD *bootSector;

    tsk_error_reset();

    if (TSK_FS_TYPE_ISFAT(a_ftype) == 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("%s: Invalid FS Type", func_name);
        return NULL;
    }

    if (a_img_info->sector_size == 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("fatfs_open: sector size is 0");
        return NULL;
    }

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
        TSK_OFF_T boot_sector_offset;

        switch (find_boot_sector_attempt) {
            case 0:
                boot_sector_offset = 0;
                break;
            case 1:
			    // The FATXX backup boot sector is located in sector 6, look there.
                boot_sector_offset = 6 * fs->img_info->sector_size; 
                break;
            case 2:
                // The exFAT backup boot sector is located in sector 12, look there.
                boot_sector_offset = 12 * fs->img_info->sector_size;
                break;
		}

        // Read in the prospective boot sector. 
        bytes_read = tsk_fs_read(fs, boot_sector_offset, fatfs->boot_sector_buffer, FATFS_MASTER_BOOT_RECORD_SIZE);
        if (bytes_read != FATFS_MASTER_BOOT_RECORD_SIZE) {
            if (bytes_read >= 0) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_FS_READ);
            }
            tsk_error_set_errstr2("%s: boot sector", func_name);
			tsk_fs_free((TSK_FS_INFO *)fatfs);
			return NULL;
        }

        // Check it out...
        bootSector = (FATFS_MASTER_BOOT_RECORD*)fatfs->boot_sector_buffer;
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
				tsk_fs_free((TSK_FS_INFO *)fatfs);
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
    if ((a_ftype == TSK_FS_TYPE_FAT_DETECT && (fatxxfs_open(fatfs) == 0 || exfatfs_open(fatfs) == 0)) ||
		(a_ftype == TSK_FS_TYPE_EXFAT && exfatfs_open(fatfs) == 0) ||
		(fatxxfs_open(fatfs) == 0)) {
    	return (TSK_FS_INFO*)fatfs;
	} 
    else {
        tsk_fs_free((TSK_FS_INFO *)fatfs);
		return NULL;
    }
}

/* TTL is 0 if the entry has not been used.  TTL of 1 means it was the
 * most recently used, and TTL of FATFS_FAT_CACHE_N means it was the least 
 * recently used.  This function has a LRU replacement algo
 *
 * Note: This routine assumes &fatfs->cache_lock is locked by the caller.
 */
// return -1 on error, or cache index on success (0 to FATFS_FAT_CACHE_N)

static int
getFATCacheIdx(FATFS_INFO * fatfs, TSK_DADDR_T sect)
{
    int i, cidx;
    ssize_t cnt;
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & fatfs->fs_info;

    // see if we already have it in the cache
    for (i = 0; i < FATFS_FAT_CACHE_N; i++) {
        if ((fatfs->fatc_ttl[i] > 0) &&
            (sect >= fatfs->fatc_addr[i]) &&
            (sect < (fatfs->fatc_addr[i] + (FATFS_FAT_CACHE_B >> fatfs->ssize_sh)))) {
            int a;

            // update the TTLs to push i to the front
            for (a = 0; a < FATFS_FAT_CACHE_N; a++) {
                if (fatfs->fatc_ttl[a] == 0)
                    continue;

                if (fatfs->fatc_ttl[a] < fatfs->fatc_ttl[i])
                    fatfs->fatc_ttl[a]++;
            }
            fatfs->fatc_ttl[i] = 1;
//          fprintf(stdout, "FAT Hit: %d\n", sect);
//          fflush(stdout);
            return i;
        }
    }

//    fprintf(stdout, "FAT Miss: %d\n", (int)sect);
//    fflush(stdout);

    // Look for an unused entry or an entry with a TTL of FATFS_FAT_CACHE_N
    cidx = 0;
    for (i = 0; i < FATFS_FAT_CACHE_N; i++) {
        if ((fatfs->fatc_ttl[i] == 0) ||
            (fatfs->fatc_ttl[i] >= FATFS_FAT_CACHE_N)) {
            cidx = i;
        }
    }
//    fprintf(stdout, "FAT Removing: %d\n", (int)fatfs->fatc_addr[cidx]);
    //   fflush(stdout);

    // read the data
    cnt =
        tsk_fs_read(fs, sect * fs->block_size, fatfs->fatc_buf[cidx],
        FATFS_FAT_CACHE_B);
    if (cnt != FATFS_FAT_CACHE_B) {
        if (cnt >= 0) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_READ);
        }
        tsk_error_set_errstr2("getFATCacheIdx: FAT: %" PRIuDADDR, sect);
        return -1;
    }

    // update the TTLs
    if (fatfs->fatc_ttl[cidx] == 0)     // special case for unused entry
        fatfs->fatc_ttl[cidx] = FATFS_FAT_CACHE_N + 1;

    for (i = 0; i < FATFS_FAT_CACHE_N; i++) {
        if (fatfs->fatc_ttl[i] == 0)
            continue;

        if (fatfs->fatc_ttl[i] < fatfs->fatc_ttl[cidx])
            fatfs->fatc_ttl[i]++;
    }

    fatfs->fatc_ttl[cidx] = 1;
    fatfs->fatc_addr[cidx] = sect;

    return cidx;
}

/*
 * Set *value to the entry in the File Allocation Table (FAT) 
 * for the given cluster
 *
 * *value is in clusters and may need to be converted to
 * sectors by the calling function
 *
 * Invalid values in the FAT (i.e. greater than the largest
 * cluster have a value of 0 returned and a 0 return value.
 *
 * Return 1 on error and 0 on success
 */
uint8_t
fatfs_getFAT(FATFS_INFO * fatfs, TSK_DADDR_T clust, TSK_DADDR_T * value)
{
    uint8_t *a_ptr;
    uint16_t tmp16;
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & fatfs->fs_info;
    TSK_DADDR_T sect, offs;
    ssize_t cnt;
    int cidx;

    /* Sanity Check */
    if (clust > fatfs->lastclust) {
        /* silently ignore requests for the unclustered sectors... */
        if ((clust == fatfs->lastclust + 1) &&
            ((fatfs->firstclustsect + fatfs->csize * fatfs->clustcnt -
                    1) != fs->last_block)) {
            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "fatfs_getFAT: Ignoring request for non-clustered sector\n");
            return 0;
        }

        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("fatfs_getFAT: invalid cluster address: %"
            PRIuDADDR, clust);
        return 1;
    }

    switch (fatfs->fs_info.ftype) {
    case TSK_FS_TYPE_FAT12:
        if (clust & 0xf000) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_ARG);
            tsk_error_set_errstr
                ("fatfs_getFAT: TSK_FS_TYPE_FAT12 Cluster %" PRIuDADDR
                " too large", clust);
            return 1;
        }

        /* id the sector in the FAT */
        sect = fatfs->firstfatsect +
            ((clust + (clust >> 1)) >> fatfs->ssize_sh);

        tsk_take_lock(&fatfs->cache_lock);

        /* Load the FAT if we don't have it */
        // see if it is in the cache
        if (-1 == (cidx = getFATCacheIdx(fatfs, sect))) {
            tsk_release_lock(&fatfs->cache_lock);
            return 1;
        }

        /* get the offset into the cache */
        offs = ((sect - fatfs->fatc_addr[cidx]) << fatfs->ssize_sh) +
            (clust + (clust >> 1)) % fatfs->ssize;

        /* special case when the 12-bit value goes across the cache
         * we load the cache to start at this sect.  The cache
         * size must therefore be at least 2 sectors large 
         */
        if (offs == (FATFS_FAT_CACHE_B - 1)) {

            // read the data -- TTLs will already have been updated
            cnt =
                tsk_fs_read(fs, sect * fs->block_size,
                fatfs->fatc_buf[cidx], FATFS_FAT_CACHE_B);
            if (cnt != FATFS_FAT_CACHE_B) {
                tsk_release_lock(&fatfs->cache_lock);
                if (cnt >= 0) {
                    tsk_error_reset();
                    tsk_error_set_errno(TSK_ERR_FS_READ);
                }
                tsk_error_set_errstr2
                    ("fatfs_getFAT: TSK_FS_TYPE_FAT12 FAT overlap: %"
                    PRIuDADDR, sect);
                return 1;
            }
            fatfs->fatc_addr[cidx] = sect;

            offs = (clust + (clust >> 1)) % fatfs->ssize;
        }

        /* get pointer to entry in current buffer */
        a_ptr = (uint8_t *) fatfs->fatc_buf[cidx] + offs;

        tmp16 = tsk_getu16(fs->endian, a_ptr);

        tsk_release_lock(&fatfs->cache_lock);

        /* slide it over if it is one of the odd clusters */
        if (clust & 1)
            tmp16 >>= 4;

        *value = tmp16 & FATFS_12_MASK;

        /* sanity check */
        if ((*value > (fatfs->lastclust)) &&
            (*value < (0x0ffffff7 & FATFS_12_MASK))) {
            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "fatfs_getFAT: TSK_FS_TYPE_FAT12 cluster (%" PRIuDADDR
                    ") too large (%" PRIuDADDR ") - resetting\n", clust,
                    *value);
            *value = 0;
        }
        return 0;

    case TSK_FS_TYPE_FAT16:
        /* Get sector in FAT for cluster and load it if needed */
        sect = fatfs->firstfatsect + ((clust << 1) >> fatfs->ssize_sh);

        tsk_take_lock(&fatfs->cache_lock);

        if (-1 == (cidx = getFATCacheIdx(fatfs, sect))) {
            tsk_release_lock(&fatfs->cache_lock);
            return 1;
        }


        /* get pointer to entry in the cache buffer */
        a_ptr = (uint8_t *) fatfs->fatc_buf[cidx] +
            ((sect - fatfs->fatc_addr[cidx]) << fatfs->ssize_sh) +
            ((clust << 1) % fatfs->ssize);

        *value = tsk_getu16(fs->endian, a_ptr) & FATFS_16_MASK;

        tsk_release_lock(&fatfs->cache_lock);

        /* sanity check */
        if ((*value > (fatfs->lastclust)) &&
            (*value < (0x0ffffff7 & FATFS_16_MASK))) {
            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "fatfs_getFAT: contents of TSK_FS_TYPE_FAT16 entry %"
                    PRIuDADDR " too large - resetting\n", clust);
            *value = 0;
        }
        return 0;

    case TSK_FS_TYPE_FAT32:
    case TSK_FS_TYPE_EXFAT:
        /* Get sector in FAT for cluster and load if needed */
        sect = fatfs->firstfatsect + ((clust << 2) >> fatfs->ssize_sh);

        tsk_take_lock(&fatfs->cache_lock);

        if (-1 == (cidx = getFATCacheIdx(fatfs, sect))) {
            tsk_release_lock(&fatfs->cache_lock);
            return 1;
        }

        /* get pointer to entry in current buffer */
        a_ptr = (uint8_t *) fatfs->fatc_buf[cidx] +
            ((sect - fatfs->fatc_addr[cidx]) << fatfs->ssize_sh) +
            (clust << 2) % fatfs->ssize;

        *value = tsk_getu32(fs->endian, a_ptr) & FATFS_32_MASK;

        tsk_release_lock(&fatfs->cache_lock);

        /* sanity check */
        if ((*value > fatfs->lastclust) &&
            (*value < (0x0ffffff7 & FATFS_32_MASK))) {
            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "fatfs_getFAT: contents of entry %" PRIuDADDR
                    " too large - resetting\n", clust);

            *value = 0;
        }
        return 0;

    default:
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("fatfs_getFAT: Unknown FAT type: %d",
            fatfs->fs_info.ftype);
        return 1;
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
     * cluster separate from the data area */
    addr = a_start_blk;

    /* Before the data area beings (FAT, root directory etc.) */
    if ((a_start_blk < fatfs->firstclustsect)
        && (a_flags & TSK_FS_BLOCK_WALK_FLAG_ALLOC)) {

        if (tsk_verbose)
            tsk_fprintf(stderr,
                "fatfs_block_walk: Walking non-data area (pre %"
                PRIuDADDR "\n)", fatfs->firstclustsect);

        if ((data_buf = (char *) tsk_malloc(fs->block_size * 8)) == NULL) {
            tsk_fs_block_free(fs_block);
            return 1;
        }

        /* Read 8 sectors at a time to be faster */
        for (; addr < fatfs->firstclustsect && addr <= a_end_blk;) {

            if ((a_flags & TSK_FS_BLOCK_WALK_FLAG_AONLY) == 0) {
                cnt =
                    tsk_fs_read_block(fs, addr, data_buf,
                    fs->block_size * 8);
                if (cnt != fs->block_size * 8) {
                    if (cnt >= 0) {
                        tsk_error_reset();
                        tsk_error_set_errno(TSK_ERR_FS_READ);
                    }
                    tsk_error_set_errstr2
                        ("fatfs_block_walk: pre-data area block: %"
                        PRIuDADDR, addr);
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
                tsk_error_set_errstr2("fatfs_block_walk: block: %"
                    PRIuDADDR, addr);
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

TSK_FS_BLOCK_FLAG_ENUM
fatfs_block_getflags(TSK_FS_INFO * a_fs, TSK_DADDR_T a_addr)
{
    FATFS_INFO *fatfs = (FATFS_INFO *) a_fs;
    int flags = 0;

    // FATs and boot sector
    if (a_addr < fatfs->firstdatasect) {
        flags = TSK_FS_BLOCK_FLAG_META | TSK_FS_BLOCK_FLAG_ALLOC;
    }
    // root directory for FAT12/16
    else if (a_addr < fatfs->firstclustsect) {
        flags = TSK_FS_BLOCK_FLAG_CONT | TSK_FS_BLOCK_FLAG_ALLOC;
    }
    else {
        int retval;
        flags = TSK_FS_BLOCK_FLAG_CONT;

        /* Identify its allocation status */
        retval = fatfs_is_sectalloc(fatfs, a_addr);
        if (retval != -1) {
            if (retval == 1)
                flags |= TSK_FS_BLOCK_FLAG_ALLOC;
            else
                flags |= TSK_FS_BLOCK_FLAG_UNALLOC;
        }
    }
    return (TSK_FS_BLOCK_FLAG_ENUM)flags;
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

    return fatfs->is_cluster_alloc(fatfs, FATFS_SECT_2_CLUST(fatfs, sect));
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
fatfs_fscheck(TSK_FS_INFO * fs, FILE * hFile)
{
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_UNSUPFUNC);
    tsk_error_set_errstr("fscheck not implemented for FAT yet");
    return 1;

    /* Check that allocated dentries point to start of allocated cluster chain */


    /* Size of file is consistent with cluster chain length */


    /* Allocated cluster chains have a corresponding alloc dentry */


    /* Non file dentries have no clusters */


    /* Only one volume label */


    /* Dump Bad Sector Addresses */


    /* Dump unused sector addresses 
     * Reserved area, end of FAT, end of Data Area */
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
	memset(fatfs->boot_sector_buffer, 0, FATFS_MASTER_BOOT_RECORD_SIZE);
    tsk_deinit_lock(&fatfs->cache_lock);
    tsk_deinit_lock(&fatfs->dir_lock);
	
    tsk_fs_free(fs);
}

