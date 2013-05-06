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
 * \file exfatfs.c
 * Contains the internal TSK exFAT file system code to handle basic file system
 * processing for opening file system, processing sectors, and directory entries. 
 */

#include "tsk_exfatfs.h"
#include "tsk_fs_i.h"
#include "tsk_fatfs.h"

#define BIT_IS_SET(bits, pos) ((bits) & (1 << (pos))) 

static int 
exfatfs_get_fs_size_params(FATFS_INFO *fatfs)
{
    const char *func_name = "exfatfs_get_fs_size_params";
	TSK_FS_INFO *fs = &(fatfs->fs_info);
	exfatfs_sb *fatsb = (exfatfs_sb*)(&fatfs->boot_sector_buffer);

    /* Get bytes per sector.
     * Bytes per sector is a base 2 logarithm, defining a range of sizes with 
     * a min of 512 bytes and a max of 4096 bytes. */ 
    fatfs->ssize_sh = (uint16_t)fatsb->bytes_per_sector;
    if ((fatfs->ssize_sh < 9) || (fatfs->ssize_sh > 12))
    {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_MAGIC);
        tsk_error_set_errstr("Not an FATFS file system (invalid sector size)");
        if (tsk_verbose) {
            fprintf(stderr, "%s: Invalid sector size base 2 logarithm (%d), not in range (9 - 12)\n", func_name, fatfs->ssize);
        }
        return 0;
    }
    fatfs->ssize = (1 << fatfs->ssize_sh);

    /* Get sectors per cluster. 
     * Sectors per cluster is a base 2 logarithm. The max cluster size is 
     * 32 MiB, so the sum of the bytes per sector and sectors per cluster
     * logs cannot exceed 25. */
    if ((fatfs->ssize_sh + fatsb->sectors_per_cluster) > 25) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_MAGIC);
        tsk_error_set_errstr("Not an exFAT file system (invalid cluster size)");
        if (tsk_verbose) {
            fprintf(stderr, "%s: Invalid cluster size (%d)\n", func_name, fatfs->csize);
        }
        return 0;
    }
    fatfs->csize = (1 << fatsb->sectors_per_cluster);

    /* Get sectors per FAT. 
     * It will at least be non-zero. */
    fatfs->sectperfat = tsk_getu32(fs->endian, fatsb->fat_len);
    if (fatfs->sectperfat == 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_MAGIC);
        tsk_error_set_errstr("Not an exFAT file system (invalid sectors per FAT)");
        if (tsk_verbose) {
            fprintf(stderr, "%s: Invalid number of sectors per FAT (%d)\n", func_name, fatfs->sectperfat);
        }
        return 0;
    }

    return 1;
}

static int 
exfatfs_get_fs_layout(FATFS_INFO *fatfs)
{
    const char *func_name = "exfatfs_get_fs_layout";
	TSK_FS_INFO *fs = &(fatfs->fs_info);
	exfatfs_sb *fatsb = (exfatfs_sb*)(&fatfs->boot_sector_buffer);

    /* Get maximum number of sectors in the file system, i.e., the size of 
     * the volume. It should be non-zero. */
    uint64_t vol_len_in_sectors = tsk_getu64(fs->endian, fatsb->vol_len_in_sectors);
    if (vol_len_in_sectors == 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_MAGIC);
        tsk_error_set_errstr("Not an exFAT file system (invalid volume length)");
        if (tsk_verbose) {
            fprintf(stderr, "%s: Invalid volume length (%d)\n", func_name, vol_len_in_sectors);
        }
        return 0;
    }

    /* Get number of FATs.
     * There will be one FAT for exFAT and two FATs for TexFAT. */
    fatfs->numfat = fatsb->num_fats;
    if ((fatfs->numfat != 1) && (fatfs->numfat != 2)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_MAGIC);
        tsk_error_set_errstr("Not an exFAT file system (number of FATs)");
        if (tsk_verbose) {
            fprintf(stderr, "%s: Invalid number of FATs (%d)\n", func_name, fatfs->numfat);
        }
        return 0;
    }

    /* Get the sector address of the first FAT. 
     * It should be non-zero and within the boundaries of the volume. */
    fatfs->firstfatsect = tsk_getu32(fs->endian, fatsb->fat_offset);
    if ((fatfs->firstfatsect == 0) || ((uint64_t)fatfs->firstfatsect >= vol_len_in_sectors)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("Not an exFAT file system (invalid first FAT sector)");
        if (tsk_verbose) {
            fprintf(stderr, "%s: Invalid first FAT sector (%" PRIuDADDR ")\n", func_name, fatfs->firstfatsect);
        }
        return 0;
    }

    // RJCTODO: What about the sector address of the second FAT, if TexFAT is in use?

    /* Get the sector address of the cluster heap (data area). 
     * It should be after the first FAT and within the boundaries 
     * of the volume. */
    fatfs->firstdatasect = tsk_getu32(fs->endian, fatsb->cluster_heap_offset);  
    if ((fatfs->firstdatasect == 0) || 
        (fatfs->firstdatasect < (fatfs->firstfatsect + fatfs->sectperfat)) ||
        ((uint64_t)fatfs->firstdatasect >= vol_len_in_sectors)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("Not an exFAT file system (invalid first data sector");
        if (tsk_verbose) {
            fprintf(stderr, "%s: Invalid first data sector (%" PRIuDADDR ")\n", func_name, fatfs->firstdatasect);
        }
        return 0;
    }

    /* Unlike FAT12 and FAT16, but like FAT32, the sector address of the first
     * cluster (cluster #2, there is no cluster #0 or cluster #1) is the same
     * as the sector address of the cluster heap (data area). */
    fatfs->firstclustsect = fatfs->firstdatasect;

    /* Get the total number of clusters. 
     * It should be non-zero, and should define a cluster heap (data area)
     * that is within the boundaries of the volume. */
    fatfs->clustcnt = tsk_getu32(fs->endian, fatsb->cluster_cnt);
    if ((fatfs->clustcnt == 0) || 
        ((uint64_t)(fatfs->firstdatasect + (fatfs->clustcnt * fatfs->csize)) > vol_len_in_sectors)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("Not an exFAT file system (invalid cluster count)");
        if (tsk_verbose) {
            fprintf(stderr, "%s: Invalid first data sector (%" PRIuDADDR ")\n", func_name, fatfs->firstdatasect);
        }
        return 0;
    }

    /* The first cluster is #2, so the final cluster is: */
     fatfs->lastclust = 1 + fatfs->clustcnt;

     /* This bit mask is required to make the FATFS_CLUST_2_SECT macro work
      * for exFAT. It is the same as the FAT32 mask. */
     fatfs->mask = EXFATFS_MASK;

    /* Get the sector address of the root directory.
     * It should be within the cluster heap (data area) and within the 
     * boundaries of the volume. */
    fatfs->rootsect = FATFS_CLUST_2_SECT(fatfs, tsk_getu32(fs->endian, fatsb->root_dir_cluster));
    if ((fatfs->rootsect == 0) || 
        (fatfs->rootsect < fatfs->firstclustsect) ||
        ((uint64_t)fatfs->rootsect >= vol_len_in_sectors)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("Not an exFAT file system (invalid root directory sector address)");
        if (tsk_verbose) {
            fprintf(stderr, "%s: Invalid root directory sector address (%d)\n", func_name, fatfs->rootsect);
        }
        return 0;
    }

    /* The number of directory entries in the root directory is not specified
     * in the exFAT boot sector. */
    fatfs->numroot = 0;

    // RJCTODO: More validation?

    return 1;
}

static int 
exfatfs_map_fs_layout_to_blocks(FATFS_INFO *fatfs)
{
	TSK_FS_INFO *fs = &(fatfs->fs_info);
	exfatfs_sb *fatsb = (exfatfs_sb*)(&fatfs->boot_sector_buffer);

    /* There are no blocks in exFAT. To conform to the SleuthKit file system 
     * model, sectors and clusters will be mapped to blocks. Calculate the
     * values needed for the mapping. */
    fs->block_size = fatfs->ssize;    
    fs->block_count = tsk_getu64(fs->endian, fatsb->vol_len_in_sectors);
    fs->first_block = 0;
    fs->last_block = fs->last_block_act = fs->block_count - 1;

    /* Determine the last block actually included in the image - 
     * the end of the file system could be "cut off." */
    if ((TSK_DADDR_T) ((fs->img_info->size - fs->offset) / fs->block_size) <
        fs->block_count) {
        fs->last_block_act = (fs->img_info->size - fs->offset) / fs->block_size - 1;
    }

    fs->duname = "Sector";

    // RJCTODO: Don't need inode mapping yet

    return 1;
}

static void 
exfatfs_get_volume_id(FATFS_INFO *fatfs)
{
	TSK_FS_INFO *fs = &(fatfs->fs_info);
	exfatfs_sb *fatsb = (exfatfs_sb*)(&fatfs->boot_sector_buffer);

    for (fs->fs_id_used = 0; fs->fs_id_used < 4; fs->fs_id_used++) {
        fs->fs_id[fs->fs_id_used] = fatsb->vol_serial_no[fs->fs_id_used];
    }
}

static int
exfatfs_get_alloc_bitmap(FATFS_INFO *fatfs)
{
    const char *func_name = "exfatfs_get_alloc_bitmap";
	TSK_FS_INFO *fs = &(fatfs->fs_info);
    TSK_DADDR_T current_sector = fatfs->rootsect;
    TSK_DADDR_T last_sector_of_data_area = fatfs->firstdatasect + (fatfs->clustcnt * fatfs->csize);
    char *sector_buf = NULL;
    ssize_t bytes_read = 0;
    uint8_t *dir_entry_buf = NULL;
    uint8_t num_bitmaps_found = 0;
    int i = 0;

    if ((sector_buf = (char*)tsk_malloc(fatfs->ssize)) == NULL) {
        return 1;
    }

    while (current_sector < last_sector_of_data_area && num_bitmaps_found < fatfs->numfat) {
        /* Read in a sector from the root directory. */
        bytes_read = tsk_fs_read_block(fs, current_sector, sector_buf, fatfs->ssize);
        if (bytes_read != fatfs->ssize) {
            if (bytes_read >= 0) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_FS_READ);
            }
            tsk_error_set_errstr2("%s: sector: %" PRIuDADDR, func_name, current_sector);
            free(sector_buf);
            return 1;
        }

        /* Read the directory entries in the sector, looking for allocation
         * bitmap entries. There will be one entry unless the file system is 
         * TexFAT. */
        for (i = 0; i < fatfs->ssize; i += EXFAT_DIR_ENTRY_SIZE_IN_BYTES) {
            dir_entry_buf = (uint8_t*)&(sector_buf[i]); 
            if (dir_entry_buf[0] == TSK_FS_EXFAT_DIR_ENTRY_TYPE_ALLOC_BITMAP) {
                EXFATFS_ALLOC_BITMAP_DIR_ENTRY *dir_entry = (EXFATFS_ALLOC_BITMAP_DIR_ENTRY *)&dir_entry_buf;
                if (dir_entry->flags & 0x01) {
                    fatfs->EXFATFS_INFO.second_alloc_bitmap_cluster_addr = tsk_getu32(fs->endian, dir_entry->first_cluster_addr);
                    fatfs->EXFATFS_INFO.second_alloc_bitmap_length_in_bytes = tsk_getu32(fs->endian, dir_entry->length_in_bytes);
                }
                else {
                    fatfs->EXFATFS_INFO.alloc_bitmap_cluster_addr = tsk_getu32(fs->endian, dir_entry->first_cluster_addr);
                    fatfs->EXFATFS_INFO.alloc_bitmap_length_in_bytes = tsk_getu32(fs->endian, dir_entry->length_in_bytes);
                }
                ++num_bitmaps_found;
                if (num_bitmaps_found == fatfs->numfat) {
                    break;
                }
            }
        }
    }

    return (num_bitmaps_found == fatfs->numfat);
}

static void 
exfatfs_set_func_ptrs(FATFS_INFO *fatfs)
{
	TSK_FS_INFO *fs = &(fatfs->fs_info);

    /* Content category functions. */ 
    fs->block_walk = fatfs_block_walk;

    // RJCTODO: Set remaining pointers, grouped and commented
    fs->block_getflags = 0;
    fs->inode_walk = 0;
    fs->istat = 0;
    fs->file_add_meta = 0;
    fs->get_default_attr_type = 0;
    fs->load_attrs = 0;
    fs->dir_open_meta = 0;
    fs->name_cmp = 0;
    fs->fsstat = 0;
    fs->fscheck = 0;
    fs->close = 0;

    /* Unimplemented journal functions - exFAT has no file system journal. */
    fs->jblk_walk = fatfs_jblk_walk;
    fs->jentry_walk = fatfs_jentry_walk;
    fs->jopen = fatfs_jopen;
}

static void 
exfatfs_init_caches(FATFS_INFO *fatfs)
{
    int i = 0;

    // RJCTODO: Are these needed?
    for (i = 0; i < FAT_CACHE_N; i++) {
        fatfs->fatc_addr[i] = 0;
        fatfs->fatc_ttl[i] = 0;
    }

    tsk_init_lock(&fatfs->cache_lock);
    tsk_init_lock(&fatfs->dir_lock);
    fatfs->inum2par = NULL;
}

int
exfatfs_open(FATFS_INFO *fatfs)
{
    const char *func_name = "exfatfs_open";

    tsk_error_reset();

    /* Is is really an exFAT file system? */
    if (!exfatfs_get_fs_size_params(fatfs) ||
        !exfatfs_get_fs_layout(fatfs) || 
        !exfatfs_map_fs_layout_to_blocks(fatfs) ||
        !exfatfs_get_alloc_bitmap(fatfs)) {
        return 0;
    }

    exfatfs_get_volume_id(fatfs);
    exfatfs_set_func_ptrs(fatfs);
    exfatfs_init_caches(fatfs);

	return 1;
}

int8_t exfatfs_is_clust_alloc(FATFS_INFO *fatfs, TSK_DADDR_T clust)
{
    return 0;
}