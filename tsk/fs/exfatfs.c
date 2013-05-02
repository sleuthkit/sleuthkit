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

static int 
exfatfs_get_fs_data_unit_sizes(FATFS_INFO *fatfs)
{
    const char *func_name = "exfatfs_get_fs_data_unit_sizes";
	TSK_FS_INFO *fs = &(fatfs->fs_info);
	exfatfs_sb *fatsb = (exfatfs_sb*)(&fatfs->boot_sector_buffer);

    /* Get bytes per sector.
     * Bytes per sector must be a base 2 logarithm, defining a range of sizes
     * with a min of 512 bytes and a max of 4096 bytes. */ 
    fatfs->ssize_sh = (uint16_t)fatsb->bytes_per_sector;
    if (fatfs->ssize_sh < 9 || fatfs->ssize_sh > 12)
    {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_MAGIC);
        tsk_error_set_errstr("sector size (%d) is not a multiple of device size (%d), do you have a disk image instead of a partition image?", fatfs->ssize, fs->dev_bsize);
        if (tsk_verbose) {
            fprintf(stderr, "%s: invalid sector size (%d)\n", func_name, fatfs->ssize);
        }
        return 0;
    }
    fatfs->ssize = (1 << fatfs->ssize_sh);

    /* Get sectors per cluster. 
     * Sectors per cluster must be a base 2 logarithm. The max cluster size is 
     *  32 MiB, so the sum of the bytes per sector and sectors per cluster logs 
     *  cannot exceed 25. */
    if (fatfs->ssize_sh + fatsb->sectors_per_cluster > 25) {
        if (tsk_verbose) {
            fprintf(stderr, "%s: invalid cluster size (%d)\n", func_name, fatfs->csize);
        }
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_MAGIC);
        tsk_error_set_errstr("not a FATFS file system (invalid cluster size)");
        return 0;
    }
    fatfs->csize = (1 << fatsb->sectors_per_cluster);

    /* Get sectors per FAT. */
    fatfs->sectperfat = tsk_getu32(fs->endian, fatsb->fat_len);
    if (fatfs->sectperfat == 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_MAGIC);
        tsk_error_set_errstr("not a FATFS file system (invalid sectors per FAT)");
        if (tsk_verbose) {
            fprintf(stderr, "%s: invalid number of sectors per FAT (%d)\n", func_name, fatfs->sectperfat);
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

    /* Get number of FATs.
     * There will be one FAT for exFAT and two FATs for TexFAT. */
    fatfs->numfat = fatsb->num_fats;
    if ((fatfs->numfat != 1) && (fatfs->numfat != 2)) {
        if (tsk_verbose) {
            fprintf(stderr, "%s: Invalid number of FATS (%d)\n", func_name, fatfs->numfat);
        }
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_MAGIC);
        tsk_error_set_errstr("Not a FATFS file system (number of FATs)");
        return 0;
    }

    /* Get the sector offset of the first FAT. */
    fatfs->firstfatsect = tsk_getu32(fs->endian, fatsb->fat_offset);
    // RJCTODO: What is the appropriate check for this? How about being sure it is before the cluster heap offset? And a multiple of sector size...
    //if ((fatfs->firstfatsect == 0) || (fatfs->firstfatsect > fatfs->sectperfat)) {
    //    tsk_error_reset();
    //    tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
    //    tsk_error_set_errstr("Not a FATFS file system (invalid first FAT sector %" PRIuDADDR ")", fatfs->firstfatsect);
    //    if (tsk_verbose) {
    //        fprintf(stderr, "%s: Invalid first FAT (%" PRIuDADDR ")\n", func_name, fatfs->firstfatsect);
    //    }
    //    return 0;
    //}

    /* Get the sector offset of the cluster heap (data area). */
    // RJCTODO: The cluster heap should follow the FATS...validatation opportunity!
    fatfs->firstdatasect = tsk_getu32(fs->endian, fatsb->cluster_heap_offset);  
    fatfs->firstclustsect = fatfs->firstdatasect;

    /* Get the total number of clusters. */
    fatfs->clustcnt = tsk_getu32(fs->endian, fatsb->cluster_cnt);

    /* The first cluster is #2, so the final cluster is: */
    // RJCTODO: This appears to be using last fatfs->lastclust as a FAT index, not sure if this works for exFAT.
     fatfs->lastclust = 1 + fatfs->clustcnt;

    // RJCTODO: What is this?
    // fatfs->mask

    // RJCTODO: This is actually a cluster address...
    fatfs->rootsect = tsk_getu32(fs->endian, fatsb->root_dir_cluster);

    /* The number of directory entries in the root directory is not specified
     *in the exFAT boot sector. */
    fatfs->numroot = 0;


    // RJCTODO: More stuff?

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
    fs->block_count = tsk_getu32(fs->endian, fatsb->vol_len_in_sectors);
    fs->first_block = 0;
    fs->last_block = fs->last_block_act = fs->block_count - 1;

    /* Determine the last block actually included in the image - 
     * the end of the file system could be "cut off." */
    if ((TSK_DADDR_T) ((fs->img_info->size - fs->offset) / fs->block_size) <
        fs->block_count) {
        fs->last_block_act = (fs->img_info->size - fs->offset) / fs->block_size - 1;
    }

    fs->duname = "Sector";

    ///*
    // * inode calculations
    // */

    ///* maximum number of dentries in a sector & cluster */
    //fatfs->dentry_cnt_se = fatfs->ssize / sizeof(fatfs_dentry);
    //fatfs->dentry_cnt_cl = fatfs->dentry_cnt_se * fatfs->csize;

    //fs->root_inum = FATFS_ROOTINO;
    //fs->first_inum = FATFS_FIRSTINO;
    //// Add on extras for Orphan and special files
    //fs->last_inum =
    //    (FATFS_SECT_2_INODE(fatfs,
    //        fs->last_block_act + 1) - 1) + FATFS_NUM_SPECFILE;
    //fs->inum_count = fs->last_inum - fs->first_inum + 1;


    return 1;
}

static void 
exfatfs_get_volume_id(FATFS_INFO *fatfs)
{
	TSK_FS_INFO *fs = &(fatfs->fs_info);
	exfatfs_sb *fatsb = (exfatfs_sb*)(&fatfs->boot_sector_buffer);
    uint8_t vol_serial_no = tsk_getu32(fs->endian, fatsb->vol_serial_no);

    // RJCTODO: Figure out how to do this, is this a number or a string?
    for (fs->fs_id_used = 0; fs->fs_id_used < 4; fs->fs_id_used++) {
        //fs->fs_id[fs->fs_id_used] = vol_serial_no[fs->fs_id_used];
    }
}

static void 
exfatfs_set_func_ptrs(FATFS_INFO *fatfs)
{
	TSK_FS_INFO *fs = &(fatfs->fs_info);

    // RJCTODO:
    fs->block_walk = fatfs_block_walk; // RJCTODO: does this work?
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
    fs->jblk_walk = 0;
    fs->jentry_walk = 0;
    fs->jopen = 0;
    fs->journ_inum = 0;
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

    if (!exfatfs_get_fs_data_unit_sizes(fatfs) ||
        !exfatfs_get_fs_layout(fatfs) || 
        !exfatfs_map_fs_layout_to_blocks(fatfs)) {
        return 0;
    }

    exfatfs_set_func_ptrs(fatfs);
    exfatfs_init_caches(fatfs);

	return 1;
}
