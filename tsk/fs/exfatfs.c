/*
** The Sleuth Kit
**
** Copyright (c) 2013 Basis Technology Corp.  All rights reserved
** Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
**
** This software is distributed under the Common Public License 1.0
**
*/

/*
 * This code makes use of research presented in the following paper:
 * "Reverse Engineering the exFAT File System" by Robert Shullich
 * Retrieved May 2013 from:
 * http://www.sans.org/reading_room/whitepapers/forensics/reverse-engineering-microsoft-exfat-file-system_33274
 *
 * Some additional details concerning TexFAT were obtained in May 2013
 * from:
 * http://msdn.microsoft.com/en-us/library/ee490643(v=winembedded.60).aspx
 */

/**
 * \file exfatfs.c
 * Contains the internal TSK exFAT file system code to "open" an exFAT file
 * system found in a device image and do the equivalent of a UNIX "stat" call 
 * on the file system.
 */

#include "tsk_exfatfs.h"
#include "tsk_fs_i.h"
#include "tsk_fatfs.h"
#include <assert.h>

/**
 * \internal
 * Parses the MBR of an exFAT file system to obtain file system size 
 * information - bytes per sector, sectors per cluster, and sectors per FAT -
 * to add to a FATFS_INFO object.
 *
 * @param [in, out] a_fatfs Generic FAT file system info structure.
 * @return 0 on success, 1 otherwise, per TSK convention.
 */
static uint8_t 
exfatfs_get_fs_size_params(FATFS_INFO *a_fatfs)
{
    const char *func_name = "exfatfs_get_fs_size_params";
    TSK_FS_INFO *fs = &(a_fatfs->fs_info);
    EXFATFS_MASTER_BOOT_REC *exfatbs = NULL;

    assert(a_fatfs != NULL);
    
    exfatbs = (EXFATFS_MASTER_BOOT_REC*)(&a_fatfs->boot_sector_buffer);

    /* Get bytes per sector.
     * Bytes per sector is a base 2 logarithm, defining a range of sizes with 
     * a min of 512 bytes and a max of 4096 bytes. */ 
    a_fatfs->ssize_sh = (uint16_t)exfatbs->bytes_per_sector;
    if ((a_fatfs->ssize_sh < 9) || (a_fatfs->ssize_sh > 12))
    {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_MAGIC);
        tsk_error_set_errstr("Not an exFAT file system (invalid sector size)");
        if (tsk_verbose) {
            fprintf(stderr, "%s: Invalid sector size base 2 logarithm (%d), not in range (9 - 12)\n", func_name, a_fatfs->ssize);
        }
        return FATFS_FAIL;
    }
    a_fatfs->ssize = (1 << a_fatfs->ssize_sh);

    /* Get sectors per cluster. 
     * Sectors per cluster is a base 2 logarithm. The max cluster size is 
     * 32 MiB, so the sum of the bytes per sector and sectors per cluster
     * logs cannot exceed 25. */
    if ((a_fatfs->ssize_sh + exfatbs->sectors_per_cluster) > 25) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_MAGIC);
        tsk_error_set_errstr("Not an exFAT file system (invalid cluster size)");
        if (tsk_verbose) {
            fprintf(stderr, "%s: Invalid cluster size (%d)\n", func_name, exfatbs->sectors_per_cluster);
        }
        return FATFS_FAIL;
    }
    a_fatfs->csize = (1 << exfatbs->sectors_per_cluster);

    /* Get sectors per FAT. 
     * It will at least be non-zero. */
    a_fatfs->sectperfat = tsk_getu32(fs->endian, exfatbs->fat_len_in_sectors);
    if (a_fatfs->sectperfat == 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_MAGIC);
        tsk_error_set_errstr("Not an exFAT file system (invalid sectors per FAT)");
        if (tsk_verbose) {
            fprintf(stderr, "%s: Invalid number of sectors per FAT (%d)\n", func_name, a_fatfs->sectperfat);
        }
        return FATFS_FAIL;
    }

    return FATFS_OK;
}

/**
 * \internal
 * Parses the MBR of an exFAT file system to obtain file system layout 
 * information to add to a FATFS_INFO object.
 *
 * @param [in, out] a_fatfs Generic FAT file system info structure.
 * @return 0 on success, 1 otherwise, per TSK convention.
 */
static uint8_t 
exfatfs_get_fs_layout(FATFS_INFO *a_fatfs)
{
    const char *func_name = "exfatfs_get_fs_layout";
    TSK_FS_INFO *fs = &(a_fatfs->fs_info);
    EXFATFS_MASTER_BOOT_REC *exfatbs = NULL;
    uint64_t vol_len_in_sectors = 0;
    uint64_t last_sector_of_cluster_heap = 0;

    assert(a_fatfs != NULL);
    
    /* Get the size of the volume. It should be non-zero. */
    exfatbs = (EXFATFS_MASTER_BOOT_REC*)(&a_fatfs->boot_sector_buffer);
    vol_len_in_sectors = tsk_getu64(fs->endian, exfatbs->vol_len_in_sectors);
    if (vol_len_in_sectors == 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_MAGIC);
        tsk_error_set_errstr("Not an exFAT file system (invalid volume length)");
        if (tsk_verbose) {
            fprintf(stderr, "%s: Invalid volume length in sectors (%" PRIu64 ")\n", func_name, vol_len_in_sectors);
        }
        return FATFS_FAIL;
    }

    /* Get the number of FATs. There will be one FAT for regular exFAT and two 
     * FATs for TexFAT (transactional exFAT). */
    a_fatfs->numfat = exfatbs->num_fats;
    if ((a_fatfs->numfat != 1) && (a_fatfs->numfat != 2)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_MAGIC);
        tsk_error_set_errstr("Not an exFAT file system (number of FATs)");
        if (tsk_verbose) {
            fprintf(stderr, "%s: Invalid number of FATs (%d)\n", func_name, a_fatfs->numfat);
        }
        return FATFS_FAIL;
    }

    /* Get the sector address of the first FAT (FAT0). 
     * It should be non-zero and within the boundaries of the volume.
     * Note that if the file system is TexFAT, FAT1 will be the working copy
     * of the FAT and FAT0 will be the stable copy of the last known good FAT. 
     * Therefore, the Sleuthkit should use FAT0. */
    a_fatfs->firstfatsect = tsk_getu32(fs->endian, exfatbs->fat_offset);
    if ((a_fatfs->firstfatsect == 0) || ((uint64_t)a_fatfs->firstfatsect >= vol_len_in_sectors)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("Not an exFAT file system (invalid first FAT sector)");
        if (tsk_verbose) {
            fprintf(stderr, "%s: Invalid first FAT sector (%" PRIuDADDR ")\n", func_name, a_fatfs->firstfatsect);
        }
        return FATFS_FAIL;
    }

    /* Get the sector address of the cluster heap (data area). It should be 
     * after the FATs and within the boundaries of the volume. */
    a_fatfs->firstdatasect = tsk_getu32(fs->endian, exfatbs->cluster_heap_offset);  
    if ((a_fatfs->firstdatasect <= (a_fatfs->firstfatsect + (a_fatfs->sectperfat * a_fatfs->numfat) - 1)) ||
        ((uint64_t)a_fatfs->firstdatasect >= vol_len_in_sectors)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("Not an exFAT file system (invalid first data sector");
        if (tsk_verbose) {
            fprintf(stderr, "%s: Invalid first data sector (%" PRIuDADDR ")\n", func_name, a_fatfs->firstdatasect);
        }
        return FATFS_FAIL;
    }

    /* Unlike FAT12 and FAT16, but like FAT32, the sector address of the first
     * cluster (cluster #2, there is no cluster #0 or cluster #1) is the same
     * as the sector address of the cluster heap (data area). */
    a_fatfs->firstclustsect = a_fatfs->firstdatasect;

    /* Get the total number of clusters. It should be non-zero, and should 
     * define a cluster heap (data area) that is within the boundaries of the
     * volume. */
    a_fatfs->clustcnt = tsk_getu32(fs->endian, exfatbs->cluster_cnt);
    last_sector_of_cluster_heap = a_fatfs->firstdatasect + (a_fatfs->clustcnt * a_fatfs->csize) - 1;
    if ((a_fatfs->clustcnt == 0) || 
        (last_sector_of_cluster_heap >= vol_len_in_sectors)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("Not an exFAT file system (invalid cluster count)");
        if (tsk_verbose) {
            fprintf(stderr, "%s: Invalid cluster count (%" PRIuDADDR ")\n", func_name, a_fatfs->clustcnt);
        }
        return FATFS_FAIL;
    }

    /* The first cluster is #2, so the final cluster is: */
     a_fatfs->lastclust = 1 + a_fatfs->clustcnt;

     /* This bit mask is required to make the FATFS_CLUST_2_SECT macro work
      * for exFAT. It is the same as the FAT32 mask. */
     a_fatfs->mask = EXFATFS_MASK;

    /* Get the sector address of the root directory. It should be within the
     * cluster heap (data area). */
    a_fatfs->rootsect = FATFS_CLUST_2_SECT(a_fatfs, tsk_getu32(fs->endian, exfatbs->root_dir_cluster));
    if ((a_fatfs->rootsect < a_fatfs->firstdatasect) ||
        ((uint64_t)a_fatfs->rootsect > last_sector_of_cluster_heap)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("Not an exFAT file system (invalid root directory sector address)");
        if (tsk_verbose) {
            fprintf(stderr, "%s: Invalid root directory sector address (%"PRIuDADDR")\n", func_name, a_fatfs->rootsect);
        }
        return FATFS_FAIL;
    }

    /* The number of directory entries in the root directory is not specified
     * in the exFAT boot sector. */
    a_fatfs->numroot = 0;

    return FATFS_OK;
}

/**
 * \internal
 * Searches the root directory of an exFAT file system for an allocation bitmap
 * directory entry. If the entry is found, data from the entry is saved to a
 * FATFS_INFO object.
 *
 * @param [in, out] a_fatfs Generic FAT file system info structure.
 * @return 0 on success, 1 otherwise, per TSK convention.
 */
static uint8_t
exfatfs_get_alloc_bitmap(FATFS_INFO *a_fatfs)
{
    const char *func_name = "exfatfs_get_alloc_bitmap";
    TSK_FS_INFO *fs = &(a_fatfs->fs_info);
    TSK_DADDR_T current_sector = 0;
    TSK_DADDR_T last_sector_of_data_area = 0;
    char *sector_buf = NULL;
    EXFATFS_ALLOC_BITMAP_DIR_ENTRY *dentry = NULL;
    uint64_t i = 0;
    uint64_t first_sector_of_alloc_bitmap = 0;
    uint64_t alloc_bitmap_length_in_bytes = 0;
    uint64_t last_sector_of_alloc_bitmap = 0;

    assert(a_fatfs != NULL);
    
    if ((sector_buf = (char*)tsk_malloc(a_fatfs->ssize)) == NULL) {
        return FATFS_FAIL;
    }

    last_sector_of_data_area = a_fatfs->firstdatasect + (a_fatfs->clustcnt * a_fatfs->csize) - 1;
    for (current_sector = a_fatfs->rootsect; current_sector < last_sector_of_data_area; current_sector++) {
        ssize_t bytes_read = 0;

        /* Read in a sector from the root directory. The allocation bitmap
         * directory entries will probably be near the beginning of the 
         * directory, probably in the first sector. */
        bytes_read = tsk_fs_read_block(fs, current_sector, sector_buf, a_fatfs->ssize);
        if (bytes_read != a_fatfs->ssize) {
            if (bytes_read >= 0) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_FS_READ);
            }
            tsk_error_set_errstr2("%s: sector: %" PRIuDADDR, func_name, current_sector);
            free(sector_buf);
            return FATFS_FAIL;
        }

        /* Read the directory entries in the sector, looking for allocation
         * bitmap entries. There will be one entry unless the file system is 
         * TexFAT (transactional exFAT), in which case there will be two. */
        for (i = 0; i < a_fatfs->ssize; i += sizeof(FATFS_DENTRY)) {
            dentry = (EXFATFS_ALLOC_BITMAP_DIR_ENTRY*)&(sector_buf[i]); 

            /* The type of the directory entry is encoded in the first byte 
             * of the entry. See EXFATFS_DIR_ENTRY_TYPE_ENUM. */ 
            if (exfatfs_get_enum_from_type(dentry->entry_type) == EXFATFS_DIR_ENTRY_TYPE_ALLOC_BITMAP) {
                /* Do an in-depth test. */
                if (!exfatfs_is_alloc_bitmap_dentry((FATFS_DENTRY*)dentry, FATFS_DATA_UNIT_ALLOC_STATUS_UNKNOWN, a_fatfs)) {
                    continue;
                }

                /* The first bit of the flags byte is 0 for the first 
                 * allocation bitmap directory entry and 1 for the second 
                 * bitmap directory entry. If TexFAT is in use and there are
                 * two allocation bitmaps, the first bitmap should be the
                 * stable copy of the last known good allocation bitmap. 
                 * Therefore, the SleuthKit will use the first bitmap to 
                 * determine which clusters are allocated. */
                if (~(dentry->flags & 0x01)) {
                    first_sector_of_alloc_bitmap = FATFS_CLUST_2_SECT(a_fatfs, tsk_getu32(fs->endian, dentry->first_cluster_of_bitmap));
                    alloc_bitmap_length_in_bytes = tsk_getu64(fs->endian, dentry->length_of_alloc_bitmap_in_bytes);
                    last_sector_of_alloc_bitmap = first_sector_of_alloc_bitmap + (roundup(alloc_bitmap_length_in_bytes, a_fatfs->ssize) / a_fatfs->ssize) - 1;

                    /* The allocation bitmap must lie within the boundaries of the data area. 
                     * It also must be big enough for the number of clusters reported in the VBR. */
                    if ((first_sector_of_alloc_bitmap >= a_fatfs->firstdatasect) &&
                        (last_sector_of_alloc_bitmap <= last_sector_of_data_area) &&
                        (alloc_bitmap_length_in_bytes >= (a_fatfs->clustcnt + 7) / 8))
                    {
                        a_fatfs->EXFATFS_INFO.first_sector_of_alloc_bitmap = first_sector_of_alloc_bitmap; 
                        a_fatfs->EXFATFS_INFO.length_of_alloc_bitmap_in_bytes = alloc_bitmap_length_in_bytes;
                        free(sector_buf);
                        return FATFS_OK;
                    }
                }
            }
        }
    }
    free(sector_buf);

    return FATFS_FAIL;
}

/**
 * \internal
 * Parses the MBR of an exFAT file system to obtain a volume serial number to
 * add to a FATFS_INFO object.
 *
 * @param [in, out] a_fatfs Generic FAT file system info structure.
 */
static void 
exfatfs_get_volume_id(FATFS_INFO *a_fatfs)
{
    TSK_FS_INFO *fs = &(a_fatfs->fs_info);
    EXFATFS_MASTER_BOOT_REC *exfatbs = NULL;

    assert(a_fatfs != NULL);
    
    exfatbs = (EXFATFS_MASTER_BOOT_REC*)(&a_fatfs->boot_sector_buffer);
    for (fs->fs_id_used = 0; fs->fs_id_used < 4; fs->fs_id_used++) {
        fs->fs_id[fs->fs_id_used] = exfatbs->vol_serial_no[fs->fs_id_used];
    }
}

/**
 * \internal
 * Sets the file system layout members of a FATFS_INFO object for an exFAT file
 * system. Note that there are no "block" or "inode" concepts in exFAT. So, to 
 * conform to the SleuthKit generic file system model, sectors are treated as 
 * blocks, directory entries are treated as inodes, and inode addresses (inode 
 * numbers) are assigned to every directory-entry-sized chunk of the file 
 * system. This is the same mapping previously established for TSK treatment of
 * the other FAT file systems. As with those sister file systems, any given 
 * inode address may or may not point to a conceptual exFAT inode.
 *
 * @param [in, out] a_fatfs Generic FAT file system info structure.
 */
static void
exfatfs_setup_fs_layout_model(FATFS_INFO *a_fatfs)
{
    TSK_FS_INFO *fs = &(a_fatfs->fs_info);
    EXFATFS_MASTER_BOOT_REC *exfatbs = NULL;

    assert(a_fatfs != NULL);

    fs->duname = "Sector";

    fs->block_size = a_fatfs->ssize;    
    
    exfatbs = (EXFATFS_MASTER_BOOT_REC*)(&a_fatfs->boot_sector_buffer);
    fs->block_count = tsk_getu64(fs->endian, exfatbs->vol_len_in_sectors);
    
    fs->first_block = 0;
    fs->last_block = fs->last_block_act = fs->block_count - 1;

    /* Determine the last block actually included in the image, since the 
     * end of the file system could be "cut off." */
    if ((TSK_DADDR_T) ((fs->img_info->size - fs->offset) / fs->block_size) <
        fs->block_count) {
        fs->last_block_act = (fs->img_info->size - fs->offset) / fs->block_size - 1;
    }

    /* Calculate the maximum number of directory entries that will fit in a 
     * sector and a cluster. */
    a_fatfs->dentry_cnt_se = a_fatfs->ssize / sizeof(FATFS_DENTRY);
    a_fatfs->dentry_cnt_cl = a_fatfs->dentry_cnt_se * a_fatfs->csize;

    /* The first entry in an exFAT FAT is a media type indicator.
     * The second entry is simply a meaningless 0xFFFFFFFF. 
     * The first inode address is therefore 2. */
    fs->first_inum = FATFS_FIRSTINO;

    fs->root_inum = FATFS_ROOTINO;

    /* Calculate inode addresses for the virtual files (MBR, one or two FATS) 
     * and the virtual orphan files directory. */
    fs->last_inum = (FATFS_SECT_2_INODE(a_fatfs, fs->last_block_act + 1) - 1) + FATFS_NUM_VIRT_FILES(a_fatfs);
    a_fatfs->mbr_virt_inum = fs->last_inum - FATFS_NUM_VIRT_FILES(a_fatfs) + 1;
    a_fatfs->fat1_virt_inum = a_fatfs->mbr_virt_inum + 1;
    if (a_fatfs->numfat == 2) {
        a_fatfs->fat2_virt_inum = a_fatfs->fat1_virt_inum + 1;
    }
    else {
        a_fatfs->fat2_virt_inum = a_fatfs->fat1_virt_inum;
    }
    
    /* Calculate the total number of inodes. */
    fs->inum_count = fs->last_inum - fs->first_inum + 1;
}

/**
 * \internal
 * Initializes the data structures used to cache the cluster addresses that 
 * make up FAT chains in an exFAT file system, and the lock used to make the
 * data structures thread-safe. 
 *
 * @param [in, out] a_fatfs Generic FAT file system info structure.
 */
static void 
exfatfs_init_fat_cache(FATFS_INFO *a_fatfs)
{
    uint32_t i = 0;

    assert(a_fatfs != NULL);

    for (i = 0; i < FATFS_FAT_CACHE_N; i++) {
        a_fatfs->fatc_addr[i] = 0;
        a_fatfs->fatc_ttl[i] = 0;
    }

    tsk_init_lock(&a_fatfs->cache_lock);
    tsk_init_lock(&a_fatfs->dir_lock);
    a_fatfs->inum2par = NULL;
}

/**
 * \internal
 * Initializes the data structure used to map inode addresses to parent inode
 * addresses in an exFAT file system, and the lock used to make the data 
 * structure thread-safe. 
 *
 * @param [in, out] a_fatfs Generic FAT file system info structure.
 */
static void 
exfatfs_init_inums_map(FATFS_INFO *a_fatfs)
{
    assert(a_fatfs != NULL);

    tsk_init_lock(&a_fatfs->dir_lock);
    a_fatfs->inum2par = NULL;
}

/**
 * \internal
 * 
 * Sets the function pointers in a FATFS_INFO object for an exFAT file system
 * to point to either generic FAT file system functions or to exFAT file system
 * functions.
 *
 * @param [in, out] a_fatfs Generic FAT file system info structure.
 */
static void 
exfatfs_set_func_ptrs(FATFS_INFO *a_fatfs)
{
    TSK_FS_INFO *fs = &(a_fatfs->fs_info);

    assert(a_fatfs != NULL);

    fs->close = fatfs_close;

    /* File system category functions. */
    fs->fsstat = exfatfs_fsstat;
    fs->fscheck = fatfs_fscheck;

    /* Content category functions. */
    fs->block_walk = fatfs_block_walk;
    fs->block_getflags = fatfs_block_getflags;

    /* Meta data category functions. */
    fs->inode_walk = fatfs_inode_walk;
    fs->istat = fatfs_istat;
    fs->file_add_meta = fatfs_inode_lookup;
    fs->get_default_attr_type = fatfs_get_default_attr_type;
    fs->load_attrs = fatfs_make_data_runs;

    /* Name category functions. */
    fs->dir_open_meta = fatfs_dir_open_meta;
    fs->name_cmp = fatfs_name_cmp;

    /* NOP journal functions - exFAT has no file system journal. */
    fs->jblk_walk = fatfs_jblk_walk;
    fs->jentry_walk = fatfs_jentry_walk;
    fs->jopen = fatfs_jopen;

    /* Specialization for exFAT functions. */
    a_fatfs->is_cluster_alloc = exfatfs_is_cluster_alloc;
    a_fatfs->is_dentry = exfatfs_is_dentry;
    a_fatfs->dinode_copy =  exfatfs_dinode_copy;
    a_fatfs->inode_lookup = exfatfs_inode_lookup;
    a_fatfs->inode_walk_should_skip_dentry = exfatfs_inode_walk_should_skip_dentry;
    a_fatfs->istat_attr_flags = exfatfs_istat_attr_flags;
    a_fatfs->dent_parse_buf = exfatfs_dent_parse_buf;
}

/**
 * Open an exFAT file system in an image file. 
 *
 * @param [in, out] a_fatfs Generic FAT file system info structure.
 * @return 0 on success, 1 otherwise, per TSK convention.
 */
uint8_t
exfatfs_open(FATFS_INFO *a_fatfs)
{
    const char *func_name = "exfatfs_open";
    TSK_FS_INFO *fs = &(a_fatfs->fs_info);

    assert(a_fatfs != NULL);    

    tsk_error_reset();
    if (fatfs_ptr_arg_is_null(a_fatfs, "a_fatfs", func_name)) {
        return FATFS_FAIL; 
    }

    if (exfatfs_get_fs_size_params(a_fatfs) == FATFS_FAIL ||
        exfatfs_get_fs_layout(a_fatfs) == FATFS_FAIL) {
        return FATFS_FAIL; 
    }

    if (exfatfs_get_fs_layout(a_fatfs) == FATFS_OK) {
        exfatfs_setup_fs_layout_model(a_fatfs);
    }
    else {
        return FATFS_FAIL;
    }

    if (exfatfs_get_alloc_bitmap(a_fatfs) == FATFS_FAIL) {
        return FATFS_FAIL;
    }

    exfatfs_get_volume_id(a_fatfs);
    exfatfs_init_inums_map(a_fatfs);
    exfatfs_init_fat_cache(a_fatfs);
    exfatfs_set_func_ptrs(a_fatfs);

    fs->ftype = TSK_FS_TYPE_EXFAT;

    return FATFS_OK;
}

/**
 * \internal
 * Searches an exFAT file system for its volume label directory entry, which 
 * should be in the root directory of the file system. If the entry is found, 
 * its metadata is copied into the TSK_FS_META object of a TSK_FS_FILE object.
 *
 * @param [in] a_fatfs Generic FAT file system info structure.
 * @param [out] a_fatfs Generic file system file structure.
 * @return 0 on success, 1 otherwise, per TSK convention.
 */
static uint8_t
exfatfs_find_volume_label_dentry(FATFS_INFO *a_fatfs, TSK_FS_FILE *a_fs_file)
{
    const char *func_name = "exfatfs_find_volume_label_dentry";
    TSK_FS_INFO *fs = (TSK_FS_INFO *)a_fatfs;
    TSK_DADDR_T current_sector = 0;
    TSK_DADDR_T last_sector_of_data_area = 0;
    char *sector_buf = NULL;
    ssize_t bytes_read = 0;
    TSK_INUM_T current_inum = 0;
    FATFS_DENTRY *dentry = NULL;
    uint64_t i = 0;

    assert(a_fatfs != NULL);
    assert(a_fs_file != NULL);

    tsk_error_reset();
    if (fatfs_ptr_arg_is_null(a_fatfs, "a_fatfs", func_name) ||
        fatfs_ptr_arg_is_null(a_fs_file, "a_fs_file", func_name)) {
        return FATFS_FAIL; 
    }

    /* Allocate or reset the TSK_FS_META object. */
    if (a_fs_file->meta == NULL) {
        if ((a_fs_file->meta =
                tsk_fs_meta_alloc(FATFS_FILE_CONTENT_LEN)) == NULL) {
            return FATFS_FAIL;
        }
    }
    else {
        tsk_fs_meta_reset(a_fs_file->meta);
    }

    /* Allocate a buffer for reading in sector-size chunks of the image. */
    if ((sector_buf = (char*)tsk_malloc(a_fatfs->ssize)) == NULL) {
        return FATFS_FAIL;
    }

    current_sector = a_fatfs->rootsect;
    last_sector_of_data_area = a_fatfs->firstdatasect + (a_fatfs->clustcnt * a_fatfs->csize) - 1;
    while (current_sector < last_sector_of_data_area) {
        int8_t sector_is_alloc = 0;

        /* Read in a sector from the root directory. The volume label
         * directory entry will probably be near the beginning of the 
         * directory, probably in the first sector. */
        bytes_read = tsk_fs_read_block(fs, current_sector, sector_buf, a_fatfs->ssize);
        if (bytes_read != a_fatfs->ssize) {
            if (bytes_read >= 0) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_FS_READ);
            }
            tsk_error_set_errstr2("%s: error reading sector: %" PRIuDADDR, func_name, current_sector);
            free(sector_buf);
            return FATFS_FAIL;
        }

        /* Get the allocation status of the sector (yes, it should be allocated). */
        sector_is_alloc = fatfs_is_sectalloc(a_fatfs, current_sector);
        if (sector_is_alloc == -1) {
            return FATFS_FAIL;
        }

        /* Get the inode address of the first directory entry of the sector. */
        current_inum = FATFS_SECT_2_INODE(a_fatfs, current_sector);

        /* Loop through the putative directory entries in the sector, 
         * until the volume label entry is found.  */
        for (i = 0; i < a_fatfs->ssize; i += sizeof(FATFS_DENTRY)) {
            dentry = (FATFS_DENTRY*)&(sector_buf[i]); 

            /* The type of the directory entry is encoded in the first byte 
             * of the entry. See EXFATFS_DIR_ENTRY_TYPE_ENUM. */ 
            if (exfatfs_get_enum_from_type(dentry->data[0]) == EXFATFS_DIR_ENTRY_TYPE_VOLUME_LABEL) {
                if (!exfatfs_is_vol_label_dentry(dentry, FATFS_DATA_UNIT_ALLOC_STATUS_UNKNOWN)) {
                    continue;
                }

                /* Found it, save it to the TSK_FS_META object of the 
                 * TSK_FS_FILE object and exit. */ 
                if (exfatfs_dinode_copy(a_fatfs, current_inum, dentry, 
                    sector_is_alloc, a_fs_file) == TSK_OK) {
                        return FATFS_OK;
                }
                else {
                    return FATFS_FAIL;
                }
            }
        }
    }

    free(sector_buf);
    return FATFS_OK;
}

/**
 * \internal
 * Prints file system category data for an exFAT file system to a file 
 * handle. 
 *
 * @param [in] a_fs Generic file system info structure for the file system.
 * @param [in] a_hFile The file handle.
 * @return 0 on success, 1 otherwise, per TSK convention.
 */
static uint8_t
exfatfs_fsstat_fs_info(TSK_FS_INFO *a_fs, FILE *a_hFile)
{
    FATFS_INFO *fatfs = NULL;
    EXFATFS_MASTER_BOOT_REC *exfatbs = NULL;
    TSK_FS_FILE *fs_file = NULL;

    assert(a_fs != NULL);
    assert(a_hFile != NULL);

    fatfs = (FATFS_INFO*)a_fs;
    exfatbs = (EXFATFS_MASTER_BOOT_REC*)&(fatfs->boot_sector_buffer);

    if ((fs_file = tsk_fs_file_alloc(a_fs)) == NULL) {
        return FATFS_FAIL;
    }

    if ((fs_file->meta = tsk_fs_meta_alloc(FATFS_FILE_CONTENT_LEN)) == NULL) {
        return FATFS_FAIL;
    }

    tsk_fprintf(a_hFile, "FILE SYSTEM INFORMATION\n");
    tsk_fprintf(a_hFile, "--------------------------------------------\n");

    tsk_fprintf(a_hFile, "File System Type: exFAT\n");

    tsk_fprintf(a_hFile, "\nVolume Serial Number: %x%x-%x%x\n", 
        exfatbs->vol_serial_no[3], exfatbs->vol_serial_no[2], 
        exfatbs->vol_serial_no[1], exfatbs->vol_serial_no[0]);

    if (exfatfs_find_volume_label_dentry(fatfs, fs_file) == 0) {
        tsk_fprintf(a_hFile, "Volume Label (from root directory): %s\n", fs_file->meta->name2->name);
    }
    else {
        tsk_fprintf(a_hFile, "Volume Label:\n");
    }

    tsk_fprintf(a_hFile, "File System Name (from MBR): %s\n", exfatbs->fs_name);

    tsk_fprintf(a_hFile, "File System Revision: %x.%x\n", 
        exfatbs->fs_revision[1], exfatbs->fs_revision[0]);

    tsk_fprintf(a_hFile, "Partition Offset: %" PRIuDADDR "\n", 
        tsk_getu64(a_fs->endian, exfatbs->partition_offset));

    tsk_fprintf(a_hFile, "Number of FATs: %d\n", fatfs->numfat);

    tsk_fs_file_close(fs_file);

    return FATFS_OK;
}

/**
 * \internal
 * Prints file system layout data for an exFAT file system to a file 
 * handle. 
 *
 * @param [in] a_fs Generic file system info structure for the file system.
 * @param [in] a_hFile The file handle.
 * @return 0 on success, 1 otherwise, per TSK convention.
 */
static uint8_t
exfatfs_fsstat_fs_layout_info(TSK_FS_INFO *a_fs, FILE *a_hFile)
{
    const char *func_name = "exfatfs_fsstat_fs_layout_info";
    FATFS_INFO *fatfs = NULL;
    uint64_t i = 0;
    TSK_DADDR_T fat_base_sect = 0;
    TSK_DADDR_T clust_heap_len = 0;
    TSK_LIST *root_dir_clusters_seen = NULL;
    TSK_DADDR_T current_cluster;
    TSK_DADDR_T next_cluster = 0; 

    assert(a_fs != NULL);
    assert(a_hFile != NULL);

    fatfs = (FATFS_INFO*)a_fs;

    tsk_fprintf(a_hFile, "\nFile System Layout (in sectors):\n");

    tsk_fprintf(a_hFile, "Range: %" PRIuDADDR " - %" PRIuDADDR "\n",
        a_fs->first_block, a_fs->last_block);

    if (a_fs->last_block != a_fs->last_block_act)
        tsk_fprintf(a_hFile,
            "Range in Image: %" PRIuDADDR " - %" PRIuDADDR "\n",
            a_fs->first_block, a_fs->last_block_act);

    tsk_fprintf(a_hFile, "* Reserved: 0 - %" PRIuDADDR "\n",
        fatfs->firstfatsect - 1);

    tsk_fprintf(a_hFile, "** Volume Boot Record (VBR): 0 - 11\n");

    tsk_fprintf(a_hFile, "*** Boot Sector (MBR): 0\n");

    tsk_fprintf(a_hFile, "** Backup Volume Boot Record (VBR): 12 - 23\n");

    tsk_fprintf(a_hFile, "*** Backup Boot Sector (MBR): 12\n");

    tsk_fprintf(a_hFile, "** FAT alignment space: 24 - %" PRIuDADDR "\n", 
        fatfs->firstfatsect - 1);

    for (i = 0; i < fatfs->numfat; i++) {
        fat_base_sect = fatfs->firstfatsect + i * (fatfs->sectperfat);
        tsk_fprintf(a_hFile, "* FAT %" PRIuDADDR ": %" PRIuDADDR " - %" PRIuDADDR "\n",
            i + 1, fat_base_sect, (fat_base_sect + fatfs->sectperfat - 1));
    }

    if (fat_base_sect + fatfs->sectperfat < fatfs->firstdatasect) {
        tsk_fprintf(a_hFile, "* Data Area alignment space: %" PRIuDADDR " - %" PRIuDADDR "\n", 
            fat_base_sect + fatfs->sectperfat, fatfs->firstdatasect - 1);
    }

    tsk_fprintf(a_hFile, "* Data Area: %" PRIuDADDR " - %" PRIuDADDR "\n",
        fatfs->firstdatasect, a_fs->last_block);

    clust_heap_len = fatfs->csize * (fatfs->lastclust - 1);
    tsk_fprintf(a_hFile,
        "** Cluster Heap: %" PRIuDADDR " - %" PRIuDADDR "\n",
        fatfs->firstclustsect, (fatfs->firstclustsect + clust_heap_len - 1));

    /* Walk the FAT chain for the root directory. */
    current_cluster = fatfs->rootsect;
    next_cluster = FATFS_SECT_2_CLUST(fatfs, fatfs->rootsect);
    while ((next_cluster) && (0 == FATFS_ISEOF(next_cluster, FATFS_32_MASK))) {
        TSK_DADDR_T nxt;
        current_cluster = next_cluster;

        /* Make sure we do not get into an infinite loop */
        if (tsk_list_find(root_dir_clusters_seen, next_cluster)) {
            if (tsk_verbose) {
                tsk_fprintf(stderr,
                    "%s : Loop found while determining root directory size\n",
                    func_name);
            }
            break;
        }

        if (tsk_list_add(&root_dir_clusters_seen, next_cluster)) {
            tsk_list_free(root_dir_clusters_seen);
            root_dir_clusters_seen = NULL;
            return FATFS_FAIL;
        }

        if (fatfs_getFAT(fatfs, next_cluster, &nxt)) {
            break;
        }

        next_cluster = nxt;
    }
    tsk_list_free(root_dir_clusters_seen);
    root_dir_clusters_seen = NULL;

    tsk_fprintf(a_hFile,
        "*** Root Directory: %" PRIuDADDR " - %" PRIuDADDR "\n",
        fatfs->rootsect, (FATFS_CLUST_2_SECT(fatfs, current_cluster + 1) - 1));

    if ((fatfs->firstclustsect + clust_heap_len - 1) != a_fs->last_block) {
        tsk_fprintf(a_hFile,
            "** Non-clustered: %" PRIuDADDR " - %" PRIuDADDR "\n",
            (fatfs->firstclustsect + clust_heap_len), a_fs->last_block);
    }

    return FATFS_OK;
}

/**
 * \internal
 * Prints metadata category data for an exFAT file system to a file 
 * handle. 
 *
 * @param [in] a_fs Generic file system info structure for the file system.
 * @param [in] a_hFile The file handle.
 */
static void
exfatfs_fsstat_fs_metadata_info(TSK_FS_INFO *a_fs, FILE *a_hFile)
{
    assert(a_fs != NULL);
    assert(a_hFile != NULL);

    tsk_fprintf(a_hFile, "\nMETADATA INFORMATION\n");
    tsk_fprintf(a_hFile, "--------------------------------------------\n");

    tsk_fprintf(a_hFile, "Metadata Layout (in virtual inodes):\n");

    tsk_fprintf(a_hFile, "Range: %" PRIuINUM " - %" PRIuINUM "\n",
        a_fs->first_inum, a_fs->last_inum);
    
    tsk_fprintf(a_hFile, "* Root Directory: %" PRIuINUM "\n", a_fs->root_inum);
}

/**
 * \internal
 * Prints metadata category data for an exFAT file system to a file 
 * handle. 
 *
 * @param [in] a_fs Generic file system info structure for the file system.
 * @param [in] a_hFile The file handle.
 */
static void
exfatfs_fsstat_fs_content_info(TSK_FS_INFO *a_fs, FILE *a_hFile)
{
    FATFS_INFO *fatfs = NULL;
    uint64_t i = 0;
    ssize_t bad_sector_cnt = 0;

    assert(a_fs != NULL);
    assert(a_hFile != NULL);

    fatfs = (FATFS_INFO*)a_fs;

    tsk_fprintf(a_hFile, "\nCONTENT INFORMATION\n");
    tsk_fprintf(a_hFile, "--------------------------------------------\n");
    tsk_fprintf(a_hFile, "Sector Size: %" PRIu16 "\n", fatfs->ssize);
    tsk_fprintf(a_hFile, "Cluster Size: %" PRIu32 "\n",
        (uint32_t) fatfs->csize << fatfs->ssize_sh);

    tsk_fprintf(a_hFile, "Cluster Range: 2 - %" PRIuDADDR "\n",
        fatfs->lastclust);

    /* Check each cluster of the data area to see if it is marked as bad in the
     * FAT. If the cluster is bad, list the bad sectors. */
    bad_sector_cnt = 0;
    for (i = 2; i <= fatfs->lastclust; ++i) {
        TSK_DADDR_T entry;
        TSK_DADDR_T sect;

        /* Get the FAT table entry */
        if (fatfs_getFAT(fatfs, i, &entry)) {
            break;
        }

        if (FATFS_ISBAD(entry, fatfs->mask) == 0) {
            continue;
        }

        if (bad_sector_cnt == 0) {
            tsk_fprintf(a_hFile, "Bad Sectors: ");
        }

        sect = FATFS_CLUST_2_SECT(fatfs, i);
        for (i = 0; i < fatfs->csize; ++i) {
            tsk_fprintf(a_hFile, "%" PRIuDADDR " ", sect + i);
            if ((++bad_sector_cnt % 8) == 0) {
                tsk_fprintf(a_hFile, "\n");
            }
        }
    }
    if ((bad_sector_cnt > 0) && ((bad_sector_cnt % 8) != 0)) {
        tsk_fprintf(a_hFile, "\n");
    }
}

/**
 * \internal
 * Prints FAT chains data for an exFAT file system to a file 
 * handle. 
 *
 * @param [in] a_fs Generic file system info structure for the file system.
 * @param [in] a_hFile The file handle.
 */
#if 0
static void
exfatfs_fsstat_fs_fat_chains_info(TSK_FS_INFO *a_fs, FILE *a_hFile)
{
    FATFS_INFO *fatfs = NULL;
    uint64_t i = 0;
    TSK_DADDR_T sect_run_start = 0;
    TSK_DADDR_T sect_run_end = 0;
    TSK_DADDR_T next_cluster = 0; 
    TSK_DADDR_T next_sector = 0;

    assert(a_fs != NULL);
    assert(a_hFile != NULL);

    fatfs = (FATFS_INFO*)a_fs;

    tsk_fprintf(a_hFile, "\nFAT CHAINS (in sectors)\n");
    tsk_fprintf(a_hFile, "--------------------------------------------\n");

    /* Check each cluster of the data area to see if it has a FAT chain. 
     * If so, print out the sectors tha make up the chain. Note that exFAT file 
     * systems only use FAT chains for the root directory, the allocation
     * bitmap, the upcase table, and fragmented files. 
     */
    sect_run_start = fatfs->firstclustsect;
    for (i = 2; i <= fatfs->lastclust; i++) {
        sect_run_end = FATFS_CLUST_2_SECT(fatfs, i + 1) - 1;

        if (fatfs_getFAT(fatfs, i, &next_cluster)) {
            break;
        }

        next_sector = FATFS_CLUST_2_SECT(fatfs, next_cluster);

        if ((next_cluster & fatfs->mask) == (i + 1)) {
            continue;
        }
        else if ((next_cluster & fatfs->mask)) {
            if (FATFS_ISEOF(next_cluster, fatfs->mask)) {
                tsk_fprintf(a_hFile,
                    "%" PRIuDADDR "-%" PRIuDADDR " (%" PRIuDADDR
                    ") -> EOF\n", sect_run_start, sect_run_end, sect_run_end - sect_run_start + 1);
            }
            else if (FATFS_ISBAD(next_cluster, fatfs->mask)) {
                tsk_fprintf(a_hFile,
                    "%" PRIuDADDR "-%" PRIuDADDR " (%" PRIuDADDR
                    ") -> BAD\n", sect_run_start, sect_run_end, sect_run_end - sect_run_start + 1);
            }
            else {
                tsk_fprintf(a_hFile,
                    "%" PRIuDADDR "-%" PRIuDADDR " (%" PRIuDADDR
                    ") -> %" PRIuDADDR "\n", sect_run_start, sect_run_end,
                    sect_run_end - sect_run_start + 1, next_sector);
            }
        }

        sect_run_start = sect_run_end + 1;
    }
}
#endif

/**
 * \internal
 * Print details about an exFAT file system to a file handle. 
 *
 * @param [in] a_fs Generic file system info structure for the file system.
 * @param [in] a_hFile The file handle.
 * @return 0 on success, 1 otherwise, per TSK convention.
 */
uint8_t
exfatfs_fsstat(TSK_FS_INFO *a_fs, FILE *a_hFile)
{
    const char *func_name = "exfatfs_fsstat";

    assert(a_fs != NULL);
    assert(a_hFile != NULL);

    tsk_error_reset();
    if (fatfs_ptr_arg_is_null(a_fs, "a_fs", func_name) ||
        fatfs_ptr_arg_is_null(a_hFile, "a_hFile", func_name)) {
        return FATFS_FAIL; 
    }

    if (exfatfs_fsstat_fs_info(a_fs, a_hFile)) {
        return FATFS_FAIL;
    }

    if (exfatfs_fsstat_fs_layout_info(a_fs, a_hFile)) {
        return FATFS_FAIL;
    }

    exfatfs_fsstat_fs_metadata_info(a_fs, a_hFile);
    exfatfs_fsstat_fs_content_info(a_fs, a_hFile);

    /* Since exFAT does not store all file data in FAT chains (only fragmented files),
     * printing the chains could give the mistaken impression that those are the only
     * sectors containing file data. 
     *
     * exfatfs_fsstat_fs_fat_chains_info(a_fs, a_hFile);
     */

    return FATFS_OK;
}
