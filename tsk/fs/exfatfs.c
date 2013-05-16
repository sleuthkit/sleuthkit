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
 * Contains the internal TSK exFAT file system code to handle opening an exFAT
 * file system. 
 */

#include "tsk_exfatfs.h"
#include "tsk_fs_i.h"
#include "tsk_fatfs.h"

static uint8_t 
exfatfs_get_fs_size_params(FATFS_INFO *a_fatfs)
{
    const char *func_name = "exfatfs_get_fs_size_params";
	TSK_FS_INFO *fs = &(a_fatfs->fs_info);
	EXFATFS_VOL_BOOT_REC *exfatbs = (EXFATFS_VOL_BOOT_REC*)(&a_fatfs->boot_sector_buffer);

    /* Get bytes per sector.
     * Bytes per sector is a base 2 logarithm, defining a range of sizes with 
     * a min of 512 bytes and a max of 4096 bytes. */ 
    a_fatfs->ssize_sh = (uint16_t)exfatbs->bytes_per_sector;
    if ((a_fatfs->ssize_sh < 9) || (a_fatfs->ssize_sh > 12))
    {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_MAGIC);
        tsk_error_set_errstr("Not an FATFS file system (invalid sector size)");
        if (tsk_verbose) {
            fprintf(stderr, "%s: Invalid sector size base 2 logarithm (%d), not in range (9 - 12)\n", func_name, a_fatfs->ssize);
        }
        return 0;
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
            fprintf(stderr, "%s: Invalid cluster size (%d)\n", func_name, a_fatfs->csize);
        }
        return 0;
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
        return 0;
    }

    return 1;
}

static uint8_t 
exfatfs_get_fs_layout(FATFS_INFO *a_fatfs)
{
    const char *func_name = "exfatfs_get_fs_layout";
	TSK_FS_INFO *fs = &(a_fatfs->fs_info);
	EXFATFS_VOL_BOOT_REC *exfatbs = (EXFATFS_VOL_BOOT_REC*)(&a_fatfs->boot_sector_buffer);
    uint64_t vol_len_in_sectors = 0;
    uint64_t last_sector_of_cluster_heap = 0;

    /* Get the size of the volume. It should be non-zero. */
    vol_len_in_sectors = tsk_getu64(fs->endian, exfatbs->vol_len_in_sectors);
    if (vol_len_in_sectors == 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_MAGIC);
        tsk_error_set_errstr("Not an exFAT file system (invalid volume length)");
        if (tsk_verbose) {
            fprintf(stderr, "%s: Invalid volume length in sectors (%d)\n", func_name, vol_len_in_sectors);
        }
        return 0;
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
        return 0;
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
        return 0;
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
        return 0;
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
        return 0;
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
            fprintf(stderr, "%s: Invalid root directory sector address (%d)\n", func_name, a_fatfs->rootsect);
        }
        return 0;
    }

    /* The number of directory entries in the root directory is not specified
     * in the exFAT boot sector. */
    a_fatfs->numroot = 0;

    // RJCTODO: Need more validation? Special validation for the backup VBR? Think about this.

    return 1;
}

static void 
exfatfs_get_volume_id(FATFS_INFO *a_fatfs)
{
	TSK_FS_INFO *fs = &(a_fatfs->fs_info);
	EXFATFS_VOL_BOOT_REC *exfatbs = (EXFATFS_VOL_BOOT_REC*)(&a_fatfs->boot_sector_buffer);

    for (fs->fs_id_used = 0; fs->fs_id_used < 4; fs->fs_id_used++) {
        fs->fs_id[fs->fs_id_used] = exfatbs->vol_serial_no[fs->fs_id_used];
    }
}

static uint8_t
exfatfs_get_alloc_bitmap(FATFS_INFO *a_fatfs)
{
    const char *func_name = "exfatfs_get_alloc_bitmap";
	TSK_FS_INFO *fs = &(a_fatfs->fs_info);
    TSK_DADDR_T current_sector = a_fatfs->rootsect;
    TSK_DADDR_T last_sector_of_data_area = 0;
    char *sector_buf = NULL;
    ssize_t bytes_read = 0;
    EXFATFS_ALLOC_BITMAP_DIR_ENTRY *dentry = NULL;
    uint64_t i = 0;
    uint64_t first_sector_of_alloc_bitmap = 0;
    uint64_t alloc_bitmap_length_in_bytes = 0;
    uint64_t last_sector_of_alloc_bitmap = 0;

    if ((sector_buf = (char*)tsk_malloc(a_fatfs->ssize)) == NULL) {
        return 1;
    }

    last_sector_of_data_area = a_fatfs->firstdatasect + (a_fatfs->clustcnt * a_fatfs->csize) - 1;
    while (current_sector < last_sector_of_data_area) {
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
            return 1;
        }

        /* Read the directory entries in the sector, looking for allocation
         * bitmap entries. There will be one entry unless the file system is 
         * TexFAT (transactional exFAT), in which case there will be two. */
        for (i = 0; i < a_fatfs->ssize; i += sizeof(FATFS_DENTRY)) {
            dentry = (EXFATFS_ALLOC_BITMAP_DIR_ENTRY*)&(sector_buf[i]); 

            /* The type of the directory entry is encoded in the first byte 
             * of the entry. See EXFATFS_DIR_ENTRY_TYPE_ENUM. */ 
            if (dentry->entry_type == EXFATFS_DIR_ENTRY_TYPE_ALLOC_BITMAP) {
                /* Do an in-depth test. */
                if (!exfatfs_is_alloc_bitmap_dentry(a_fatfs, (FATFS_DENTRY*)dentry, 1)) {
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
                    alloc_bitmap_length_in_bytes = tsk_getu32(fs->endian, dentry->length_of_alloc_bitmap_in_bytes);
                    last_sector_of_alloc_bitmap = first_sector_of_alloc_bitmap + (alloc_bitmap_length_in_bytes / a_fatfs->ssize) - 1;

                    /* The allocation bitmap must lie within the boundaries of the data area. 
                     * It also must be big enough for the number of clusters reported in the VBR. */
                    if ((first_sector_of_alloc_bitmap >= a_fatfs->firstdatasect) &&
                        (last_sector_of_alloc_bitmap <= last_sector_of_data_area) &&
                        (alloc_bitmap_length_in_bytes >= (a_fatfs->clustcnt + 7) / 8))
                    {
                        a_fatfs->EXFATFS_INFO.first_sector_of_alloc_bitmap = first_sector_of_alloc_bitmap; 
                        a_fatfs->EXFATFS_INFO.length_of_alloc_bitmap_in_bytes = alloc_bitmap_length_in_bytes;
                        free(sector_buf);
                        return 1;
                    }
                }
            }
        }
    }
    free(sector_buf);

    return 0;
}

/* There are no blocks in exFAT. To conform to the SleuthKit file system 
 * model, sectors and clusters will be mapped to blocks. */
static uint8_t 
exfatfs_map_fs_layout_to_blocks(FATFS_INFO *a_fatfs)
{
	TSK_FS_INFO *fs = &(a_fatfs->fs_info);
	EXFATFS_VOL_BOOT_REC *exfatbs = (EXFATFS_VOL_BOOT_REC*)(&a_fatfs->boot_sector_buffer);

    fs->duname = "Sector";
    fs->block_size = a_fatfs->ssize;    
    fs->block_count = tsk_getu64(fs->endian, exfatbs->vol_len_in_sectors);
    fs->first_block = 0;
    fs->last_block = fs->last_block_act = fs->block_count - 1;

    /* Determine the last block actually included in the image, since the 
     * end of the file system could be "cut off." */
    if ((TSK_DADDR_T) ((fs->img_info->size - fs->offset) / fs->block_size) <
        fs->block_count) {
        fs->last_block_act = (fs->img_info->size - fs->offset) / fs->block_size - 1;
    }

    return 1;
}

/* There are no blocks in exFAT. To conform to the SleuthKit file system 
 * model, sectors and clusters will be mapped to inodes. */
static uint8_t
exfatfs_map_fs_layout_to_inodes(FATFS_INFO *a_fatfs)
{
	TSK_FS_INFO *fs = &(a_fatfs->fs_info);

    /* Calculate the maximum number of directory entries that will fit in a 
     * sector and a cluster. */
    a_fatfs->dentry_cnt_se = a_fatfs->ssize / sizeof(FATFS_DENTRY);
    a_fatfs->dentry_cnt_cl = a_fatfs->dentry_cnt_se * a_fatfs->csize;

    /* The first entry in an exFAT FAT is a media type indicator.
     * The second entry is simply a meaningless 0xFFFFFFFF. 
     * The first inode address is therefore 2. */
    fs->first_inum = FATFS_FIRSTINO;

    fs->root_inum = FATFS_SECT_2_INODE(a_fatfs, a_fatfs->rootsect);

    /* Calulate the last inode and add some extras for virtual
     * directories and files: root directory, MBR, and two FATS. */
    fs->last_inum =
        (FATFS_SECT_2_INODE(a_fatfs,
            fs->last_block_act + 1) - 1) + FATFS_NUM_SPECFILE;
    fs->inum_count = fs->last_inum - fs->first_inum + 1;

    return 1;
}

static void 
exfatfs_set_func_ptrs(FATFS_INFO *a_fatfs)
{
	TSK_FS_INFO *fs = &(a_fatfs->fs_info);

    /* Content category functions. */ 
    fs->block_walk = fatfs_block_walk;
    fs->block_getflags = 0;

    /* Metadata category functions. */
    fs->inode_walk = fatfs_inode_walk;
    fs->istat = fatfs_istat;
    fs->file_add_meta = fatfs_inode_lookup;

    // RJCTODO: Set remaining pointers, group and comment.
    fs->get_default_attr_type = 0;
    fs->load_attrs = 0;
    fs->dir_open_meta = 0;
    fs->name_cmp = 0;
    fs->fsstat = 0;
    fs->fscheck = 0;

    /* NOP journal functions - exFAT has no file system journal. */
    fs->jblk_walk = fatfs_jblk_walk;
    fs->jentry_walk = fatfs_jentry_walk;
    fs->jopen = fatfs_jopen;

    fs->close = fatfs_close;
}

static void 
exfatfs_init_caches(FATFS_INFO *a_fatfs)
{
    // RJCTODO: Is all of this needed for exFAT?
    uint32_t i = 0;

    for (i = 0; i < FAT_CACHE_N; i++) {
        a_fatfs->fatc_addr[i] = 0;
        a_fatfs->fatc_ttl[i] = 0;
    }

    tsk_init_lock(&a_fatfs->cache_lock);
    tsk_init_lock(&a_fatfs->dir_lock);
    a_fatfs->inum2par = NULL;
}

/**
 * \internal
 * Open part of a disk image as an exFAT file system. 
 *
 * @param a_fatfs Generic FAT file system info structure.
 * @returns 1 on sucess, 0 otherwise.
 */
int
exfatfs_open(FATFS_INFO *a_fatfs)
{
    const char *func_name = "exfatfs_open";
    TSK_FS_INFO *fs = &(a_fatfs->fs_info);

    tsk_error_reset();

    /* Is is really an exFAT file system? */
    if (!exfatfs_get_fs_size_params(a_fatfs) ||
        !exfatfs_get_fs_layout(a_fatfs) || 
        !exfatfs_map_fs_layout_to_blocks(a_fatfs) ||
        !exfatfs_map_fs_layout_to_inodes(a_fatfs) ||
        !exfatfs_get_alloc_bitmap(a_fatfs)) {
        return 0;
    }

    exfatfs_get_volume_id(a_fatfs);
    exfatfs_set_func_ptrs(a_fatfs);
    exfatfs_init_caches(a_fatfs);

    fs->ftype = TSK_FS_TYPE_EXFAT;

	return 1;
}

/**
 * \internal
 * Determine whether a specified cluster is allocated. 
 *
 * @param a_fatfs Generic FAT file system info structure.
 * @param a_cluster_addr Address of the cluster to check. 
 * @return 1 if the cluster is allocated, 0 otherwise.
 */
int8_t 
exfatfs_is_clust_alloc(FATFS_INFO *a_fatfs, TSK_DADDR_T a_cluster_addr)
{
    const char *func_name = "exfatfs_is_clust_alloc";
    TSK_FS_INFO *fs = &(a_fatfs->fs_info);
    TSK_DADDR_T bitmap_byte_offset = (a_fatfs->EXFATFS_INFO.first_sector_of_alloc_bitmap * a_fatfs->ssize) + ((a_cluster_addr - 2) / 8);
    uint8_t bitmap_byte[1];
    ssize_t bytes_read = 0;

    uint8_t x;

    tsk_error_reset();

    /* Read the byte that contains the bit for the specified cluster. */
    bytes_read = tsk_fs_read(fs, bitmap_byte_offset, (char*)(&bitmap_byte[0]), 1);
    if (bytes_read != 1) {
        if (bytes_read >= 0) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_READ);
        }
        tsk_error_set_errstr2("%s: failed to read bitmap byte", func_name);
        return -1;
    }

    /* Check the bit that corresponds to the specified cluster. */
    return ((1 << (a_cluster_addr % 8)) & bitmap_byte[0]);
    //return isset(&bitmap_byte[0], a_cluster_addr);
}