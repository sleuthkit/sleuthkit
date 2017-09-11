/*
** fatxxfs
** The Sleuth Kit 
**
** Content and meta data layer support for the FATXX file system 
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2006-2013 Brian Carrier, Basis Technology. All Rights reserved
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
 * \file fatxxfs.c
 * Contains the internal TSK FATXX (FAT12, FAT16, FAT32) file system code to 
 * handle basic file system processing for opening file system, processing 
 * sectors, and directory entries. 
 */

#include "tsk_fatxxfs.h"

/*
 * Implementation NOTES 
 *
 * TSK_FS_META contains the first cluster.  file_walk will return sector
 * values though because the cluster numbers do not start until after
 * the FAT.  That makes it very hard to address the first few blocks!
 *
 * Inodes numbers do not exist in FAT.  To make up for this we will count
 * directory entries as the inodes.   As the root directory does not have
 * any records in FAT, we will give it times of 0 and call it inode 2 to
 * keep consistent with UNIX.  After that, each 32-byte slot is numbered
 * as though it were a directory entry (even if it is not).  Therefore,
 * when an inode walk is performed, not all inode values will be displayed
 * even when '-e' is given for ils. 
 *
 * Progs like 'ils -e' are very slow because we have to look at each
 * block to see if it is a file system structure.
 */

/**
 * Print details about the file system to a file handle. 
 *
 * @param fs File system to print details on
 * @param hFile File handle to print text to
 * 
 * @returns 1 on error and 0 on success
 */
static uint8_t
fatxxfs_fsstat(TSK_FS_INFO * fs, FILE * hFile)
{
    unsigned int i;
    TSK_DADDR_T next, snext, sstart, send;
    FATFS_INFO *fatfs = (FATFS_INFO *) fs;
    FATXXFS_SB *sb = (FATXXFS_SB*)fatfs->boot_sector_buffer;
    char *data_buf;
    FATXXFS_DENTRY *vol_label_dentry = NULL;
    ssize_t cnt;

    // clean up any error messages that are lying around
    tsk_error_reset();

    if ((data_buf = (char *) tsk_malloc(fs->block_size)) == NULL) {
        return 1;
    }


    /* Read the root directory sector so that we can get the volume
     * label from it */
    cnt = tsk_fs_read_block(fs, fatfs->rootsect, data_buf, fs->block_size);
    if (cnt != fs->block_size) {
        if (cnt >= 0) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_READ);
        }
        tsk_error_set_errstr2("fatxxfs_fsstat: root directory: %" PRIuDADDR,
            fatfs->rootsect);
        free(data_buf);
        return 1;
    }


    /* Find the dentry that is set as the volume label */
    vol_label_dentry = NULL;
    if (fatfs->ssize <= fs->block_size) {
        FATXXFS_DENTRY *current_entry = (FATXXFS_DENTRY *) data_buf;
        for (i = 0; i < fatfs->ssize; i += sizeof(*current_entry)) {
            if (current_entry->attrib == FATFS_ATTR_VOLUME) {
                vol_label_dentry = current_entry;
                break;
            }
            current_entry++;
        }
    }


    /* Print the general file system information */

    tsk_fprintf(hFile, "FILE SYSTEM INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");

    tsk_fprintf(hFile, "File System Type: FAT");
    if (fs->ftype == TSK_FS_TYPE_FAT12)
        tsk_fprintf(hFile, "12\n");
    else if (fs->ftype == TSK_FS_TYPE_FAT16)
        tsk_fprintf(hFile, "16\n");
    else if (fs->ftype == TSK_FS_TYPE_FAT32)
        tsk_fprintf(hFile, "32\n");
    else
        tsk_fprintf(hFile, "\n");

    tsk_fprintf(hFile, "\nOEM Name: %c%c%c%c%c%c%c%c\n", sb->oemname[0],
        sb->oemname[1], sb->oemname[2], sb->oemname[3], sb->oemname[4],
        sb->oemname[5], sb->oemname[6], sb->oemname[7]);


    if (fatfs->fs_info.ftype != TSK_FS_TYPE_FAT32) {
        tsk_fprintf(hFile, "Volume ID: 0x%" PRIx32 "\n",
            tsk_getu32(fs->endian, sb->a.f16.vol_id));

        tsk_fprintf(hFile,
            "Volume Label (Boot Sector): %c%c%c%c%c%c%c%c%c%c%c\n",
            sb->a.f16.vol_lab[0], sb->a.f16.vol_lab[1],
            sb->a.f16.vol_lab[2], sb->a.f16.vol_lab[3],
            sb->a.f16.vol_lab[4], sb->a.f16.vol_lab[5],
            sb->a.f16.vol_lab[6], sb->a.f16.vol_lab[7],
            sb->a.f16.vol_lab[8], sb->a.f16.vol_lab[9],
            sb->a.f16.vol_lab[10]);

        if ((vol_label_dentry) && (vol_label_dentry->name[0])) {
            tsk_fprintf(hFile,
                "Volume Label (Root Directory): %c%c%c%c%c%c%c%c%c%c%c\n",
                vol_label_dentry->name[0], vol_label_dentry->name[1], vol_label_dentry->name[2], vol_label_dentry->name[3],
                vol_label_dentry->name[4], vol_label_dentry->name[5], vol_label_dentry->name[6], vol_label_dentry->name[7],
                vol_label_dentry->ext[0], vol_label_dentry->ext[1], vol_label_dentry->ext[2]);
        }
        else {
            tsk_fprintf(hFile, "Volume Label (Root Directory):\n");
        }

        tsk_fprintf(hFile, "File System Type Label: %c%c%c%c%c%c%c%c\n",
            sb->a.f16.fs_type[0], sb->a.f16.fs_type[1],
            sb->a.f16.fs_type[2], sb->a.f16.fs_type[3],
            sb->a.f16.fs_type[4], sb->a.f16.fs_type[5],
            sb->a.f16.fs_type[6], sb->a.f16.fs_type[7]);
    }
    else {

        char *fat_fsinfo_buf;

        if ((fat_fsinfo_buf = (char *)
                tsk_malloc(sizeof(FATXXFS_FSINFO))) == NULL) {
            free(data_buf);
            return 1;
        }

        tsk_fprintf(hFile, "Volume ID: 0x%" PRIx32 "\n",
            tsk_getu32(fs->endian, sb->a.f32.vol_id));

        tsk_fprintf(hFile,
            "Volume Label (Boot Sector): %c%c%c%c%c%c%c%c%c%c%c\n",
            sb->a.f32.vol_lab[0], sb->a.f32.vol_lab[1],
            sb->a.f32.vol_lab[2], sb->a.f32.vol_lab[3],
            sb->a.f32.vol_lab[4], sb->a.f32.vol_lab[5],
            sb->a.f32.vol_lab[6], sb->a.f32.vol_lab[7],
            sb->a.f32.vol_lab[8], sb->a.f32.vol_lab[9],
            sb->a.f32.vol_lab[10]);

        if ((vol_label_dentry) && (vol_label_dentry->name[0])) {
            tsk_fprintf(hFile,
                "Volume Label (Root Directory): %c%c%c%c%c%c%c%c%c%c%c\n",
                vol_label_dentry->name[0], vol_label_dentry->name[1], vol_label_dentry->name[2], vol_label_dentry->name[3],
                vol_label_dentry->name[4], vol_label_dentry->name[5], vol_label_dentry->name[6], vol_label_dentry->name[7],
                vol_label_dentry->ext[0], vol_label_dentry->ext[1], vol_label_dentry->ext[2]);
        }
        else {
            tsk_fprintf(hFile, "Volume Label (Root Directory):\n");
        }

        tsk_fprintf(hFile, "File System Type Label: %c%c%c%c%c%c%c%c\n",
            sb->a.f32.fs_type[0], sb->a.f32.fs_type[1],
            sb->a.f32.fs_type[2], sb->a.f32.fs_type[3],
            sb->a.f32.fs_type[4], sb->a.f32.fs_type[5],
            sb->a.f32.fs_type[6], sb->a.f32.fs_type[7]);


        /* Process the FS info */
        if (tsk_getu16(fs->endian, sb->a.f32.fsinfo)) {
            FATXXFS_FSINFO *fat_info;
            cnt =
                tsk_fs_read(fs, 
                    (TSK_DADDR_T) tsk_getu16(fs->endian, sb->a.f32.fsinfo) * fs->block_size, 
                    fat_fsinfo_buf, sizeof(FATXXFS_FSINFO));

            if (cnt != sizeof(FATXXFS_FSINFO)) {
                if (cnt >= 0) {
                    tsk_error_reset();
                    tsk_error_set_errno(TSK_ERR_FS_READ);
                }
                tsk_error_set_errstr2
                    ("fatxxfs_fsstat: TSK_FS_TYPE_FAT32 FSINFO block: %"
                    PRIuDADDR, (TSK_DADDR_T) tsk_getu16(fs->endian,
                        sb->a.f32.fsinfo));
                free(data_buf);
                free(fat_fsinfo_buf);
                return 1;
            }


            fat_info = (FATXXFS_FSINFO *) fat_fsinfo_buf;
            tsk_fprintf(hFile,
                "Next Free Sector (FS Info): %" PRIuDADDR "\n",
                FATFS_CLUST_2_SECT(fatfs, tsk_getu32(fs->endian,
                        fat_info->nextfree)));

            tsk_fprintf(hFile,
                "Free Sector Count (FS Info): %" PRIu32 "\n",
                (tsk_getu32(fs->endian,
                        fat_info->freecnt) * fatfs->csize));

            free(fat_fsinfo_buf);
        }
    }

    free(data_buf);

    tsk_fprintf(hFile, "\nSectors before file system: %" PRIu32 "\n",
        tsk_getu32(fs->endian, sb->prevsect));

    tsk_fprintf(hFile, "\nFile System Layout (in sectors)\n");

    tsk_fprintf(hFile, "Total Range: %" PRIuDADDR " - %" PRIuDADDR "\n",
        fs->first_block, fs->last_block);

    if (fs->last_block != fs->last_block_act)
        tsk_fprintf(hFile,
            "Total Range in Image: %" PRIuDADDR " - %" PRIuDADDR "\n",
            fs->first_block, fs->last_block_act);

    tsk_fprintf(hFile, "* Reserved: 0 - %" PRIuDADDR "\n",
        fatfs->firstfatsect - 1);

    tsk_fprintf(hFile, "** Boot Sector: 0\n");

    if (fatfs->fs_info.ftype == TSK_FS_TYPE_FAT32) {
        tsk_fprintf(hFile, "** FS Info Sector: %" PRIu16 "\n",
            tsk_getu16(fs->endian, sb->a.f32.fsinfo));

        tsk_fprintf(hFile, "** Backup Boot Sector: %" PRIu16 "\n",
            tsk_getu16(fs->endian, sb->a.f32.bs_backup));
    }

    for (i = 0; i < fatfs->numfat; i++) {
        TSK_DADDR_T base = fatfs->firstfatsect + i * (fatfs->sectperfat);

        tsk_fprintf(hFile, "* FAT %d: %" PRIuDADDR " - %" PRIuDADDR "\n",
            i, base, (base + fatfs->sectperfat - 1));
    }

    tsk_fprintf(hFile, "* Data Area: %" PRIuDADDR " - %" PRIuDADDR "\n",
        fatfs->firstdatasect, fs->last_block);

    if (fatfs->fs_info.ftype != TSK_FS_TYPE_FAT32) {
        TSK_DADDR_T x = fatfs->csize * fatfs->clustcnt;

        tsk_fprintf(hFile,
            "** Root Directory: %" PRIuDADDR " - %" PRIuDADDR "\n",
            fatfs->firstdatasect, fatfs->firstclustsect - 1);

        tsk_fprintf(hFile,
            "** Cluster Area: %" PRIuDADDR " - %" PRIuDADDR "\n",
            fatfs->firstclustsect, (fatfs->firstclustsect + x - 1));

        if ((fatfs->firstclustsect + x - 1) != fs->last_block) {
            tsk_fprintf(hFile,
                "** Non-clustered: %" PRIuDADDR " - %" PRIuDADDR "\n",
                (fatfs->firstclustsect + x), fs->last_block);
        }
    }
    else {
        TSK_LIST *list_seen = NULL;
        TSK_DADDR_T x = fatfs->csize * (fatfs->lastclust - 1);
        TSK_DADDR_T clust, clust_p;

        tsk_fprintf(hFile,
            "** Cluster Area: %" PRIuDADDR " - %" PRIuDADDR "\n",
            fatfs->firstclustsect, (fatfs->firstclustsect + x - 1));


        clust_p = fatfs->rootsect;
        clust = FATFS_SECT_2_CLUST(fatfs, fatfs->rootsect);
        while ((clust) && (0 == FATFS_ISEOF(clust, FATFS_32_MASK))) {
            TSK_DADDR_T nxt;
            clust_p = clust;

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

            if (fatfs_getFAT(fatfs, clust, &nxt))
                break;
            clust = nxt;
        }
        tsk_list_free(list_seen);
        list_seen = NULL;

        tsk_fprintf(hFile,
            "*** Root Directory: %" PRIuDADDR " - %" PRIuDADDR "\n",
            fatfs->rootsect, (FATFS_CLUST_2_SECT(fatfs, clust_p + 1) - 1));

        if ((fatfs->firstclustsect + x - 1) != fs->last_block) {
            tsk_fprintf(hFile,
                "** Non-clustered: %" PRIuDADDR " - %" PRIuDADDR "\n",
                (fatfs->firstclustsect + x), fs->last_block);
        }
    }


    tsk_fprintf(hFile, "\nMETADATA INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");

    tsk_fprintf(hFile, "Range: %" PRIuINUM " - %" PRIuINUM "\n",
        fs->first_inum, fs->last_inum);
    tsk_fprintf(hFile, "Root Directory: %" PRIuINUM "\n", fs->root_inum);


    tsk_fprintf(hFile, "\nCONTENT INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");
    tsk_fprintf(hFile, "Sector Size: %" PRIu16 "\n", fatfs->ssize);
    tsk_fprintf(hFile, "Cluster Size: %" PRIu32 "\n",
        (uint32_t) fatfs->csize << fatfs->ssize_sh);

    tsk_fprintf(hFile, "Total Cluster Range: 2 - %" PRIuDADDR "\n",
        fatfs->lastclust);


    /* cycle via cluster and look at each cluster in the FAT 
     * for clusters marked as bad */
    cnt = 0;
    for (i = 2; i <= fatfs->lastclust; i++) {
        TSK_DADDR_T entry;
        TSK_DADDR_T sect;
        unsigned int a;

        /* Get the FAT table entry */
        if (fatfs_getFAT(fatfs, i, &entry))
            break;

        if (FATFS_ISBAD(entry, fatfs->mask) == 0) {
            continue;
        }

        if (cnt == 0)
            tsk_fprintf(hFile, "Bad Sectors: ");

        sect = FATFS_CLUST_2_SECT(fatfs, i);
        for (a = 0; a < fatfs->csize; a++) {
            tsk_fprintf(hFile, "%" PRIuDADDR " ", sect + a);
            if ((++cnt % 8) == 0)
                tsk_fprintf(hFile, "\n");
        }
    }
    if ((cnt > 0) && ((cnt % 8) != 0))
        tsk_fprintf(hFile, "\n");

    /* Display the FAT Table */
    tsk_fprintf(hFile, "\nFAT CONTENTS (in sectors)\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");

    /* 'sstart' marks the first sector of the current run to print */
    sstart = fatfs->firstclustsect;

    /* cycle via cluster and look at each cluster in the FAT  to make runs */
    for (i = 2; i <= fatfs->lastclust; i++) {

        /* 'send' marks the end sector of the current run, which will extend
         * when the current cluster continues to the next 
         */
        send = FATFS_CLUST_2_SECT(fatfs, i + 1) - 1;

        /* get the next cluster */
        if (fatfs_getFAT(fatfs, i, &next))
            break;

        snext = FATFS_CLUST_2_SECT(fatfs, next);

        /* we are also using the next sector (clust) */
        if ((next & fatfs->mask) == (i + 1)) {
            continue;
        }

        /* The next clust is either further away or the clust is available,
         * print it if is further away 
         */
        else if ((next & fatfs->mask)) {
            if (FATFS_ISEOF(next, fatfs->mask))
                tsk_fprintf(hFile,
                    "%" PRIuDADDR "-%" PRIuDADDR " (%" PRIuDADDR
                    ") -> EOF\n", sstart, send, send - sstart + 1);
            else if (FATFS_ISBAD(next, fatfs->mask))
                tsk_fprintf(hFile,
                    "%" PRIuDADDR "-%" PRIuDADDR " (%" PRIuDADDR
                    ") -> BAD\n", sstart, send, send - sstart + 1);
            else
                tsk_fprintf(hFile,
                    "%" PRIuDADDR "-%" PRIuDADDR " (%" PRIuDADDR
                    ") -> %" PRIuDADDR "\n", sstart, send,
                    send - sstart + 1, snext);
        }

        /* reset the starting counter */
        sstart = send + 1;
    }

    return 0;
}

uint8_t
fatxxfs_open(FATFS_INFO *fatfs)
{
    const char *func_name = "fatxxfs_open";
	TSK_FS_INFO *fs = &(fatfs->fs_info);
	FATXXFS_SB *fatsb = (FATXXFS_SB*)(&fatfs->boot_sector_buffer);
	int i = 0;
    TSK_DADDR_T sectors = 0;
	TSK_FS_DIR * test_dir1; // Directories used to try opening the root directory

    // clean up any error messages that are lying around
    tsk_error_reset();

    /* Calculate block sizes and layout info */
    // sector size
    fatfs->ssize = tsk_getu16(fs->endian, fatsb->ssize);
    if (fatfs->ssize == 512) {
        fatfs->ssize_sh = 9;
    }
    else if (fatfs->ssize == 1024) {
        fatfs->ssize_sh = 10;
    }
    else if (fatfs->ssize == 2048) {
        fatfs->ssize_sh = 11;
    }
    else if (fatfs->ssize == 4096) {
        fatfs->ssize_sh = 12;
    }
    else {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_MAGIC);
        tsk_error_set_errstr
            ("Error: sector size (%d) is not a multiple of device size (%d)\nDo you have a disk image instead of a partition image?",
            fatfs->ssize, fs->dev_bsize);
        if (tsk_verbose)
            fprintf(stderr, "%s: Invalid sector size (%d)\n",
                func_name, fatfs->ssize);
        return 1;
    }

    // cluster size 
    fatfs->csize = fatsb->csize;
    if ((fatfs->csize != 0x01) &&
        (fatfs->csize != 0x02) &&
        (fatfs->csize != 0x04) &&
        (fatfs->csize != 0x08) &&
        (fatfs->csize != 0x10) &&
        (fatfs->csize != 0x20) &&
        (fatfs->csize != 0x40) && (fatfs->csize != 0x80)) {
        if (tsk_verbose)
            fprintf(stderr, "%s: Invalid cluster size (%d)\n",
                func_name, fatfs->csize);
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_MAGIC);
        tsk_error_set_errstr("Not a FATXX file system (cluster size)");
        return 1;
    }

    // number of FAT tables
    fatfs->numfat = fatsb->numfat;
    if ((fatfs->numfat == 0) || (fatfs->numfat > 8)) {
        if (tsk_verbose)
            fprintf(stderr, "%s: Invalid number of FATS (%d)\n",
                func_name, fatfs->numfat);
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_MAGIC);
        tsk_error_set_errstr("Not a FATXX file system (number of FATs)");
        return 1;
    }

    /* We can't do a sanity check on this b.c. TSK_FS_TYPE_FAT32 has a value of 0 */
    /* num of root entries */
    fatfs->numroot = tsk_getu16(fs->endian, fatsb->numroot);

    /* if sectors16 is 0, then the number of sectors is stored in sectors32 */
    if (0 == (sectors = tsk_getu16(fs->endian, fatsb->sectors16)))
        sectors = tsk_getu32(fs->endian, fatsb->sectors32);

    /* if secperfat16 is 0, then read sectperfat32 */
    if (0 == (fatfs->sectperfat =
            tsk_getu16(fs->endian, fatsb->sectperfat16)))
        fatfs->sectperfat =
            tsk_getu32(fs->endian, fatsb->a.f32.sectperfat32);

    if (fatfs->sectperfat == 0) {
        if (tsk_verbose)
            fprintf(stderr,
                "%s: Invalid number of sectors per FAT (%d)\n",
                func_name, fatfs->sectperfat);
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_MAGIC);
        tsk_error_set_errstr
            ("Not a FATXX file system (invalid sectors per FAT)");
        return 1;
    }

    fatfs->firstfatsect = tsk_getu16(fs->endian, fatsb->reserved);
    if ((fatfs->firstfatsect == 0) || (fatfs->firstfatsect > sectors)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr
            ("Not a FATXX file system (invalid first FAT sector %"
            PRIuDADDR ")", fatfs->firstfatsect);
        if (tsk_verbose)
            fprintf(stderr,
                "%s: Invalid first FAT (%" PRIuDADDR ")\n",
                func_name, fatfs->firstfatsect);
        return 1;
    }

    /* Calculate the block info
     * 
     * The sector of the beginning of the data area  - which is 
     * after all of the FATs
     *
     * For TSK_FS_TYPE_FAT12 and TSK_FS_TYPE_FAT16, the data area starts with the root
     * directory entries and then the first cluster.  For TSK_FS_TYPE_FAT32,
     * the data area starts with clusters and the root directory
     * is somewhere in the data area
     */
    fatfs->firstdatasect = fatfs->firstfatsect +
        fatfs->sectperfat * fatfs->numfat;

    /* The sector where the first cluster is located.  It will be used
     * to translate cluster addresses to sector addresses 
     *
     * For TSK_FS_TYPE_FAT32, the first cluster is the start of the data area and
     * it is after the root directory for TSK_FS_TYPE_FAT12 and TSK_FS_TYPE_FAT16.  At this
     * point in the program, numroot is set to 0 for TSK_FS_TYPE_FAT32
     */
    fatfs->firstclustsect = fatfs->firstdatasect +
        ((fatfs->numroot * 32 + fatfs->ssize - 1) / fatfs->ssize);

    /* total number of clusters */
    fatfs->clustcnt = (sectors - fatfs->firstclustsect) / fatfs->csize;

    /* the first cluster is #2, so the final cluster is: */
    fatfs->lastclust = 1 + fatfs->clustcnt;


    /* identify the FAT type by the total number of data clusters
     * this calculation is from the MS FAT Overview Doc
     *
     * A FAT file system made by another OS could use different values
     */
    if (fatfs->fs_info.ftype == TSK_FS_TYPE_FAT_DETECT) {

        if (fatfs->clustcnt < 4085) {
            fatfs->fs_info.ftype = TSK_FS_TYPE_FAT12;
        }
        else if (fatfs->clustcnt < 65525) {
            fatfs->fs_info.ftype = TSK_FS_TYPE_FAT16;
        }
        else {
            fatfs->fs_info.ftype = TSK_FS_TYPE_FAT32;
        }

        fatfs->fs_info.ftype = fatfs->fs_info.ftype;
    }

    /* Some sanity checks */
    else {
        if ((fatfs->fs_info.ftype == TSK_FS_TYPE_FAT12)
            && (fatfs->clustcnt >= 4085)) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_MAGIC);
            tsk_error_set_errstr
                ("Too many sectors for TSK_FS_TYPE_FAT12: try auto-detect mode");
            if (tsk_verbose)
                fprintf(stderr,
                    "%s: Too many sectors for FAT12\n", func_name);
            return 1;
        }
    }

    if ((fatfs->fs_info.ftype == TSK_FS_TYPE_FAT32) && (fatfs->numroot != 0)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_MAGIC);
        tsk_error_set_errstr
            ("Invalid TSK_FS_TYPE_FAT32 image (numroot != 0)");
        if (tsk_verbose)
            fprintf(stderr, "%s: numroom != 0 for FAT32\n", func_name);
        return 1;
    }

    if ((fatfs->fs_info.ftype != TSK_FS_TYPE_FAT32) && (fatfs->numroot == 0)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_MAGIC);
        tsk_error_set_errstr
            ("Invalid FAT image (numroot == 0, and not TSK_FS_TYPE_FAT32)");
        if (tsk_verbose)
            fprintf(stderr, "%s: numroom == 0 and not FAT32\n", func_name);
        return 1;
    }

    /* additional sanity checks if we think we are using the backup boot sector.
     * The scenario to prevent here is if fat_open is called 6 sectors before the real start
     * of the file system, then we want to detect that it was not a backup that we saw.  
     */
    if (fatfs->using_backup_boot_sector) {
        // only FAT32 has backup boot sectors..
        if (fatfs->fs_info.ftype != TSK_FS_TYPE_FAT32) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_MAGIC);
            tsk_error_set_errstr
                ("Invalid FAT image (Used what we thought was a backup boot sector, but it is not TSK_FS_TYPE_FAT32)");
            if (tsk_verbose)
                fprintf(stderr,
                    "%s: Had to use backup boot sector, but this isn't FAT32\n", func_name);
            return 1;
        }
        if (fatfs->numroot > 1) {
            uint8_t buf1[512];
            uint8_t buf2[512];
            int i2;
            int numDiffs;
	        ssize_t cnt = 0;

            cnt =
                tsk_fs_read(fs, fatfs->firstfatsect * fatfs->ssize,
                (char *) buf1, 512);
            if (cnt != 512) {
                if (cnt >= 0) {
                    tsk_error_reset();
                    tsk_error_set_errno(TSK_ERR_FS_READ);
                }
                tsk_error_set_errstr2("%s: FAT1", func_name);
                fs->tag = 0;
                return 1;
            }

            cnt =
                tsk_fs_read(fs,
                (fatfs->firstfatsect + fatfs->sectperfat) * fatfs->ssize,
                (char *) buf2, 512);
            if (cnt != 512) {
                if (cnt >= 0) {
                    tsk_error_reset();
                    tsk_error_set_errno(TSK_ERR_FS_READ);
                }
                tsk_error_set_errstr2("%s: FAT2", func_name);
                fs->tag = 0;
                return 1;
            }

            numDiffs = 0;
            for (i2 = 0; i2 < 512; i2++) {
                if (buf1[i2] != buf2[i2]) {
                    numDiffs++;
                }
            }
            if (numDiffs > 25) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_FS_MAGIC);
                tsk_error_set_errstr
                    ("Invalid FAT image (Too many differences between FATS from guessing (%d diffs))",
                    numDiffs);
                if (tsk_verbose)
                    fprintf(stderr,
                        "%s: Too many differences in FAT from guessing (%d diffs)\n",
                        func_name, numDiffs);
                return 1;
            }
        }
    }

    /* Set the mask to use on the cluster values */
    if (fatfs->fs_info.ftype == TSK_FS_TYPE_FAT12) {
        fatfs->mask = FATFS_12_MASK;
    }
    else if (fatfs->fs_info.ftype == TSK_FS_TYPE_FAT16) {
        fatfs->mask = FATFS_16_MASK;
    }
    else if (fatfs->fs_info.ftype == TSK_FS_TYPE_FAT32) {
        fatfs->mask = FATFS_32_MASK;
    }
    else {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("Unknown FAT type in %s: %d\n",
            func_name, fatfs->fs_info.ftype);
        return 1;
    }
    fs->duname = "Sector";

    /* the root directories are always after the FAT for TSK_FS_TYPE_FAT12 and TSK_FS_TYPE_FAT16,
     * but are dynamically located for TSK_FS_TYPE_FAT32
     */
    if (fatfs->fs_info.ftype == TSK_FS_TYPE_FAT32)
        fatfs->rootsect = FATFS_CLUST_2_SECT(fatfs,
            tsk_getu32(fs->endian, fatsb->a.f32.rootclust));
    else
        fatfs->rootsect = fatfs->firstdatasect;

    for (i = 0; i < FATFS_FAT_CACHE_N; i++) {
        fatfs->fatc_addr[i] = 0;
        fatfs->fatc_ttl[i] = 0;
    }

    /*
     * block calculations : although there are no blocks in fat, we will
     * use these fields for sector calculations
     */
    fs->first_block = 0;
    fs->block_count = sectors;
    fs->last_block = fs->last_block_act = fs->block_count - 1;
    fs->block_size = fatfs->ssize;

    // determine the last block we have in this image
    if ((TSK_DADDR_T) ((fatfs->fs_info.img_info->size - fatfs->fs_info.offset) / fs->block_size) <
        fs->block_count)
        fs->last_block_act =
            (fatfs->fs_info.img_info->size - fatfs->fs_info.offset) / fs->block_size - 1;

    /*
     * inode calculations
     */

    /* maximum number of dentries in a sector & cluster */
    fatfs->dentry_cnt_se = fatfs->ssize / sizeof(FATXXFS_DENTRY);
    fatfs->dentry_cnt_cl = fatfs->dentry_cnt_se * fatfs->csize;

    fs->root_inum = FATFS_ROOTINO;
    fs->first_inum = FATFS_FIRSTINO;

    /* Calculate inode addresses for the virtual files (MBR, one or two FATS) 
     * and the virtual orphan files directory. */
    fs->last_inum = (FATFS_SECT_2_INODE(fatfs, fs->last_block_act + 1) - 1) + FATFS_NUM_VIRT_FILES(fatfs);
    fatfs->mbr_virt_inum = fs->last_inum - FATFS_NUM_VIRT_FILES(fatfs) + 1;
    fatfs->fat1_virt_inum = fatfs->mbr_virt_inum + 1;
    if (fatfs->numfat == 2) {
        fatfs->fat2_virt_inum = fatfs->fat1_virt_inum + 1;
    }
    else {
        fatfs->fat2_virt_inum = fatfs->fat1_virt_inum;
    }

    /* Calculate the total number of inodes. */
    fs->inum_count = fs->last_inum - fs->first_inum + 1;

    /* Volume ID */
    for (fs->fs_id_used = 0; fs->fs_id_used < 4; fs->fs_id_used++) {
        if (fatfs->fs_info.ftype == TSK_FS_TYPE_FAT32)
            fs->fs_id[fs->fs_id_used] =
                fatsb->a.f32.vol_id[fs->fs_id_used];
        else
            fs->fs_id[fs->fs_id_used] =
                fatsb->a.f16.vol_id[fs->fs_id_used];
    }

    /*
     * Set the function pointers  
     */

    fs->block_walk = fatfs_block_walk;
    fs->block_getflags = fatfs_block_getflags;

    fs->inode_walk = fatfs_inode_walk;
    fs->istat = fatfs_istat;
    fs->file_add_meta = fatfs_inode_lookup;

    fs->get_default_attr_type = fatfs_get_default_attr_type;
    fs->load_attrs = fatfs_make_data_runs;

    fs->dir_open_meta = fatfs_dir_open_meta;
    fs->name_cmp = fatfs_name_cmp;

    fs->fsstat = fatxxfs_fsstat;
    fs->fscheck = fatfs_fscheck;

    fs->close = fatfs_close;

    fs->jblk_walk = fatfs_jblk_walk;
    fs->jentry_walk = fatfs_jentry_walk;
    fs->jopen = fatfs_jopen;

    fatfs->is_cluster_alloc = fatxxfs_is_cluster_alloc;
    fatfs->is_dentry = fatxxfs_is_dentry;
    fatfs->dinode_copy =  fatxxfs_dinode_copy;
    fatfs->inode_lookup = fatxxfs_inode_lookup;
    fatfs->inode_walk_should_skip_dentry = fatxxfs_inode_walk_should_skip_dentry;
    fatfs->istat_attr_flags = fatxxfs_istat_attr_flags;
    fatfs->dent_parse_buf = fatxxfs_dent_parse_buf;

    // initialize the caches
    tsk_init_lock(&fatfs->cache_lock);
    tsk_init_lock(&fatfs->dir_lock);
    fatfs->inum2par = NULL;

	// Test to see if this is the odd Android case where the FAT entries have no short name
	//
	// If there are no entries found with the normal short name
	// and we find more entries by removing the short name test for allocated directories, then assume
	// this is the case where we have no short names
	fatfs->subtype = TSK_FATFS_SUBTYPE_SPEC;
	test_dir1 = tsk_fs_dir_open_meta(fs, fs->root_inum);

	if (test_dir1 != NULL && test_dir1->names_used <= 4){ // At most four automatic directories ($MBR, $FAT1, $FAT1, $OrphanFiles)
	    TSK_FS_DIR * test_dir2; //  to see if it's the Android FAT version

		fatfs->subtype = TSK_FATFS_SUBTYPE_ANDROID_1;
		test_dir2 = tsk_fs_dir_open_meta(fs, fs->root_inum);

		if (test_dir2 != NULL && test_dir2->names_used > test_dir1->names_used){
			fatfs->subtype = TSK_FATFS_SUBTYPE_ANDROID_1;
		}
		else{
			fatfs->subtype = TSK_FATFS_SUBTYPE_SPEC;
		}
		tsk_fs_dir_close(test_dir2);
	}
	tsk_fs_dir_close(test_dir1);

    return 0;
}

/* Return 1 if allocated, 0 if unallocated, and -1 if error */
int8_t
fatxxfs_is_cluster_alloc(FATFS_INFO *fatfs, TSK_DADDR_T clust)
{
    TSK_DADDR_T content = 0;

    if (fatfs_getFAT(fatfs, clust, &content))
        return -1;
    else if (content == FATFS_UNALLOC)
        return 0;
    else
        return 1;
}
