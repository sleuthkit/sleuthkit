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

/* TTL is 0 if the entry has not been used.  TTL of 1 means it was the
 * most recently used, and TTL of FAT_CACHE_N means it was the least 
 * recently used.  This function has a LRU replacement algo
 *
 * Note: This routine assumes &fatfs->cache_lock is locked by the caller.
 */
// return -1 on error, or cache index on success (0 to FAT_CACHE_N)

static int
getFATCacheIdx(FATFS_INFO * fatfs, TSK_DADDR_T sect)
{
    int i, cidx;
    ssize_t cnt;
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & fatfs->fs_info;

    // see if we already have it in the cache
    for (i = 0; i < FAT_CACHE_N; i++) {
        if ((fatfs->fatc_ttl[i] > 0) &&
            (sect >= fatfs->fatc_addr[i]) &&
            (sect < (fatfs->fatc_addr[i] + FAT_CACHE_S))) {
            int a;

            // update the TTLs to push i to the front
            for (a = 0; a < FAT_CACHE_N; a++) {
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

    // Look for an unused entry or an entry with a TTL of FAT_CACHE_N
    cidx = 0;
    for (i = 0; i < FAT_CACHE_N; i++) {
        if ((fatfs->fatc_ttl[i] == 0) ||
            (fatfs->fatc_ttl[i] >= FAT_CACHE_N)) {
            cidx = i;
        }
    }
//    fprintf(stdout, "FAT Removing: %d\n", (int)fatfs->fatc_addr[cidx]);
    //   fflush(stdout);

    // read the data
    cnt =
        tsk_fs_read(fs, sect * fs->block_size, fatfs->fatc_buf[cidx],
        FAT_CACHE_B);
    if (cnt != FAT_CACHE_B) {
        if (cnt >= 0) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_READ);
        }
        tsk_error_set_errstr2("getFATCacheIdx: FAT: %" PRIuDADDR, sect);
        return -1;
    }

    // update the TTLs
    if (fatfs->fatc_ttl[cidx] == 0)     // special case for unused entry
        fatfs->fatc_ttl[cidx] = FAT_CACHE_N + 1;

    for (i = 0; i < FAT_CACHE_N; i++) {
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
 * *value is in clusters and may need to be coverted to
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
        if (offs == (FAT_CACHE_B - 1)) {

            // read the data -- TTLs will already have been updated
            cnt =
                tsk_fs_read(fs, sect * fs->block_size,
                fatfs->fatc_buf[cidx], FAT_CACHE_B);
            if (cnt != FAT_CACHE_B) {
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

/* return 1 on error and 0 on success */
static uint8_t
fatfs_fscheck(TSK_FS_INFO * fs, FILE * hFile)
{
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_UNSUPFUNC);
    tsk_error_set_errstr("fscheck not implemented for FAT yet");
    return 1;

    /* Check that allocated dentries point to start of allcated cluster chain */


    /* Size of file is consistent with cluster chain length */


    /* Allocated cluster chains have a corresponding alloc dentry */


    /* Non file dentries have no clusters */


    /* Only one volume label */


    /* Dump Bad Sector Addresses */


    /* Dump unused sector addresses 
     * Reserved area, end of FAT, end of Data Area */

}

/**
 * Print details about the file system to a file handle. 
 *
 * @param fs File system to print details on
 * @param hFile File handle to print text to
 * 
 * @returns 1 on error and 0 on success
 */
static uint8_t
fatfs_fsstat(TSK_FS_INFO * fs, FILE * hFile)
{
    unsigned int i;
    int a;
    TSK_DADDR_T next, snext, sstart, send;
    FATFS_INFO *fatfs = (FATFS_INFO *) fs;
    fatfs_sb *sb = (fatfs_sb*)fatfs->boot_sector_buffer;
    char *data_buf;
    FATXXFS_DENTRY *de;
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
        tsk_error_set_errstr2("fatfs_fsstat: root directory: %" PRIuDADDR,
            fatfs->rootsect);
        free(data_buf);
        return 1;
    }


    /* Find the dentry that is set as the volume label */
    de = (FATXXFS_DENTRY *) data_buf;
    for (i = 0; i < fatfs->ssize; i += sizeof(*de)) {
        if (de->attrib == FATFS_ATTR_VOLUME)
            break;
        de++;
    }
    /* If we didn't find it, then reset de */
    if (de->attrib != FATFS_ATTR_VOLUME)
        de = NULL;


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

        if ((de) && (de->name)) {
            tsk_fprintf(hFile,
                "Volume Label (Root Directory): %c%c%c%c%c%c%c%c%c%c%c\n",
                de->name[0], de->name[1], de->name[2], de->name[3],
                de->name[4], de->name[5], de->name[6], de->name[7],
                de->ext[0], de->ext[1], de->ext[2]);
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
        fatfs_fsinfo *fat_info;

        if ((fat_fsinfo_buf = (char *)
                tsk_malloc(sizeof(fatfs_fsinfo))) == NULL) {
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

        if ((de) && (de->name)) {
            tsk_fprintf(hFile,
                "Volume Label (Root Directory): %c%c%c%c%c%c%c%c%c%c%c\n",
                de->name[0], de->name[1], de->name[2], de->name[3],
                de->name[4], de->name[5], de->name[6], de->name[7],
                de->ext[0], de->ext[1], de->ext[2]);
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
            cnt =
                tsk_fs_read_block(fs, (TSK_DADDR_T) tsk_getu16(fs->endian,
                    sb->a.f32.fsinfo), fat_fsinfo_buf,
                sizeof(fatfs_fsinfo));

            if (cnt != sizeof(fatfs_fsinfo)) {
                if (cnt >= 0) {
                    tsk_error_reset();
                    tsk_error_set_errno(TSK_ERR_FS_READ);
                }
                tsk_error_set_errstr2
                    ("fatfs_fsstat: TSK_FS_TYPE_FAT32 FSINFO block: %"
                    PRIuDADDR, (TSK_DADDR_T) tsk_getu16(fs->endian,
                        sb->a.f32.fsinfo));
                free(data_buf);
                free(fat_fsinfo_buf);
                return 1;
            }


            fat_info = (fatfs_fsinfo *) fat_fsinfo_buf;
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

static TSK_FS_ATTR_TYPE_ENUM
fatfs_get_default_attr_type(const TSK_FS_FILE * a_file)
{
    return TSK_FS_ATTR_TYPE_DEFAULT;
}

int
fatxxfs_open(FATFS_INFO *fatfs)
{
    const char *func_name = "fatxxfs_open";
	TSK_FS_INFO *fs = &(fatfs->fs_info);
	fatfs_sb *fatsb = (fatfs_sb*)(&fatfs->boot_sector_buffer);
	int i = 0;
	ssize_t cnt = 0;
    TSK_DADDR_T sectors = 0;

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
        return 0;
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
        return 0;
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
        return 0;
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
        return 0;
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
        return 0;
    }

    /* Calculate the block info
     * 
     * The sector of the begining of the data area  - which is 
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
            return 0;
        }
    }

    if ((fatfs->fs_info.ftype == TSK_FS_TYPE_FAT32) && (fatfs->numroot != 0)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_MAGIC);
        tsk_error_set_errstr
            ("Invalid TSK_FS_TYPE_FAT32 image (numroot != 0)");
        if (tsk_verbose)
            fprintf(stderr, "%s: numroom != 0 for FAT32\n", func_name);
        return 0;
    }

    if ((fatfs->fs_info.ftype != TSK_FS_TYPE_FAT32) && (fatfs->numroot == 0)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_MAGIC);
        tsk_error_set_errstr
            ("Invalid FAT image (numroot == 0, and not TSK_FS_TYPE_FAT32)");
        if (tsk_verbose)
            fprintf(stderr, "%s: numroom == 0 and not FAT32\n", func_name);
        return 0;
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
            return 0;
        }
        if (fatfs->numroot > 1) {
            uint8_t buf1[512];
            uint8_t buf2[512];
            int i2;
            int numDiffs;

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
                return 0;
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
                return 0;
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
                return 0;
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
        return 0;
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

    for (i = 0; i < FAT_CACHE_N; i++) {
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
    // Add on extras for Orphan and special files
    fs->last_inum =
        (FATFS_SECT_2_INODE(fatfs,
            fs->last_block_act + 1) - 1) + FATFS_NUM_SPECFILE;
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
    fs->load_attrs = fatfs_make_data_run;

    fs->dir_open_meta = fatfs_dir_open_meta;
    fs->name_cmp = fatfs_name_cmp;

    fs->fsstat = fatfs_fsstat;
    fs->fscheck = fatfs_fscheck;

    fs->close = fatfs_close;

    fs->jblk_walk = fatfs_jblk_walk;
    fs->jentry_walk = fatfs_jentry_walk;
    fs->jopen = fatfs_jopen;

    // initialize the caches
    tsk_init_lock(&fatfs->cache_lock);
    tsk_init_lock(&fatfs->dir_lock);
    fatfs->inum2par = NULL;

    return 1;
}

/* Return 1 if allocated, 0 if unallocated, and -1 if error */
int8_t
fatxxfs_is_clust_alloc(FATFS_INFO *fatfs, TSK_DADDR_T clust)
{
    TSK_DADDR_T content = 0;

    if (fatfs_getFAT(fatfs, clust, &content))
        return -1;
    else if (content == FATFS_UNALLOC)
        return 0;
    else
        return 1;
}

uint8_t
fatxxfs_is_dentry(FATFS_INFO * fatfs, FATFS_DENTRY * a_de, uint8_t a_basic)
{
    const char *func_name = "fatxxfs_is_dentry";
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & fatfs->fs_info;
    FATXXFS_DENTRY *de = (FATXXFS_DENTRY *) a_de; 

    if (!de)
        return 0;

    /* LFN have their own checks, which are pretty weak since most
     * fields are UTF16 */
    if ((de->attrib & FATFS_ATTR_LFN) == FATFS_ATTR_LFN) {
        fatfs_dentry_lfn *de_lfn = (fatfs_dentry_lfn *) de;

        if ((de_lfn->seq > (FATFS_LFN_SEQ_FIRST | 0x0f))
            && (de_lfn->seq != FATFS_SLOT_DELETED)) {
            if (tsk_verbose)
                fprintf(stderr, "%s: LFN seq\n", func_name);
            return 0;
        }

        return 1;
    }
    else {
        // the basic test is only for the 'essential data'.
        if (a_basic == 0) {
            if (de->lowercase & ~(FATFS_CASE_LOWER_ALL)) {
                if (tsk_verbose)
                    fprintf(stderr, "%s: lower case all\n", func_name);
                return 0;
            }
            else if (de->attrib & ~(FATFS_ATTR_ALL)) {
                if (tsk_verbose)
                    fprintf(stderr, "%s: attribute all\n", func_name);
                return 0;
            }

            // verify we do not have too many flags set
            if (de->attrib & FATFS_ATTR_VOLUME) {
                if ((de->attrib & FATFS_ATTR_DIRECTORY) ||
                    (de->attrib & FATFS_ATTR_READONLY) ||
                    (de->attrib & FATFS_ATTR_ARCHIVE)) {
                    if (tsk_verbose)
                        fprintf(stderr,
                            "%s: Vol and Dir/RO/Arch\n", func_name);
                    return 0;
                }
            }

            /* The ctime, cdate, and adate fields are optional and 
             * therefore 0 is a valid value
             * We have had scenarios where ISDATE and ISTIME return true,
             * but the unix2dos fail during the conversion.  This has been
             * useful to detect corrupt entries, so we do both. 
             */
            if ((tsk_getu16(fs->endian, de->ctime) != 0) &&
                (FATFS_ISTIME(tsk_getu16(fs->endian, de->ctime)) == 0)) {
                if (tsk_verbose)
                    fprintf(stderr, "%s: ctime\n", func_name);
                return 0;
            }
            else if ((tsk_getu16(fs->endian, de->wtime) != 0) &&
                (FATFS_ISTIME(tsk_getu16(fs->endian, de->wtime)) == 0)) {
                if (tsk_verbose)
                    fprintf(stderr, "%s: wtime\n", func_name);
                return 0;
            }
            else if ((tsk_getu16(fs->endian, de->cdate) != 0) &&
                ((FATFS_ISDATE(tsk_getu16(fs->endian, de->cdate)) == 0) ||
                    (dos2unixtime(tsk_getu16(fs->endian, de->cdate),
                            tsk_getu16(fs->endian, de->ctime),
                            de->ctimeten) == 0))) {
                if (tsk_verbose)
                    fprintf(stderr, "%s: cdate\n", func_name);
                return 0;
            }
            else if (de->ctimeten > 200) {
                if (tsk_verbose)
                    fprintf(stderr, "%s: ctimeten\n", func_name);
                return 0;
            }
            else if ((tsk_getu16(fs->endian, de->adate) != 0) &&
                ((FATFS_ISDATE(tsk_getu16(fs->endian, de->adate)) == 0) ||
                    (dos2unixtime(tsk_getu16(fs->endian, de->adate),
                            0, 0) == 0))) {
                if (tsk_verbose)
                    fprintf(stderr, "%s: adate\n", func_name);
                return 0;
            }
            else if ((tsk_getu16(fs->endian, de->wdate) != 0) &&
                ((FATFS_ISDATE(tsk_getu16(fs->endian, de->wdate)) == 0) ||
                    (dos2unixtime(tsk_getu16(fs->endian, de->wdate),
                            tsk_getu16(fs->endian, de->wtime), 0) == 0))) {
                if (tsk_verbose)
                    fprintf(stderr, "%s: wdate\n", func_name);
                return 0;
            }
        }

        /* verify the starting cluster is small enough */
        if ((FATFS_DENTRY_CLUST(fs, de) > (fatfs->lastclust)) &&
            (FATFS_ISEOF(FATFS_DENTRY_CLUST(fs, de), fatfs->mask) == 0)) {
            if (tsk_verbose)
                fprintf(stderr, "%s: start cluster\n", func_name);
            return 0;
        }

        /* Verify the file size is smaller than the data area */
        else if (tsk_getu32(fs->endian, de->size) >
            ((fatfs->clustcnt * fatfs->csize) << fatfs->ssize_sh)) {
            if (tsk_verbose)
                fprintf(stderr, "%s: size\n", func_name);
            return 0;
        }

        else if ((tsk_getu32(fs->endian, de->size) > 0)
            && (FATFS_DENTRY_CLUST(fs, de) == 0)) {
            if (tsk_verbose)
                fprintf(stderr,
                    "%s: non-zero size and NULL starting cluster\n", func_name);
            return 0;
        }

        else if (is_83_name(de) == 0)
            return 0;

        // basic sanity check on values
        else if ((tsk_getu16(fs->endian, de->ctime) == 0)
            && (tsk_getu16(fs->endian, de->wtime) == 0)
            && (tsk_getu16(fs->endian, de->cdate) == 0)
            && (tsk_getu16(fs->endian, de->adate) == 0)
            && (tsk_getu16(fs->endian, de->wdate) == 0)
            && (FATFS_DENTRY_CLUST(fs, de) == 0)
            && (tsk_getu32(fs->endian, de->size) == 0)) {
            if (tsk_verbose)
                fprintf(stderr,
                    "s: nearly all values zero\n", func_name);
            return 0;
        }

        return 1;
    }
}

/* timetens is number of tenths of a second for a 2 second range (values 0 to 199) */
static uint32_t
dos2nanosec(uint8_t timetens)
{
    timetens %= 100;
    return timetens * 10000000;
}

/*
 * convert the attribute list in FAT to a UNIX mode
 */
static TSK_FS_META_TYPE_ENUM
attr2type(uint16_t attr)
{
    if (attr & FATFS_ATTR_DIRECTORY)
        return TSK_FS_META_TYPE_DIR;
    else
        return TSK_FS_META_TYPE_REG;
}


static int
attr2mode(uint16_t attr)
{
    int mode;

    /* every file is executable */
    mode =
        (TSK_FS_META_MODE_IXUSR | TSK_FS_META_MODE_IXGRP |
        TSK_FS_META_MODE_IXOTH);

    if ((attr & FATFS_ATTR_READONLY) == 0)
        mode |=
            (TSK_FS_META_MODE_IRUSR | TSK_FS_META_MODE_IRGRP |
            TSK_FS_META_MODE_IROTH);

    if ((attr & FATFS_ATTR_HIDDEN) == 0)
        mode |=
            (TSK_FS_META_MODE_IWUSR | TSK_FS_META_MODE_IWGRP |
            TSK_FS_META_MODE_IWOTH);

    return mode;
}

TSK_RETVAL_ENUM
fatxxfs_dinode_copy(FATFS_INFO * fatfs, TSK_FS_META * fs_meta,
    FATFS_DENTRY * a_in, TSK_DADDR_T sect, TSK_INUM_T inum)
{
    const char *func_name = "fatxxfs_dinode_copy";
    int retval;
    int i;
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & fatfs->fs_info;
    TSK_DADDR_T *addr_ptr;
    FATXXFS_DENTRY *in = (FATXXFS_DENTRY *) a_in;

    if (fs_meta->content_len < FATFS_FILE_CONTENT_LEN) {
        if ((fs_meta =
                tsk_fs_meta_realloc(fs_meta,
                    FATFS_FILE_CONTENT_LEN)) == NULL) {
            return 1;
        }
    }

    fs_meta->attr_state = TSK_FS_META_ATTR_EMPTY;
    if (fs_meta->attr) {
        tsk_fs_attrlist_markunused(fs_meta->attr);
    }

    fs_meta->mode = attr2mode(in->attrib);
    fs_meta->type = attr2type(in->attrib);

    fs_meta->addr = inum;

    /* Use the allocation status of the sector to determine if the
     * dentry is allocated or not */
    retval = fatfs_is_sectalloc(fatfs, sect);
    if (retval == -1) {
        return TSK_ERR;
    }
    else if (retval == 1) {
        fs_meta->flags = ((in->name[0] == FATFS_SLOT_DELETED) ?
            TSK_FS_META_FLAG_UNALLOC : TSK_FS_META_FLAG_ALLOC);
    }
    else {
        fs_meta->flags = TSK_FS_META_FLAG_UNALLOC;
    }

    /* Slot has not been used yet */
    fs_meta->flags |= ((in->name[0] == FATFS_SLOT_EMPTY) ?
        TSK_FS_META_FLAG_UNUSED : TSK_FS_META_FLAG_USED);

    if ((in->attrib & FATFS_ATTR_LFN) == FATFS_ATTR_LFN) {
        /* LFN entries don't have these values */
        fs_meta->nlink = 0;
        fs_meta->size = 0;
        fs_meta->mtime = 0;
        fs_meta->atime = 0;
        fs_meta->ctime = 0;
        fs_meta->crtime = 0;
        fs_meta->mtime_nano = fs_meta->atime_nano = fs_meta->ctime_nano =
            fs_meta->crtime_nano = 0;
    }
    else {
        /* There is no notion of link in FAT, just deleted or not */
        fs_meta->nlink = (in->name[0] == FATFS_SLOT_DELETED) ? 0 : 1;
        fs_meta->size = (TSK_OFF_T) tsk_getu32(fs->endian, in->size);

        /* If these are valid dates, then convert to a unix date format */
        if (FATFS_ISDATE(tsk_getu16(fs->endian, in->wdate)))
            fs_meta->mtime =
                dos2unixtime(tsk_getu16(fs->endian, in->wdate),
                tsk_getu16(fs->endian, in->wtime), 0);
        else
            fs_meta->mtime = 0;
        fs_meta->mtime_nano = 0;

        if (FATFS_ISDATE(tsk_getu16(fs->endian, in->adate)))
            fs_meta->atime =
                dos2unixtime(tsk_getu16(fs->endian, in->adate), 0, 0);
        else
            fs_meta->atime = 0;
        fs_meta->atime_nano = 0;


        /* cdate is the creation date in FAT and there is no change,
         * so we just put in into change and set create to 0.  The other
         * front-end code knows how to handle it and display it
         */
        if (FATFS_ISDATE(tsk_getu16(fs->endian, in->cdate))) {
            fs_meta->crtime =
                dos2unixtime(tsk_getu16(fs->endian, in->cdate),
                tsk_getu16(fs->endian, in->ctime), in->ctimeten);
            fs_meta->crtime_nano = dos2nanosec(in->ctimeten);
        }
        else {
            fs_meta->crtime = 0;
            fs_meta->crtime_nano = 0;
        }

        // FAT does not have a changed time
        fs_meta->ctime = 0;
        fs_meta->ctime_nano = 0;
    }

    /* Values that do not exist in FAT */
    fs_meta->uid = 0;
    fs_meta->gid = 0;
    fs_meta->seq = 0;


    /* We will be copying a name, so allocate a structure */
    if (fs_meta->name2 == NULL) {
        if ((fs_meta->name2 = (TSK_FS_META_NAME_LIST *)
                tsk_malloc(sizeof(TSK_FS_META_NAME_LIST))) == NULL)
            return TSK_ERR;
        fs_meta->name2->next = NULL;
    }

    /* If we have a LFN entry, then we need to convert the three
     * parts of the name to UTF-8 and copy it into the name structure .
     */
    if ((in->attrib & FATFS_ATTR_LFN) == FATFS_ATTR_LFN) {
        fatfs_dentry_lfn *lfn = (fatfs_dentry_lfn *) in;

        /* Convert the first part of the name */
        UTF8 *name8 = (UTF8 *) fs_meta->name2->name;
        UTF16 *name16 = (UTF16 *) lfn->part1;

        int retVal = tsk_UTF16toUTF8(fs->endian, (const UTF16 **) &name16,
            (UTF16 *) & lfn->part1[10],
            &name8,
            (UTF8 *) ((uintptr_t) fs_meta->name2->name +
                sizeof(fs_meta->name2->name)),
            TSKlenientConversion);

        if (retVal != TSKconversionOK) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_UNICODE);
            tsk_error_set_errstr
                ("%s: Error converting FAT LFN (1) to UTF8: %d",
                func_name, retVal);
            *name8 = '\0';

            return TSK_COR;
        }

        /* Convert the second part of the name */
        name16 = (UTF16 *) lfn->part2;
        retVal = tsk_UTF16toUTF8(fs->endian, (const UTF16 **) &name16,
            (UTF16 *) & lfn->part2[12],
            &name8,
            (UTF8 *) ((uintptr_t) fs_meta->name2->name +
                sizeof(fs_meta->name2->name)), TSKlenientConversion);

        if (retVal != TSKconversionOK) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_UNICODE);
            tsk_error_set_errstr
                ("%s: Error converting FAT LFN (2) to UTF8: %d",
                func_name, retVal);
            *name8 = '\0';

            return TSK_COR;
        }

        /* Convert the third part of the name */
        name16 = (UTF16 *) lfn->part3;
        retVal = tsk_UTF16toUTF8(fs->endian, (const UTF16 **) &name16,
            (UTF16 *) & lfn->part3[4],
            &name8,
            (UTF8 *) ((uintptr_t) fs_meta->name2->name +
                sizeof(fs_meta->name2->name)), TSKlenientConversion);

        if (retVal != TSKconversionOK) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_UNICODE);
            tsk_error_set_errstr
                ("%s: Error converting FAT LFN (3) to UTF8: %d",
                func_name, retVal);
            *name8 = '\0';

            return TSK_COR;
        }

        /* Make sure it is NULL Terminated */
        if ((uintptr_t) name8 >
            (uintptr_t) fs_meta->name2->name +
            sizeof(fs_meta->name2->name))
            fs_meta->name2->name[sizeof(fs_meta->name2->name) - 1] = '\0';
        else
            *name8 = '\0';
    }
    /* If the entry is for a volume label, then copy the name and
     * append a special label
     */
    else if ((in->attrib & FATFS_ATTR_VOLUME) == FATFS_ATTR_VOLUME) {
        int a;

        i = 0;
        for (a = 0; a < 8; a++) {
            if ((in->name[a] != 0x00) && (in->name[a] != 0xff))
                fs_meta->name2->name[i++] = in->name[a];
        }
        for (a = 0; a < 3; a++) {
            if ((in->ext[a] != 0x00) && (in->ext[a] != 0xff))
                fs_meta->name2->name[i++] = in->ext[a];
        }
        fs_meta->name2->name[i] = '\0';

        /* clean up non-ASCII because we are
         * copying it into a buffer that is supposed to be UTF-8 and
         * we don't know what encoding it is actually in or if it is 
         * simply junk. */
        fatfs_cleanup_ascii(fs_meta->name2->name);
    }
    /* If the entry is a normal short entry, then copy the name
     * and add the '.' for the extension
     */
    else {
        for (i = 0; (i < 8) && (in->name[i] != 0) && (in->name[i] != ' ');
            i++) {
            if ((i == 0) && (in->name[0] == FATFS_SLOT_DELETED))
                fs_meta->name2->name[0] = '_';
            else if ((in->lowercase & FATFS_CASE_LOWER_BASE) &&
                (in->name[i] >= 'A') && (in->name[i] <= 'Z'))
                fs_meta->name2->name[i] = in->name[i] + 32;
            else
                fs_meta->name2->name[i] = in->name[i];
        }

        if ((in->ext[0]) && (in->ext[0] != ' ')) {
            int a;
            fs_meta->name2->name[i++] = '.';
            for (a = 0;
                (a < 3) && (in->ext[a] != 0) && (in->ext[a] != ' ');
                a++, i++) {
                if ((in->lowercase & FATFS_CASE_LOWER_EXT)
                    && (in->ext[a] >= 'A') && (in->ext[a] <= 'Z'))
                    fs_meta->name2->name[i] = in->ext[a] + 32;
                else
                    fs_meta->name2->name[i] = in->ext[a];
            }
        }
        fs_meta->name2->name[i] = '\0';

        /* clean up non-ASCII because we are
         * copying it into a buffer that is supposed to be UTF-8 and
         * we don't know what encoding it is actually in or if it is 
         * simply junk. */
        fatfs_cleanup_ascii(fs_meta->name2->name);
    }

    /* Clean up name to remove control characters */
    i = 0;
    while (fs_meta->name2->name[i] != '\0') {
        if (TSK_IS_CNTRL(fs_meta->name2->name[i]))
            fs_meta->name2->name[i] = '^';
        i++;
    }

    /* get the starting cluster */
    addr_ptr = (TSK_DADDR_T *) fs_meta->content_ptr;
    if ((in->attrib & FATFS_ATTR_LFN) == FATFS_ATTR_LFN) {
        addr_ptr[0] = 0;
    }
    else {
        addr_ptr[0] = FATFS_DENTRY_CLUST(fs, in) & fatfs->mask;
    }

    /* FAT does not store a size for its directories so make one based
     * on the number of allocated sectors
     */
    if ((in->attrib & FATFS_ATTR_DIRECTORY) &&
        ((in->attrib & FATFS_ATTR_LFN) != FATFS_ATTR_LFN)) {
        if (fs_meta->flags & TSK_FS_META_FLAG_ALLOC) {
            TSK_LIST *list_seen = NULL;

            /* count the total number of clusters in this file */
            TSK_DADDR_T clust = FATFS_DENTRY_CLUST(fs, in);
            int cnum = 0;

            while ((clust) && (0 == FATFS_ISEOF(clust, fatfs->mask))) {
                TSK_DADDR_T nxt;

                /* Make sure we do not get into an infinite loop */
                if (tsk_list_find(list_seen, clust)) {
                    if (tsk_verbose)
                        tsk_fprintf(stderr,
                            "Loop found while determining directory size\n");
                    break;
                }
                if (tsk_list_add(&list_seen, clust)) {
                    tsk_list_free(list_seen);
                    list_seen = NULL;
                    return TSK_ERR;
                }

                cnum++;

                if (fatfs_getFAT(fatfs, clust, &nxt))
                    break;
                else
                    clust = nxt;
            }

            tsk_list_free(list_seen);
            list_seen = NULL;

            fs_meta->size =
                (TSK_OFF_T) ((cnum * fatfs->csize) << fatfs->ssize_sh);
        }
        /* if the dir is unallocated, then assume 0 or cluster size
         * Ideally, we would have a smart algo here to do recovery
         * and look for dentries.  However, we do not have that right
         * now and if we do not add this special check then it can
         * assume that an allocated file cluster chain belongs to the
         * directory */
        else {
            // if the first cluster is allocated, then set size to be 0
            if (fatfs_is_clustalloc(fatfs, FATFS_DENTRY_CLUST(fs,
                        in)) == 1)
                fs_meta->size = 0;
            else
                fs_meta->size = fatfs->csize << fatfs->ssize_sh;
        }
    }


    return TSK_OK;
}

