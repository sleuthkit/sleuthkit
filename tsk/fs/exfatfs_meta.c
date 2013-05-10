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
 */

/**
 * \file exfatfs.c
 * Contains the internal TSK exFAT file system code to handle metadata structures. 
 */

#include "tsk_exfatfs.h" /* Include first to make sure it stands alone. */
#include "tsk_fs_i.h"
#include "tsk_fatfs.h"

static uint8_t
exfatfs_is_vol_label_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_de, uint8_t a_basic)
{
    EXFATFS_VOL_LABEL_DIR_ENTRY *dentry = (EXFATFS_VOL_LABEL_DIR_ENTRY*)a_de;

    if (!a_basic) {
        /* There is not enough data in a volume label directory entry for an 
         * in-depth test. */
         return 0;
    }

    /* The character count should not exceed the maximum length of the volume 
     * label. */
    if (dentry->utf16_char_count > EXFATFS_MAX_VOLUME_LABEL_LEN)
    {
        return 0;
    }

    return 1;
}

static uint8_t
exfatfs_is_vol_guid_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_de, uint8_t a_basic)
{
    if (!a_basic) {
        /* There is not enough data in a volume GUID directory entry for an
         * in-depth test. */
         return 0;
    }

    return 1;
}

uint8_t
exfatfs_is_alloc_bitmap_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_de, uint8_t a_basic)
{
    const char *func_name = "exfatfs_is_alloc_bitmap_dentry";
    TSK_FS_INFO *fs = &(a_fatfs->fs_info);
    EXFATFS_ALLOC_BITMAP_DIR_ENTRY *dentry = (EXFATFS_ALLOC_BITMAP_DIR_ENTRY*)a_de;
    uint32_t first_cluster_of_bitmap = 0;
    uint64_t length_of_alloc_bitmap_in_bytes = 0;

    if (!a_basic) {
        /* The length of the allocation bitmap should be consistent with the 
         * number of clusters in the data area as specified in the volume boot
         * record. */
        length_of_alloc_bitmap_in_bytes = tsk_getu64(fs->endian, dentry->length_of_alloc_bitmap_in_bytes);
        if (length_of_alloc_bitmap_in_bytes != (a_fatfs->clustcnt + 7) / 8) {
            if (tsk_verbose) {
                fprintf(stderr, "%s: bitmap length incorrect\n", func_name);
            }
            return 0;
        }
    }

    /* The first cluster of the bit map should be within the data area.
     * It is usually in the first cluster. */
    first_cluster_of_bitmap = tsk_getu32(fs->endian, dentry->first_cluster_of_bitmap);
    if ((first_cluster_of_bitmap < EXFATFS_FIRST_CLUSTER) ||
        (first_cluster_of_bitmap > a_fatfs->lastclust)) {
        if (tsk_verbose) {
            fprintf(stderr, "%s: first cluster not in cluster heap\n", func_name);
        }
        return 0;
    }

    return 1;
}

static uint8_t
exfatfs_is_upcase_table_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_de, uint8_t a_basic)
{
    const char *func_name = "exfatfs_is_upcase_table_dentry";
    TSK_FS_INFO *fs = &(a_fatfs->fs_info);
    EXFATFS_UPCASE_TABLE_DIR_ENTRY *dentry = (EXFATFS_UPCASE_TABLE_DIR_ENTRY*)a_de;
    uint32_t first_cluster_of_table = 0;

    if (!a_basic) {
        /* There is not enough data in an UP-Case table directory entry
         * for an in-depth test. */
         return 0;
    }

    /* The first cluster of the Up-Case table should be within the 
     * data area. */
    first_cluster_of_table = tsk_getu32(fs->endian, dentry->first_cluster_of_table);
    if ((first_cluster_of_table < EXFATFS_FIRST_CLUSTER) ||
        (first_cluster_of_table > a_fatfs->lastclust)) {
        if (tsk_verbose) {
            fprintf(stderr, "%s: first cluster not in cluster heap\n", func_name);
        }
        return 0;
    }

    return 1;
}

static uint8_t
exfatfs_is_tex_fat_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_de, uint8_t a_basic)
{
    if (!a_basic) {
        /* There is not enough data in a UP-TexFAT directory entry
         * for an in-depth test. */
         return 0;
    }

    return 1;
}

static uint8_t
exfatfs_is_access_ctrl_table_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_de, uint8_t a_basic)
{
    if (!a_basic) {
        /* There is not enough data in an access control table directory entry
         * for an in-depth test. */
         return 0;
    }

    return 1;
}

static uint8_t
exfatfs_is_file_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_de, uint8_t a_basic)
{
    const char *func_name = "exfatfs_is_file_dentry";
    TSK_FS_INFO *fs = &(a_fatfs->fs_info);
    EXFATFS_FILE_DIR_ENTRY *dir_entry = (EXFATFS_FILE_DIR_ENTRY*)a_de;

    if (!a_basic == 0)
    {
        // RJCTODO: Check MAC times
        // RJCTODO: Consider using additional tests similar to bulk extractor tests, e.g., sanity check attributes
    }

    /* The MAC times should not be all zero. */ 
    //RJCTODO: Is this legitimate? 
    if ((tsk_getu16(fs->endian, dir_entry->mtime) == 0) &&
        (tsk_getu16(fs->endian, dir_entry->atime) == 0) &&
        (tsk_getu16(fs->endian, dir_entry->ctime) == 0))
    {
        if (tsk_verbose) {
            fprintf(stderr, "%s: MAC times all zero\n", func_name);
        }
        return 0;
    }

    return 1;
}

static uint8_t
exfatfs_is_file_stream_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_de, uint8_t a_basic)
{
    const char *func_name = "exfatfs_is_file_stream_dentry";
    TSK_FS_INFO *fs = &(a_fatfs->fs_info);

    if (!a_basic) {
        // RJCTODO: Validate this entry
    }

    // RJCTODO: Validate this entry

    return 1;
}

static uint8_t
exfatfs_is_file_name_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_de, uint8_t a_basic)
{
    if (!a_basic) {
        /* There is not enough data in an access control table directory entry
         * for an in-depth test. */
         return 0;
    }

    // RJCTODO: Make sure allocation possible bit is not set. Invalid FAT chain bit should be set.
    // CAn this be used for other entries?

    return 1;
}

uint8_t
exfatfs_is_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_de, uint8_t a_basic)
{
    TSK_FS_INFO *fs = &(a_fatfs->fs_info);

    if (a_fatfs == NULL || a_de == NULL) {
        // RJCTODO: Should record errors? This is a programming error...perhaps an assert?
        return 0;
    }

    // RJCTODO: Handling of deleted file is correct?
    switch (a_de->data[0])
    {
    case EXFATFS_DIR_ENTRY_TYPE_VOLUME_LABEL:
    case EXFATFS_DIR_ENTRY_TYPE_VOLUME_LABEL_EMPTY:
        return exfatfs_is_vol_label_dentry(a_fatfs, a_de, a_basic);
    case EXFATFS_DIR_ENTRY_TYPE_VOLUME_GUID:
        return exfatfs_is_vol_guid_dentry(a_fatfs, a_de, a_basic);
    case EXFATFS_DIR_ENTRY_TYPE_ALLOC_BITMAP:
        return exfatfs_is_alloc_bitmap_dentry(a_fatfs, a_de, a_basic);
    case EXFATFS_DIR_ENTRY_TYPE_UPCASE_TABLE:
        return exfatfs_is_upcase_table_dentry(a_fatfs, a_de, a_basic);
    case EXFATFS_DIR_ENTRY_TYPE_TEX_FAT:
        return exfatfs_is_tex_fat_dentry(a_fatfs, a_de, a_basic);
    case EXFATFS_DIR_ENTRY_TYPE_ACT:
        return exfatfs_is_access_ctrl_table_dentry(a_fatfs, a_de, a_basic);
    case EXFATFS_DIR_ENTRY_TYPE_FILE:
    case EXFATFS_DIR_ENTRY_TYPE_FILE_DELETED:
        return exfatfs_is_file_dentry(a_fatfs, a_de, a_basic);
    case EXFATFS_DIR_ENTRY_TYPE_FILE_STREAM:
    case EXFATFS_DIR_ENTRY_TYPE_FILE_STREAM_DELETED:
        return exfatfs_is_file_stream_dentry(a_fatfs, a_de, a_basic);
    case EXFATFS_DIR_ENTRY_TYPE_FILE_NAME:
    case EXFATFS_DIR_ENTRY_TYPE_FILE_NAME_DELETED:
        return exfatfs_is_file_name_dentry(a_fatfs, a_de, a_basic);
    default:
        return 0;
    }
}

static TSK_RETVAL_ENUM 
exfatfs_copy_vol_label_dinode(FATFS_INFO *a_fatfs, TSK_FS_META *a_fs_meta, FATFS_DENTRY *a_dentry, TSK_INUM_T a_inum)
{
    EXFATFS_VOL_LABEL_DIR_ENTRY *dir_entry = (EXFATFS_VOL_LABEL_DIR_ENTRY*)a_dentry;

    if (dir_entry->entry_type != EXFATFS_DIR_ENTRY_TYPE_VOLUME_LABEL_EMPTY) {
        if (fatfs_copy_utf16_str_2_meta_name(a_fatfs, a_fs_meta, (UTF16*)dir_entry->volume_label, dir_entry->utf16_char_count, a_inum, "volume label") == TSKconversionOK) {
            return TSK_OK;
        }
        else {
            return TSK_COR;
        }
    }
    else {
        strcpy(a_fs_meta->name2->name, EXFATFS_NO_VOLUME_LABEL_VIRT_FILENAME);
        return TSK_OK;
    }
}

static TSK_RETVAL_ENUM 
exfatfs_copy_file_dinode(FATFS_INFO *a_fatfs, TSK_FS_META *a_fs_meta, FATFS_DENTRY *a_dentry, TSK_INUM_T a_inum)
{
    const char *func_name = "exfatfs_copy_file_dinode";
    TSK_FS_INFO *fs = &(a_fatfs->fs_info);
    EXFATFS_FILE_DIR_ENTRY *dir_entry = (EXFATFS_FILE_DIR_ENTRY*)a_dentry;

    //a_fs_meta->mode = attr2mode(in->attrib);
    //a_fs_meta->type = attr2type(in->attrib);

    ///* There is no notion of link in FAT, just deleted or not */
    //fs_meta->nlink = (in->name[0] == FATFS_SLOT_DELETED) ? 0 : 1;
    //fs_meta->size = (TSK_OFF_T) tsk_getu32(fs->endian, in->size);

    ///* If these are valid dates, then convert to a unix date format */
    //if (FATFS_ISDATE(tsk_getu16(fs->endian, in->wdate)))
    //    fs_meta->mtime =
    //        dos2unixtime(tsk_getu16(fs->endian, in->wdate),
    //        tsk_getu16(fs->endian, in->wtime), 0);
    //else
    //    fs_meta->mtime = 0;
    //fs_meta->mtime_nano = 0;

    //if (FATFS_ISDATE(tsk_getu16(fs->endian, in->adate)))
    //    fs_meta->atime =
    //        dos2unixtime(tsk_getu16(fs->endian, in->adate), 0, 0);
    //else
    //    fs_meta->atime = 0;
    //fs_meta->atime_nano = 0;


    ///* cdate is the creation date in FAT and there is no change,
    //    * so we just put in into change and set create to 0.  The other
    //    * front-end code knows how to handle it and display it
    //    */
    //if (FATFS_ISDATE(tsk_getu16(fs->endian, in->cdate))) {
    //    fs_meta->crtime =
    //        dos2unixtime(tsk_getu16(fs->endian, in->cdate),
    //        tsk_getu16(fs->endian, in->ctime), in->ctimeten);
    //    fs_meta->crtime_nano = dos2nanosec(in->ctimeten);
    //}
    //else {
    //    fs_meta->crtime = 0;
    //    fs_meta->crtime_nano = 0;
    //}

    //// FAT does not have a changed time
    //fs_meta->ctime = 0;
    //fs_meta->ctime_nano = 0;

    return TSK_OK;
}

static TSK_RETVAL_ENUM 
exfatfs_copy_file_stream_dinode(FATFS_INFO *a_fatfs, TSK_FS_META *a_fs_meta, FATFS_DENTRY *a_dentry, TSK_INUM_T a_inum)
{
    const char *func_name = "exfatfs_copy_file_stream_dinode";
    TSK_FS_INFO *fs = &(a_fatfs->fs_info);
    EXFATFS_FILE_STREAM_DIR_ENTRY *dir_entry = (EXFATFS_FILE_STREAM_DIR_ENTRY*)a_dentry;

    ///* get the starting cluster */
    //addr_ptr = (TSK_DADDR_T *) fs_meta->content_ptr;
    //if ((in->attrib & FATFS_ATTR_LFN) == FATFS_ATTR_LFN) {
    //    addr_ptr[0] = 0;
    //}
    //else {
    //    addr_ptr[0] = FATFS_DENTRY_CLUST(fs, in) & fatfs->mask;
    //}

    ///* FAT does not store a size for its directories so make one based
    // * on the number of allocated sectors
    // */
    //if ((in->attrib & FATFS_ATTR_DIRECTORY) &&
    //    ((in->attrib & FATFS_ATTR_LFN) != FATFS_ATTR_LFN)) {
    //    if (fs_meta->flags & TSK_FS_META_FLAG_ALLOC) {
    //        TSK_LIST *list_seen = NULL;

    //        /* count the total number of clusters in this file */
    //        TSK_DADDR_T clust = FATFS_DENTRY_CLUST(fs, in);
    //        int cnum = 0;

    //        while ((clust) && (0 == FATFS_ISEOF(clust, fatfs->mask))) {
    //            TSK_DADDR_T nxt;

    //            /* Make sure we do not get into an infinite loop */
    //            if (tsk_list_find(list_seen, clust)) {
    //                if (tsk_verbose)
    //                    tsk_fprintf(stderr,
    //                        "Loop found while determining directory size\n");
    //                break;
    //            }
    //            if (tsk_list_add(&list_seen, clust)) {
    //                tsk_list_free(list_seen);
    //                list_seen = NULL;
    //                return TSK_ERR;
    //            }

    //            cnum++;

    //            if (fatfs_getFAT(fatfs, clust, &nxt))
    //                break;
    //            else
    //                clust = nxt;
    //        }

    //        tsk_list_free(list_seen);
    //        list_seen = NULL;

    //        fs_meta->size =
    //            (TSK_OFF_T) ((cnum * fatfs->csize) << fatfs->ssize_sh);
    //    }
    //    /* if the dir is unallocated, then assume 0 or cluster size
    //     * Ideally, we would have a smart algo here to do recovery
    //     * and look for dentries.  However, we do not have that right
    //     * now and if we do not add this special check then it can
    //     * assume that an allocated file cluster chain belongs to the
    //     * directory */
    //    else {
    //        // if the first cluster is allocated, then set size to be 0
    //        if (fatfs_is_clustalloc(fatfs, FATFS_DENTRY_CLUST(fs,
    //                    in)) == 1)
    //            fs_meta->size = 0;
    //        else
    //            fs_meta->size = fatfs->csize << fatfs->ssize_sh;
    //    }
    //}


    return TSK_OK;
}

static TSK_RETVAL_ENUM 
exfatfs_copy_file_name_dinode(FATFS_INFO *a_fatfs, TSK_FS_META *a_fs_meta, FATFS_DENTRY *a_dentry, TSK_INUM_T a_inum)
{
    EXFATFS_FILE_NAME_DIR_ENTRY *dir_entry = (EXFATFS_FILE_NAME_DIR_ENTRY*)a_dentry;

    if (fatfs_copy_utf16_str_2_meta_name(a_fatfs, a_fs_meta, (UTF16*)dir_entry->utf16_name_chars, EXFATFS_MAX_FILE_NAME_SEGMENT_LENGTH, a_inum, "file name segment") == TSKconversionOK) {
        return TSK_OK;
    }
    else {
        return TSK_COR;
    }
}

TSK_RETVAL_ENUM
exfatfs_dinode_copy(FATFS_INFO *a_fatfs, TSK_FS_META *a_fs_meta,
    FATFS_DENTRY *a_dentry, TSK_DADDR_T a_sect, TSK_INUM_T a_inum)
{
    TSK_FS_INFO *fs = &(a_fatfs->fs_info);
    int8_t ret_val = 0;

    // RJCTO: Param checks

    // RJCTODO: Comment
    if (a_fs_meta->content_len < FATFS_FILE_CONTENT_LEN) {
        if ((a_fs_meta =
                tsk_fs_meta_realloc(a_fs_meta,
                    FATFS_FILE_CONTENT_LEN)) == NULL) {
            return TSK_ERR;
        }
    }

    // RJCTODO: What's all this?
    a_fs_meta->attr_state = TSK_FS_META_ATTR_EMPTY;
    if (a_fs_meta->attr) {
        tsk_fs_attrlist_markunused(a_fs_meta->attr);
    }

    a_fs_meta->addr = a_inum;

    // RJCTODO: Map to in use flag of dir entry?
    /* Slot has not been used yet */
    //fs_meta->flags |= ((in->name[0] == FATFS_SLOT_EMPTY) ?
    //    TSK_FS_META_FLAG_UNUSED : TSK_FS_META_FLAG_USED);

    /* Default values for metadata that only exists in file entries. */
    a_fs_meta->nlink = 0; // RJCTODO: SHould this be used?
    a_fs_meta->size = 0;
    a_fs_meta->mtime = 0;
    a_fs_meta->atime = 0;
    a_fs_meta->ctime = 0;
    a_fs_meta->crtime = 0;
    a_fs_meta->mtime_nano = a_fs_meta->atime_nano = a_fs_meta->ctime_nano = a_fs_meta->crtime_nano = 0;

    /* Metadata that does not exist in exFAT. */
    a_fs_meta->uid = 0;
    a_fs_meta->gid = 0;
    a_fs_meta->seq = 0;

    // RJCTODO: Update comment and verify correctness.
    /* Use the allocation status of the sector to determine if the
     * dentry is allocated or not. */
    ret_val = fatfs_is_sectalloc(a_fatfs, a_sect);
    if (ret_val != -1) {
        a_fs_meta->flags = ret_val == 1 ? TSK_FS_META_FLAG_ALLOC : TSK_FS_META_FLAG_UNALLOC;
    }
    else {
        return TSK_ERR;
    }

    // RJCTODO: I think this applies
    /* We will be copying a name, so allocate a structure */
    if (a_fs_meta->name2 == NULL) {
        if ((a_fs_meta->name2 = (TSK_FS_META_NAME_LIST *)
                tsk_malloc(sizeof(TSK_FS_META_NAME_LIST))) == NULL) {
            return TSK_ERR;
        }
        a_fs_meta->name2->next = NULL;
    }

    switch (a_dentry->data[0])
    {
    case EXFATFS_DIR_ENTRY_TYPE_VOLUME_LABEL:
    case EXFATFS_DIR_ENTRY_TYPE_VOLUME_LABEL_EMPTY:
        return exfatfs_copy_vol_label_dinode(a_fatfs, a_fs_meta, a_dentry, a_inum);
    case EXFATFS_DIR_ENTRY_TYPE_VOLUME_GUID:
        strcpy(a_fs_meta->name2->name, EXFATFS_VOLUME_GUID_VIRT_FILENAME);
        return TSK_OK;
    case EXFATFS_DIR_ENTRY_TYPE_ALLOC_BITMAP:
        strcpy(a_fs_meta->name2->name, EXFATFS_ALLOC_BITMAP_VIRT_FILENAME);
        return TSK_OK;
    case EXFATFS_DIR_ENTRY_TYPE_UPCASE_TABLE:
        strcpy(a_fs_meta->name2->name, EXFATFS_UPCASE_TABLE_VIRT_FILENAME);
        return TSK_OK;
    case EXFATFS_DIR_ENTRY_TYPE_TEX_FAT:
        strcpy(a_fs_meta->name2->name, EXFATFS_TEX_FAT_VIRT_FILENAME);
        return TSK_OK;
    case EXFATFS_DIR_ENTRY_TYPE_ACT:
        strcpy(a_fs_meta->name2->name, EXFATFS_ACT_VIRT_FILENAME);
        return TSK_OK;
    case EXFATFS_DIR_ENTRY_TYPE_FILE:
    case EXFATFS_DIR_ENTRY_TYPE_FILE_DELETED:
        return exfatfs_copy_file_dinode(a_fatfs, a_fs_meta, a_dentry, a_inum);
    case EXFATFS_DIR_ENTRY_TYPE_FILE_STREAM:
    case EXFATFS_DIR_ENTRY_TYPE_FILE_STREAM_DELETED:
        return exfatfs_copy_file_stream_dinode(a_fatfs, a_fs_meta, a_dentry, a_inum);
    case EXFATFS_DIR_ENTRY_TYPE_FILE_NAME:
    case EXFATFS_DIR_ENTRY_TYPE_FILE_NAME_DELETED:
        return exfatfs_copy_file_name_dinode(a_fatfs, a_fs_meta, a_dentry, a_inum);
    default:
        return TSK_ERR;
    }

    return TSK_OK;
}

