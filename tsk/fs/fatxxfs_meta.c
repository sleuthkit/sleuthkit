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
#include <assert.h>

/*
 * Identify if the dentry is a valid 8.3 name
 *
 * returns 1 if it is, 0 if it does not
 */
static uint8_t
is_83_name(FATXXFS_DENTRY * de)
{
    if (!de)
        return 0;

    /* The IS_NAME macro will fail if the value is 0x05, which is only
     * valid in name[0], similarly with '.' */
    if ((de->name[0] != FATXXFS_SLOT_E5) && (de->name[0] != '.') &&
        (FATXXFS_IS_83_NAME(de->name[0]) == 0)) {
        if (tsk_verbose)
            fprintf(stderr, "fatfs_is_83_name: name[0] is invalid\n");
        return 0;
    }

    // the name cannot start with 0x20
    else if (de->name[0] == 0x20) {
        if (tsk_verbose)
            fprintf(stderr, "fatfs_is_83_name: name[0] has 0x20\n");
        return 0;
    }

    /* the second name field can only be . if the first one is a . */
    if (de->name[1] == '.') {
        if (de->name[0] != '.') {
            if (tsk_verbose)
                fprintf(stderr, "fatfs_is_83_name: name[1] is .\n");
            return 0;
        }
    }
    else if (FATXXFS_IS_83_NAME(de->name[1]) == 0) {
        if (tsk_verbose)
            fprintf(stderr, "fatfs_is_83_name: name[1] is invalid\n");
        return 0;
    }

    if (FATXXFS_IS_83_NAME(de->name[2]) == 0) {
        if (tsk_verbose)
            fprintf(stderr, "fatfs_is_83_name: name[2] is invalid\n");
        return 0;
    }
    else if (FATXXFS_IS_83_NAME(de->name[3]) == 0) {
        if (tsk_verbose)
            fprintf(stderr, "fatfs_is_83_name: name[3] is invalid\n");
        return 0;
    }
    else if (FATXXFS_IS_83_NAME(de->name[4]) == 0) {
        if (tsk_verbose)
            fprintf(stderr, "fatfs_is_83_name: name[4] is invalid\n");
        return 0;
    }
    else if (FATXXFS_IS_83_NAME(de->name[5]) == 0) {
        if (tsk_verbose)
            fprintf(stderr, "fatfs_is_83_name: name[5] is invalid\n");
        return 0;
    }
    else if (FATXXFS_IS_83_NAME(de->name[6]) == 0) {
        if (tsk_verbose)
            fprintf(stderr, "fatfs_is_83_name: name[6] is invalid\n");
        return 0;
    }
    else if (FATXXFS_IS_83_NAME(de->name[7]) == 0) {
        if (tsk_verbose)
            fprintf(stderr, "fatfs_is_83_name: name[7] is invalid\n");
        return 0;
    }
    else if (FATXXFS_IS_83_NAME(de->ext[0]) == 0) {
        if (tsk_verbose)
            fprintf(stderr, "fatfs_is_83_name: ext[0] is invalid\n");
        return 0;
    }
    else if (FATXXFS_IS_83_NAME(de->ext[1]) == 0) {
        if (tsk_verbose)
            fprintf(stderr, "fatfs_is_83_name: ext[1] is invalid\n");
        return 0;
    }
    else if (FATXXFS_IS_83_NAME(de->ext[2]) == 0) {
        if (tsk_verbose)
            fprintf(stderr, "fatfs_is_83_name: ext[2] is invalid\n");
        return 0;
    }

    /* Ensure that if we get a "space", that the rest of the
     * name is spaces.  This is not in the spec, but is how
     * windows operates and serves as a good check to remove
     * false positives.  We do not do this check for the
     * volume label though. */
    if ((de->attrib & FATFS_ATTR_VOLUME) != FATFS_ATTR_VOLUME) {
        if (((de->name[1] == 0x20) && (de->name[2] != 0x20)) ||
            ((de->name[2] == 0x20) && (de->name[3] != 0x20)) ||
            ((de->name[3] == 0x20) && (de->name[4] != 0x20)) ||
            ((de->name[4] == 0x20) && (de->name[5] != 0x20)) ||
            ((de->name[5] == 0x20) && (de->name[6] != 0x20)) ||
            ((de->name[6] == 0x20) && (de->name[7] != 0x20)) ||
            ((de->ext[1] == 0x20) && (de->ext[2] != 0x20))) {
            if (tsk_verbose)
                fprintf(stderr,
                    "fatfs_is_83_name: space before non-space\n");
            return 0;
        }
    }

    return 1;
}

/**
 * \internal
 * Determine whether a buffer likely contains a directory entry.
 * For the most reliable results, request the in-depth test.
 *
 * @param [in] a_fatfs Source file system for the directory entry.
 * @param [in] a_dentry Buffer that may contain a directory entry.
 * @param [in] a_cluster_is_alloc The allocation status, possibly unknown, of the 
 * cluster from which the buffer was filled. 
 * @param [in] a_do_basic_tests_only Whether to do basic or in-depth testing. 
 * @return 1 if the buffer likely contains a directory entry, 0 otherwise
 */
uint8_t
fatxxfs_is_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_dentry, FATFS_DATA_UNIT_ALLOC_STATUS_ENUM a_cluster_is_alloc, uint8_t a_do_basic_tests_only)
{
    const char *func_name = "fatxxfs_is_dentry";
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & a_fatfs->fs_info;
    FATXXFS_DENTRY *dentry = (FATXXFS_DENTRY*)a_dentry;

    if (!a_dentry)
        return 0;

    /* LFN have their own checks, which are pretty weak since most
     * fields are UTF16 */
    if ((dentry->attrib & FATFS_ATTR_LFN) == FATFS_ATTR_LFN) {
        FATXXFS_DENTRY_LFN *de_lfn = (FATXXFS_DENTRY_LFN*) dentry;

        if ((de_lfn->seq > (FATXXFS_LFN_SEQ_FIRST | 0x0f))
            && (de_lfn->seq != FATXXFS_SLOT_DELETED)) {
            if (tsk_verbose)
                fprintf(stderr, "%s: LFN seq\n", func_name);
            return 0;
        }

        return 1;
    }
    else {
        // the basic test is only for the 'essential data'.
        if (a_do_basic_tests_only == 0) {
            if (dentry->lowercase & ~(FATXXFS_CASE_LOWER_ALL)) {
                if (tsk_verbose)
                    fprintf(stderr, "%s: lower case all\n", func_name);
                return 0;
            }
            else if (dentry->attrib & ~(FATFS_ATTR_ALL)) {
                if (tsk_verbose)
                    fprintf(stderr, "%s: attribute all\n", func_name);
                return 0;
            }

            // verify we do not have too many flags set
            if (dentry->attrib & FATFS_ATTR_VOLUME) {
                if ((dentry->attrib & FATFS_ATTR_DIRECTORY) ||
                    (dentry->attrib & FATFS_ATTR_READONLY) ||
                    (dentry->attrib & FATFS_ATTR_ARCHIVE)) {
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
            if ((tsk_getu16(fs->endian, dentry->ctime) != 0) &&
                (FATFS_ISTIME(tsk_getu16(fs->endian, dentry->ctime)) == 0)) {
                if (tsk_verbose)
                    fprintf(stderr, "%s: ctime\n", func_name);
                return 0;
            }
            else if ((tsk_getu16(fs->endian, dentry->wtime) != 0) &&
                (FATFS_ISTIME(tsk_getu16(fs->endian, dentry->wtime)) == 0)) {
                if (tsk_verbose)
                    fprintf(stderr, "%s: wtime\n", func_name);
                return 0;
            }
            else if ((tsk_getu16(fs->endian, dentry->cdate) != 0) &&
                ((FATFS_ISDATE(tsk_getu16(fs->endian, dentry->cdate)) == 0) ||
                    (fatfs_dos_2_unix_time(tsk_getu16(fs->endian, dentry->cdate),
                            tsk_getu16(fs->endian, dentry->ctime),
                            dentry->ctimeten) == 0))) {
                if (tsk_verbose)
                    fprintf(stderr, "%s: cdate\n", func_name);
                return 0;
            }
            else if (dentry->ctimeten > 200) {
                if (tsk_verbose)
                    fprintf(stderr, "%s: ctimeten\n", func_name);
                return 0;
            }
            else if ((tsk_getu16(fs->endian, dentry->adate) != 0) &&
                ((FATFS_ISDATE(tsk_getu16(fs->endian, dentry->adate)) == 0) ||
                    (fatfs_dos_2_unix_time(tsk_getu16(fs->endian, dentry->adate),
                            0, 0) == 0))) {
                if (tsk_verbose)
                    fprintf(stderr, "%s: adate\n", func_name);
                return 0;
            }
            else if ((tsk_getu16(fs->endian, dentry->wdate) != 0) &&
                ((FATFS_ISDATE(tsk_getu16(fs->endian, dentry->wdate)) == 0) ||
                    (fatfs_dos_2_unix_time(tsk_getu16(fs->endian, dentry->wdate),
                            tsk_getu16(fs->endian, dentry->wtime), 0) == 0))) {
                if (tsk_verbose)
                    fprintf(stderr, "%s: wdate\n", func_name);
                return 0;
            }
        }

        /* verify the starting cluster is small enough */
        if ((FATXXFS_DENTRY_CLUST(fs, dentry) > (a_fatfs->lastclust)) &&
            (FATFS_ISEOF(FATXXFS_DENTRY_CLUST(fs, dentry), a_fatfs->mask) == 0)) {
            if (tsk_verbose)
                fprintf(stderr, "%s: start cluster\n", func_name);
            return 0;
        }

        /* Verify the file size is smaller than the data area */
        else if (tsk_getu32(fs->endian, dentry->size) >
            ((a_fatfs->clustcnt * a_fatfs->csize) << a_fatfs->ssize_sh)) {
            if (tsk_verbose)
                fprintf(stderr, "%s: size\n", func_name);
            return 0;
        }

        else if ((tsk_getu32(fs->endian, dentry->size) > 0)
            && (FATXXFS_DENTRY_CLUST(fs, dentry) == 0)) {
            if (tsk_verbose)
                fprintf(stderr,
                    "%s: non-zero size and NULL starting cluster\n", func_name);
            return 0;
        }
		
		else if((a_fatfs->subtype == TSK_FATFS_SUBTYPE_SPEC) && (is_83_name(dentry) == 0))
			return 0;

        // basic sanity check on values
        else if ((tsk_getu16(fs->endian, dentry->ctime) == 0)
            && (tsk_getu16(fs->endian, dentry->wtime) == 0)
            && (tsk_getu16(fs->endian, dentry->cdate) == 0)
            && (tsk_getu16(fs->endian, dentry->adate) == 0)
            && (tsk_getu16(fs->endian, dentry->wdate) == 0)
            && (FATXXFS_DENTRY_CLUST(fs, dentry) == 0)
            && (tsk_getu32(fs->endian, dentry->size) == 0)) {
            if (tsk_verbose)
                fprintf(stderr,
                    "%s: nearly all values zero\n", func_name);
            return 0;
        }

        return 1;
    }
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
fatxxfs_dinode_copy(FATFS_INFO *a_fatfs, TSK_INUM_T a_inum, 
    FATFS_DENTRY *a_dentry, uint8_t a_cluster_is_alloc, TSK_FS_FILE *a_fs_file)
{
    const char *func_name = "fatxxfs_dinode_copy";
    int i;
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & a_fatfs->fs_info;
    TSK_FS_META *fs_meta = a_fs_file->meta;
    FATXXFS_DENTRY *dentry = (FATXXFS_DENTRY*)a_dentry;
    TSK_DADDR_T *addr_ptr;
    uint32_t flags = 0;

    if (fs_meta->content_len < FATFS_FILE_CONTENT_LEN) {
        if ((fs_meta =
                tsk_fs_meta_realloc(fs_meta,
                    FATFS_FILE_CONTENT_LEN)) == NULL) {
            return TSK_ERR;
        }
    }

    fs_meta->attr_state = TSK_FS_META_ATTR_EMPTY;
    if (fs_meta->attr) {
        tsk_fs_attrlist_markunused(fs_meta->attr);
    }

    fs_meta->mode = (TSK_FS_META_MODE_ENUM)attr2mode(dentry->attrib);
    fs_meta->type = attr2type(dentry->attrib);

    fs_meta->addr = a_inum;

    if (a_cluster_is_alloc) {
		if(FATXXFS_IS_DELETED(dentry->name, a_fatfs)){
			flags = TSK_FS_META_FLAG_UNALLOC;
		}
		else{
			flags = TSK_FS_META_FLAG_ALLOC;
		}
    }
    else {
        flags = TSK_FS_META_FLAG_UNALLOC;
    }

    flags |= (dentry->name[0] == FATXXFS_SLOT_EMPTY ?
              TSK_FS_META_FLAG_UNUSED : TSK_FS_META_FLAG_USED);

    fs_meta->flags = (TSK_FS_META_FLAG_ENUM)flags;

    if ((dentry->attrib & FATFS_ATTR_LFN) == FATFS_ATTR_LFN) {
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
		if(FATXXFS_IS_DELETED(dentry->name, a_fatfs)){
			fs_meta->nlink = 0;
		}
		else{
			fs_meta->nlink = 1;
		}
        fs_meta->size = (TSK_OFF_T) tsk_getu32(fs->endian, dentry->size);

        /* If these are valid dates, then convert to a unix date format */
        if (FATFS_ISDATE(tsk_getu16(fs->endian, dentry->wdate)))
            fs_meta->mtime =
                fatfs_dos_2_unix_time(tsk_getu16(fs->endian, dentry->wdate),
                tsk_getu16(fs->endian, dentry->wtime), 0);
        else
            fs_meta->mtime = 0;
        fs_meta->mtime_nano = 0;

        if (FATFS_ISDATE(tsk_getu16(fs->endian, dentry->adate)))
            fs_meta->atime =
                fatfs_dos_2_unix_time(tsk_getu16(fs->endian, dentry->adate), 0, 0);
        else
            fs_meta->atime = 0;
        fs_meta->atime_nano = 0;


        /* cdate is the creation date in FAT and there is no change,
         * so we just put in into change and set create to 0.  The other
         * front-end code knows how to handle it and display it
         */
        if (FATFS_ISDATE(tsk_getu16(fs->endian, dentry->cdate))) {
            fs_meta->crtime =
                fatfs_dos_2_unix_time(tsk_getu16(fs->endian, dentry->cdate),
                tsk_getu16(fs->endian, dentry->ctime), dentry->ctimeten);
            fs_meta->crtime_nano = fatfs_dos_2_nanosec(dentry->ctimeten);
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
    if ((dentry->attrib & FATFS_ATTR_LFN) == FATFS_ATTR_LFN) {
        FATXXFS_DENTRY_LFN *lfn = (FATXXFS_DENTRY_LFN *) dentry;

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
    /* If the entry is for a volume label, then copy the label.
     */
    else if ((dentry->attrib & FATFS_ATTR_VOLUME) == FATFS_ATTR_VOLUME) {
        int a;

        i = 0;
        for (a = 0; a < 8; a++) {
            if ((dentry->name[a] != 0x00) && (dentry->name[a] != 0xff))
                fs_meta->name2->name[i++] = dentry->name[a];
        }
        for (a = 0; a < 3; a++) {
            if ((dentry->ext[a] != 0x00) && (dentry->ext[a] != 0xff))
                fs_meta->name2->name[i++] = dentry->ext[a];
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
        for (i = 0; (i < 8) && (dentry->name[i] != 0) && (dentry->name[i] != ' ');
            i++) {
            if ((i == 0) && (dentry->name[0] == FATXXFS_SLOT_DELETED))
                fs_meta->name2->name[0] = '_';
            else if ((dentry->lowercase & FATXXFS_CASE_LOWER_BASE) &&
                (dentry->name[i] >= 'A') && (dentry->name[i] <= 'Z'))
                fs_meta->name2->name[i] = dentry->name[i] + 32;
            else
                fs_meta->name2->name[i] = dentry->name[i];
        }

        if ((dentry->ext[0]) && (dentry->ext[0] != ' ')) {
            int a;
            fs_meta->name2->name[i++] = '.';
            for (a = 0;
                (a < 3) && (dentry->ext[a] != 0) && (dentry->ext[a] != ' ');
                a++, i++) {
                if ((dentry->lowercase & FATXXFS_CASE_LOWER_EXT)
                    && (dentry->ext[a] >= 'A') && (dentry->ext[a] <= 'Z'))
                    fs_meta->name2->name[i] = dentry->ext[a] + 32;
                else
                    fs_meta->name2->name[i] = dentry->ext[a];
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
    if ((dentry->attrib & FATFS_ATTR_LFN) == FATFS_ATTR_LFN) {
        addr_ptr[0] = 0;
    }
    else {
        addr_ptr[0] = FATXXFS_DENTRY_CLUST(fs, dentry) & a_fatfs->mask;
    }

    /* FAT does not store a size for its directories so make one based
     * on the number of allocated sectors
     */
    if ((dentry->attrib & FATFS_ATTR_DIRECTORY) &&
        ((dentry->attrib & FATFS_ATTR_LFN) != FATFS_ATTR_LFN)) {
        if (fs_meta->flags & TSK_FS_META_FLAG_ALLOC) {
            TSK_LIST *list_seen = NULL;

            /* count the total number of clusters in this file */
            TSK_DADDR_T clust = FATXXFS_DENTRY_CLUST(fs, dentry);
            int cnum = 0;

            while ((clust) && (0 == FATFS_ISEOF(clust, a_fatfs->mask))) {
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

                if (fatfs_getFAT(a_fatfs, clust, &nxt))
                    break;
                else
                    clust = nxt;
            }

            tsk_list_free(list_seen);
            list_seen = NULL;

            fs_meta->size =
                (TSK_OFF_T) ((cnum * a_fatfs->csize) << a_fatfs->ssize_sh);
        }
        /* if the dir is unallocated, then assume 0 or cluster size
         * Ideally, we would have a smart algo here to do recovery
         * and look for dentries.  However, we do not have that right
         * now and if we do not add this special check then it can
         * assume that an allocated file cluster chain belongs to the
         * directory */
        else {
            // if the first cluster is allocated, then set size to be 0
            if (fatxxfs_is_cluster_alloc(a_fatfs, FATXXFS_DENTRY_CLUST(fs,
                        dentry)) == 1)
                fs_meta->size = 0;
            else
                fs_meta->size = a_fatfs->csize << a_fatfs->ssize_sh;
        }
    }

    return TSK_OK;
}

/**
 * \internal
 * Populate the TSK_FS_META object of a TSK_FS_FILE object for a 
 * given inode address.
 *
 * @param [in] a_fs File system that contains the inode.
 * @param [out] a_fs_file The file corresponding to the inode.
 * @param [in] a_inum The inode address.
 * @returns 1 if an error occurs or if the inode address is not
 * for a valid inode, 0 otherwise.
 */
uint8_t
fatxxfs_inode_lookup(FATFS_INFO *a_fatfs, TSK_FS_FILE *a_fs_file,
    TSK_INUM_T a_inum)
{
    const char *func_name = "fatxxfs_inode_lookup";
    TSK_DADDR_T sector = 0;
    int8_t ret_val = 0;
    FATFS_DATA_UNIT_ALLOC_STATUS_ENUM sector_alloc_status = FATFS_DATA_UNIT_ALLOC_STATUS_UNKNOWN;
    FATFS_DENTRY dentry;
    TSK_RETVAL_ENUM copy_result = TSK_OK;

    tsk_error_reset();
    if (fatfs_ptr_arg_is_null(a_fatfs, "a_fatfs", func_name) ||
        fatfs_ptr_arg_is_null(a_fs_file, "a_fs_file", func_name) ||
        !fatfs_inum_arg_is_in_range(a_fatfs, a_inum, func_name)) {
        return 1;
    }

    sector = FATFS_INODE_2_SECT(a_fatfs, a_inum);
    if (sector > a_fatfs->fs_info.last_block) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_INODE_NUM);
        tsk_error_set_errstr("%s: Inode %" PRIuINUM
            " in sector too big for image: %" PRIuDADDR, func_name, a_inum, sector);
        return 1;
    }

    if (fatfs_dentry_load(a_fatfs, &dentry, a_inum) != 0) {
        return 1;
    }

    ret_val = fatfs_is_sectalloc(a_fatfs, sector);
    if (ret_val == -1) {
        return 1;
    }
    else {
        sector_alloc_status = (FATFS_DATA_UNIT_ALLOC_STATUS_ENUM)ret_val;
    }

    /* Note that only the sector allocation status is used to choose
     * between the basic or in-depth version of the inode validity 
     * test. In other places in the code information about whether or not 
     * the sector that contains the inode is part of a folder is used to 
     * make this decision. Here, that information is not available. Thus, 
     * the test here is less reliable and may result in some false 
     * positives. */
    if (!fatxxfs_is_dentry(a_fatfs, &dentry, sector_alloc_status, sector_alloc_status)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_INODE_NUM);
        tsk_error_set_errstr("%s: %" PRIuINUM
            " is not an inode", func_name, a_inum);
        return 1;
    }

    copy_result = fatxxfs_dinode_copy(a_fatfs, a_inum, &dentry, (uint8_t)sector_alloc_status, a_fs_file);
    if (copy_result == TSK_OK) {
        return 0;
    }
    else if (copy_result == TSK_COR) {
        /* If there was a Unicode conversion error,
         * then still return the inode. */
        if (tsk_verbose) {
            tsk_error_print(stderr);
        }
        tsk_error_reset();
        return 0;
    }
    else {
        return 1;
    }
}

/**
 * Output the file attributes of an exFAT file directory entry in 
 * human-readable form.
 *
 * @param a_fatfs Source file system for the directory entry.
 * @param a_inum Inode address associated with the directory entry.
 * @param a_hFile Handle of the file to which to write.
 * @return 0 on success, 1 on failure, per TSK convention
 */
uint8_t
fatxxfs_istat_attr_flags(FATFS_INFO *a_fatfs, TSK_INUM_T a_inum, FILE *a_hFile)
{
    const char *func_name = "fatxxfs_istat_attr_flags";
    FATXXFS_DENTRY dentry;

    tsk_error_reset();
    if (fatfs_ptr_arg_is_null(a_fatfs, "a_fatfs", func_name) ||
        fatfs_ptr_arg_is_null(a_hFile, "a_hFile", func_name) ||
        !fatfs_inum_arg_is_in_range(a_fatfs, a_inum, func_name)) {
        return 1; 
    }

    if (fatfs_dentry_load(a_fatfs, (FATFS_DENTRY*)(&dentry), a_inum)) {
        return 1; 
    }

    if ((dentry.attrib & FATFS_ATTR_LFN) == FATFS_ATTR_LFN) {
        tsk_fprintf(a_hFile, "Long File Name\n");
    }
    else {
        if (dentry.attrib & FATFS_ATTR_DIRECTORY)
            tsk_fprintf(a_hFile, "Directory");
        else if (dentry.attrib & FATFS_ATTR_VOLUME)
            tsk_fprintf(a_hFile, "Volume Label");
        else
            tsk_fprintf(a_hFile, "File");

        if (dentry.attrib & FATFS_ATTR_READONLY)
            tsk_fprintf(a_hFile, ", Read Only");
        if (dentry.attrib & FATFS_ATTR_HIDDEN)
            tsk_fprintf(a_hFile, ", Hidden");
        if (dentry.attrib & FATFS_ATTR_SYSTEM)
            tsk_fprintf(a_hFile, ", System");
        if (dentry.attrib & FATFS_ATTR_ARCHIVE)
            tsk_fprintf(a_hFile, ", Archive");

        tsk_fprintf(a_hFile, "\n");
    }

    return 0;
}

uint8_t
fatxxfs_inode_walk_should_skip_dentry(FATFS_INFO *a_fatfs, TSK_INUM_T a_inum, 
    FATFS_DENTRY *a_dentry, unsigned int a_selection_flags, 
    int a_cluster_is_alloc)
{
    const char *func_name = "fatxxfs_inode_walk_should_skip_dentry";
    FATXXFS_DENTRY *dentry = (FATXXFS_DENTRY*)a_dentry;
    unsigned int dentry_flags = 0;

    assert(a_fatfs != NULL);
    assert(fatfs_inum_is_in_range(a_fatfs, a_inum));
    assert(a_dentry != NULL);

    tsk_error_reset();
    if (fatfs_ptr_arg_is_null(a_fatfs, "a_fatfs", func_name) ||
        !fatfs_inum_arg_is_in_range(a_fatfs, a_inum, func_name) ||
        fatfs_ptr_arg_is_null(a_dentry, "a_dentry", func_name)) {
        return 1; 
    }

    /* If this is a long file name entry, then skip it and
     * wait for the short name. */
    if ((dentry->attrib & FATFS_ATTR_LFN) == FATFS_ATTR_LFN) {
        return 1;
    }

    /* Skip the "." and ".." entries because they are redundant. */
    if (((dentry->attrib & FATFS_ATTR_DIRECTORY) == FATFS_ATTR_DIRECTORY) &&
         (dentry->name[0] == '.')) {
        return 1;
    }

    /* Compare directory entry allocation status with the inode selection
     * flags. Allocation status is determined first by the allocation status 
     * of the sector that contains the entry, then by the deleted status of 
     * the file. This is necessary because when a directory is deleted, its 
     * contents are not always marked as unallocated. */
    if (a_cluster_is_alloc == 1) {
		if(FATXXFS_IS_DELETED(dentry->name, a_fatfs)){
			dentry_flags = TSK_FS_META_FLAG_UNALLOC;
		}
		else{
			dentry_flags = TSK_FS_META_FLAG_ALLOC;
		}
    }
    else {
        dentry_flags = TSK_FS_META_FLAG_UNALLOC;
    }

    if ((a_selection_flags & dentry_flags) != dentry_flags) {
        return 1;
    }

    /* If the processing flags call for only processing orphan files, check 
     * whether or not this inode is in list of non-orphan files found via name
     * walk. */
    if ((dentry_flags & TSK_FS_META_FLAG_UNALLOC) &&
        (a_selection_flags & TSK_FS_META_FLAG_ORPHAN) &&
        (tsk_fs_dir_find_inum_named(&(a_fatfs->fs_info), a_inum))) {
        return 1;
    }

    return 0;
}
