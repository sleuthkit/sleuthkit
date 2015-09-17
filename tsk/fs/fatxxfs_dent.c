/*
** fatfs_dent
** The Sleuth Kit
**
** file name layer support for the FAT file system
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2006-2013 Brian Carrier, Basis Technology.  All Rights reserved
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
* \file fatfs_dent.cpp
* Contains the internal TSK FAT file name processing code.
*/

#include "tsk_fs_i.h"
#include "tsk_fatxxfs.h"
#include <assert.h>

/* Special data structure allocated for each directory to hold the long
* file name entries until all entries have been found */
typedef struct {
    uint8_t name[FATFS_MAXNAMLEN_UTF8]; /* buffer for lfn - in reverse order */
    uint16_t start;             /* current start of name */
    uint8_t chk;                /* current checksum */
    uint8_t seq;                /* seq of first entry in lfn */
} FATXXFS_LFN;

/**
 * /internal
 * Parse a buffer containing the contents of a directory and add TSK_FS_NAME 
 * objects for each named file found to the TSK_FS_DIR representation of the 
 * directory.
 *
 * @param fatfs File system information structure for file system that
 * contains the directory.
 * @param a_fs_dir Directory structure into to which parsed file metadata will
 * be added.
 * @param buf Buffer that contains the directory contents.
 * @param len Length of buffer in bytes (must be a multiple of sector
*  size).
 * @param addrs Array where each element is the original address of
 * the corresponding sector in a_buf (size of array is number of sectors in
 * the directory).
 * @return TSK_RETVAL_ENUM
*/
TSK_RETVAL_ENUM
fatxxfs_dent_parse_buf(FATFS_INFO *fatfs, TSK_FS_DIR *a_fs_dir, char *buf,
    TSK_OFF_T len, TSK_DADDR_T *addrs)
{
    char *func_name = "fatxxfs_dent_parse_buf";
    unsigned int idx = 0; 
    unsigned int sidx = 0;
    int a = 0;
    int b = 0;
    TSK_INUM_T ibase = 0;
    FATXXFS_DENTRY *dep = NULL;
    TSK_FS_INFO *fs = (TSK_FS_INFO*)&fatfs->fs_info;
    int sectalloc = 0;
    TSK_FS_NAME *fs_name = NULL;
    FATXXFS_LFN lfninfo;
    int entrySeenCount = 0;
    int entryInvalidCount = 0;
    uint8_t isCorruptDir = 0;

    tsk_error_reset();
    if (fatfs_ptr_arg_is_null(fatfs, "fatfs", func_name) ||
        fatfs_ptr_arg_is_null(a_fs_dir, "a_fs_dir", func_name) ||
        fatfs_ptr_arg_is_null(buf, "buf", func_name) ||
        fatfs_ptr_arg_is_null(addrs, "addrs", func_name)) {
        return TSK_ERR; 
    }

    assert(len > 0);
    if (len < 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("%s: invalid buffer length", func_name);
        return TSK_ERR; 
    }

    dep = (FATXXFS_DENTRY*)buf;

    if ((fs_name = tsk_fs_name_alloc(FATFS_MAXNAMLEN_UTF8, 32)) == NULL) {
        return TSK_ERR;
    }

    memset(&lfninfo, 0, sizeof(FATXXFS_LFN));
    lfninfo.start = FATFS_MAXNAMLEN_UTF8 - 1;

    /* Loop through the sectors in the buffer. */ 
    for (sidx = 0; sidx < (unsigned int) (len / fatfs->ssize); sidx++) {

        /* Get the base inode for the current sector */
        ibase = FATFS_SECT_2_INODE(fatfs, addrs[sidx]);
        if (ibase > fs->last_inum) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_ARG);
            tsk_error_set_errstr
                ("fatfs_parse: inode address is too large");
            tsk_fs_name_free(fs_name);
            return TSK_COR;
        }

        if (tsk_verbose)
            tsk_fprintf(stderr,
            "fatfs_dent_parse_buf: Parsing sector %" PRIuDADDR
            " for dir %" PRIuINUM "\n", addrs[sidx], a_fs_dir->addr);

        /* Get the allocation status of the current sector. */
        if ((sectalloc = fatfs_is_sectalloc(fatfs, addrs[sidx])) == -1) {
            if (tsk_verbose) {
                tsk_fprintf(stderr,
                    "fatfs_dent_parse_buf: Error looking up sector allocation: %"
                    PRIuDADDR "\n", addrs[sidx]);
                tsk_error_print(stderr);
            }
            tsk_error_reset();
            continue;
        }

        /* Loop through the putative directory entries in the current sector. */
        for (idx = 0; idx < fatfs->dentry_cnt_se; idx++, dep++) {
            FATXXFS_DENTRY *dir;
            TSK_INUM_T inode;

            entrySeenCount++;

            /* Is the current entry a valid entry? */
            if (0 == fatxxfs_is_dentry(fatfs, (FATFS_DENTRY*)dep, 
                (FATFS_DATA_UNIT_ALLOC_STATUS_ENUM)sectalloc,
                ((isCorruptDir == 0) && (sectalloc)) ? 1 : 0)) {
                    if (tsk_verbose)
                        tsk_fprintf(stderr,
                        "fatfs_dent_parse_buf: Entry %u is invalid\n",
                        idx);
                    entryInvalidCount++;
                    /* If we have seen four entries and all of them are corrupt,
                    * then test every remaining entry in this folder -- 
                    * even if the sector is allocated. The scenario is one
                    * where we are processing a cluster that is allocated
                    * to a file and we happen to get some data that matches
                    * every now and then. */
                    if ((entrySeenCount == 4) && (entryInvalidCount == 4)) {
                        isCorruptDir = 1;
                    }
                    continue;
            }

            dir = dep;

            /* Compute the inode address corresponding to this directory entry. */
            inode = ibase + idx;

            if ((dir->attrib & FATFS_ATTR_LFN) == FATFS_ATTR_LFN) {
                /* The current entry is a long file name entry. */
                FATXXFS_DENTRY_LFN *dirl = (FATXXFS_DENTRY_LFN *) dir;

                /* Store the name in dinfo until we get the 8.3 name
                 * Use the checksum to identify a new sequence. */
                if (((dirl->seq & FATXXFS_LFN_SEQ_FIRST) && (dirl->seq != FATXXFS_SLOT_DELETED)) || 
                    (dirl->chksum != lfninfo.chk)) {
                    // @@@ Do a partial output here
                    
                    /* This is the last long file name entry in a sequence. 
                     * Reset the sequence number, check sum, and next char
                     * address. */
                    lfninfo.seq = dirl->seq & FATXXFS_LFN_SEQ_MASK;
                    lfninfo.chk = dirl->chksum;
                    lfninfo.start = FATFS_MAXNAMLEN_UTF8 - 1;
                }
                else if (dirl->seq != lfninfo.seq - 1) {
                    // @@@ Check the sequence number - the checksum is correct though...
                }

                /* Copy the UTF16 values starting at end of buffer */
                for (a = 3; a >= 0; a--) {
                    if ((lfninfo.start > 0))
                        lfninfo.name[lfninfo.start--] = dirl->part3[a];
                }
                for (a = 11; a >= 0; a--) {
                    if ((lfninfo.start > 0))
                        lfninfo.name[lfninfo.start--] = dirl->part2[a];
                }
                for (a = 9; a >= 0; a--) {
                    if ((lfninfo.start > 0))
                        lfninfo.name[lfninfo.start--] = dirl->part1[a];
                }

                // Skip ahead until we get a new sequence num or the 8.3 name
                continue;
            }
            else if ((dir->attrib & FATFS_ATTR_VOLUME) == FATFS_ATTR_VOLUME) {
                /* Special case for volume label: name does not have an
                * extension and we add a note at the end that it is a label */
                a = 0;

                for (b = 0; b < 8; b++) {
                    if ((dir->name[b] >= 0x20) && (dir->name[b] != 0xff)) {
                        fs_name->name[a++] = dir->name[b];
                    }
                    else {
                        fs_name->name[a++] = '^';
                    }
                }
                for (b = 0; b < 3; b++) {
                    if ((dir->ext[b] >= 0x20) && (dir->ext[b] != 0xff)) {
                        fs_name->name[a++] = dir->ext[b];
                    }
                    else {
                        fs_name->name[a++] = '^';
                    }
                }

                fs_name->name[a] = '\0';
                /* Append a string to show it is a label */
                if (a + 22 < FATFS_MAXNAMLEN_UTF8) {
                    const char *volstr = " (Volume Label Entry)";
                    strncat(fs_name->name, volstr,
                        FATFS_MAXNAMLEN_UTF8 - a);
                }
            }
            else {
                /* A short (8.3) entry */
                char *name_ptr; // The dest location for the short name

                /* if we have a lfn, copy it into fs_name->name
                * and put the short name in fs_name->shrt_name */
                if (lfninfo.start != FATFS_MAXNAMLEN_UTF8 - 1) {
                    int retVal;

                    /* @@@ Check the checksum */

                    /* Convert the UTF16 to UTF8 */
                    UTF16 *name16 =
                        (UTF16 *) ((uintptr_t) & lfninfo.
                        name[lfninfo.start + 1]);
                    UTF8 *name8 = (UTF8 *) fs_name->name;

                    retVal =
                        tsk_UTF16toUTF8(fs->endian,
                        (const UTF16 **) &name16,
                        (UTF16 *) & lfninfo.name[FATFS_MAXNAMLEN_UTF8],
                        &name8,
                        (UTF8 *) ((uintptr_t) name8 +
                        FATFS_MAXNAMLEN_UTF8), TSKlenientConversion);

                    if (retVal != TSKconversionOK) {
                        tsk_error_reset();
                        tsk_error_set_errno(TSK_ERR_FS_UNICODE);
                        tsk_error_set_errstr
                            ("fatfs_parse: Error converting FAT LFN to UTF8: %d",
                            retVal);
                        continue;
                    }

                    /* Make sure it is NULL Terminated */
                    if ((uintptr_t) name8 >
                        (uintptr_t) fs_name->name + FATFS_MAXNAMLEN_UTF8)
                        fs_name->name[FATFS_MAXNAMLEN_UTF8 - 1] = '\0';
                    else
                        *name8 = '\0';

                    lfninfo.start = FATFS_MAXNAMLEN_UTF8 - 1;
                    name_ptr = fs_name->shrt_name;      // put 8.3 into shrt_name
                }
                /* We don't have a LFN, so put the short name in
                * fs_name->name */
                else {
                    fs_name->shrt_name[0] = '\0';
                    name_ptr = fs_name->name;   // put 8.3 into normal location
                }

                /* copy in the short name into the place specified above.
                * Skip spaces and put in the . */
                a = 0;
                for (b = 0; b < 8; b++) {
                    if ((dir->name[b] != 0) && (dir->name[b] != 0xff) &&
                        (dir->name[b] != 0x20)) {

                            if ((b == 0)
                                && (dir->name[0] == FATXXFS_SLOT_DELETED)) {
                                    name_ptr[a++] = '_';
                            }
                            else if ((dir->lowercase & FATXXFS_CASE_LOWER_BASE)
                                && (dir->name[b] >= 'A')
                                && (dir->name[b] <= 'Z')) {
                                    name_ptr[a++] = dir->name[b] + 32;
                            }
                            else {
                                name_ptr[a++] = dir->name[b];
                            }
                    }
                }

                for (b = 0; b < 3; b++) {
                    if ((dir->ext[b] != 0) && (dir->ext[b] != 0xff) &&
                        (dir->ext[b] != 0x20)) {
                            if (b == 0)
                                name_ptr[a++] = '.';
                            if ((dir->lowercase & FATXXFS_CASE_LOWER_EXT) &&
                                (dir->ext[b] >= 'A') && (dir->ext[b] <= 'Z'))
                                name_ptr[a++] = dir->ext[b] + 32;
                            else
                                name_ptr[a++] = dir->ext[b];
                    }
                }
                name_ptr[a] = '\0';

                // make sure that only ASCII is in the short name
                fatfs_cleanup_ascii(name_ptr);
            }

            /* file type: FAT only knows DIR and FILE */
            if ((dir->attrib & FATFS_ATTR_DIRECTORY) ==
                FATFS_ATTR_DIRECTORY)
                fs_name->type = TSK_FS_NAME_TYPE_DIR;
            else
                fs_name->type = TSK_FS_NAME_TYPE_REG;

            /* set the inode */
            fs_name->meta_addr = inode;
            inode = 0;  // so that we don't use it anymore -- use only fs_name->meta_addr

            /* Handle the . and .. entries specially
            * The current inode 'address' they have is for the current
            * slot in the cluster, but it needs to refer to the original
            * slot
            */
            if (TSK_FS_ISDOT(fs_name->name)
                    && (fs_name->type == TSK_FS_NAME_TYPE_DIR)
                    && idx < 2) {
                if (fs_name->name[1] == '\0') {
                    /* Current directory - "." */
                    fs_name->meta_addr =
                        a_fs_dir->fs_file->meta->addr;
                }
                /* for the parent directory, look up in the list that
                * is maintained in fafs_info */
                else if (fs_name->name[1] == '.') {
                    /* Parent directory - ".." */
                    uint8_t dir_found = 0;

                    if (fatfs_dir_buf_get(fatfs, a_fs_dir->fs_file->meta->addr, &(fs_name->meta_addr)) == 0)  {
                        dir_found = 1;
                    }

                    if ((dir_found == 0)
                        && (addrs[0] == fatfs->firstdatasect)) {
                            /* if we are currently in the root directory, we aren't going to find
                            * a parent.  This shouldn't happen, but could result in an infinite loop. */
                            fs_name->meta_addr = 0;
                            dir_found = 1;
                    }
                    if (dir_found == 0) {
                        if (tsk_verbose)
                            fprintf(stderr,
                            "fatfs_dent_parse_buf: Walking directory to find parent\n");

                        /* The parent directory is not in the list.  We are going to walk
                        * the directory until we hit this directory. This process will
                        * populate the buffer table and we will then rescan it */
                        if (tsk_fs_dir_walk(fs, fs->root_inum,
                            (TSK_FS_DIR_WALK_FLAG_ENUM)(TSK_FS_DIR_WALK_FLAG_ALLOC |
                            TSK_FS_DIR_WALK_FLAG_UNALLOC |
                            TSK_FS_DIR_WALK_FLAG_RECURSE),
                            fatfs_find_parent_act,
                            (void *) &a_fs_dir->fs_file->meta->addr)) {
                                return TSK_OK;
                        }

                        if (tsk_verbose)
                            fprintf(stderr,
                            "fatfs_dent_parse_buf: Finished walking directory to find parent\n");

                        if (fatfs_dir_buf_get(fatfs, a_fs_dir->fs_file->meta->addr, &(fs_name->meta_addr)) == 0) {
                            dir_found = 1;
                        }

                        // if we did not find it, then it was probably
                        // from the orphan directory...
                        if (dir_found == 0)
                            fs_name->meta_addr = TSK_FS_ORPHANDIR_INUM(fs);
                    }
                }
            }
            else {
                /* Save the (non-. or ..) directory to parent directory info to local
                * structures so that we can later fill into the inode
                * info for '..' entries */
                if (fs_name->type == TSK_FS_NAME_TYPE_DIR) {
                    if (fatfs_dir_buf_add(fatfs,
                        a_fs_dir->fs_file->meta->addr, fs_name->meta_addr))
                        return TSK_ERR;
                }
            }


            /* The allocation status of an entry is based on the allocation
            * status of the sector it is in and the flag.  Deleted directories
            * do not always clear the flags of each entry
            */
            if (sectalloc == 1) {
				if(FATXXFS_IS_DELETED(dep->name, fatfs)){
						fs_name->flags = TSK_FS_NAME_FLAG_UNALLOC;
				}
				else{
					fs_name->flags = TSK_FS_NAME_FLAG_ALLOC;
				}
            }
            else {
                fs_name->flags = TSK_FS_NAME_FLAG_UNALLOC;
            }

            tsk_fs_dir_add(a_fs_dir, fs_name);
        }
    }
    tsk_fs_name_free(fs_name);

    return TSK_OK;
}
