/*
** ifind (inode find)
** The Sleuth Kit
**
** Given an image  and block number, identify which inode it is used by
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2006-2011 Brian Carrier, Basis Technology.  All Rights reserved
** Copyright (c) 2003-2005 Brian Carrier.  All rights reserved
**
** TASK
** Copyright (c) 2002 Brian Carrier, @stake Inc.  All rights reserved
**
** TCTUTILs
** Copyright (c) 2001 Brian Carrier.  All rights reserved
**
**
** This software is distributed under the Common Public License 1.0
**
*/

/**
 * \file ifind_lib.c
 * Contains the library API functions used by the TSK ifind command
 * line tool.
 */

#include "tsk_fs_i.h"
#include "tsk_hfs.h"


/*******************************************************************************
 * Find an unallocated NTFS MFT entry based on its parent directory
 */

typedef struct {
    TSK_INUM_T parinode;
    TSK_FS_IFIND_FLAG_ENUM flags;
    uint8_t found;
} IFIND_PAR_DATA;


/* inode walk call back for tsk_fs_ifind_par to find unallocated files
 * based on parent directory
 */
static TSK_WALK_RET_ENUM
ifind_par_act(TSK_FS_FILE * fs_file, void *ptr)
{
    IFIND_PAR_DATA *data = (IFIND_PAR_DATA *) ptr;
    TSK_FS_META_NAME_LIST *fs_name_list;

    /* go through each file name attribute for this file */
    fs_name_list = fs_file->meta->name2;
    while (fs_name_list) {

        /* we found a file that has the target parent directory.
         * Make a FS_NAME structure and print it.  */
        if (fs_name_list->par_inode == data->parinode) {
            int i, cnt;
            uint8_t printed;
            TSK_FS_NAME *fs_name;

            if ((fs_name = tsk_fs_name_alloc(256, 0)) == NULL)
                return TSK_WALK_ERROR;

            /* Fill in the basics of the fs_name entry
             * so we can print in the fls formats */
            fs_name->meta_addr = fs_file->meta->addr;
            fs_name->flags = TSK_FS_NAME_FLAG_UNALLOC;
            strncpy(fs_name->name, fs_name_list->name, fs_name->name_size);

            // now look for the $Data and $IDXROOT attributes
            fs_file->name = fs_name;
            printed = 0;

            // cycle through the attributes
            cnt = tsk_fs_file_attr_getsize(fs_file);
            for (i = 0; i < cnt; i++) {
                const TSK_FS_ATTR *fs_attr =
                    tsk_fs_file_attr_get_idx(fs_file, i);
                if (!fs_attr)
                    continue;

                if ((fs_attr->type == TSK_FS_ATTR_TYPE_NTFS_DATA)
                    || (fs_attr->type == TSK_FS_ATTR_TYPE_NTFS_IDXROOT)) {

                    if (data->flags & TSK_FS_IFIND_PAR_LONG) {
                        tsk_fs_name_print_long(stdout, fs_file, NULL,
                            fs_file->fs_info, fs_attr, 0, 0);
                        tsk_printf("\n");
                    }
                    else {
                        tsk_fs_name_print(stdout, fs_file, NULL,
                            fs_file->fs_info, fs_attr, 0);
                        tsk_printf("\n");
                    }
                    printed = 1;
                }
            }

            // if there were no attributes, print what we got
            if (printed == 0) {
                if (data->flags & TSK_FS_IFIND_PAR_LONG) {
                    tsk_fs_name_print_long(stdout, fs_file, NULL,
                        fs_file->fs_info, NULL, 0, 0);
                    tsk_printf("\n");
                }
                else {
                    tsk_fs_name_print(stdout, fs_file, NULL,
                        fs_file->fs_info, NULL, 0);
                    tsk_printf("\n");
                }
            }
            tsk_fs_name_free(fs_name);
            data->found = 1;
        }
        fs_name_list = fs_name_list->next;
    }

    return TSK_WALK_CONT;
}



/**
 * Searches for unallocated MFT entries that have a given
 * MFT entry as their parent directory (as reported in FILE_NAME).
 * @param fs File system to search
 * @param lclflags Flags
 * @param par Parent directory MFT entry address
 * @returns 1 on error and 0 on success
 */
uint8_t
tsk_fs_ifind_par(TSK_FS_INFO * fs, TSK_FS_IFIND_FLAG_ENUM lclflags,
    TSK_INUM_T par)
{
    IFIND_PAR_DATA data;

    data.found = 0;
    data.flags = lclflags;
    data.parinode = par;

    /* Walk unallocated MFT entries */
    if (fs->inode_walk(fs, fs->first_inum, fs->last_inum,
            TSK_FS_META_FLAG_UNALLOC, ifind_par_act, &data)) {
        return 1;
    }

    return 0;
}




/**
 * \ingroup fslib
 *
 * Find the meta data address for a given file name (UTF-8).
 * The basic idea of the function is to break the given name into its
 * subdirectories and start looking for each (starting in the root
 * directory).
 *
 * @param a_fs FS to analyze
 * @param a_path UTF-8 path of file to search for
 * @param [out] a_result Meta data address of file
 * @param [out] a_fs_name Copy of name details (or NULL if details not wanted)
 * @returns -1 on (system) error, 0 if found, and 1 if not found
 */
int8_t
tsk_fs_path2inum(TSK_FS_INFO * a_fs, const char *a_path,
    TSK_INUM_T * a_result, TSK_FS_NAME * a_fs_name)
{
    char *cpath;
    size_t clen;
    char *cur_dir;              // The "current" directory or file we are looking for
    char *cur_attr;             // The "current" attribute of the dir we are looking for
    TSK_INUM_T next_meta;
    uint8_t is_done;
    char *strtok_last;
    *a_result = 0;

    // copy path to a buffer that we can modify
    clen = strlen(a_path) + 1;
    if ((cpath = (char *) tsk_malloc(clen)) == NULL) {
        return -1;
    }
    strncpy(cpath, a_path, clen);

    // Get the first part of the directory path.
    cur_dir = (char *) strtok_r(cpath, "/", &strtok_last);
    cur_attr = NULL;

    /* If there is no token, then only a '/' was given */
    if (cur_dir == NULL) {
        free(cpath);
        *a_result = a_fs->root_inum;

        // create the dummy entry if needed
        if (a_fs_name) {
            a_fs_name->meta_addr = a_fs->root_inum;
            // Note that we are not filling in meta_seq -- we could, we just aren't

            a_fs_name->type = TSK_FS_NAME_TYPE_DIR;
            a_fs_name->flags = TSK_FS_NAME_FLAG_ALLOC;
            if (a_fs_name->name)
                a_fs_name->name[0] = '\0';
            if (a_fs_name->shrt_name)
                a_fs_name->shrt_name[0] = '\0';
        }
        return 0;
    }

    /* If this is NTFS, separate out the attribute of the current directory */
    if (TSK_FS_TYPE_ISNTFS(a_fs->ftype)
        && ((cur_attr = strchr(cur_dir, ':')) != NULL)) {
        *(cur_attr) = '\0';
        cur_attr++;
    }

    if (tsk_verbose)
        tsk_fprintf(stderr, "Looking for %s\n", cur_dir);

    // initialize the first place to look, the root dir
    next_meta = a_fs->root_inum;

    // we loop until we know the outcome and then exit.
    // everything should return from inside the loop.
    is_done = 0;
    while (is_done == 0) {
        size_t i;
        TSK_FS_FILE *fs_file_alloc = NULL;      // set to the allocated file that is our target
        TSK_FS_FILE *fs_file_del = NULL;        // set to an unallocated file that matches our criteria

        TSK_FS_DIR *fs_dir = NULL;

        // open the next directory in the recursion
        if ((fs_dir = tsk_fs_dir_open_meta(a_fs, next_meta)) == NULL) {
            free(cpath);
            return -1;
        }

        /* Verify this is indeed a directory.  We had one reported
         * problem where a file was a disk image and opening it as
         * a directory found the directory entries inside of the file
         * and this caused problems... */
        if ( !TSK_FS_IS_DIR_META(fs_dir->fs_file->meta->type)) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_GENFS);
            tsk_error_set_errstr("Address %" PRIuINUM
                " is not for a directory\n", next_meta);
            free(cpath);
            return -1;
        }

        // cycle through each entry
        for (i = 0; i < tsk_fs_dir_getsize(fs_dir); i++) {

            TSK_FS_FILE *fs_file;
            uint8_t found_name = 0;

            if ((fs_file = tsk_fs_dir_get(fs_dir, i)) == NULL) {
                tsk_fs_dir_close(fs_dir);
                free(cpath);
                return -1;
            }

            /*
             * Check if this is the name that we are currently looking for,
             * as identified in 'cur_dir'
             */
            if ((fs_file->name->name)
                && (a_fs->name_cmp(a_fs, fs_file->name->name,
                        cur_dir) == 0)) {
                found_name = 1;
            }
            else if ((fs_file->name->shrt_name)
                && (a_fs->name_cmp(a_fs, fs_file->name->shrt_name,
                        cur_dir) == 0)) {
                found_name = 1;
            }

            /* For NTFS, we have to check the attribute name. */
            if ((found_name == 1) && (TSK_FS_TYPE_ISNTFS(a_fs->ftype))) {
                /*  ensure we have the right attribute name */
                if (cur_attr != NULL) {
                    found_name = 0;
                    if (fs_file->meta) {
                        int cnt, i;

                        // cycle through the attributes
                        cnt = tsk_fs_file_attr_getsize(fs_file);
                        for (i = 0; i < cnt; i++) {
                            const TSK_FS_ATTR *fs_attr =
                                tsk_fs_file_attr_get_idx(fs_file, i);
                            if (!fs_attr)
                                continue;

                            if ((fs_attr->name)
                                && (a_fs->name_cmp(a_fs, fs_attr->name,
                                        cur_attr) == 0)) {
                                found_name = 1;
                                break;
                            }
                        }
                    }
                }
            }

            if (found_name) {
                /* If we found our file and it is allocated, then stop. If
                 * it is unallocated, keep on going to see if we can get
                 * an allocated hit */
                if (fs_file->name->flags & TSK_FS_NAME_FLAG_ALLOC) {
                    fs_file_alloc = fs_file;
                    break;
                }
                else {
                    // if we already have an unalloc and its addr is 0, then use the new one
                    if ((fs_file_del)
                        && (fs_file_del->name->meta_addr == 0)) {
                        tsk_fs_file_close(fs_file_del);
                    }
                    fs_file_del = fs_file;
                }
            }
            // close the file if we did not save it for future analysis.
            else {
                tsk_fs_file_close(fs_file);
                fs_file = NULL;
            }
        }

        // we found a directory, go into it
        if ((fs_file_alloc) || (fs_file_del)) {

            const char *pname;
            TSK_FS_FILE *fs_file_tmp;

            // choose the alloc one first (if they both exist)
            if (fs_file_alloc)
                fs_file_tmp = fs_file_alloc;
            else
                fs_file_tmp = fs_file_del;

            pname = cur_dir;    // save a copy of the current name pointer

            // advance to the next name
            cur_dir = (char *) strtok_r(NULL, "/", &(strtok_last));
            cur_attr = NULL;

            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "Found it (%s), now looking for %s\n", pname, cur_dir);

            /* That was the last name in the path -- we found the file! */
            if (cur_dir == NULL) {
                *a_result = fs_file_tmp->name->meta_addr;

                // make a copy if one was requested
                if (a_fs_name) {
                    tsk_fs_name_copy(a_fs_name, fs_file_tmp->name);
                }

                if (fs_file_alloc)
                    tsk_fs_file_close(fs_file_alloc);
                if (fs_file_del)
                    tsk_fs_file_close(fs_file_del);

                tsk_fs_dir_close(fs_dir);
                free(cpath);
                return 0;
            }

            // update the attribute field, if needed
            if (TSK_FS_TYPE_ISNTFS(a_fs->ftype)
                && ((cur_attr = strchr(cur_dir, ':')) != NULL)) {
                *(cur_attr) = '\0';
                cur_attr++;
            }

            // update the value for the next directory to open
            next_meta = fs_file_tmp->name->meta_addr;

            if (fs_file_alloc) {
                tsk_fs_file_close(fs_file_alloc);
                fs_file_alloc = NULL;
            }
            if (fs_file_del) {
                tsk_fs_file_close(fs_file_del);
                fs_file_del = NULL;
            }
        }

        // no hit in directory
        else {
            is_done = 1;
        }

        tsk_fs_dir_close(fs_dir);
        fs_dir = NULL;
    }

    free(cpath);
    return 1;
}


/**
 * Find the meta data address for a given file TCHAR name
 *
 * @param fs FS to analyze
 * @param tpath Path of file to search for
 * @param [out] result Meta data address of file
 * @returns -1 on error, 0 if found, and 1 if not found
 */
int8_t
tsk_fs_ifind_path(TSK_FS_INFO * fs, TSK_TCHAR * tpath, TSK_INUM_T * result)
{

#ifdef TSK_WIN32
    // Convert the UTF-16 path to UTF-8
    {
        size_t clen;
        UTF8 *ptr8;
        UTF16 *ptr16;
        int retval;
        char *cpath;

        clen = TSTRLEN(tpath) * 4;
        if ((cpath = (char *) tsk_malloc(clen)) == NULL) {
            return -1;
        }
        ptr8 = (UTF8 *) cpath;
        ptr16 = (UTF16 *) tpath;

        retval =
            tsk_UTF16toUTF8_lclorder((const UTF16 **) &ptr16, (UTF16 *)
            & ptr16[TSTRLEN(tpath) + 1], &ptr8,
            (UTF8 *) ((uintptr_t) ptr8 + clen), TSKlenientConversion);
        if (retval != TSKconversionOK) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_UNICODE);
            tsk_error_set_errstr
                ("tsk_fs_ifind_path: Error converting path to UTF-8: %d",
                retval);
            free(cpath);
            return -1;
        }
        return tsk_fs_path2inum(fs, cpath, result, NULL);
    }
#else
    return tsk_fs_path2inum(fs, (const char *) tpath, result, NULL);
#endif
}






/*******************************************************************************
 * Find an inode given a data unit
 */

typedef struct {
    TSK_DADDR_T block;          /* the block to find */
    TSK_FS_IFIND_FLAG_ENUM flags;
    uint8_t found;

    TSK_INUM_T curinode;        /* the inode being analyzed */
    uint32_t curtype;           /* the type currently being analyzed: NTFS */
    uint16_t curid;
} IFIND_DATA_DATA;


/*
 * file_walk action for non-ntfs
 */
static TSK_WALK_RET_ENUM
ifind_data_file_act(TSK_FS_FILE * fs_file, TSK_OFF_T a_off,
    TSK_DADDR_T addr, char *buf, size_t size, TSK_FS_BLOCK_FLAG_ENUM flags,
    void *ptr)
{
    TSK_FS_INFO *fs = fs_file->fs_info;
    IFIND_DATA_DATA *data = (IFIND_DATA_DATA *) ptr;

    /* Ignore sparse blocks because they do not reside on disk */
    if (flags & TSK_FS_BLOCK_FLAG_SPARSE)
        return TSK_WALK_CONT;

    if (addr == data->block) {
        if (TSK_FS_TYPE_ISNTFS(fs->ftype))
            tsk_printf("%" PRIuINUM "-%" PRIu32 "-%" PRIu16 "\n",
                data->curinode, data->curtype, data->curid);
        else
            tsk_printf("%" PRIuINUM "\n", data->curinode);
        data->found = 1;
        return TSK_WALK_STOP;
    }
    return TSK_WALK_CONT;
}


/*
** find_inode
**
** Callback action for inode_walk
*/
static TSK_WALK_RET_ENUM
ifind_data_act(TSK_FS_FILE * fs_file, void *ptr)
{
    IFIND_DATA_DATA *data = (IFIND_DATA_DATA *) ptr;
    int file_flags =
        (TSK_FS_FILE_WALK_FLAG_AONLY | TSK_FS_FILE_WALK_FLAG_SLACK);
    int i, cnt;

    data->curinode = fs_file->meta->addr;

    /* Search all attributes */
    cnt = tsk_fs_file_attr_getsize(fs_file);
    for (i = 0; i < cnt; i++) {
        const TSK_FS_ATTR *fs_attr = tsk_fs_file_attr_get_idx(fs_file, i);
        if (!fs_attr)
            continue;

        data->curtype = fs_attr->type;
        data->curid = fs_attr->id;
        if (fs_attr->flags & TSK_FS_ATTR_NONRES) {
            if (tsk_fs_attr_walk(fs_attr,
                    file_flags, ifind_data_file_act, ptr)) {
                if (tsk_verbose)
                    tsk_fprintf(stderr,
                        "Error walking file %" PRIuINUM
                        " Attribute: %i", fs_file->meta->addr, i);

                /* Ignore these errors */
                tsk_error_reset();
            }

            // stop if we only want one hit
            if ((data->found) && (!(data->flags & TSK_FS_IFIND_ALL)))
                break;
        }
    }

    if ((data->found) && (!(data->flags & TSK_FS_IFIND_ALL)))
        return TSK_WALK_STOP;
    else
        return TSK_WALK_CONT;
}




/*
 * Find the inode that has allocated block blk
 * Return 1 on error, 0 if no error */
uint8_t
tsk_fs_ifind_data(TSK_FS_INFO * fs, TSK_FS_IFIND_FLAG_ENUM lclflags,
    TSK_DADDR_T blk)
{
    IFIND_DATA_DATA data;

    memset(&data, 0, sizeof(IFIND_DATA_DATA));
    data.flags = lclflags;
    data.block = blk;

    if (fs->inode_walk(fs, fs->first_inum, fs->last_inum,
            TSK_FS_META_FLAG_ALLOC | TSK_FS_META_FLAG_UNALLOC,
            ifind_data_act, &data)) {
        return 1;
    }

    /* If we did not find an inode yet, get the block's
     * flags so we can identify it as a meta data block */
    if (!data.found) {
        TSK_FS_BLOCK *fs_block;

        if ((fs_block = tsk_fs_block_get(fs, NULL, blk)) != NULL) {
            if (fs_block->flags & TSK_FS_BLOCK_FLAG_META) {
                tsk_printf("Meta Data\n");
                data.found = 1;
            }
            tsk_fs_block_free(fs_block);
        }
    }

    if (!data.found) {
        tsk_printf("Inode not found\n");
    }
    return 0;
}
