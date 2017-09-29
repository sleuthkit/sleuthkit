/*
** fls
** The Sleuth Kit
**
** Given an image and directory inode, display the file names and
** directories that exist (both active and deleted)
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2006-2011 Brian Carrier, Basis Technology.  All Rights reserved
** Copyright (c) 2003-2005 Brian Carier.  All rights reserved
**
** TASK
** Copyright (c) 2002 @stake Inc.  All rights reserved
**
** TCTUTILs
** Copyright (c) 2001 Brian Carrier.  All rights reserved
**
**
** This software is distributed under the Common Public License 1.0
**
*/

/** \file fls_lib.c
 * Contains the library code associated with the TSK fls tool to list files in a directory.
 */

#include "tsk_fs_i.h"

/** \internal
* Structure to store data for callbacks.
*/
typedef struct {
    /* Time skew of the system in seconds */
    int32_t sec_skew;

    /*directory prefix for printing mactime output */
    char *macpre;
    int flags;
} FLS_DATA;




/* this is a wrapper type function that takes care of the runtime
 * flags
 *
 * fs_attr should be set to NULL for all non-NTFS file systems
 */
static void
printit(TSK_FS_FILE * fs_file, const char *a_path,
    const TSK_FS_ATTR * fs_attr, const FLS_DATA * fls_data)
{
    TSK_FS_HASH_RESULTS hash_results;

    if ((!(fls_data->flags & TSK_FS_FLS_FULL)) && (a_path)) {
        uint8_t printed = 0;
        unsigned int i;

        // lazy way to find out how many dirs there could be
        for (i = 0; a_path[i] != '\0'; i++) {
            if ((a_path[i] == '/') && (i != 0)) {
                tsk_fprintf(stdout, "+");
                printed = 1;
            }
        }
        if (printed)
            tsk_fprintf(stdout, " ");
    }


    if (fls_data->flags & TSK_FS_FLS_MAC) {
        if (fls_data->flags & TSK_FS_FLS_HASH) {
            if(0 == tsk_fs_file_hash_calc(fs_file, &hash_results,
                TSK_BASE_HASH_MD5)){
				tsk_fs_name_print_mac_md5(stdout, fs_file, a_path, fs_attr,
					fls_data->macpre, fls_data->sec_skew,
					hash_results.md5_digest);
                                tsk_printf("\n");
			}
			else {
	            unsigned char null_buf[16];
				// If the hash calculation had errors, pass in a buffer of nulls
				memset(null_buf, 0, 16);
				tsk_fs_name_print_mac_md5(stdout, fs_file, a_path, fs_attr,
					fls_data->macpre, fls_data->sec_skew,
					null_buf);
                                tsk_printf("\n");
			}
        }
        else {
            tsk_fs_name_print_mac(stdout, fs_file, a_path,
                fs_attr, fls_data->macpre, fls_data->sec_skew);
            tsk_printf("\n");
        }
    }
    else if (fls_data->flags & TSK_FS_FLS_LONG) {
        tsk_fs_name_print_long(stdout, fs_file, a_path, fs_file->fs_info,
            fs_attr, TSK_FS_FLS_FULL & fls_data->flags ? 1 : 0,
            fls_data->sec_skew);
        tsk_printf("\n");
    }
    else {
        tsk_fs_name_print(stdout, fs_file, a_path, fs_file->fs_info,
            fs_attr, TSK_FS_FLS_FULL & fls_data->flags ? 1 : 0);
        tsk_printf("\n");
    }
}


/*
 * call back action function for dent_walk
 */
static TSK_WALK_RET_ENUM
print_dent_act(TSK_FS_FILE * fs_file, const char *a_path, void *ptr)
{
    FLS_DATA *fls_data = (FLS_DATA *) ptr;

    /* only print dirs if TSK_FS_FLS_DIR is set and only print everything
     ** else if TSK_FS_FLS_FILE is set (or we aren't sure what it is)
     */
    if (((fls_data->flags & TSK_FS_FLS_DIR) &&
            ((fs_file->meta) &&
                (TSK_FS_IS_DIR_META(fs_file->meta->type))))
        || ((fls_data->flags & TSK_FS_FLS_FILE) && (((fs_file->meta)
                    && ( ! TSK_FS_IS_DIR_META(fs_file->meta->type)))
                || (!fs_file->meta)))) {


        /* Make a special case for NTFS so we can identify all of the
         * alternate data streams!
         */
        if ((TSK_FS_TYPE_ISNTFS(fs_file->fs_info->ftype))
            && (fs_file->meta)) {
            uint8_t printed = 0;
            int i, cnt;

            // cycle through the attributes
            cnt = tsk_fs_file_attr_getsize(fs_file);
            for (i = 0; i < cnt; i++) {
                const TSK_FS_ATTR *fs_attr =
                    tsk_fs_file_attr_get_idx(fs_file, i);
                if (!fs_attr)
                    continue;

                if (fs_attr->type == TSK_FS_ATTR_TYPE_NTFS_DATA) {
                    printed = 1;

                    if (fs_file->meta->type == TSK_FS_META_TYPE_DIR) {

                        /* we don't want to print the ..:blah stream if
                         * the -a flag was not given
                         */
                        if ((fs_file->name->name[0] == '.')
                            && (fs_file->name->name[1])
                            && (fs_file->name->name[2] == '\0')
                            && ((fls_data->flags & TSK_FS_FLS_DOT) == 0)) {
                            continue;
                        }
                    }

                    printit(fs_file, a_path, fs_attr, fls_data);
                }
                else if (fs_attr->type == TSK_FS_ATTR_TYPE_NTFS_IDXROOT) {
                    printed = 1;

                    /* If it is . or .. only print it if the flags say so,
                     * we continue with other streams though in case the
                     * directory has a data stream
                     */
                    if (!((TSK_FS_ISDOT(fs_file->name->name)) &&
                            ((fls_data->flags & TSK_FS_FLS_DOT) == 0)))
                        printit(fs_file, a_path, fs_attr, fls_data);
                }
                /* Print the FILE_NAME times if this is the same attribute
                 * that we collected the times from. */
                else if ((fs_attr->type == TSK_FS_ATTR_TYPE_NTFS_FNAME) &&
                    (fs_attr->id == fs_file->meta->time2.ntfs.fn_id) &&
                    (fls_data->flags & TSK_FS_FLS_MAC)) {
                    /* If it is . or .. only print it if the flags say so,
                     * we continue with other streams though in case the
                     * directory has a data stream
                     */
                    if (!((TSK_FS_ISDOT(fs_file->name->name)) &&
                            ((fls_data->flags & TSK_FS_FLS_DOT) == 0)))
                        printit(fs_file, a_path, fs_attr, fls_data);
                }
            }

            /* A user reported that an allocated file had the standard
             * attributes, but no $Data.  We should print something */
            if (printed == 0) {
                printit(fs_file, a_path, NULL, fls_data);
            }

        }
        else {
            /* skip it if it is . or .. and we don't want them */
            if (!((TSK_FS_ISDOT(fs_file->name->name))
                    && ((fls_data->flags & TSK_FS_FLS_DOT) == 0)))
                printit(fs_file, a_path, NULL, fls_data);
        }
    }
    return TSK_WALK_CONT;
}


/* Returns 0 on success and 1 on error */
uint8_t
tsk_fs_fls(TSK_FS_INFO * fs, TSK_FS_FLS_FLAG_ENUM lclflags,
    TSK_INUM_T inode, TSK_FS_DIR_WALK_FLAG_ENUM flags, TSK_TCHAR * tpre,
    int32_t skew)
{
    FLS_DATA data;

    data.flags = lclflags;
    data.sec_skew = skew;

#ifdef TSK_WIN32
    {
        UTF8 *ptr8;
        UTF16 *ptr16;
        int retval;

        if ((tpre != NULL) && (TSTRLEN(tpre) > 0)) {
            size_t clen = TSTRLEN(tpre) * 4;
            data.macpre = (char *) tsk_malloc(clen);
            if (data.macpre == NULL) {
                return 1;
            }
            ptr8 = (UTF8 *) data.macpre;
            ptr16 = (UTF16 *) tpre;

            retval =
                tsk_UTF16toUTF8_lclorder((const UTF16 **) &ptr16, (UTF16 *)
                & ptr16[TSTRLEN(tpre) + 1], &ptr8,
                (UTF8 *) ((uintptr_t) ptr8 + clen), TSKlenientConversion);
            if (retval != TSKconversionOK) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_FS_UNICODE);
                tsk_error_set_errstr
                    ("Error converting fls mactime pre-text to UTF-8 %d\n",
                    retval);
                return 1;
            }
        }
        else {
            data.macpre = (char *) tsk_malloc(1);
            if (data.macpre == NULL) {
                return 1;
            }
            data.macpre[0] = '\0';
        }

        retval = tsk_fs_dir_walk(fs, inode, flags, print_dent_act, &data);

        free(data.macpre);
        data.macpre = NULL;
        return retval;
    }
#else
    data.macpre = tpre;
    return tsk_fs_dir_walk(fs, inode, flags, print_dent_act, &data);
#endif
}
