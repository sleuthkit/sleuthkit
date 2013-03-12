/*
 * The Sleuth Kit
 *
 * Copyright (c) 2006-2011 Brian Carrier, Basis Technology.  All Rights reserved
 *
 * LICENSE
 *	This software is distributed under the IBM Public License.
 * AUTHOR(S)
 *	Wietse Venema
 *	IBM T.J. Watson Research
 *	P.O. Box 704
 *	Yorktown Heights, NY 10598, USA
--*/

/**
 * \file fs_inode.c
 * Contains functions to allocate, free, and process the generic inode
 * structures
 */
#include "tsk_fs_i.h"

/**
 * Contains the short (1 character) name of the file type
 */
char tsk_fs_meta_type_str[TSK_FS_META_TYPE_STR_MAX][2] =
    { "-", "r", "d", "p", "c", "b", "l", "s", "h", "w", "v"
};

/**
 * \internal
 * Allocates a generic inode / metadata structure.
 *
 * @param a_buf_len Number of bytes needed to store fs-specific data regarding where content is stored.
 * @returns NULL on error
 */
TSK_FS_META *
tsk_fs_meta_alloc(size_t a_buf_len)
{
    TSK_FS_META *fs_meta;

    if ((fs_meta =
            (TSK_FS_META *) tsk_malloc(sizeof(TSK_FS_META))) == NULL)
        return NULL;

    fs_meta->attr_state = TSK_FS_META_ATTR_EMPTY;

    if (a_buf_len > 0) {
        if ((fs_meta->content_ptr = tsk_malloc(a_buf_len)) == NULL) {
            free(fs_meta);
            return NULL;
        }
        fs_meta->content_len = a_buf_len;
    }

    // assign the id so we know the structure is still alloc
    fs_meta->tag = TSK_FS_META_TAG;

    return (fs_meta);
}


/**
 * \internal
 * Resize an existing TSK_FS_META structure -- changes the number of
 * block pointers. 
 *
 * @param fs_meta Structure to resize
 * @param a_buf_len Size of file system specific data that is used to store references to file content
 * @return NULL on error 
 */
TSK_FS_META *
tsk_fs_meta_realloc(TSK_FS_META * a_fs_meta, size_t a_buf_len)
{
    if (a_fs_meta->content_len != a_buf_len) {
        a_fs_meta->content_len = a_buf_len;
        a_fs_meta->content_ptr =
            tsk_realloc((char *) a_fs_meta->content_ptr, a_buf_len);
        if (a_fs_meta->content_ptr == NULL) {
            return NULL;
        }
    }
    return (a_fs_meta);
}


/**
 * \internal
 * Free the memory allocated to the TSK_FS_META structure.
 *
 * @param fs_meta Structure to free
 */
void
tsk_fs_meta_close(TSK_FS_META * fs_meta)
{
    TSK_FS_META_NAME_LIST *fs_name, *fs_name2;

    if ((!fs_meta) || (fs_meta->tag != TSK_FS_META_TAG))
        return;

    // clear the tag so we know the structure isn't alloc
    fs_meta->tag = 0;

    if (fs_meta->content_ptr)
        free((char *) fs_meta->content_ptr);
    fs_meta->content_ptr = NULL;
    fs_meta->content_len = 0;

    if (fs_meta->attr)
        tsk_fs_attrlist_free(fs_meta->attr);
    fs_meta->attr = NULL;

    if (fs_meta->link)
        free(fs_meta->link);
    fs_meta->link = NULL;

    fs_name = fs_meta->name2;
    while (fs_name) {
        fs_name2 = fs_name->next;
        fs_name->next = NULL;
        free(fs_name);
        fs_name = fs_name2;
    }

    free((char *) fs_meta);
}

/** \internal
 * Reset the contents of a TSK_FS_META structure.
 * @param a_fs_meta Structure to reset
 */
void
tsk_fs_meta_reset(TSK_FS_META * a_fs_meta)
{
    void *content_ptr_tmp;
    size_t content_len_tmp;
    TSK_FS_ATTRLIST *attr_tmp;
    TSK_FS_META_NAME_LIST *name2_tmp;
    char *link_tmp;

    // backup pointers
    content_ptr_tmp = a_fs_meta->content_ptr;
    content_len_tmp = a_fs_meta->content_len;
    attr_tmp = a_fs_meta->attr;
    name2_tmp = a_fs_meta->name2;
    link_tmp = a_fs_meta->link;

    // clear all data
    memset(a_fs_meta, 0, sizeof(TSK_FS_META));
    a_fs_meta->tag = TSK_FS_META_TAG;

    // restore and clear the pointers
    a_fs_meta->content_ptr = content_ptr_tmp;
    a_fs_meta->content_len = content_len_tmp;

    a_fs_meta->attr = attr_tmp;
    a_fs_meta->attr_state = TSK_FS_META_ATTR_EMPTY;

    a_fs_meta->name2 = name2_tmp;

    a_fs_meta->link = link_tmp;
    if (a_fs_meta->link)
        a_fs_meta->link[0] = '\0';


    if (a_fs_meta->name2) {
        name2_tmp = a_fs_meta->name2;
        while (name2_tmp) {
            name2_tmp->name[0] = '\0';
            name2_tmp->par_inode = 0;
            name2_tmp->par_seq = 0;
            name2_tmp = name2_tmp->next;
        }

    }
}

/**
 * \ingroup fslib
 * Walk a range of metadata structures and call a callback for each
 * structure that matches the flags supplied.   For example, it can
 * call the callback on only allocated or unallocated entries. 
 *
 * @param a_fs File system to process
 * @param a_start Metadata address to start walking from
 * @param a_end Metadata address to walk to
 * @param a_flags Flags that specify the desired metadata features
 * @param a_cb Callback function to call
 * @param a_ptr Pointer to pass to the callback
 * @returns 1 on error and 0 on success
 */
uint8_t
tsk_fs_meta_walk(TSK_FS_INFO * a_fs, TSK_INUM_T a_start,
    TSK_INUM_T a_end, TSK_FS_META_FLAG_ENUM a_flags,
    TSK_FS_META_WALK_CB a_cb, void *a_ptr)
{
    if ((a_fs == NULL) || (a_fs->tag != TSK_FS_INFO_TAG))
        return 1;

    return a_fs->inode_walk(a_fs, a_start, a_end, a_flags, a_cb, a_ptr);
}
