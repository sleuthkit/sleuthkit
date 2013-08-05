/*
 ** fs_attrlist
 ** The Sleuth Kit
 **
 ** Brian Carrier [carrier <at> sleuthkit [dot] org]
 ** Copyright (c) 2008-2011 Brian Carrier.  All Rights reserved
 **
 ** This software is distributed under the Common Public License 1.0
 */

/**
 * \file fs_attrlist.c
 * File that contains functions to process TSK_FS_ATTRLIST structures, which
 * hold a linked list of TSK_FS_ATTR attribute structures.
 */

#include "tsk_fs_i.h"

/** \internal
 * Allocate a new data list structure
 *
 * @returns Pointer to new list structure or NULL on error
 */
TSK_FS_ATTRLIST *
tsk_fs_attrlist_alloc()
{
    TSK_FS_ATTRLIST *fs_attrlist;

    if ((fs_attrlist =
            (TSK_FS_ATTRLIST *) tsk_malloc(sizeof(TSK_FS_ATTRLIST))) ==
        NULL)
        return NULL;
    return fs_attrlist;
}

/** \internal
 * Free a list and the attributes inside of it
 */
void
tsk_fs_attrlist_free(TSK_FS_ATTRLIST * a_fs_attrlist)
{
    TSK_FS_ATTR *fs_attr_cur, *fs_attr_tmp;
    if (a_fs_attrlist == NULL)
        return;

    fs_attr_cur = a_fs_attrlist->head;
    while (fs_attr_cur) {
        fs_attr_tmp = fs_attr_cur->next;
        tsk_fs_attr_free(fs_attr_cur);
        fs_attr_cur = fs_attr_tmp;
    }
    free(a_fs_attrlist);
}

/** \internal
 * Add a new attribute to the list.
 *
 * @param a_fs_attrlist List structure to add to
 * @param a_fs_attr Data attribute to add
 * @returns 1 on error and 0 on success. Caller must free memory on error.
 */
uint8_t
tsk_fs_attrlist_add(TSK_FS_ATTRLIST * a_fs_attrlist,
    TSK_FS_ATTR * a_fs_attr)
{
    if (a_fs_attrlist == NULL) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("Null list in tsk_fs_attrlist_add");
        return 1;
    }

    // verify INUSE is set
    a_fs_attr->flags |= TSK_FS_ATTR_INUSE;

    if (a_fs_attrlist->head == NULL) {
        a_fs_attrlist->head = a_fs_attr;
    }
    else {
        TSK_FS_ATTR *fs_attr_cur;
        fs_attr_cur = a_fs_attrlist->head;
        while (fs_attr_cur) {
            // check if it already exists
            if ((fs_attr_cur->type == a_fs_attr->type)
                && (fs_attr_cur->id == a_fs_attr->id)) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_FS_ARG);
                tsk_error_set_errstr
                    ("datalist_add: Type %d and Id %d already in list",
                    a_fs_attr->type, a_fs_attr->id);
                return 1;
            }
            if (fs_attr_cur->next == NULL) {
                fs_attr_cur->next = a_fs_attr;
                break;
            }
            fs_attr_cur = fs_attr_cur->next;
        }
    }
    return 0;
}



/**
 * \internal
 * Return either an empty element in the list or create a new one at the end
 *
 * Preference is given to finding one of the same type to prevent
 * excessive malloc's, but if one is not found then a different
 * type is used: type = [TSK_FS_ATTR_NONRES | TSK_FS_ATTR_RES]
 *
 * @param a_fs_attrlist Attribute list to search
 * @param a_atype Preference for attribute type to reuse
 * @return NULL on error or attribute in list to use
 */
TSK_FS_ATTR *
tsk_fs_attrlist_getnew(TSK_FS_ATTRLIST * a_fs_attrlist,
    TSK_FS_ATTR_FLAG_ENUM a_atype)
{
    TSK_FS_ATTR *fs_attr_cur;
    TSK_FS_ATTR *fs_attr_ok = NULL;

    if (a_fs_attrlist == NULL) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("Null list in tsk_fs_attrlist_getnew()");
        return NULL;
    }

    if ((a_atype != TSK_FS_ATTR_NONRES) && (a_atype != TSK_FS_ATTR_RES)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("Invalid Type in tsk_fs_attrlist_getnew()");
        return NULL;
    }

    for (fs_attr_cur = a_fs_attrlist->head; fs_attr_cur;
        fs_attr_cur = fs_attr_cur->next) {
        if (fs_attr_cur->flags == 0) {
            if (a_atype == TSK_FS_ATTR_NONRES) {
                if (fs_attr_cur->nrd.run)
                    break;
                else if (!fs_attr_ok)
                    fs_attr_ok = fs_attr_cur;
            }
            /* we want one with an allocated buf */
            else {
                if (fs_attr_cur->rd.buf_size)
                    break;
                else if (!fs_attr_ok)
                    fs_attr_ok = fs_attr_cur;
            }
        }
    }

    /* if we fell out then check fs_attr_tmp */
    if (!fs_attr_cur) {
        if (fs_attr_ok)
            fs_attr_cur = fs_attr_ok;
        else {
            /* make a new one */
            if ((fs_attr_cur = tsk_fs_attr_alloc(a_atype)) == NULL)
                return NULL;

            // add it to the list
            if (tsk_fs_attrlist_add(a_fs_attrlist, fs_attr_cur)) {
                tsk_fs_attr_free(fs_attr_cur);
                return NULL;
            }
        }
    }

    fs_attr_cur->flags = (TSK_FS_ATTR_INUSE | a_atype);
    return fs_attr_cur;
}


/** \internal
 * Cycle through the attributes and mark them as unused.  Does not free anything.
 * @param a_fs_attrlist Attribute list too mark.
 */
void
tsk_fs_attrlist_markunused(TSK_FS_ATTRLIST * a_fs_attrlist)
{
    TSK_FS_ATTR *fs_attr_cur;
    if (a_fs_attrlist == NULL)
        return;

    fs_attr_cur = a_fs_attrlist->head;
    while (fs_attr_cur) {
        tsk_fs_attr_clear(fs_attr_cur);
        fs_attr_cur = fs_attr_cur->next;
    }
}

/**
 * \internal
 * Search the attribute list of TSK_FS_ATTR structures for an entry with a given
 * type (no ID).  If more than one entry with the same type exists, the one with
 * the lowest ID will be returned.
 *
 * @param a_fs_attrlist Data list structure to search in
 * @param a_type Type of attribute to find
 *
 * @return NULL is returned on error and if an entry could not be found.
 * tsk_errno will be set to TSK_ERR_FS_ATTR_NOTFOUND if entry could not be found.
 */
const TSK_FS_ATTR *
tsk_fs_attrlist_get(const TSK_FS_ATTRLIST * a_fs_attrlist,
    TSK_FS_ATTR_TYPE_ENUM a_type)
{
    TSK_FS_ATTR *fs_attr_cur;
    TSK_FS_ATTR *fs_attr_ok = NULL;

    if (!a_fs_attrlist) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("tsk_fs_attrlist_get: Null list pointer");
        return NULL;
    }

    for (fs_attr_cur = a_fs_attrlist->head; fs_attr_cur;
        fs_attr_cur = fs_attr_cur->next) {
        if ((fs_attr_cur->flags & TSK_FS_ATTR_INUSE)
            && (fs_attr_cur->type == a_type)) {

            /* If we are looking for NTFS $Data,
             * then return default when we see it */
            if ((fs_attr_cur->type == TSK_FS_ATTR_TYPE_NTFS_DATA) &&
                (fs_attr_cur->name == NULL)) {
                return fs_attr_cur;
            }

            // make sure we return the lowest if multiple exist
            if ((fs_attr_ok == NULL) || (fs_attr_ok->id > fs_attr_cur->id))
                fs_attr_ok = fs_attr_cur;
        }
    }

    if (!fs_attr_ok) {
        tsk_error_set_errno(TSK_ERR_FS_ATTR_NOTFOUND);
        tsk_error_set_errstr("tsk_fs_attrlist_get: Attribute %d not found",
            a_type);
        return NULL;
    }
    else {
        return fs_attr_ok;
    }
}

/**
 * \internal
 * Search the attribute list of TSK_FS_ATTR structures for an entry with a given
 * type and id.
 *
 * @param a_fs_attrlist Data list structure to search in
 * @param a_type Type of attribute to find
 * @param a_id Id of attribute to find.
 *
 * @return NULL is returned on error and if an entry could not be found.
 * tsk_errno will be set to TSK_ERR_FS_ATTR_NOTFOUND if entry could not be found.
 */
const TSK_FS_ATTR *
tsk_fs_attrlist_get_id(const TSK_FS_ATTRLIST * a_fs_attrlist,
    TSK_FS_ATTR_TYPE_ENUM a_type, uint16_t a_id)
{
    TSK_FS_ATTR *fs_attr_cur;

    if (!a_fs_attrlist) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("tsk_fs_attrlist_get_id: Null list pointer");
        return NULL;
    }

    for (fs_attr_cur = a_fs_attrlist->head; fs_attr_cur;
        fs_attr_cur = fs_attr_cur->next) {
        if ((fs_attr_cur->flags & TSK_FS_ATTR_INUSE)
            && (fs_attr_cur->type == a_type) && (fs_attr_cur->id == a_id))
            return fs_attr_cur;
    }

    tsk_error_set_errno(TSK_ERR_FS_ATTR_NOTFOUND);
    tsk_error_set_errstr
        ("tsk_fs_attrlist_get_id: Attribute %d-%d not found", a_type,
        a_id);
    return NULL;
}


/**
 * \internal
 * Search the attribute list of TSK_FS_ATTR structures for an entry with a
 given
 * type (no ID) and a given name. If more than one entry with the same
 type exists,
 * the one with the lowest ID will be returned.
 *
 * @param a_fs_attrlist Data list structure to search in
 * @param a_type Type of attribute to find
 * @param name Name of the attribute to find (NULL for an entry with no name)
 *
 * @return NULL is returned on error and if an entry could not be found.
 * tsk_errno will be set to TSK_ERR_FS_ATTR_NOTFOUND if entry could not be
 found.
 */
const TSK_FS_ATTR *
tsk_fs_attrlist_get_name_type(const TSK_FS_ATTRLIST * a_fs_attrlist,
    TSK_FS_ATTR_TYPE_ENUM a_type, const char *name)
{
    TSK_FS_ATTR *fs_attr_cur;
    TSK_FS_ATTR *fs_attr_ok = NULL;

    if (!a_fs_attrlist) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr
            ("tsk_fs_attrlist_get_name_type: Null list pointer");
        return NULL;
    }

    for (fs_attr_cur = a_fs_attrlist->head; fs_attr_cur; fs_attr_cur =
        fs_attr_cur->next) {
        if ((fs_attr_cur->flags & TSK_FS_ATTR_INUSE) &&
            (fs_attr_cur->type == a_type)) {

            if (((name == NULL) && (fs_attr_cur->name == NULL)) ||
                ((name) && (fs_attr_cur->name)
                    && (!strcmp(fs_attr_cur->name, name)))) {

                /* If we are looking for NTFS $Data,
                 * then return default when we see it */
                if ((fs_attr_cur->type == TSK_FS_ATTR_TYPE_NTFS_DATA) &&
                    (fs_attr_cur->name == NULL)) {
                    return fs_attr_cur;
                }

                // make sure we return the lowest if multiple exist
                if ((fs_attr_ok == NULL)
                    || (fs_attr_ok->id > fs_attr_cur->id))
                    fs_attr_ok = fs_attr_cur;
            }
        }
    }

    if (!fs_attr_ok) {
        tsk_error_set_errno(TSK_ERR_FS_ATTR_NOTFOUND);
        tsk_error_set_errstr("tsk_fs_attrlist_get: Attribute %d not found",
            a_type);
        return NULL;
    }
    else {
        return fs_attr_ok;
    }
}


/**
 * \internal
 * Return the a_idx'th attribute in the attribute list.
 *
 * @param a_fs_attrlist Data list structure to search in
 * @param a_idx 0-based index of attribute to return
 *
 * @return NULL is returned on error and if an entry could not be found.
 * tsk_errno will be set to TSK_ERR_FS_ATTR_NOTFOUND if entry could not be found.
 */
const TSK_FS_ATTR *
tsk_fs_attrlist_get_idx(const TSK_FS_ATTRLIST * a_fs_attrlist, int a_idx)
{
    TSK_FS_ATTR *fs_attr_cur;
    int i = 0;

    if (!a_fs_attrlist) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("tsk_fs_attrlist_get_idx: Null list pointer");
        return NULL;
    }

    for (fs_attr_cur = a_fs_attrlist->head; fs_attr_cur;
        fs_attr_cur = fs_attr_cur->next) {
        if (fs_attr_cur->flags & TSK_FS_ATTR_INUSE) {
            if (i == a_idx) {
                return fs_attr_cur;
            }
            i++;
        }
    }

    tsk_error_set_errno(TSK_ERR_FS_ATTR_NOTFOUND);
    tsk_error_set_errstr
        ("tsk_fs_attrlist_get_idx: Attribute index %d not found", a_idx);
    return NULL;
}


/**
 * \internal
 * Return the number of attributes in the attribute list
 *
 * @param a_fs_attrlist Data list structure to analyze
 *
 * @return the number of attributes and 0 if error (if argument is NULL)
 */
int
tsk_fs_attrlist_get_len(const TSK_FS_ATTRLIST * a_fs_attrlist)
{
    TSK_FS_ATTR *fs_attr_cur;
    int len = 0;

    if (!a_fs_attrlist) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("tsk_fs_attrlist_get_len: Null list pointer");
        return 0;
    }

    for (fs_attr_cur = a_fs_attrlist->head; fs_attr_cur;
        fs_attr_cur = fs_attr_cur->next) {
        if (fs_attr_cur->flags & TSK_FS_ATTR_INUSE)
            len++;
    }
    return len;
}
