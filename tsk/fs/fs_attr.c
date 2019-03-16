/*
** fs_attr
** The Sleuth Kit 
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2006-2011 Brian Carrier, Basis Technology.  All Rights reserved
** Copyright (c) 2003-2005 Brian Carrier.  All rights reserved 
**
** TASK
** Copyright (c) 2002 Brian Carrier, @stake Inc.  All rights reserved
**
**
** This software is distributed under the Common Public License 1.0
**
*/

/**
 * \file fs_attr.c
 * Functions to allocate and add structures to maintain generic file
 * system attributes and run lists.  
 */


/*
 * The TSK_FS_ATTR structure is motivated by NTFS.  NTFS (and others) allow
 * one to have more than one data area per file.  Furthermore, there is
 * more than one way to store the data (resident in the MFT entry or
 * in the Data Area runs).  To handle this in 
 * a generic format, the TSK_FS_ATTR structure was created.  
 *
 * TSK_FS_ATTR structures have a type and id that describe it and then
 * a flag identifies it as a resident stream or a non-resident run
 * They form a linked list and are added to the TSK_FS_META structure
 */
#include "tsk_fs_i.h"


/**
 * \internal
 * Allocate a run list entry.
 *
 * @returns NULL on error
 */
TSK_FS_ATTR_RUN *
tsk_fs_attr_run_alloc()
{
    TSK_FS_ATTR_RUN *fs_attr_run =
        (TSK_FS_ATTR_RUN *) tsk_malloc(sizeof(TSK_FS_ATTR_RUN));
    if (fs_attr_run == NULL)
        return NULL;

    return fs_attr_run;
}

/**
 * \internal
 * Free a list of data_runs
 *
 * @param fs_attr_run Head of list to free
 */
void
tsk_fs_attr_run_free(TSK_FS_ATTR_RUN * fs_attr_run)
{
    while (fs_attr_run) {
        TSK_FS_ATTR_RUN *fs_attr_run_prev = fs_attr_run;
        fs_attr_run = fs_attr_run->next;
        fs_attr_run_prev->next = NULL;
        free(fs_attr_run_prev);
    }
}




/** 
 * \internal
 * Allocates and initializes a new structure.  
 *
 * @param type The type of attribute to create (Resident or Non-resident)
 * @returns NULL on error
 */
TSK_FS_ATTR *
tsk_fs_attr_alloc(TSK_FS_ATTR_FLAG_ENUM type)
{
    TSK_FS_ATTR *fs_attr = (TSK_FS_ATTR *) tsk_malloc(sizeof(TSK_FS_ATTR));
    if (fs_attr == NULL) {
        return NULL;
    }

    fs_attr->name_size = 128;
    if ((fs_attr->name = (char *) tsk_malloc(fs_attr->name_size)) == NULL) {
        free(fs_attr);
        return NULL;
    }

    if (type == TSK_FS_ATTR_NONRES) {
        fs_attr->flags = (TSK_FS_ATTR_NONRES | TSK_FS_ATTR_INUSE);
    }
    else if (type == TSK_FS_ATTR_RES) {
        fs_attr->rd.buf_size = 1024;
        fs_attr->rd.buf = (uint8_t *) tsk_malloc(fs_attr->rd.buf_size);
        if (fs_attr->rd.buf == NULL) {
            free(fs_attr->name);
            return NULL;
        }
        fs_attr->flags = (TSK_FS_ATTR_RES | TSK_FS_ATTR_INUSE);
    }
    else {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("tsk_fs_attr_alloc: Invalid Type: %d\n",
            type);
        return NULL;
    }

    return fs_attr;
}


/**
 * \internal
 * Free a single TSK_FS_ATTR structure.  This does not free the linked list.
 *
 * @param a_fs_attr Structure to free.
 */
void
tsk_fs_attr_free(TSK_FS_ATTR * a_fs_attr)
{
    if (a_fs_attr == NULL)
        return;

    if (a_fs_attr->nrd.run)
        tsk_fs_attr_run_free(a_fs_attr->nrd.run);
    a_fs_attr->nrd.run = NULL;

    free(a_fs_attr->rd.buf);
    a_fs_attr->rd.buf = NULL;

    free(a_fs_attr->name);
    a_fs_attr->name = NULL;

    free(a_fs_attr);
}


/**
 * \internal
 * Clear the run_lists fields of a single FS_DATA structure
 *
 * @param a_fs_attr Structure to clear for reuse
 */
void
tsk_fs_attr_clear(TSK_FS_ATTR * a_fs_attr)
{
    a_fs_attr->size = a_fs_attr->type =
        a_fs_attr->id = a_fs_attr->flags = 0;
    if (a_fs_attr->nrd.run) {
        tsk_fs_attr_run_free(a_fs_attr->nrd.run);
        a_fs_attr->nrd.run = NULL;
        a_fs_attr->nrd.run_end = NULL;
        a_fs_attr->nrd.allocsize = 0;
        a_fs_attr->nrd.initsize = 0;
    }
}




/**
 * Add a name to an existing FS_DATA structure.  Will reallocate
 * space for the name if needed.
 *
 * @param fs_attr Structure to add name to
 * @param name UTF-8 name to add
 *
 * @return 1 on error and 0 on success
 */
static uint8_t
fs_attr_put_name(TSK_FS_ATTR * fs_attr, const char *name)
{
    if ((name == NULL) || (strlen(name) == 0)) {
        if (fs_attr->name_size > 0) {
            free(fs_attr->name);
            fs_attr->name_size = 0;
        }
        fs_attr->name = NULL;
        return 0;
    }

    if (fs_attr->name_size < (strlen(name) + 1)) {
        fs_attr->name = tsk_realloc(fs_attr->name, strlen(name) + 1);
        if (fs_attr->name == NULL)
            return 1;
        fs_attr->name_size = strlen(name) + 1;
    }
    strncpy(fs_attr->name, name, fs_attr->name_size);
    return 0;
}

/**
 * \internal
 * Copy resident data to an attribute. 
 *
 * @param a_fs_attr Attribute to add data to (cannot be NULL)
 * @param name Name of the attribute to set
 * @param type Type of the attribute to set
 * @param id Id of the attribute to set
 * @param res_data Pointer to where resident data is located (data will
 * be copied from here into FS_DATA)
 * @param len Length of resident data
 * @return 1 on error and 0 on success
 */
uint8_t
tsk_fs_attr_set_str(TSK_FS_FILE * a_fs_file, TSK_FS_ATTR * a_fs_attr,
    const char *name, TSK_FS_ATTR_TYPE_ENUM type, uint16_t id,
    void *res_data, size_t len)
{
    if (a_fs_attr == NULL) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("Null fs_attr in tsk_fs_attr_set_str");
        return 1;
    }

    a_fs_attr->fs_file = a_fs_file;
    a_fs_attr->flags = (TSK_FS_ATTR_INUSE | TSK_FS_ATTR_RES);
    a_fs_attr->type = type;
    a_fs_attr->id = id;
    a_fs_attr->nrd.compsize = 0;

    if (fs_attr_put_name(a_fs_attr, name)) {
        return 1;
    }

    if (a_fs_attr->rd.buf_size < len) {
        a_fs_attr->rd.buf =
            (uint8_t *) tsk_realloc((char *) a_fs_attr->rd.buf, len);
        if (a_fs_attr->rd.buf == NULL)
            return 1;
        a_fs_attr->rd.buf_size = len;
    }

    memset(a_fs_attr->rd.buf, 0, a_fs_attr->rd.buf_size);
    memcpy(a_fs_attr->rd.buf, res_data, len);
    a_fs_attr->size = len;

    return 0;
}


/**
 * \internal
 * Set the needed fields along with an initial run list for a data attribute.  To add more 
 * runs, use ...._add_run().
 *
 * @param a_fs_file File to add attribute to
 * @param a_fs_attr The data attribute to initialize and add the run to
 * @param a_data_run_new The set of runs to add (can be NULL).
 * @param name Name of the attribute (can be NULL)
 * @param type Type of attribute to add run to
 * @param id Id of attribute to add run to
 * @param size Total size of the attribute (can be larger than length of initial run being added) 
 * @param init_size Number of bytes in attribute that have been initialized (less then or equal to size)
 * (note that this sets the initialized size for the attribute and it will not be updated as more runs are added).
 * @param alloc_size Allocated size of the attribute (>= size).  Identifies the slack space. 
 * (note that this sets the allocated size for the attribute and it will not be updated as more runs are added).
 * @param flags Flags about compression, sparse etc. of data
 * @param compsize Compression unit size (in case it needs to be created)
 *
 * @returns 1 on error and 0 on success
 */
uint8_t
tsk_fs_attr_set_run(TSK_FS_FILE * a_fs_file, TSK_FS_ATTR * a_fs_attr,
    TSK_FS_ATTR_RUN * a_data_run_new, const char *name,
    TSK_FS_ATTR_TYPE_ENUM type, uint16_t id, TSK_OFF_T size,
    TSK_OFF_T init_size, TSK_OFF_T alloc_size,
    TSK_FS_ATTR_FLAG_ENUM flags, uint32_t compsize)
{
    if ((a_fs_file == NULL) || (a_fs_file->meta == NULL)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("Null fs_file in tsk_fs_attr_set_run");
        return 1;
    }
    if (a_fs_attr == NULL) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("Null fs_attr in tsk_fs_attr_set_run");
        return 1;
    }

    if (alloc_size < size) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("tsk_fs_attr_set_run: alloc_size (%" PRIuOFF
            ") is less than size (%" PRIuOFF ")", alloc_size, size);
        return 1;
    }

    a_fs_attr->fs_file = a_fs_file;
    a_fs_attr->flags = (TSK_FS_ATTR_INUSE | TSK_FS_ATTR_NONRES | flags);
    a_fs_attr->type = type;
    a_fs_attr->id = id;
    a_fs_attr->size = size;
    a_fs_attr->nrd.allocsize = alloc_size;
    a_fs_attr->nrd.initsize = init_size;
    a_fs_attr->nrd.compsize = compsize;

    if (fs_attr_put_name(a_fs_attr, name)) {
        return 1;
    }

    /* Add the a_data_run_new to the attribute. */

    /* We support the ODD case where the run is NULL.  In this case, 
     * we set the attribute size info, but set everything else to NULL.
     */
    if (a_data_run_new == NULL) {
        a_fs_attr->nrd.run = NULL;
        a_fs_attr->nrd.run_end = NULL;
        return 0;
    }

    /*
     * If this is not in the beginning, then we need to make a filler 
     * to account for the cluster numbers we haven't seen yet
     *
     * This commonly happens when we process an MFT entry that
     * is not a base entry and it is referenced in an $ATTR_LIST
     *
     * The $DATA attribute in the non-base have a non-zero
     * a_data_run_new->offset.  
     */
    if (a_data_run_new->offset != 0) {
        TSK_FS_ATTR_RUN *fill_run = tsk_fs_attr_run_alloc();
        fill_run->flags = TSK_FS_ATTR_RUN_FLAG_FILLER;
        fill_run->offset = 0;
        fill_run->addr = 0;
        fill_run->len = a_data_run_new->offset;
        fill_run->next = a_data_run_new;
        a_data_run_new = fill_run;
    }

    a_fs_attr->nrd.run = a_data_run_new;

    // update the pointer to the end of the list
    a_fs_attr->nrd.run_end = a_data_run_new;
    while (a_fs_attr->nrd.run_end->next) {
        a_fs_attr->nrd.run_end = a_fs_attr->nrd.run_end->next;
    }

    return 0;
}

static void
dump_attr(TSK_FS_ATTR * a_fs_attr)
{
    TSK_FS_ATTR_RUN *cur_run;
    cur_run = a_fs_attr->nrd.run;

    fprintf(stderr, "Attribute Run Dump:\n");
    for (cur_run = a_fs_attr->nrd.run; cur_run; cur_run = cur_run->next) {
        fprintf(stderr, "  %" PRIuDADDR " to %" PRIuDADDR " %sFiller\n",
            cur_run->offset, cur_run->offset + cur_run->len - 1,
            (cur_run->flags & TSK_FS_ATTR_RUN_FLAG_FILLER) ? "" : "Not");
    }
}

/*
 * Prints the data runs for a non-resident attribute
 */
uint8_t
tsk_fs_attr_print(const TSK_FS_ATTR * a_fs_attr, FILE* hFile) {
    TSK_FS_ATTR_RUN *cur_run;
    TSK_FS_ATTR_RUN *fs_attr_run;
    uint32_t skip_remain;
    TSK_OFF_T tot_size;
    TSK_FS_INFO *fs = a_fs_attr->fs_file->fs_info;
    TSK_OFF_T off = 0;
    uint8_t stop_loop = 0;

    if ( ! (a_fs_attr->flags & TSK_FS_ATTR_NONRES)) {
        tsk_error_set_errstr("tsk_fs_attr_print called on non-resident attribute");
        return TSK_ERR;
    }

    cur_run = a_fs_attr->nrd.run;
    tot_size = a_fs_attr->size;
    skip_remain = a_fs_attr->nrd.skiplen;

    for (fs_attr_run = a_fs_attr->nrd.run; fs_attr_run;
        fs_attr_run = fs_attr_run->next) {
        TSK_DADDR_T addr, len_idx, run_len, run_start_addr;

        addr = fs_attr_run->addr;
        run_len = 0;
        run_start_addr = addr;

        /* cycle through each block in the run */
        for (len_idx = 0; len_idx < fs_attr_run->len; len_idx++) {


            /* If the address is too large then give an error */
            if (addr + len_idx > fs->last_block) {
                if (a_fs_attr->fs_file->
                    meta->flags & TSK_FS_META_FLAG_UNALLOC)
                    tsk_error_set_errno(TSK_ERR_FS_RECOVER);
                else
                    tsk_error_set_errno(TSK_ERR_FS_BLK_NUM);
                tsk_error_set_errstr
                    ("Invalid address in run (too large): %" PRIuDADDR "",
                    addr + len_idx);
                return TSK_ERR;
            }


            /* Need to account for the skip length, which is the number of bytes
            * in the start of the attribute that are skipped and that are not
            * included in the overall length.  We will seek past those and not
            * return those in the action.  We just read a block size so check
            * if there is data to be returned in this buffer. */

            if (skip_remain >= fs->block_size) {
                skip_remain -= fs->block_size;
                run_start_addr++;
            }
            else {
                size_t ret_len;

                /* Do we want to return a full block, or just the end? */
                if ((TSK_OFF_T)fs->block_size - skip_remain <
                    tot_size - off)
                    ret_len = fs->block_size - skip_remain;
                else
                    ret_len = (size_t)(tot_size - off);

                off += ret_len;
                run_len++;
                skip_remain = 0;

                if (off >= tot_size) {
                    stop_loop = 1;
                    break;
                }
            }
        }    

        if (cur_run->flags & TSK_FS_ATTR_RUN_FLAG_SPARSE) {
            tsk_fprintf(hFile, "  Staring address: X, length: %lld  Sparse", run_len);
        }
        else if (cur_run->flags & TSK_FS_ATTR_RUN_FLAG_FILLER) {
            tsk_fprintf(hFile, "  Staring address: X, length: %lld  Filler", run_len);
        }
        else {
            tsk_fprintf(hFile, "  Staring address: %lld, length: %lld", run_start_addr, run_len);
        }
        tsk_fprintf(hFile, "\n");
        if (stop_loop) {
            break;
        }
    }
    return TSK_OK;
}

/**
 * \internal
 * Add a set of consecutive runs to an attribute. This will add and remove FILLER entries
 * as needed and update internal variables. 
 *
 * @param a_fs File system run is from
 * @param fs_attr Attribute to add run to
 * @param a_data_run_new The set of runs to add.  
 *
 * @returns 1 on error and 0 on succes
 */
uint8_t
tsk_fs_attr_add_run(TSK_FS_INFO * a_fs, TSK_FS_ATTR * a_fs_attr,
    TSK_FS_ATTR_RUN * a_data_run_new)
{
    TSK_FS_ATTR_RUN *data_run_cur, *data_run_prev;
    TSK_DADDR_T run_len;

    tsk_error_reset();

    if (a_fs_attr == NULL) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr
            ("tsk_fs_attr_add_run: Error, a_fs_attr is NULL");
        return 1;
    }

    // we only support the case of a null run if it is the only run...
    if (a_data_run_new == NULL) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr
            ("tsk_fs_attr_add_run: Error, a_data_run_new is NULL (%"
            PRIuINUM ")", a_fs_attr->fs_file->meta->addr);
        return 1;
    }

    run_len = 0;
    data_run_cur = a_data_run_new;
    while (data_run_cur) {
        run_len += data_run_cur->len;
        data_run_cur = data_run_cur->next;
    }

    /* First thing, is to check if we can just add it to the end */
    if ((a_fs_attr->nrd.run_end)
        && (a_fs_attr->nrd.run_end->offset + a_fs_attr->nrd.run_end->len ==
            a_data_run_new->offset)) {

        a_fs_attr->nrd.run_end->next = a_data_run_new;
        // update the pointer to the end of the list
        while (a_fs_attr->nrd.run_end->next)
            a_fs_attr->nrd.run_end = a_fs_attr->nrd.run_end->next;

        /* return head of a_fs_attr list */
        return 0;
    }

    // cycle through existing runs and see if we can add this into a filler spot
    data_run_cur = a_fs_attr->nrd.run;
    data_run_prev = NULL;
    while (data_run_cur) {

        if (tsk_verbose)
            tsk_fprintf(stderr,
                "tsk_fs_attr_add: %" PRIuOFF "@%" PRIuOFF
                " (Filler: %s)\n", data_run_cur->offset, data_run_cur->len,
                (data_run_cur->flags & TSK_FS_ATTR_RUN_FLAG_FILLER) ? "Yes"
                : "No");

        /* Do we replace this filler spot? */
        if (data_run_cur->flags & TSK_FS_ATTR_RUN_FLAG_FILLER) {

            /* This should never happen because we always add 
             * the filler to start from VCN 0 */
            if (data_run_cur->offset > a_data_run_new->offset) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_FS_GENFS);
                tsk_error_set_errstr
                    ("tsk_fs_attr_add_run: could not add data_run b.c. offset (%"
                    PRIuOFF ") is larger than FILLER (%" PRIuOFF ") (%"
                    PRIuINUM ")", a_data_run_new->offset,
                    data_run_cur->offset, a_fs_attr->fs_file->meta->addr);
                if (tsk_verbose)
                    dump_attr(a_fs_attr);
                return 1;
            }

            /* Check if the new run starts inside of this filler. */
            if (data_run_cur->offset + data_run_cur->len >
                a_data_run_new->offset) {
                TSK_FS_ATTR_RUN *endrun;

                /* if the new starts at the same as the filler, 
                 * replace the pointer */
                if (data_run_cur->offset == a_data_run_new->offset) {
                    if (data_run_prev)
                        data_run_prev->next = a_data_run_new;
                    else
                        a_fs_attr->nrd.run = a_data_run_new;
                }

                /* The new run does not start at the beginning of
                 * the filler, so make a new start filler
                 */
                else {
                    TSK_FS_ATTR_RUN *newfill = tsk_fs_attr_run_alloc();
                    if (newfill == NULL)
                        return 1;

                    if (data_run_prev)
                        data_run_prev->next = newfill;
                    else
                        a_fs_attr->nrd.run = newfill;

                    newfill->next = a_data_run_new;
                    newfill->len =
                        a_data_run_new->offset - data_run_cur->offset;
                    newfill->offset = data_run_cur->offset;
                    newfill->flags = TSK_FS_ATTR_RUN_FLAG_FILLER;

                    data_run_cur->len -= newfill->len;
                }

                /* get to the end of the run that we are trying to add */
                endrun = a_data_run_new;
                while (endrun->next)
                    endrun = endrun->next;

                /* if the filler is the same size as the
                 * new one, replace it 
                 */
                if (run_len == data_run_cur->len) {
                    endrun->next = data_run_cur->next;

                    // update the pointer to the end of the list (if we are the end)
                    if (endrun->next == NULL)
                        a_fs_attr->nrd.run_end = endrun;

                    free(data_run_cur);
                }
                /* else adjust the last filler entry */
                else {
                    endrun->next = data_run_cur;
                    data_run_cur->len -= run_len;
                    data_run_cur->offset =
                        a_data_run_new->offset + a_data_run_new->len;
                }

                return 0;
            }
        }

        data_run_prev = data_run_cur;
        data_run_cur = data_run_cur->next;
    }


    /* 
     * There is no filler holding the location of this run, so
     * we will add it to the end of the list 
     * 
     * we got here because it did not fit in the current list or
     * because the current list is NULL
     *
     * At this point data_run_prev is the end of the existing list or
     * 0 if there is no list
     */
    /* This is an error condition.  
     * It means that we cycled through the existing runs,
     * ended at a VCN that is larger than what we are adding,
     * and never found a filler entry to insert it into... 
     */
    if ((data_run_prev)
        && (data_run_prev->offset + data_run_prev->len >
            a_data_run_new->offset)) {

        /* MAYBE this is because of a duplicate entry .. */
        if ((data_run_prev->addr == a_data_run_new->addr) &&
            (data_run_prev->len == a_data_run_new->len)) {
            // @@@ Sould be we freeing this....?  What if the caller tries to write to it?
            tsk_fs_attr_run_free(a_data_run_new);
            return 0;
        }

        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_GENFS);
        tsk_error_set_errstr
            ("fs_attr_add_run: error adding additional run (%" PRIuINUM
            "): No filler entry for %" PRIuDADDR ". Final: %" PRIuDADDR,
            a_fs_attr->fs_file->meta->addr, a_data_run_new->offset,
            data_run_prev->offset + data_run_prev->len);
        if (tsk_verbose)
            dump_attr(a_fs_attr);
        return 1;
    }

    /* we should add it right here */
    else if (((data_run_prev)
            && (data_run_prev->offset + data_run_prev->len ==
                a_data_run_new->offset))
        || (a_data_run_new->offset == 0)) {
        if (data_run_prev)
            data_run_prev->next = a_data_run_new;
        else
            a_fs_attr->nrd.run = a_data_run_new;
    }
    /* we need to make a filler before it */
    else {
        TSK_FS_ATTR_RUN *tmprun = tsk_fs_attr_run_alloc();
        if (tmprun == NULL)
            return 1;

        if (data_run_prev) {
            data_run_prev->next = tmprun;
            tmprun->offset = data_run_prev->offset + data_run_prev->len;
        }
        else {
            a_fs_attr->nrd.run = tmprun;
        }

        tmprun->len = a_data_run_new->offset - tmprun->offset;
        tmprun->flags = TSK_FS_ATTR_RUN_FLAG_FILLER;
        tmprun->next = a_data_run_new;
    }

    // update the pointer to the end of the list
    a_fs_attr->nrd.run_end = a_data_run_new;
    while (a_fs_attr->nrd.run_end->next)
        a_fs_attr->nrd.run_end = a_fs_attr->nrd.run_end->next;

    return 0;
}


/**
 * Append a data run to the end of the attribute and update its offset
 * value.  This ignores the offset in the data run and blindly appends.
 *
 * @param a_fs File system run is from
 * @param a_fs_attr Data attribute to append to
 * @param a_data_run Data run to append.
 */
void
tsk_fs_attr_append_run(TSK_FS_INFO * a_fs, TSK_FS_ATTR * a_fs_attr,
    TSK_FS_ATTR_RUN * a_data_run)
{
    TSK_FS_ATTR_RUN *data_run_cur;

    if ((a_fs_attr == NULL) || (a_data_run == NULL)) {
        return;
    }

    if (a_fs_attr->nrd.run == NULL) {
        a_fs_attr->nrd.run = a_data_run;
        a_data_run->offset = 0;
    }
    else {
        // just in case this was not updated
        if ((a_fs_attr->nrd.run_end == NULL)
            || (a_fs_attr->nrd.run_end->next != NULL)) {
            data_run_cur = a_fs_attr->nrd.run;
            while (data_run_cur->next) {
                data_run_cur = data_run_cur->next;
            }
            a_fs_attr->nrd.run_end = data_run_cur;
        }
        a_fs_attr->nrd.run_end->next = a_data_run;
        a_data_run->offset =
            a_fs_attr->nrd.run_end->offset + a_fs_attr->nrd.run_end->len;
    }

    // update the rest of the offsets in the run (if any exist)
    data_run_cur = a_data_run;
    while (data_run_cur->next) {
        data_run_cur->next->offset =
            data_run_cur->offset + data_run_cur->len;
        a_fs_attr->nrd.run_end = data_run_cur->next;
        data_run_cur = data_run_cur->next;
    }
}

/** \internal
 * Processes a resident TSK_FS_ATTR structure and calls the callback with the associated
 * data. The size of the buffer in the callback will be block_size at max. 
 *
 * @param a_fs File system being analyzed
 * @param fs_attr Resident data structure to be walked
 * @param a_flags Flags for walking
 * @param a_action Callback action
 * @param a_ptr Pointer to data that is passed to callback
 * @returns 1 on error or 0 on success
 */
static uint8_t
tsk_fs_attr_walk_res(const TSK_FS_ATTR * fs_attr,
    TSK_FS_FILE_WALK_FLAG_ENUM a_flags, TSK_FS_FILE_WALK_CB a_action,
    void *a_ptr)
{
    char *buf = NULL;
    int myflags;
    int retval;
    size_t buf_len = 0;
    TSK_OFF_T off;
    size_t read_len;
    TSK_FS_INFO *fs;

    fs = fs_attr->fs_file->fs_info;

    if ((fs_attr->flags & TSK_FS_ATTR_RES) == 0) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr
            ("tsk_fs_file_walk_res: called with non-resident data");
        return 1;
    }

    /* Allocate a buffer that is at most a block size in length */
    buf_len = (size_t) fs_attr->size;
    if (buf_len > fs->block_size)
        buf_len = fs->block_size;

    if ((a_flags & TSK_FS_FILE_WALK_FLAG_AONLY) == 0) {
        if ((buf = tsk_malloc(buf_len)) == NULL) {
            return 1;
        }
    }

    myflags =
        TSK_FS_BLOCK_FLAG_CONT | TSK_FS_BLOCK_FLAG_ALLOC |
        TSK_FS_BLOCK_FLAG_RES;

    // Call the callback in (at max) block-sized chunks.
    retval = TSK_WALK_CONT;
    for (off = 0; off < fs_attr->size; off += read_len) {

        if ((uint64_t) (fs_attr->size - off) > buf_len)
            read_len = buf_len;
        else
            read_len = (size_t) (fs_attr->size - off);

        if (buf) {
            // wipe rest of buffer if we are not going to read into all of it
            if (read_len != buf_len)
                memset(&buf[read_len], 0, buf_len - read_len);

            memcpy(buf, &fs_attr->rd.buf[off], read_len);
        }
        retval =
            a_action(fs_attr->fs_file, off, 0, buf, read_len, myflags,
            a_ptr);

        if (retval != TSK_WALK_CONT)
            break;
    }

    free(buf);

    if (retval == TSK_WALK_ERROR)
        return 1;
    else
        return 0;
}


/** \internal
 * Processes a non-resident TSK_FS_ATTR structure and calls the callback with the associated
 * data. 
 *
 * @param fs_attr Resident data structure to be walked
 * @param a_flags Flags for walking
 * @param a_action Callback action
 * @param a_ptr Pointer to data that is passed to callback
 * @returns 1 on error or 0 on success
 */
static uint8_t
tsk_fs_attr_walk_nonres(const TSK_FS_ATTR * fs_attr,
    TSK_FS_FILE_WALK_FLAG_ENUM a_flags, TSK_FS_FILE_WALK_CB a_action,
    void *a_ptr)
{
    char *buf = NULL;
    TSK_OFF_T tot_size;
    TSK_OFF_T off = 0;
    TSK_FS_ATTR_RUN *fs_attr_run;
    int retval;
    uint32_t skip_remain;
    TSK_FS_INFO *fs = fs_attr->fs_file->fs_info;
    uint8_t stop_loop = 0;

    if ((fs_attr->flags & TSK_FS_ATTR_NONRES) == 0) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr
            ("tsk_fs_file_walk_nonres: called with non-non-resident data");
        return 1;
    }

    /* if we want the slack space too, then use the allocsize  */
    if (a_flags & TSK_FS_FILE_WALK_FLAG_SLACK)
        tot_size = fs_attr->nrd.allocsize;
    else
        tot_size = fs_attr->size;

    skip_remain = fs_attr->nrd.skiplen;

    if ((a_flags & TSK_FS_FILE_WALK_FLAG_AONLY) == 0) {
        if ((buf = (char *) tsk_malloc(fs->block_size)) == NULL) {
            return 1;
        }
    }

    /* cycle through the number of runs we have */
    retval = TSK_WALK_CONT;
    for (fs_attr_run = fs_attr->nrd.run; fs_attr_run;
        fs_attr_run = fs_attr_run->next) {
        TSK_DADDR_T addr, len_idx;

        addr = fs_attr_run->addr;

        /* cycle through each block in the run */
        for (len_idx = 0; len_idx < fs_attr_run->len; len_idx++) {

            TSK_FS_BLOCK_FLAG_ENUM myflags;

            /* If the address is too large then give an error */
            if (addr + len_idx > fs->last_block) {
                if (fs_attr->fs_file->
                    meta->flags & TSK_FS_META_FLAG_UNALLOC)
                    tsk_error_set_errno(TSK_ERR_FS_RECOVER);
                else
                    tsk_error_set_errno(TSK_ERR_FS_BLK_NUM);
                tsk_error_set_errstr
                    ("Invalid address in run (too large): %" PRIuDADDR "",
                    addr + len_idx);
                free(buf);
                return 1;
            }

            // load the buffer if they want more than just the address
            if ((a_flags & TSK_FS_FILE_WALK_FLAG_AONLY) == 0) {

                /* sparse files just get 0s */
                if (fs_attr_run->flags & TSK_FS_ATTR_RUN_FLAG_SPARSE) {
                    memset(buf, 0, fs->block_size);
                }
                /* FILLER entries exist when the source file system can store run
                 * info out of order and we did not get all of the run info.  We
                 * return 0s if data is read from this type of run. */
                else if (fs_attr_run->flags & TSK_FS_ATTR_RUN_FLAG_FILLER) {
                    memset(buf, 0, fs->block_size);
                    if (tsk_verbose)
                        fprintf(stderr,
                            "tsk_fs_attr_walk_nonres: File %" PRIuINUM
                            " has FILLER entry, using 0s\n",
                            fs_attr->fs_file->meta->addr);
                }

                // we return 0s for reads past the initsize
                else if ((off >= fs_attr->nrd.initsize)
                    && ((a_flags & TSK_FS_FILE_READ_FLAG_SLACK) == 0)) {
                    memset(buf, 0, fs->block_size);
                }
                else {
                    ssize_t cnt;

                    cnt = tsk_fs_read_block
                        (fs, addr + len_idx, buf, fs->block_size);
                    if (cnt != fs->block_size) {
                        if (cnt >= 0) {
                            tsk_error_reset();
                            tsk_error_set_errno(TSK_ERR_FS_READ);
                        }
                        tsk_error_set_errstr2
                            ("tsk_fs_file_walk: Error reading block at %"
                            PRIuDADDR, addr + len_idx);
                        free(buf);
                        return 1;
                    }
                    if ((off + fs->block_size > fs_attr->nrd.initsize)
                        && ((a_flags & TSK_FS_FILE_READ_FLAG_SLACK) == 0)) {
                        memset(&buf[fs_attr->nrd.initsize - off], 0,
                            fs->block_size -
                            (size_t) (fs_attr->nrd.initsize - off));
                    }
                }
            }

            /* Need to account for the skip length, which is the number of bytes
             * in the start of the attribute that are skipped and that are not
             * included in the overall length.  We will seek past those and not
             * return those in the action.  We just read a block size so check
             * if there is data to be returned in this buffer. */
            if (skip_remain >= fs->block_size) {
                skip_remain -= fs->block_size;
            }
            else {
                size_t ret_len;

                /* Do we want to return a full block, or just the end? */
                if ((TSK_OFF_T) fs->block_size - skip_remain <
                    tot_size - off)
                    ret_len = fs->block_size - skip_remain;
                else
                    ret_len = (size_t) (tot_size - off);

                /* Only do sparse or FILLER clusters if NOSPARSE is not set */
                if ((fs_attr_run->flags & TSK_FS_ATTR_RUN_FLAG_SPARSE) ||
                    (fs_attr_run->flags & TSK_FS_ATTR_RUN_FLAG_FILLER) ||
                    (off > fs_attr->nrd.initsize)) {
                    myflags = fs->block_getflags(fs, 0);
                    myflags |= TSK_FS_BLOCK_FLAG_SPARSE;
                    if ((a_flags & TSK_FS_FILE_WALK_FLAG_NOSPARSE) == 0) {
                        retval =
                            a_action(fs_attr->fs_file, off, 0,
                            &buf[skip_remain], ret_len, myflags, a_ptr);
                    }
                }
                else {
                    myflags = fs->block_getflags(fs, addr + len_idx);
                    myflags |= TSK_FS_BLOCK_FLAG_RAW;

                    retval =
                        a_action(fs_attr->fs_file, off, addr + len_idx,
                        &buf[skip_remain], ret_len, myflags, a_ptr);
                }
                off += ret_len;
                skip_remain = 0;

                if (retval != TSK_WALK_CONT) {
                    stop_loop = 1;
                    break;
                }

                if (off >= tot_size) {
                    stop_loop = 1;
                    break;
                }
            }
        }
        if (stop_loop)
            break;
    }

    free(buf);

    if (retval == TSK_WALK_ERROR)
        return 1;
    else
        return 0;
}


/**
 * \ingroup fslib
 * Process an attribute and call a callback function with its contents. The callback will be 
 * called with chunks of data that are fs->block_size or less.  The address given in the callback
 * will be correct only for raw files (when the raw file contents were stored in the block).  For
 * compressed and sparse attributes, the address may be zero.
 *
 * @param a_fs_attr Attribute to process
 * @param a_flags Flags to use while processing attribute
 * @param a_action Callback action to call with content
 * @param a_ptr Pointer that will passed to callback
 * @returns 1 on error and 0 on success.
 */
uint8_t
tsk_fs_attr_walk(const TSK_FS_ATTR * a_fs_attr,
    TSK_FS_FILE_WALK_FLAG_ENUM a_flags, TSK_FS_FILE_WALK_CB a_action,
    void *a_ptr)
{
    TSK_FS_INFO *fs;

    // clean up any error messages that are lying around
    tsk_error_reset();

    // check the FS_INFO, FS_FILE structures
    if ((a_fs_attr == NULL) || (a_fs_attr->fs_file == NULL)
        || (a_fs_attr->fs_file->meta == NULL)
        || (a_fs_attr->fs_file->fs_info == NULL)) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr
            ("tsk_fs_attr_walk: called with NULL pointers");
        return 1;
    }
    fs = a_fs_attr->fs_file->fs_info;

    if (fs->tag != TSK_FS_INFO_TAG) {
//        || (a_fs_attr->id != TSK_FS_ATTR_ID)) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr
            ("tsk_fs_attr_walk: called with unallocated structures");
        return 1;
    }
    if (a_fs_attr->flags & TSK_FS_ATTR_COMP) {
        if (a_fs_attr->w == NULL) {
            tsk_error_set_errno(TSK_ERR_FS_ARG);
            tsk_error_set_errstr
                ("tsk_fs_attr_walk: compressed attribute found, but special function not defined");
            return 1;
        }
        return a_fs_attr->w(a_fs_attr, a_flags, a_action, a_ptr);
    }
    // resident data
    if (a_fs_attr->flags & TSK_FS_ATTR_RES) {
		fflush(stderr);
        return tsk_fs_attr_walk_res(a_fs_attr, a_flags, a_action, a_ptr);
    }
    // non-resident data
    else if (a_fs_attr->flags & TSK_FS_ATTR_NONRES) {
		fflush(stderr);
        return tsk_fs_attr_walk_nonres(a_fs_attr, a_flags, a_action,
            a_ptr);
    }

    tsk_error_set_errno(TSK_ERR_FS_ARG);
    tsk_error_set_errstr
        ("tsk_fs_attr_walk: called with unknown attribute type: %x",
        a_fs_attr->flags);
    return 1;
}



/**
 * \ingroup fslib
 * Read the contents of a given attribute using a typical read() type interface.
 * 0s are returned for missing runs. 
 * 
 * @param a_fs_attr The attribute to read.
 * @param a_offset The byte offset to start reading from.
 * @param a_buf The buffer to read the data into.
 * @param a_len The number of bytes to read from the file.
 * @param a_flags Flags to use while reading
 * @returns The number of bytes read or -1 on error (incl if offset is past end of file).
 */
ssize_t
tsk_fs_attr_read(const TSK_FS_ATTR * a_fs_attr, TSK_OFF_T a_offset,
    char *a_buf, size_t a_len, TSK_FS_FILE_READ_FLAG_ENUM a_flags)
{
    TSK_FS_INFO *fs;

    if ((a_fs_attr == NULL) || (a_fs_attr->fs_file == NULL)
        || (a_fs_attr->fs_file->fs_info == NULL)) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr
            ("tsk_fs_attr_read: Attribute has null pointers.");
        return -1;
    }
    fs = a_fs_attr->fs_file->fs_info;

    /* for compressed data, call the specialized function */
    if (a_fs_attr->flags & TSK_FS_ATTR_COMP) {
        if (a_fs_attr->r == NULL) {
            tsk_error_set_errno(TSK_ERR_FS_ARG);
            tsk_error_set_errstr
                ("tsk_fs_attr_read: Attribute has compressed type set, but no compressed read function defined");
            return -1;
        }
        return a_fs_attr->r(a_fs_attr, a_offset, a_buf, a_len);
    }

    /* For resident data, copy data from the local buffer */
    else if (a_fs_attr->flags & TSK_FS_ATTR_RES) {
        size_t len_toread;

        if (a_offset >= a_fs_attr->size) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_READ_OFF);
            tsk_error_set_errstr("tsk_fs_attr_read - %" PRIuOFF, a_offset);
            return -1;
        }

        len_toread = a_len;
        if (a_offset + (TSK_OFF_T)a_len > a_fs_attr->size) {
            len_toread = (size_t) (a_fs_attr->size - a_offset);
            memset(&a_buf[len_toread], 0, a_len - len_toread);
        }

        memcpy(a_buf, &a_fs_attr->rd.buf[a_offset], len_toread);

        return (ssize_t) len_toread;
    }

    /* For non-resident data, load the needed block and copy the data */
    else if (a_fs_attr->flags & TSK_FS_ATTR_NONRES) {
        TSK_FS_ATTR_RUN *data_run_cur;
        TSK_DADDR_T blkoffset_toread;   // block offset of where we want to start reading from
        size_t byteoffset_toread;       // byte offset in blkoffset_toread of where we want to start reading from
        ssize_t len_remain;      // length remaining to copy
        size_t len_toread;      // length total to copy

        if (((a_flags & TSK_FS_FILE_READ_FLAG_SLACK)
                && (a_offset >= a_fs_attr->nrd.allocsize))
            || (!(a_flags & TSK_FS_FILE_READ_FLAG_SLACK)
                && (a_offset >= a_fs_attr->size))) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_READ_OFF);
            tsk_error_set_errstr("tsk_fs_attr_read - %" PRIuOFF, a_offset);
            return -1;
        }

        blkoffset_toread = a_offset / fs->block_size;
        byteoffset_toread = (size_t) (a_offset % fs->block_size);

        // determine how many bytes we can copy
        len_toread = a_len;
        if (a_flags & TSK_FS_FILE_READ_FLAG_SLACK) {
            if (a_offset + (TSK_OFF_T)a_len > a_fs_attr->nrd.allocsize)
                len_toread =
                    (size_t) (a_fs_attr->nrd.allocsize - a_offset);
        }
        else {
            if (a_offset + (TSK_OFF_T)a_len > a_fs_attr->size)
                len_toread = (size_t) (a_fs_attr->size - a_offset);
        }


        // wipe the buffer we won't read into
        if (len_toread < a_len)
            memset(&a_buf[len_toread], 0, a_len - len_toread);

        len_remain = len_toread;

        // cycle through the runs until we find the one where our offset starts
        for (data_run_cur = a_fs_attr->nrd.run; data_run_cur && len_remain > 0;
            data_run_cur = data_run_cur->next) {

            TSK_DADDR_T blkoffset_inrun;
            size_t len_inrun;

            // See if this run contains the starting offset they requested
            if (data_run_cur->offset + data_run_cur->len <=
                blkoffset_toread)
                continue;

            // We want this run, so find out the offset that we want
            // we'll start at 0 if we already read data in the last run. 
            if (data_run_cur->offset < blkoffset_toread)
                blkoffset_inrun = blkoffset_toread - data_run_cur->offset;
            else
                blkoffset_inrun = 0;

            // see if we need to read the rest of this run and into the next or if it is all here
            len_inrun = len_remain;
            if ((data_run_cur->len - blkoffset_inrun) * fs->block_size -
                byteoffset_toread < (size_t)len_remain) {
                len_inrun =
                    (size_t) ((data_run_cur->len -
                        blkoffset_inrun) * fs->block_size -
                    byteoffset_toread);
            }

            /* sparse files/runs just get 0s */
            if (data_run_cur->flags & TSK_FS_ATTR_RUN_FLAG_SPARSE) {
                memset(&a_buf[len_toread - len_remain], 0, len_inrun);
            }

            /* FILLER entries exist when the source file system can store run
             * info out of order and we did not get all of the run info.  We
             * return 0s if data is read from this type of run. */
            else if (data_run_cur->flags & TSK_FS_ATTR_RUN_FLAG_FILLER) {
                memset(&a_buf[len_toread - len_remain], 0, len_inrun);
                if (tsk_verbose)
                    fprintf(stderr,
                        "tsk_fs_attr_read_type: File %" PRIuINUM
                        " has FILLER entry, using 0s\n",
                        (a_fs_attr->fs_file->meta) ? a_fs_attr->
                        fs_file->meta->addr : 0);
            }

            // we return 0s for reads past the initsize (unless they want slack space)
            else if (((TSK_OFF_T) ((data_run_cur->offset +
                            blkoffset_inrun) * fs->block_size +
                        byteoffset_toread) >= a_fs_attr->nrd.initsize)
                && ((a_flags & TSK_FS_FILE_READ_FLAG_SLACK) == 0)) {
                memset(&a_buf[len_toread - len_remain], 0, len_inrun);
                if (tsk_verbose)
                    fprintf(stderr,
                        "tsk_fs_attr_read: Returning 0s for read past end of initsize (%"
                        PRIuINUM ")\n", ((a_fs_attr->fs_file)
                            && (a_fs_attr->fs_file->
                                meta)) ? a_fs_attr->fs_file->meta->
                        addr : 0);
            }

            // we are going to read some data
            else {
                TSK_OFF_T fs_offset_b;
                ssize_t cnt;

                // calculate the byte offset in the file system that we want to read from
                fs_offset_b =
                    (data_run_cur->addr +
                    blkoffset_inrun) * fs->block_size;

                // add the byte offset in the block
                fs_offset_b += byteoffset_toread;

                cnt =
                    tsk_fs_read(fs, fs_offset_b,
                    &a_buf[len_toread - len_remain], len_inrun);
                if (cnt != (ssize_t)len_inrun) {
                    if (cnt >= 0) {
                        tsk_error_reset();
                        tsk_error_set_errno(TSK_ERR_FS_READ);
                    }
                    tsk_error_set_errstr2
                        ("tsk_fs_attr_read_type: offset: %" PRIuOFF
                        "  Len: %" PRIuSIZE "", fs_offset_b, len_inrun);
                    return cnt;
                }

                // see if part of the data is in the non-initialized space
                if (((TSK_OFF_T) ((data_run_cur->offset +
                                blkoffset_inrun) * fs->block_size +
                            byteoffset_toread + len_inrun) >
                        a_fs_attr->nrd.initsize)
                    && ((a_flags & TSK_FS_FILE_READ_FLAG_SLACK) == 0)) {

                    size_t uninit_off = (size_t) (a_fs_attr->nrd.initsize -
                        ((data_run_cur->offset +
                                blkoffset_inrun) * fs->block_size +
                            byteoffset_toread));

                    memset(&a_buf[len_toread - len_remain + uninit_off], 0,
                        len_inrun - uninit_off);
                }

            }

            len_remain -= len_inrun;

            // reset this in case we need to also read from the next run 
            byteoffset_toread = 0;
        }
        return (ssize_t) (len_toread - len_remain);
    }

    tsk_error_set_errno(TSK_ERR_FS_ARG);
    tsk_error_set_errstr("tsk_fs_attr_read: Unknown attribute type: %x",
        a_fs_attr->flags);
    return -1;
}
