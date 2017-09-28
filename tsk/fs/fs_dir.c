/*
 * fs_dir
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2008-2011 Brian Carrier.  All Rights reserved
 *
 * This software is distributed under the Common Public License 1.0
 *
 */

/**
 * \file fs_dir.c
 * Create, manage, etc. the TSK_FS_DIR structures.
 */

#include "tsk_fs_i.h"
#include "tsk_fatfs.h"


/** \internal
* Allocate a FS_DIR structure to load names into.
*
* @param a_addr Address of this directory.
* @param a_cnt target number of FS_DENT entries to fit in
* @returns NULL on error
*/
TSK_FS_DIR *
tsk_fs_dir_alloc(TSK_FS_INFO * a_fs, TSK_INUM_T a_addr, size_t a_cnt)
{
    TSK_FS_DIR *fs_dir;
    size_t i;

    // allocate and initialize the structure
    if ((fs_dir = (TSK_FS_DIR *) tsk_malloc(sizeof(TSK_FS_DIR))) == NULL) {
        return NULL;
    }

    fs_dir->names_alloc = a_cnt;
    fs_dir->names_used = 0;
    if ((fs_dir->names =
            (TSK_FS_NAME *) tsk_malloc(sizeof(TSK_FS_NAME) *
                fs_dir->names_alloc)) == NULL) {
        free(fs_dir);
        return NULL;
    }
    fs_dir->fs_info = a_fs;
    fs_dir->addr = a_addr;
    fs_dir->tag = TSK_FS_DIR_TAG;
    for (i = 0; i < a_cnt; i++) {
        fs_dir->names[i].tag = TSK_FS_NAME_TAG;
    }

    return fs_dir;
}


/** \internal
* Make the buffer in the FS_DIR structure larger.
*
* @param a_fs_dir Structure to enhance
* @param a_cnt target number of FS_DENT entries to fit in
* @returns 1 on error and 0 on success
*/
uint8_t
tsk_fs_dir_realloc(TSK_FS_DIR * a_fs_dir, size_t a_cnt)
{
    size_t prev_cnt, i;
    if ((a_fs_dir == NULL) || (a_fs_dir->tag != TSK_FS_DIR_TAG))
        return 1;

    if (a_fs_dir->names_alloc >= a_cnt)
        return 0;
    prev_cnt = a_fs_dir->names_alloc;

    a_fs_dir->names_alloc = a_cnt;
    if ((a_fs_dir->names =
            (TSK_FS_NAME *) tsk_realloc((void *) a_fs_dir->names,
                sizeof(TSK_FS_NAME) * a_fs_dir->names_alloc)) == NULL) {
        return 1;
    }

    memset(&a_fs_dir->names[prev_cnt], 0,
        (a_cnt - prev_cnt) * sizeof(TSK_FS_NAME));
    for (i = prev_cnt; i < a_cnt; i++) {
        a_fs_dir->names[i].tag = TSK_FS_NAME_TAG;
    }
    return 0;
}

/** \internal
* Reset the structures in a FS_DIR so that it can be reused.
* @param a_fs_dir FS_DIR structure to re-use
*/
void
tsk_fs_dir_reset(TSK_FS_DIR * a_fs_dir)
{
    if ((a_fs_dir == NULL) || (a_fs_dir->tag != TSK_FS_DIR_TAG))
        return;

    if (a_fs_dir->fs_file) {
        tsk_fs_file_close(a_fs_dir->fs_file);
        a_fs_dir->fs_file = NULL;
    }
    a_fs_dir->names_used = 0;
    a_fs_dir->addr = 0;
    a_fs_dir->seq = 0;
}



/** \internal
 * Copy the contents of one directory structure to another.
 * Note that this currently does not copy the FS_FILE info.
 * It is only used to make a copy of the orphan directory.
 * It does not check for duplicate entries.
 * @returns 1 on error
 */
static uint8_t
tsk_fs_dir_copy(const TSK_FS_DIR * a_src_dir, TSK_FS_DIR * a_dst_dir)
{
    size_t i;

    a_dst_dir->names_used = 0;

    // make sure we got the room
    if (a_src_dir->names_used > a_dst_dir->names_alloc) {
        if (tsk_fs_dir_realloc(a_dst_dir, a_src_dir->names_used))
            return 1;
    }

    for (i = 0; i < a_src_dir->names_used; i++) {
        if (tsk_fs_name_copy(&a_dst_dir->names[i], &a_src_dir->names[i]))
            return 1;
    }

    a_dst_dir->names_used = a_src_dir->names_used;
    a_dst_dir->addr = a_src_dir->addr;
    a_dst_dir->seq = a_src_dir->seq;
    return 0;
}




/**
 * Test if a_fs_dir already contains an entry for the given
 * meta data address. If so, return the allocation state.
 *
 * @returns TSK_FS_NAME_FLAG_ALLOC, TSK_FS_NAME_FLAG_UNALLOC, or 0 if not found.
 */
uint8_t
tsk_fs_dir_contains(TSK_FS_DIR * a_fs_dir, TSK_INUM_T meta_addr, uint32_t hash)
{
    size_t i;
    uint8_t bestFound = 0;

    for (i = 0; i < a_fs_dir->names_used; i++) {
        if (meta_addr == a_fs_dir->names[i].meta_addr) {
            if (hash == tsk_fs_dir_hash(a_fs_dir->names[i].name)) {
                bestFound = a_fs_dir->names[i].flags;
                // stop as soon as we get an alloc. 
                // if we get unalloc, keep going in case there
                // is alloc later.
                if (bestFound == TSK_FS_NAME_FLAG_ALLOC)
                    break;
            }
        }
    }
    return bestFound;
}

/** \internal
 * Frees the allocated memory in a name structure when we are reshuffling
 * things around. Does not free the outer TSK_FS_NAME structure.  Just the names
 * inside of it.
 */
static void 
tsk_fs_dir_free_name_internal(TSK_FS_NAME *fs_name) 
{
    if (fs_name->name) {
	    free(fs_name->name);
	    fs_name->name = NULL;
	    fs_name->name_size = 0;
    }
    if (fs_name->shrt_name) {
        free(fs_name->shrt_name);
        fs_name->shrt_name = NULL;
        fs_name->shrt_name_size = 0;
    }
}


/** \internal
 * Add a FS_DENT structure to a FS_DIR structure by copying its
 * contents into the internal buffer. Checks for
 * duplicates and expands buffer as needed.
 * @param a_fs_dir DIR to add to
 * @param a_fs_name DENT to add
 * @returns 1 on error (memory allocation problems) and 0 on success
 */
uint8_t
tsk_fs_dir_add(TSK_FS_DIR * a_fs_dir, const TSK_FS_NAME * a_fs_name)
{
    TSK_FS_NAME *fs_name_dest = NULL;
    size_t i;

    /* see if we already have it in the buffer / queue
     * We skip this check for FAT because it will always fail because two entries
     * never have the same meta address. */
    // @@@ We could do something more efficient here too with orphan files because we do not 
    // need to check the contents of that directory either and this takes a lot of time on those
    // large images.
    if (TSK_FS_TYPE_ISFAT(a_fs_dir->fs_info->ftype) == 0) {
        for (i = 0; i < a_fs_dir->names_used; i++) {
            if ((a_fs_name->meta_addr == a_fs_dir->names[i].meta_addr) &&
                (strcmp(a_fs_name->name, a_fs_dir->names[i].name) == 0)) {

                if (tsk_verbose)
                    tsk_fprintf(stderr,
                        "tsk_fs_dir_add: removing duplicate entry: %s (%"
                        PRIuINUM ")\n", a_fs_name->name,
                        a_fs_name->meta_addr);

                /* We do not check type because then we cannot detect NTFS orphan file
                 * duplicates that are added as "-/r" while a similar entry exists as "r/r"
                 (a_fs_name->type == a_fs_dir->names[i].type)) { */

                // if the one in the list is unalloc and we have an alloc, replace it
                if ((a_fs_dir->names[i].flags & TSK_FS_NAME_FLAG_UNALLOC)
                    && (a_fs_name->flags & TSK_FS_NAME_FLAG_ALLOC)) {
                    fs_name_dest = &a_fs_dir->names[i];

                    // free the memory - not the most efficient, but prevents
                    // duplicate code.
                    tsk_fs_dir_free_name_internal(fs_name_dest);
                    break;
                }
                else {
                    return 0;
                }
            }
        }
    }

    if (fs_name_dest == NULL) {
        // make sure we got the room
        if (a_fs_dir->names_used >= a_fs_dir->names_alloc) {
            if (tsk_fs_dir_realloc(a_fs_dir, a_fs_dir->names_used + 512))
                return 1;
        }

        fs_name_dest = &a_fs_dir->names[a_fs_dir->names_used++];
    }

    if (tsk_fs_name_copy(fs_name_dest, a_fs_name))
        return 1;

    // add the parent address
    if (a_fs_dir->addr) {
        fs_name_dest->par_addr = a_fs_dir->addr;
        fs_name_dest->par_seq = a_fs_dir->seq;
    }

    return 0;
}



/** \ingroup fslib
* Open a directory (using its metadata addr) so that each of the files in it can be accessed.
* @param a_fs File system to analyze
* @param a_addr Metadata address of the directory to open
* @returns NULL on error
*/
TSK_FS_DIR *
tsk_fs_dir_open_meta(TSK_FS_INFO * a_fs, TSK_INUM_T a_addr)
{
    TSK_FS_DIR *fs_dir = NULL;
    TSK_RETVAL_ENUM retval;

    if ((a_fs == NULL) || (a_fs->tag != TSK_FS_INFO_TAG)
        || (a_fs->dir_open_meta == NULL)) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr
            ("tsk_fs_dir_open_meta: called with NULL or unallocated structures");
        return NULL;
    }

    retval = a_fs->dir_open_meta(a_fs, &fs_dir, a_addr);
    if (retval != TSK_OK) {
        tsk_fs_dir_close(fs_dir);
        return NULL;
    }

    return fs_dir;
}


/** \ingroup fslib
* Open a directory (using its path) so that each of the files in it can be accessed.
* @param a_fs File system to analyze
* @param a_dir Path of the directory to open
* @returns NULL on error
*/
TSK_FS_DIR *
tsk_fs_dir_open(TSK_FS_INFO * a_fs, const char *a_dir)
{
    TSK_INUM_T inum;
    int8_t retval;
    TSK_FS_DIR *fs_dir;
    TSK_FS_NAME *fs_name;

    if ((a_fs == NULL) || (a_fs->tag != TSK_FS_INFO_TAG)) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr
            ("tsk_fs_dir_open: called with NULL or unallocated structures");
        return NULL;
    }

    // allocate a structure to store the name in
    if ((fs_name = tsk_fs_name_alloc(128, 32)) == NULL) {
        return NULL;
    }

    retval = tsk_fs_path2inum(a_fs, a_dir, &inum, fs_name);
    if (retval == -1) {
        tsk_fs_name_free(fs_name);
        return NULL;
    }
    else if (retval == 1) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("tsk_fs_dir_open: path not found: %s", a_dir);
        tsk_fs_name_free(fs_name);
        return NULL;
    }

    fs_dir = tsk_fs_dir_open_meta(a_fs, inum);

    // add the name structure on to it
    if ((fs_dir) && (fs_dir->fs_file))
        fs_dir->fs_file->name = fs_name;

    return fs_dir;
}


/** \ingroup fslib
* Close the directory that was opened with tsk_fs_dir_open()
 * @param a_fs_dir Directory to close
 */
void
tsk_fs_dir_close(TSK_FS_DIR * a_fs_dir)
{
    size_t i;
    if ((a_fs_dir == NULL) || (a_fs_dir->tag != TSK_FS_DIR_TAG)) {
        return;
    }

    for (i = 0; i < a_fs_dir->names_used; i++) {
        tsk_fs_dir_free_name_internal(&a_fs_dir->names[i]);
    }
    free(a_fs_dir->names);

    if (a_fs_dir->fs_file) {
        tsk_fs_file_close(a_fs_dir->fs_file);
        a_fs_dir->fs_file = NULL;
    }

    a_fs_dir->tag = 0;
    free(a_fs_dir);
}

/** \ingroup fslib
* Returns the number of files and subdirectories in a directory.
 * @param a_fs_dir Directory to get information about
 * @returns Number of files and subdirectories (or 0 on error)
 */
size_t
tsk_fs_dir_getsize(const TSK_FS_DIR * a_fs_dir)
{
    if ((a_fs_dir == NULL) || (a_fs_dir->tag != TSK_FS_DIR_TAG)) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr
            ("tsk_fs_dir_getsize: called with NULL or unallocated structures");
        return 0;
    }
    return a_fs_dir->names_used;
}

/** \ingroup fslib
* Return a specific file or subdirectory from an open directory.
 * @param a_fs_dir Directory to analyze
 * @param a_idx Index of file in directory to open (0-based)
 * @returns NULL on error
 */
TSK_FS_FILE *
tsk_fs_dir_get(const TSK_FS_DIR * a_fs_dir, size_t a_idx)
{
    TSK_FS_NAME *fs_name;
    TSK_FS_FILE *fs_file;

    if ((a_fs_dir == NULL) || (a_fs_dir->tag != TSK_FS_DIR_TAG)
        || (a_fs_dir->fs_info == NULL)) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr
            ("tsk_fs_dir_get: called with NULL or unallocated structures");
        return NULL;
    }
    if (a_fs_dir->names_used <= a_idx) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("tsk_fs_dir_get: Index (%" PRIuSIZE
            ") too large (%" PRIuSIZE ")", a_idx, a_fs_dir->names_used);
        return NULL;
    }

    // allocate a structure to return
    if ((fs_file = tsk_fs_file_alloc(a_fs_dir->fs_info)) == NULL)
        return NULL;

    fs_name = &(a_fs_dir->names[a_idx]);

    // copy the name into another structure that we can return and later free
    if ((fs_file->name =
            tsk_fs_name_alloc(fs_name->name ? strlen(fs_name->name) +
                1 : 0,
                fs_name->shrt_name ? strlen(fs_name->shrt_name) +
                1 : 0)) == NULL) {
        return NULL;
    }
    if (tsk_fs_name_copy(fs_file->name, fs_name))
        return NULL;

    /* load the fs_meta structure if possible.
     * Must have non-zero inode addr or have allocated name (if inode is 0) */
    if (((fs_name->meta_addr)
            || (fs_name->flags & TSK_FS_NAME_FLAG_ALLOC))) {
        if (a_fs_dir->fs_info->file_add_meta(a_fs_dir->fs_info, fs_file,
                fs_name->meta_addr)) {
            if (tsk_verbose)
                tsk_error_print(stderr);
            tsk_error_reset();
        }

        // if the sequence numbers don't match, then don't load the meta
        // should ideally have sequence in previous lookup, but it isn't 
        // in all APIs yet
        if ((fs_file->meta) && (fs_file->meta->seq != fs_name->meta_seq)) {
            tsk_fs_meta_close(fs_file->meta);
            fs_file->meta = NULL;
        }
    }
    return fs_file;
}

/** \ingroup fslib
 * Return only the name for a file or subdirectory from an open directory.
 * Useful when wanting to find files of a given name and you don't need the 
 * additional metadata. 
 *
 * @param a_fs_dir Directory to analyze
 * @param a_idx Index of file in directory to open (0-based)
 * @returns NULL on error
 */
const TSK_FS_NAME *
tsk_fs_dir_get_name(const TSK_FS_DIR * a_fs_dir, size_t a_idx)
{
    if ((a_fs_dir == NULL) || (a_fs_dir->tag != TSK_FS_DIR_TAG)
        || (a_fs_dir->fs_info == NULL)) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr
        ("tsk_fs_dir_get: called with NULL or unallocated structures");
        return NULL;
    }
    if (a_fs_dir->names_used <= a_idx) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("tsk_fs_dir_get: Index (%" PRIuSIZE
                             ") too large (%" PRIuSIZE ")", a_idx, a_fs_dir->names_used);
        return NULL;
    }
    
    return &(a_fs_dir->names[a_idx]);
}


#define MAX_DEPTH   128
#define DIR_STRSZ   4096

/** \internal
 * used to keep state between calls to dir_walk_lcl
 */
typedef struct {
    /* Recursive path stuff */

    /* how deep in the directory tree are we */
    unsigned int depth;

    /* pointer in dirs string to where '/' is for given depth */
    char *didx[MAX_DEPTH];

    /* The current directory name string */
    char dirs[DIR_STRSZ];

    TSK_STACK *stack_seen;

    /* Set to one to collect inode info that can be used for orphan listing */
    uint8_t save_inum_named;

    /* We keep list_inum_named inside DENT_DINFO so different threads
     * have their own copies.  On successful completion of the dir
     * walk we reassigned ownership of this pointer into the shared
     * TSK_FS_INFO list_inum_named field.  We're trading off the extra
     * work in each thread for cleaner locking code.
     */
    TSK_LIST *list_inum_named;

} DENT_DINFO;


/**
 * Saves the list_inum_named from DENT_DINFO to FS_INFO.
 * This can be called from a couple of places, so the logic
 * is here in a single method.
 */
static void
save_inum_named(TSK_FS_INFO *a_fs, DENT_DINFO *dinfo) {

    /* We finished the dir walk successfully, so reassign
     * ownership of the dinfo's list_inum_named to the shared
     * list_inum_named in TSK_FS_INFO, under a lock, if
     * another thread hasn't already done so.
     */
    tsk_take_lock(&a_fs->list_inum_named_lock);
    if (a_fs->list_inum_named == NULL) {
        a_fs->list_inum_named = dinfo->list_inum_named;
    }
    else {
        tsk_list_free(dinfo->list_inum_named);
    }
    dinfo->list_inum_named = NULL;
    tsk_release_lock(&a_fs->list_inum_named_lock);
}

/* dir_walk local function that is used for recursive calls.  Callers
 * should initially call the non-local version. */
static TSK_WALK_RET_ENUM
tsk_fs_dir_walk_lcl(TSK_FS_INFO * a_fs, DENT_DINFO * a_dinfo,
    TSK_INUM_T a_addr, TSK_FS_DIR_WALK_FLAG_ENUM a_flags,
    TSK_FS_DIR_WALK_CB a_action, void *a_ptr)
{
    TSK_FS_DIR *fs_dir;
    TSK_FS_FILE *fs_file;
    size_t i;

    // get the list of entries in the directory
    if ((fs_dir = tsk_fs_dir_open_meta(a_fs, a_addr)) == NULL) {
        return TSK_WALK_ERROR;
    }

    /* Allocate a file structure for the callbacks.  We
     * will allocate fs_meta structures as needed and
     * point into the fs_dir structure for the names. */
    if ((fs_file = tsk_fs_file_alloc(a_fs)) == NULL) {
        tsk_fs_dir_close(fs_dir);
        return TSK_WALK_ERROR;
    }

    for (i = 0; i < fs_dir->names_used; i++) {
        TSK_WALK_RET_ENUM retval;

        /* Point name to the buffer of names.  We need to be
         * careful about resetting this before we free fs_file */
        fs_file->name = (TSK_FS_NAME *) & fs_dir->names[i];

        /* load the fs_meta structure if possible.
         * Must have non-zero inode addr or have allocated name (if inode is 0) */
        if (((fs_file->name->meta_addr)
                || (fs_file->name->flags & TSK_FS_NAME_FLAG_ALLOC))) {

            /* Note that the NTFS code behind here has a slight hack to use the
             * correct sequence number based on the data in fs_file->name */
            if (a_fs->file_add_meta(a_fs, fs_file,
                    fs_file->name->meta_addr)) {
                if (tsk_verbose)
                    tsk_error_print(stderr);
                tsk_error_reset();
            }
        }

        // call the action if we have the right flags.
        if ((fs_file->name->flags & a_flags) == fs_file->name->flags) {

            retval = a_action(fs_file, a_dinfo->dirs, a_ptr);
            if (retval == TSK_WALK_STOP) {
                tsk_fs_dir_close(fs_dir);
                fs_file->name = NULL;
                tsk_fs_file_close(fs_file);

                /* free the list -- fs_dir_walk has no way
                 * of knowing that we stopped early w/out error.
                 */
                if (a_dinfo->save_inum_named) {
                    tsk_list_free(a_dinfo->list_inum_named);
                    a_dinfo->list_inum_named = NULL;
                    a_dinfo->save_inum_named = 0;
                }
                return TSK_WALK_STOP;
            }
            else if (retval == TSK_WALK_ERROR) {
                tsk_fs_dir_close(fs_dir);
                fs_file->name = NULL;
                tsk_fs_file_close(fs_file);
                return TSK_WALK_ERROR;
            }
        }

        // save the inode info for orphan finding - if requested
        if ((a_dinfo->save_inum_named) && (fs_file->meta)
            && (fs_file->meta->flags & TSK_FS_META_FLAG_UNALLOC)) {

            if (tsk_list_add(&a_dinfo->list_inum_named,
                    fs_file->meta->addr)) {

                // if there is an error, then clear the list
                tsk_list_free(a_dinfo->list_inum_named);
                a_dinfo->list_inum_named = NULL;
                a_dinfo->save_inum_named = 0;
            }
        }


        /* Optimization. If we are about to recurse into the
         * orphan directory and we are the last item in the
         * directory and the flag has been set to save inum_named,
         * then save inum_named now to FS_INFO so that we can use
         * it for the orphan folder.  Otherwise, we do a full
         * inode walk again for nothing. */
        if ((fs_file->name->meta_addr == TSK_FS_ORPHANDIR_INUM(a_fs)) && 
            (i == fs_dir->names_used-1) && 
            (a_dinfo->save_inum_named == 1)) {
            save_inum_named(a_fs, a_dinfo);
            a_dinfo->save_inum_named = 0;
        }

        /* Recurse into a directory if:
         * - Both dir entry and inode have DIR type (or name is undefined)
         * - Recurse flag is set
         * - dir entry is allocated OR both are unallocated
         * - not one of the '.' or '..' entries
         * - A Non-Orphan Dir or the Orphan Dir with the NOORPHAN flag not set.
         */
        if ((TSK_FS_IS_DIR_NAME(fs_file->name->type)
                || (fs_file->name->type == TSK_FS_NAME_TYPE_UNDEF))
            && (fs_file->meta)
            && (TSK_FS_IS_DIR_META(fs_file->meta->type))
            && (a_flags & TSK_FS_DIR_WALK_FLAG_RECURSE)
            && ((fs_file->name->flags & TSK_FS_NAME_FLAG_ALLOC)
                || ((fs_file->name->flags & TSK_FS_NAME_FLAG_UNALLOC)
                    && (fs_file->meta->flags & TSK_FS_META_FLAG_UNALLOC))
            )
            && (!TSK_FS_ISDOT(fs_file->name->name))
            && ((fs_file->name->meta_addr != TSK_FS_ORPHANDIR_INUM(a_fs))
                || ((a_flags & TSK_FS_DIR_WALK_FLAG_NOORPHAN) == 0))
            ) {

            /* Make sure we do not get into an infinite loop */
            if (0 == tsk_stack_find(a_dinfo->stack_seen,
                    fs_file->name->meta_addr)) {
                int depth_added = 0;
                uint8_t save_bak = 0;

                if (tsk_stack_push(a_dinfo->stack_seen,
                        fs_file->name->meta_addr)) {
                    tsk_fs_dir_close(fs_dir);
                    fs_file->name = NULL;
                    tsk_fs_file_close(fs_file);
                    return TSK_WALK_ERROR;
                }

                /* If we've exceeded the max depth or max length, don't
                 * recurse any further into this directory */
                if ((a_dinfo->depth >= MAX_DEPTH) ||
                    (DIR_STRSZ <=
                        strlen(a_dinfo->dirs) +
                        strlen(fs_file->name->name))) {   
                    if (tsk_verbose) {
                        tsk_fprintf(stdout,
                            "tsk_fs_dir_walk_lcl: directory : %"
                            PRIuINUM " exceeded max length / depth\n", fs_file->name->meta_addr);
                    }
                    return TSK_WALK_ERROR;
                }

                a_dinfo->didx[a_dinfo->depth] =
                    &a_dinfo->dirs[strlen(a_dinfo->dirs)];
                strncpy(a_dinfo->didx[a_dinfo->depth],
                    fs_file->name->name,
                    DIR_STRSZ - strlen(a_dinfo->dirs));
                strncat(a_dinfo->dirs, "/", DIR_STRSZ);
                depth_added = 1;
                a_dinfo->depth++;

                /* We do not want to save info about named unalloc files
                 * when we go into the Orphan directory (because then we have
                 * no orphans).  So, disable it for this recursion.
                 */
                if (fs_file->name->meta_addr ==
                    TSK_FS_ORPHANDIR_INUM(a_fs)) {
                    save_bak = a_dinfo->save_inum_named;
                    a_dinfo->save_inum_named = 0;
                }
                retval = tsk_fs_dir_walk_lcl(a_fs,
                    a_dinfo, fs_file->name->meta_addr, a_flags,
                    a_action, a_ptr);
                if (retval == TSK_WALK_ERROR) {
                    /* If this fails because the directory could not be
                     * loaded, then we still continue */
                    if (tsk_verbose) {
                        tsk_fprintf(stderr,
                            "tsk_fs_dir_walk_lcl: error reading directory: %"
                            PRIuINUM "\n", fs_file->name->meta_addr);
                        tsk_error_print(stderr);
                    }

                    tsk_error_reset();
                }
                else if (retval == TSK_WALK_STOP) {
                    tsk_fs_dir_close(fs_dir);
                    fs_file->name = NULL;
                    tsk_fs_file_close(fs_file);
                    return TSK_WALK_STOP;
                }

                // reset the save status
                if (fs_file->name->meta_addr ==
                    TSK_FS_ORPHANDIR_INUM(a_fs)) {
                    a_dinfo->save_inum_named = save_bak;
                }

                tsk_stack_pop(a_dinfo->stack_seen);
                a_dinfo->depth--;
                if (depth_added)
                    *a_dinfo->didx[a_dinfo->depth] = '\0';
            }
            else {
                if (tsk_verbose)
                    fprintf(stderr,
                        "tsk_fs_dir_walk_lcl: Loop detected with address %"
                        PRIuINUM, fs_file->name->meta_addr);
            }
        }

        // remove the pointer to name buffer
        fs_file->name = NULL;

        // free the metadata if we allocated it
        if (fs_file->meta) {
            tsk_fs_meta_close(fs_file->meta);
            fs_file->meta = NULL;
        }
    }

    tsk_fs_dir_close(fs_dir);
    fs_file->name = NULL;
    tsk_fs_file_close(fs_file);
    return TSK_WALK_CONT;
}


/** \ingroup fslib
* Walk the file names in a directory and obtain the details of the files via a callback.
*
* @param a_fs File system to analyze
* @param a_addr Metadata address of the directory to analyze
* @param a_flags Flags used during analysis
* @param a_action Callback function that is called for each file name
* @param a_ptr Pointer to data that is passed to the callback function each time
* @returns 1 on error and 0 on success
*/
uint8_t
tsk_fs_dir_walk(TSK_FS_INFO * a_fs, TSK_INUM_T a_addr,
    TSK_FS_DIR_WALK_FLAG_ENUM a_flags, TSK_FS_DIR_WALK_CB a_action,
    void *a_ptr)
{
    DENT_DINFO dinfo;
    TSK_WALK_RET_ENUM retval;

    if ((a_fs == NULL) || (a_fs->tag != TSK_FS_INFO_TAG)) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr
            ("tsk_fs_dir_walk: called with NULL or unallocated structures");
        return 1;
    }

    memset(&dinfo, 0, sizeof(DENT_DINFO));
    if ((dinfo.stack_seen = tsk_stack_create()) == NULL)
        return 1;

    /* Sanity check on flags -- make sure at least one ALLOC is set */
    if (((a_flags & TSK_FS_DIR_WALK_FLAG_ALLOC) == 0) &&
        ((a_flags & TSK_FS_DIR_WALK_FLAG_UNALLOC) == 0)) {
        a_flags |=
            (TSK_FS_DIR_WALK_FLAG_ALLOC | TSK_FS_DIR_WALK_FLAG_UNALLOC);
    }

    /* if the flags are right, we can collect info that may be needed
     * for an orphan walk.  If the walk fails or stops, the code that
     * calls the action will clear this stuff.
     */
    tsk_take_lock(&a_fs->list_inum_named_lock);
    if ((a_fs->list_inum_named == NULL) && (a_addr == a_fs->root_inum)
        && (a_flags & TSK_FS_DIR_WALK_FLAG_RECURSE)) {
        dinfo.save_inum_named = 1;
    }
    tsk_release_lock(&a_fs->list_inum_named_lock);

    retval = tsk_fs_dir_walk_lcl(a_fs, &dinfo, a_addr, a_flags,
        a_action, a_ptr);

    // if we were saving the list of named files in the temp list,
    // then now save them to FS_INFO
    if (dinfo.save_inum_named == 1) {
        if (retval != TSK_WALK_CONT) {
            /* There was an error and we stopped early, so we should get
             * rid of the partial list we were making.
             */
            tsk_list_free(dinfo.list_inum_named);
            dinfo.list_inum_named = NULL;
        }
        else {
            save_inum_named(a_fs, &dinfo);
        }
    }

    tsk_stack_free(dinfo.stack_seen);

    if (retval == TSK_WALK_ERROR)
        return 1;
    else
        return 0;
}


/** \internal
* Create a dummy NAME entry for the Orphan file virtual directory.
* @param a_fs File system directory is for
* @param a_fs_name NAME structure to populate with data
* @returns 1 on error
*/
uint8_t
tsk_fs_dir_make_orphan_dir_name(TSK_FS_INFO * a_fs,
    TSK_FS_NAME * a_fs_name)
{
    snprintf(a_fs_name->name, a_fs_name->name_size, "$OrphanFiles");
    if (a_fs_name->shrt_name_size > 0)
        a_fs_name->shrt_name[0] = '\0';
    a_fs_name->meta_addr = TSK_FS_ORPHANDIR_INUM(a_fs);
    a_fs_name->flags = TSK_FS_NAME_FLAG_ALLOC;
    a_fs_name->type = TSK_FS_NAME_TYPE_VIRT_DIR;
    return 0;
}

/** \internal
 * Create a dummy META entry for the Orphan file virtual directory.
 * @param a_fs File system directory is for
 * @param a_fs_meta META structure to populate with data
* @returns 1 on error
*/
uint8_t
tsk_fs_dir_make_orphan_dir_meta(TSK_FS_INFO * a_fs,
    TSK_FS_META * a_fs_meta)
{
    a_fs_meta->type = TSK_FS_META_TYPE_VIRT_DIR;
    a_fs_meta->mode = 0;
    a_fs_meta->nlink = 1;

    a_fs_meta->flags = (TSK_FS_META_FLAG_USED | TSK_FS_META_FLAG_ALLOC);
    a_fs_meta->uid = a_fs_meta->gid = 0;
    a_fs_meta->mtime = a_fs_meta->atime = a_fs_meta->ctime =
        a_fs_meta->crtime = 0;
    a_fs_meta->mtime_nano = a_fs_meta->atime_nano = a_fs_meta->ctime_nano =
        a_fs_meta->crtime_nano = 0;

    if (a_fs_meta->name2 == NULL) {
        if ((a_fs_meta->name2 = (TSK_FS_META_NAME_LIST *)
                tsk_malloc(sizeof(TSK_FS_META_NAME_LIST))) == NULL)
            return 1;
        a_fs_meta->name2->next = NULL;
    }

    a_fs_meta->attr_state = TSK_FS_META_ATTR_EMPTY;
    if (a_fs_meta->attr) {
        tsk_fs_attrlist_markunused(a_fs_meta->attr);
    }

    a_fs_meta->addr = TSK_FS_ORPHANDIR_INUM(a_fs);
    strncpy(a_fs_meta->name2->name, "$OrphanFiles",
        TSK_FS_META_NAME_LIST_NSIZE);
    if (a_fs_meta->content_len) {
        TSK_DADDR_T *addr_ptr = (TSK_DADDR_T *) a_fs_meta->content_ptr;
        addr_ptr[0] = 0;
    }
    a_fs_meta->size = 0;
    return 0;
}

/** \internal
 * Searches the list of metadata addresses that are pointed to
 * by unallocated names.  Used to find orphan files. 
 * @param a_fs File system being analyzed.
 * @param a_inum Metadata address to lookup in list.
 * @returns 1 if metadata address is pointed to by an unallocated
 * file name or 0 if not.
 */
uint8_t
tsk_fs_dir_find_inum_named(TSK_FS_INFO * a_fs, TSK_INUM_T a_inum)
{
    uint8_t retval = 0;
    tsk_take_lock(&a_fs->list_inum_named_lock);
    // list can be null if no unallocated file names exist
    if (a_fs->list_inum_named)
        retval = tsk_list_find(a_fs->list_inum_named, a_inum);
    tsk_release_lock(&a_fs->list_inum_named_lock);
    return retval;
}


/* callback that is used by tsk_fs_dir_load_inum_named.  It does nothing
 * because each file system has the code needed to make caller happy. */
static TSK_WALK_RET_ENUM
load_named_dir_walk_cb(TSK_FS_FILE * a_fs_file, const char *a_path,
    void *a_ptr)
{
    return TSK_WALK_CONT;
}


/** \internal
 * Proces a file system and populate a list of the metadata structures
 * that are reachable by file names. This is used to find orphan files.
 * Each file system has code that does the populating.
 */
TSK_RETVAL_ENUM
tsk_fs_dir_load_inum_named(TSK_FS_INFO * a_fs)
{
    tsk_take_lock(&a_fs->list_inum_named_lock);
    if (a_fs->list_inum_named != NULL) {
        tsk_release_lock(&a_fs->list_inum_named_lock);
        if (tsk_verbose)
            fprintf(stderr,
                "tsk_fs_dir_load_inum_named: List already populated.  Skipping walk.\n");
        return TSK_OK;
    }
    tsk_release_lock(&a_fs->list_inum_named_lock);

    if (tsk_verbose)
        fprintf(stderr,
            "tsk_fs_dir_load_inum_named: Performing dir walk to find named files\n");

    /* Do a dir_walk.  There is internal caching code that will populate
     * the structure.  The callback is really a dummy call.  This could
     * be made more efficient in the future (not do callbacks...).  We
     * specify UNALLOC only as a flag on the assumption that there will
     * be fewer callbacks for UNALLOC than ALLOC.
     */
    if (tsk_fs_dir_walk(a_fs, a_fs->root_inum,
            TSK_FS_NAME_FLAG_UNALLOC | TSK_FS_DIR_WALK_FLAG_RECURSE |
            TSK_FS_DIR_WALK_FLAG_NOORPHAN, load_named_dir_walk_cb, NULL)) {
        tsk_error_errstr2_concat
            ("- tsk_fs_dir_load_inum_named: identifying inodes allocated by file names");
        return TSK_ERR;
    }

    return TSK_OK;
}


/* Used to keep state while populating the orphan directory */
typedef struct {
    TSK_FS_NAME *fs_name;       // temp name structure used when adding entries to fs_dir
    TSK_FS_DIR *fs_dir;         // unique names are added to this.  represents contents of OrphanFiles directory
    TSK_LIST *orphan_subdir_list;       // keep track of files that can already be accessed via orphan directory
} FIND_ORPHAN_DATA;

/* Used to process orphan directories and make sure that their contents
 * are now marked as reachable */
static TSK_WALK_RET_ENUM
load_orphan_dir_walk_cb(TSK_FS_FILE * a_fs_file, const char *a_path,
    void *a_ptr)
{
    FIND_ORPHAN_DATA *data = (FIND_ORPHAN_DATA *) a_ptr;

    if( a_fs_file == NULL ) {
        return TSK_WALK_ERROR;
    }

    // ignore DOT entries
    if ((a_fs_file->name) && (a_fs_file->name->name) &&
        (TSK_FS_ISDOT(a_fs_file->name->name)))
        return TSK_WALK_CONT;

    // add this entry to the orphan list
    if (a_fs_file->meta) {
        /* Stop if we hit an allocated entry.  We shouldn't get these, but did
         * have some trouble images that went into allocated clusters on
         * a FAT file system. */
        if (a_fs_file->meta->flags & TSK_FS_META_FLAG_ALLOC) {
            if (tsk_verbose) {
                tsk_fprintf(stderr,
                    "load_orphan_dir_walk_cb: Skipping an allocated file (ID: %"
                    PRIuINUM ")\n", a_fs_file->meta->addr);
            }
            return TSK_WALK_STOP;
        }

        /* check if we have already added it as an orphan (in a subdirectory)
         * Not entirely sure how possible this is, but it was added while
         * debugging an infinite loop problem. */
        if (tsk_list_find(data->orphan_subdir_list, a_fs_file->meta->addr)) {
            if (tsk_verbose)
                fprintf(stderr,
                    "load_orphan_dir_walk_cb: Detected loop with address %"
                    PRIuINUM, a_fs_file->meta->addr);
            return TSK_WALK_STOP;
        }

        tsk_list_add(&data->orphan_subdir_list, a_fs_file->meta->addr);

        /* FAT file systems spend a lot of time hunting for parent
         * directory addresses, so we put this code in here to save
         * the info when we have it. */
        if ((TSK_FS_IS_DIR_META(a_fs_file->meta->type))
            && (TSK_FS_TYPE_ISFAT(a_fs_file->fs_info->ftype))) {
            // Make sure a_fs_file->name->par_addr is not accessed when
            // a_fs_file->name is NULL
            if ((a_fs_file->name) &&
                (fatfs_dir_buf_add((FATFS_INFO *) a_fs_file->fs_info,
                    a_fs_file->name->par_addr, a_fs_file->meta->addr)))
                return TSK_WALK_ERROR;
        }
    }

    return TSK_WALK_CONT;
}

/* used to identify the unnamed metadata structures */
static TSK_WALK_RET_ENUM
find_orphan_meta_walk_cb(TSK_FS_FILE * a_fs_file, void *a_ptr)
{
    FIND_ORPHAN_DATA *data = (FIND_ORPHAN_DATA *) a_ptr;
    TSK_FS_INFO *fs = a_fs_file->fs_info;

    /* We want only orphans, then check if this
     * inode is in the seen list
     */
    tsk_take_lock(&fs->list_inum_named_lock);
    if ((fs->list_inum_named)
        && (tsk_list_find(fs->list_inum_named, a_fs_file->meta->addr))) {
        tsk_release_lock(&fs->list_inum_named_lock);
        return TSK_WALK_CONT;
    }
    tsk_release_lock(&fs->list_inum_named_lock);

    // check if we have already added it as an orphan (in a subdirectory)
    if (tsk_list_find(data->orphan_subdir_list, a_fs_file->meta->addr)) {
        return TSK_WALK_CONT;
    }

    // use their name if they have one
    if (a_fs_file->meta->name2 != NULL &&
        strlen(a_fs_file->meta->name2->name) > 0) {
        strncpy(data->fs_name->name, a_fs_file->meta->name2->name,
            data->fs_name->name_size);
    }
    else {
        snprintf(data->fs_name->name, data->fs_name->name_size,
            "OrphanFile-%" PRIuINUM, a_fs_file->meta->addr);
    }
    data->fs_name->meta_addr = a_fs_file->meta->addr;
    /* unalloc MFT entries have their sequence number incremented
     * when they are unallocated.  Decrement it in the file name so
     * that it matches the typical situation where the name is one
     * less. */
    data->fs_name->meta_seq = a_fs_file->meta->seq - 1;
    data->fs_name->flags = TSK_FS_NAME_FLAG_UNALLOC;
    data->fs_name->type = TSK_FS_NAME_TYPE_UNDEF;

    if (tsk_fs_dir_add(data->fs_dir, data->fs_name))
        return TSK_WALK_ERROR;

    /* FAT file systems spend a lot of time hunting for parent
     * directory addresses, so we put this code in here to save
     * the info when we have it. */
    if (TSK_FS_TYPE_ISFAT(fs->ftype)) {
        if (fatfs_dir_buf_add((FATFS_INFO *) fs,
                TSK_FS_ORPHANDIR_INUM(fs), a_fs_file->meta->addr))
            return TSK_WALK_ERROR;
    }

    /* Go into directories to mark their contents as "seen" */
    if (a_fs_file->meta->type == TSK_FS_META_TYPE_DIR) {

        if (tsk_verbose)
            fprintf(stderr,
                "find_orphan_meta_walk_cb: Going into directory %" PRIuINUM
                " to mark contents as seen\n", a_fs_file->meta->addr);

        if (tsk_fs_dir_walk(fs, a_fs_file->meta->addr,
                TSK_FS_DIR_WALK_FLAG_UNALLOC | TSK_FS_DIR_WALK_FLAG_RECURSE
                | TSK_FS_DIR_WALK_FLAG_NOORPHAN, load_orphan_dir_walk_cb,
                data)) {
            tsk_error_errstr2_concat
                (" - find_orphan_meta_walk_cb: identifying inodes allocated by file names");
            return TSK_WALK_ERROR;
        }
    }

    return TSK_WALK_CONT;
}



/** \internal
 * Adds the fake metadata entry in the FS_DIR->fs_file struct for the orphan files directory
 *
 * @returns 1 on error
 */
static uint8_t
tsk_fs_dir_add_orphan_dir_meta(TSK_FS_INFO * a_fs, TSK_FS_DIR * a_fs_dir)
{
    // populate the fake FS_FILE structure for the "Orphan Directory"
    if ((a_fs_dir->fs_file = tsk_fs_file_alloc(a_fs)) == NULL) {
        return 1;
    }

    if ((a_fs_dir->fs_file->meta =
            tsk_fs_meta_alloc(sizeof(TSK_DADDR_T))) == NULL) {
        return 1;
    }

    if (tsk_fs_dir_make_orphan_dir_meta(a_fs, a_fs_dir->fs_file->meta)) {
        return 1;
    }
    return 0;
}

/** \internal
 * Search the file system for orphan files and create the orphan file directory.
 * @param a_fs File system to search
 * @param a_fs_dir Structure to store the orphan file directory info in.
 */
TSK_RETVAL_ENUM
tsk_fs_dir_find_orphans(TSK_FS_INFO * a_fs, TSK_FS_DIR * a_fs_dir)
{
    FIND_ORPHAN_DATA data;
    size_t i;

    tsk_take_lock(&a_fs->orphan_dir_lock);

    if (a_fs->orphan_dir != NULL) {
        if (tsk_fs_dir_copy(a_fs->orphan_dir, a_fs_dir)) {
            tsk_release_lock(&a_fs->orphan_dir_lock);
            return TSK_ERR;
        }

        if (tsk_fs_dir_add_orphan_dir_meta(a_fs, a_fs_dir)) {
            tsk_release_lock(&a_fs->orphan_dir_lock);
            return TSK_ERR;
        }

        tsk_release_lock(&a_fs->orphan_dir_lock);
        return TSK_OK;
    }

    if (tsk_verbose)
        fprintf(stderr,
            "tsk_fs_dir_find_orphans: Searching for orphan files\n");

    memset(&data, 0, sizeof(FIND_ORPHAN_DATA));

    /* We first need to determine which of the unallocated meta structures
     * have a name pointing to them.  We cache this data, so see if it is
     * already known. */
    if (tsk_fs_dir_load_inum_named(a_fs) != TSK_OK) {
        tsk_release_lock(&a_fs->orphan_dir_lock);
        return TSK_ERR;
    }
    // note that list_inum_named could still be NULL if there are no deleted names.

    /* Now we walk the unallocated metadata structures and find ones that are
     * not named.  The callback will add the names to the FS_DIR structure.
     */
    data.fs_dir = a_fs_dir;

    // allocate a name once so that we will reuse for each name we add to FS_DIR
    if ((data.fs_name = tsk_fs_name_alloc(256, 0)) == NULL) {
        tsk_release_lock(&a_fs->orphan_dir_lock);
        return TSK_ERR;
    }

    if (tsk_verbose)
        fprintf(stderr,
            "tsk_fs_dir_find_orphans: Performing inode_walk to find unnamed metadata structures\n");

    if (tsk_fs_meta_walk(a_fs, a_fs->first_inum, a_fs->last_inum,
            TSK_FS_META_FLAG_UNALLOC | TSK_FS_META_FLAG_USED,
            find_orphan_meta_walk_cb, &data)) {
        tsk_fs_name_free(data.fs_name);
        if (data.orphan_subdir_list) {
            tsk_list_free(data.orphan_subdir_list);
            data.orphan_subdir_list = NULL;
        }
        tsk_release_lock(&a_fs->orphan_dir_lock);
        return TSK_ERR;
    }

    tsk_fs_name_free(data.fs_name);
    data.fs_name = NULL;


    if (tsk_verbose)
        fprintf(stderr,
            "tsk_fs_dir_find_orphans: De-duping orphan files and directories\n");

    /* do some cleanup on the final list. This cleanup will compare the
     * entries in the root orphan directory with files that can be accessed
     * from subdirectories of the orphan directory.  These entries will exist if
     * they were added before their parent directory was added to the orphan directory. */
    for (i = 0; i < a_fs_dir->names_used; i++) {
        if (tsk_list_find(data.orphan_subdir_list,
                a_fs_dir->names[i].meta_addr)) {
            if (a_fs_dir->names_used > 1) {
                tsk_fs_name_copy(&a_fs_dir->names[i],
                    &a_fs_dir->names[a_fs_dir->names_used - 1]);
            }
            tsk_fs_dir_free_name_internal(&a_fs_dir->names[a_fs_dir->names_used-1]);
            a_fs_dir->names_used--;
        }
    }

    if (data.orphan_subdir_list) {
        tsk_list_free(data.orphan_subdir_list);
        data.orphan_subdir_list = NULL;
    }


    // make copy of this so that we don't need to do it again.
    if ((a_fs->orphan_dir =
            tsk_fs_dir_alloc(a_fs, a_fs_dir->addr,
                a_fs_dir->names_used)) == NULL) {
        tsk_release_lock(&a_fs->orphan_dir_lock);
        return TSK_ERR;
    }

    if (tsk_fs_dir_copy(a_fs_dir, a_fs->orphan_dir)) {
        tsk_release_lock(&a_fs->orphan_dir_lock);
        return TSK_ERR;
    }

    // populate the fake FS_FILE structure in the struct to be returned for the "Orphan Directory"
    if (tsk_fs_dir_add_orphan_dir_meta(a_fs, a_fs_dir)) {
        tsk_release_lock(&a_fs->orphan_dir_lock);
        return TSK_ERR;
    }

    tsk_release_lock(&a_fs->orphan_dir_lock);
    return TSK_OK;
}

/** \internal
* return a hash of the passed in string. We use this
* for full paths.
* From: http://www.cse.yorku.ca/~oz/hash.html
* @param str  The path to hash
*/
uint32_t tsk_fs_dir_hash(const char *str) {
    uint32_t hash = 5381;
    int c;

    while ((c = *str++)) {
        // skip slashes -> normalizes leading/ending/double slashes
        if (c == '/')
            continue;
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }

    return hash;
}
