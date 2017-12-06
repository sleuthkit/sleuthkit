/*
 * fs_file
 * The Sleuth Kit 
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2008-2011 Brian Carrier.  All Rights reserved
 *
 * This software is distributed under the Common Public License 1.0
 *
 */

/**
* \file fs_file.c
 * Create, manage, etc. the TSK_FS_FILE structures. 
 */

#include "tsk_fs_i.h"


/**
 * \internal
 * Allocate a new FS_FILE structure
 * @param a_fs File system fiel will be in.
 * @returns NULL on error
 */
TSK_FS_FILE *
tsk_fs_file_alloc(TSK_FS_INFO * a_fs)
{
    TSK_FS_FILE *fs_file;

    fs_file = (TSK_FS_FILE *) tsk_malloc(sizeof(TSK_FS_FILE));
    if (fs_file == NULL)
        return NULL;
    fs_file->fs_info = a_fs;
    fs_file->tag = TSK_FS_FILE_TAG;
    return fs_file;
}

/** \internal
 *
 * Reset the meta and name structures.
 * @param a_fs_file File to reset
 */
void
tsk_fs_file_reset(TSK_FS_FILE * a_fs_file)
{
    if (a_fs_file->meta)
        tsk_fs_meta_reset(a_fs_file->meta);
    if (a_fs_file->name)
        tsk_fs_name_reset(a_fs_file->name);
}


/**
 * \ingroup fslib
 * Close an open file.
 * @param a_fs_file Pointer to open file
 */
void
tsk_fs_file_close(TSK_FS_FILE * a_fs_file)
{
    if ((a_fs_file == NULL) || (a_fs_file->tag != TSK_FS_FILE_TAG))
        return;

    a_fs_file->tag = 0;

    if (a_fs_file->meta) {
        tsk_fs_meta_close(a_fs_file->meta);
        a_fs_file->meta = NULL;
    }
    if (a_fs_file->name) {
        tsk_fs_name_free(a_fs_file->name);
        a_fs_file->name = NULL;
    }

    free(a_fs_file);
}



/** 
* \ingroup fslib
*
* Open a file given its metadata address. This function loads the metadata
* and returns a handle that can be used to read and process the file.   Note
* that the returned TSK_FS_FILE structure will not have the file name set because
* it was not used to load the file and this function does not search the 
* directory structure to find the name that points to the address.   In general,
* if you know the metadata address of a file, this function is more efficient 
* then tsk_fs_file_open, which first maps a file name to the metadata address 
* and then opens the file using this function. 
*
* @param a_fs File system to analyze
* @param a_fs_file Structure to store file data in or NULL to have one allocated. 
* @param a_addr Metadata address of file to lookup
* @returns NULL on error
*/
TSK_FS_FILE *
tsk_fs_file_open_meta(TSK_FS_INFO * a_fs,
    TSK_FS_FILE * a_fs_file, TSK_INUM_T a_addr)
{
    TSK_FS_FILE *fs_file;

    if ((a_fs == NULL) || (a_fs->tag != TSK_FS_INFO_TAG)) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr
            ("tsk_fs_file_open_meta: called with NULL or unallocated structures");
        return NULL;
    }

    fs_file = a_fs_file;
    if (fs_file == NULL) {
        if ((fs_file = tsk_fs_file_alloc(a_fs)) == NULL)
            return NULL;
    }
    else {
        /* if the structure passed has a name structure, free it
         * because we won't use it. */
        if (fs_file->name) {
            tsk_fs_name_free(fs_file->name);
            fs_file->name = NULL;
        }

        // reset the rest of it
        tsk_fs_file_reset(fs_file);
    }

    if (a_fs->file_add_meta(a_fs, fs_file, a_addr)) {
        if (a_fs_file == NULL)
            tsk_fs_file_close(fs_file);
        return NULL;
    }

    return fs_file;
}


/** 
* \ingroup fslib
* Return the handle structure for a specific file, given its full path. Note that
* if you have the metadata address fo the file, then tsk_fs_file_open_meta() is a
* more efficient approach. 
*
* @param a_fs File system to analyze
* @param a_fs_file Structure to store file data in or NULL to have one allocated. 
* @param a_path Path of file to open
* @returns NULL on error
*/
TSK_FS_FILE *
tsk_fs_file_open(TSK_FS_INFO * a_fs,
    TSK_FS_FILE * a_fs_file, const char *a_path)
{
    TSK_INUM_T inum;
    int8_t retval;
    TSK_FS_FILE *fs_file = NULL;
    TSK_FS_NAME *fs_name = NULL;

    if ((a_fs == NULL) || (a_fs->tag != TSK_FS_INFO_TAG)) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr
            ("tsk_fs_file_open: called with NULL or unallocated structures");
        return NULL;
    }

    // allocate a structure to store the name in
    if ((fs_name = tsk_fs_name_alloc(128, 32)) == NULL) {
        return NULL;
    }

    retval = tsk_fs_path2inum(a_fs, a_path, &inum, fs_name);
    if (retval == -1) {
        tsk_fs_name_free(fs_name);
        return NULL;
    }
    else if (retval == 1) {
        tsk_fs_name_free(fs_name);
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("tsk_fs_file_open: path not found: %s",
            a_path);
        return NULL;
    }


    fs_file = tsk_fs_file_open_meta(a_fs, a_fs_file, inum);
    if (fs_file) {
        // Add the name to the structure
        fs_file->name = fs_name;

        // path2inum did not put this in there...
        fs_name->meta_seq = fs_file->meta->seq;
    }
    else {
        tsk_fs_name_free(fs_name);
    }

    return fs_file;
}


/** \internal
 * Check the arguments for the tsk_fs_file_attr_XXX functions
 * and load the attributes if needed.
 * @param a_fs_file File argument to check.
 * @param a_func Name of function that this is checking for (for error messages)
 * @returns 1 on error
 */
static int
tsk_fs_file_attr_check(TSK_FS_FILE * a_fs_file, char *a_func)
{
    TSK_FS_INFO *fs;
    // check the FS_INFO, FS_FILE structures
    if ((a_fs_file == NULL) || (a_fs_file->meta == NULL)
        || (a_fs_file->fs_info == NULL)) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("%s: called with NULL pointers", a_func);
        return 1;
    }
    else if (a_fs_file->meta->tag != TSK_FS_META_TAG) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("%s: called with unallocated structures",
            a_func);
        return 1;
    }
    fs = a_fs_file->fs_info;

    // If the attributes haven't been loaded, then load them.
    if (a_fs_file->meta->attr_state == TSK_FS_META_ATTR_ERROR) {
        tsk_error_set_errno(TSK_ERR_FS_INODE_COR);
        tsk_error_set_errstr("%s: called for file with corrupt data",
            a_func);
        return 1;
    }
    else if ((a_fs_file->meta->attr_state != TSK_FS_META_ATTR_STUDIED)
        || (a_fs_file->meta->attr == NULL)) {
        if (fs->load_attrs(a_fs_file)) {
            return 1;
        }
    }
    return 0;
}

/** \ingroup fslib
 * Return the number of attributes in the file. 
 *
 * @param a_fs_file File to return attribute count for
 * @returns number of attributes in file
 */
int
tsk_fs_file_attr_getsize(TSK_FS_FILE * a_fs_file)
{
    if (tsk_fs_file_attr_check(a_fs_file, "tsk_fs_file_attr_getsize")) {
        // @@@ Not sure if we should be ignoring this error or not...
        // Just added the reset because we were returning 0 with error codes set
        tsk_error_reset();
        return 0;
    }

    return tsk_fs_attrlist_get_len(a_fs_file->meta->attr);
}

/** \ingroup fslib
 * Get a file's attribute based on the 0-based index in the list (and not type, id pair).
 * @param a_fs_file File to get attributes from.
 * @param a_idx 0-based index of attribute to return.
 * @returns Pointer to attribute or NULL on error
 */
const TSK_FS_ATTR *
tsk_fs_file_attr_get_idx(TSK_FS_FILE * a_fs_file, int a_idx)
{
    if (tsk_fs_file_attr_check(a_fs_file, "tsk_fs_file_attr_get_idx"))
        return NULL;

    return tsk_fs_attrlist_get_idx(a_fs_file->meta->attr, a_idx);
}

/** \ingroup fslib
* Return the default attribute for the file
* @param a_fs_file File to get data from
* @returns NULL on error
*/
const TSK_FS_ATTR *
tsk_fs_file_attr_get(TSK_FS_FILE * a_fs_file)
{
    TSK_FS_ATTR_TYPE_ENUM type;
    TSK_FS_INFO *fs;

    if (tsk_fs_file_attr_check(a_fs_file, "tsk_fs_file_attr_get"))
        return NULL;

    // since they did not give us a type, get the default for the file
    fs = a_fs_file->fs_info;
    type = fs->get_default_attr_type(a_fs_file);

    return tsk_fs_attrlist_get(a_fs_file->meta->attr, type);
}

/** \ingroup fslib
* Return a specific type and id attribute for the file.  
* @param a_fs_file File to get data from
* @param a_type Type of attribute to load
* @param a_id Id of attribute to load 
* @param a_id_used Set to 1 if ID is actually set or 0 to use default
* @returns NULL on error
*/
const TSK_FS_ATTR *
tsk_fs_file_attr_get_type(TSK_FS_FILE * a_fs_file,
    TSK_FS_ATTR_TYPE_ENUM a_type, uint16_t a_id, uint8_t a_id_used)
{
    if (tsk_fs_file_attr_check(a_fs_file, "tsk_fs_file_attr_get_type"))
        return NULL;

    if (a_id_used)
        return tsk_fs_attrlist_get_id(a_fs_file->meta->attr, a_type, a_id);
    else
        return tsk_fs_attrlist_get(a_fs_file->meta->attr, a_type);
}

/** \ingroup fslib
* Return a specific attribute by its ID for the file.  
* @param a_fs_file File to get data from
* @param a_id Id of attribute to load 
* @returns NULL on error
*/
const TSK_FS_ATTR *
tsk_fs_file_attr_get_id(TSK_FS_FILE * a_fs_file, uint16_t a_id)
{
    int i, size;
    if (tsk_fs_file_attr_check(a_fs_file, "tsk_fs_file_attr_get_type"))
        return NULL;

    size = tsk_fs_file_attr_getsize(a_fs_file);
    for (i = 0; i < size; i++) {
        const TSK_FS_ATTR *fs_attr =
            tsk_fs_file_attr_get_idx(a_fs_file, i);
        if (fs_attr == NULL)
            return NULL;

        if (fs_attr->id == a_id)
            return fs_attr;
    }
    tsk_error_set_errno(TSK_ERR_FS_ATTR_NOTFOUND);
    tsk_error_set_errstr
        ("tsk_fs_attr_get_id: Attribute ID %d not found", a_id);
    return NULL;
}


/**
* \ingroup fslib
 * Process a specific attribute in a file and call a callback function with the file contents. The callback will be 
 * called with chunks of data that are fs->block_size or less.  The address given in the callback
 * will be correct only for raw files (when the raw file contents were stored in the block).  For
 * compressed and sparse files, the address may be zero. If the file system you are analyzing does
 * not have multiple attributes per file, then you can use tsk_fs_file_walk().  For incomplete or 
 * corrupt files, some missing runs will be identified as SPARSE and zeros will be returned in the content.
 *
 * @param a_fs_file File to process
 * @param a_type Attribute type to process
 * @param a_id Id if attribute to process 
 * @param a_flags Flags to use while processing file
 * @param a_action Callback action to call with content
 * @param a_ptr Pointer that will passed to callback
 * @returns 1 on error and 0 on success.
 */
uint8_t
tsk_fs_file_walk_type(TSK_FS_FILE * a_fs_file,
    TSK_FS_ATTR_TYPE_ENUM a_type, uint16_t a_id,
    TSK_FS_FILE_WALK_FLAG_ENUM a_flags, TSK_FS_FILE_WALK_CB a_action,
    void *a_ptr)
{
    const TSK_FS_ATTR *fs_attr;

    // clean up any error messages that are lying around
    tsk_error_reset();

    // check the FS_INFO, FS_FILE structures
    if ((a_fs_file == NULL) || (a_fs_file->meta == NULL)
        || (a_fs_file->fs_info == NULL)) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr
            ("tsk_fs_file_walk: called with NULL pointers");
        return 1;
    }
    else if ((a_fs_file->fs_info->tag != TSK_FS_INFO_TAG)
        || (a_fs_file->meta->tag != TSK_FS_META_TAG)) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr
            ("tsk_fs_file_walk: called with unallocated structures");
        return 1;
    }

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "tsk_fs_file_walk: Processing file %" PRIuINUM "\n",
            a_fs_file->meta->addr);

    if ((fs_attr =
            tsk_fs_file_attr_get_type(a_fs_file, a_type, a_id,
                (a_flags & TSK_FS_FILE_WALK_FLAG_NOID) ? 0 : 1)) == NULL)
        return 1;

    return tsk_fs_attr_walk(fs_attr, a_flags, a_action, a_ptr);
}

/**
* \ingroup fslib
 * Process a file and call a callback function with the file contents. The callback will be 
 * called with chunks of data that are fs->block_size or less.  The address given in the callback
 * will be correct only for raw files (when the raw file contents were stored in the block).  For
 * compressed and sparse files, the address may be zero.  If a file has multiple attributes,
 * such as NTFS files, this  function uses the default one ($DATA for files, $IDX_ROOT for directories).
 * Use tsk_fs_file_walk_type to specify an attribute.
 *
 * @param a_fs_file File to process
 * @param a_flags Flags to use while processing file
 * @param a_action Callback action to call with content
 * @param a_ptr Pointer that will passed to callback
 * @returns 1 on error and 0 on success.
 */
uint8_t
tsk_fs_file_walk(TSK_FS_FILE * a_fs_file,
    TSK_FS_FILE_WALK_FLAG_ENUM a_flags,
    TSK_FS_FILE_WALK_CB a_action, void *a_ptr)
{
    const TSK_FS_ATTR *fs_attr;

    // clean up any error messages that are lying around
    tsk_error_reset();

    // check the FS_INFO, FS_FILE structures
    if ((a_fs_file == NULL) || (a_fs_file->meta == NULL)
        || (a_fs_file->fs_info == NULL)) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr
            ("tsk_fs_file_walk: called with NULL pointers");
        return 1;
    }
    else if ((a_fs_file->fs_info->tag != TSK_FS_INFO_TAG)
        || (a_fs_file->meta->tag != TSK_FS_META_TAG)) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr
            ("tsk_fs_file_walk: called with unallocated structures");
        return 1;
    }

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "tsk_fs_file_walk: Processing file %" PRIuINUM "\n",
            a_fs_file->meta->addr);

    if ((fs_attr = tsk_fs_file_attr_get(a_fs_file)) == NULL)
        return 1;

    return tsk_fs_attr_walk(fs_attr, a_flags, a_action, a_ptr);
}


/**
* \ingroup fslib
 * Read the contents of a specific attribute of a file using a typical read() type interface and be
 * able specify a specific attribute to read (applies only to file systems with multiple attributes
 * per file, such as NTFS).  0s are returned for missing runs of files. 
 * 
 * @param a_fs_file The file to read from
 * @param a_type The type of attribute to load
 * @param a_id The id of attribute to load (use 0 and set a_flags if you do not care)
 * @param a_offset The byte offset to start reading from.
 * @param a_buf The buffer to read the data into.
 * @param a_len The number of bytes to read from the file.
 * @param a_flags Flags to use while reading
 * @returns The number of bytes read or -1 on error (incl if offset is past EOF).
 */
ssize_t
tsk_fs_file_read_type(TSK_FS_FILE * a_fs_file,
    TSK_FS_ATTR_TYPE_ENUM a_type, uint16_t a_id, TSK_OFF_T a_offset,
    char *a_buf, size_t a_len, TSK_FS_FILE_READ_FLAG_ENUM a_flags)
{
    const TSK_FS_ATTR *fs_attr;

    // clean up any error messages that are lying around
    tsk_error_reset();

    // check the FS_INFO, FS_FILE structures
    if ((a_fs_file == NULL) || (a_fs_file->meta == NULL)
        || (a_fs_file->fs_info == NULL)) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr
            ("tsk_fs_file_read: called with NULL pointers");
        return -1;
    }
    else if ((a_fs_file->fs_info->tag != TSK_FS_INFO_TAG)
        || (a_fs_file->meta->tag != TSK_FS_META_TAG)) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr
            ("tsk_fs_file_read: called with unallocated structures");
        return -1;
    }

    if ((fs_attr =
            tsk_fs_file_attr_get_type(a_fs_file, a_type, a_id,
                (a_flags & TSK_FS_FILE_READ_FLAG_NOID) ? 0 : 1)) == NULL) {
        return -1;
    }

    return tsk_fs_attr_read(fs_attr, a_offset, a_buf, a_len, a_flags);
}


/**
 * \ingroup fslib
 * Read the contents of a specific attribute of a file using a typical read() type interface.
 * 0s are returned for missing runs of files. 
 * 
 * @param a_fs_file The inode structure of the file to read.
 * @param a_offset The byte offset to start reading from.
 * @param a_buf The buffer to read the data into.
 * @param a_len The number of bytes to read from the file.
 * @param a_flags Flags to use while reading
 * @returns The number of bytes read or -1 on error (incl if offset is past EOF).
 */
ssize_t
tsk_fs_file_read(TSK_FS_FILE * a_fs_file,
    TSK_OFF_T a_offset, char *a_buf, size_t a_len,
    TSK_FS_FILE_READ_FLAG_ENUM a_flags)
{
    const TSK_FS_ATTR *fs_attr;

    if ((a_fs_file == NULL) || (a_fs_file->fs_info == NULL)) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("tsk_fs_file_read: fs_info is NULL");
        return -1;
    }

    if ((fs_attr = tsk_fs_file_attr_get(a_fs_file)) == NULL) {
        return -1;
    }

    return tsk_fs_attr_read(fs_attr, a_offset, a_buf, a_len, a_flags);
}

/**
 * Returns a string representation of the security attributes of a file.
 *
 * @param a_fs_file The file to get security info about.
 * @param sid_str A pointer to a pointer that will contain the SID string.  This function will allocate the string and the caller must free it. 
 * @returns 0 on success or 1 on error.
 */
uint8_t
tsk_fs_file_get_owner_sid(TSK_FS_FILE * a_fs_file, char **sid_str)
{
    if ((a_fs_file == NULL) || (a_fs_file->fs_info == NULL)
        || (a_fs_file->meta == NULL) || (sid_str == NULL)) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("tsk_fs_file_get_owner_sid: fs_info is NULL");
        return 1;
    }

    // Make sure the function pointer is not NULL.
    // This function will only work on NTFS filesystems. 
    if (!a_fs_file->fs_info->fread_owner_sid) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_UNSUPFUNC);
        tsk_error_set_errstr("Unsupported function");
        return 1;
    }

    return a_fs_file->fs_info->fread_owner_sid(a_fs_file, sid_str);
}


/**
 * Internal struct used for hash calculations
 */
typedef struct {
    TSK_BASE_HASH_ENUM flags;
    TSK_MD5_CTX md5_context;
    TSK_SHA_CTX sha1_context;
} TSK_FS_HASH_DATA;

/**
 * Helper function for tsk_fs_file_get_md5
 */
TSK_WALK_RET_ENUM
tsk_fs_file_hash_calc_callback(TSK_FS_FILE * file, TSK_OFF_T offset,
    TSK_DADDR_T addr, char *buf, size_t size,
    TSK_FS_BLOCK_FLAG_ENUM a_flags, void *ptr)
{
    TSK_FS_HASH_DATA *hash_data = (TSK_FS_HASH_DATA *) ptr;
    if (hash_data == NULL)
        return TSK_WALK_CONT;

    if (hash_data->flags & TSK_BASE_HASH_MD5) {
        TSK_MD5_Update(&(hash_data->md5_context), (unsigned char *) buf,
            (unsigned int) size);
    }

    if (hash_data->flags & TSK_BASE_HASH_SHA1) {
        TSK_SHA_Update(&(hash_data->sha1_context), (unsigned char *) buf,
            (unsigned int) size);
    }


    return TSK_WALK_CONT;
}

/**
 * Returns a string containing the md5 hash of the given file
 *
 * @param a_fs_file The file to calculate the hash of
 * @param a_hash_results The results will be stored here (must be allocated beforehand)
 * @param a_flags Indicates which hash algorithm(s) to use
 * @returns 0 on success or 1 on error
 */
extern uint8_t
tsk_fs_file_hash_calc(TSK_FS_FILE * a_fs_file,
    TSK_FS_HASH_RESULTS * a_hash_results, TSK_BASE_HASH_ENUM a_flags)
{
    TSK_FS_HASH_DATA hash_data;

    if ((a_fs_file == NULL) || (a_fs_file->fs_info == NULL)
        || (a_fs_file->meta == NULL)) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("tsk_fs_file_hash_calc: fs_info is NULL");
        return 1;
    }

    if (a_hash_results == NULL) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr
            ("tsk_fs_file_hash_calc: hash_results is NULL");
        return 1;
    }

    if (a_flags & TSK_BASE_HASH_MD5) {
        TSK_MD5_Init(&(hash_data.md5_context));
    }
    if (a_flags & TSK_BASE_HASH_SHA1) {
        TSK_SHA_Init(&(hash_data.sha1_context));
    }

    hash_data.flags = a_flags;
    if (tsk_fs_file_walk(a_fs_file, TSK_FS_FILE_WALK_FLAG_NONE,
            tsk_fs_file_hash_calc_callback, (void *) &hash_data)) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("tsk_fs_file_hash_calc: error in file walk");
        return 1;
    }

    a_hash_results->flags = a_flags;
    if (a_flags & TSK_BASE_HASH_MD5) {
        TSK_MD5_Final(a_hash_results->md5_digest,
            &(hash_data.md5_context));
    }
    if (a_flags & TSK_BASE_HASH_SHA1) {
        TSK_SHA_Final(a_hash_results->sha1_digest,
            &(hash_data.sha1_context));
    }

    return 0;
}
