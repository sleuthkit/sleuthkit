/*
** The Sleuth Kit
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2006-2011 Brian Carrier, Basis Technology.  All Rights reserved
** Copyright (c) 2003-2005 Brian Carrier.  All rights reserved
**
** TASK
v** Copyright (c) 2002-2003 Brian Carrier, @stake Inc.  All rights reserved
**
** Copyright (c) 1997,1998,1999, International Business Machines
** Corporation and others. All Rights Reserved.
*/

/**
*\file yaffs.cpp
* Contains the internal TSK YAFFS2 file system functions.
*/

/* TCT
* LICENSE
*	This software is distributed under the IBM Public License.
* AUTHOR(S)
*	Wietse Venema
*	IBM T.J. Watson Research
*	P.O. Box 704
*	Yorktown Heights, NY 10598, USA
--*/

#include <vector>
#include <map>
#include <algorithm>
#include <string>
#include <set>
#include <string.h>

#include "tsk_fs_i.h"
#include "tsk_yaffs.h"
#include "tsk_fs.h"

/*
* Implementation Notes:
*    - As inode, we use object id and a version number derived from the 
*      number of unique sequence ids for the object still left in the
*      file system.
*
*    - The version numbers start at 1 and increase as they get closer to
*      the the latest version.  Version number 0 is a special version
*      that is equivalent to the latest version (without having to know
*      the latest version number.)
*
*    - Since inodes are composed using the object id in the least 
*      significant bits and the version up higher, requesting the
*      inode that matches the object id you are looking for will
*      retrieve the latest version of this object.
*
*    - Files always exist in the latest version of their parent directory 
*      only.
*
*    - Filenames are not unique even with attached version numbers, since
*      version numbers are namespaced by inode.
*
*    - The cache stores a lot of info via the structure.  As this is
*      used for investigations, we assume these decisions will be updated
*      to expose the most useful view of this log based file system.  TSK
*      doesn't seem have a real way to expose a versioned view of a log
*      based file system like this.  Shoehorning it into the framework
*      ends up dropping some information.  I looked at using resource 
*      streams as versions, but the abstraction breaks quickly.
*
*/

static const int TWELVE_BITS_MASK = 0xFFF; // Only keep 12 bits

static uint8_t 
    yaffsfs_read_header(YAFFSFS_INFO *yfs, YaffsHeader ** header, TSK_OFF_T offset);
static uint8_t
    yaffsfs_load_attrs(TSK_FS_FILE *file);

/**
 * Generate an inode number based on the file's object and version numbers
 */
static TSK_RETVAL_ENUM
    yaffscache_obj_id_and_version_to_inode(uint32_t obj_id, uint32_t version_num, TSK_INUM_T *inode) {
        if ((obj_id & ~YAFFS_OBJECT_ID_MASK) != 0) {
            return TSK_ERR;
        }

        if ((version_num & ~YAFFS_VERSION_NUM_MASK) != 0) {
            return TSK_ERR;
        }

        *inode = obj_id | (version_num << YAFFS_VERSION_NUM_SHIFT);
        return TSK_OK;
}

/**
 * Given the TSK-generated inode address, extract the object id and version number from it
 */
static TSK_RETVAL_ENUM
    yaffscache_inode_to_obj_id_and_version(TSK_INUM_T inode, uint32_t *obj_id, uint32_t *version_num) {
        *obj_id = inode & YAFFS_OBJECT_ID_MASK;
        *version_num = (inode >> YAFFS_VERSION_NUM_SHIFT) & YAFFS_VERSION_NUM_MASK;

        return TSK_OK;
}

/*
* Order it like yaffs2.git does -- sort by (seq_num, offset/block)
*/
static int
    yaffscache_chunk_compare(YaffsCacheChunk *curr, uint32_t addee_obj_id, TSK_OFF_T addee_offset, uint32_t addee_seq_number)
{
    if (curr->ycc_obj_id == addee_obj_id) {
        if (curr->ycc_seq_number == addee_seq_number) {
            if (curr->ycc_offset == addee_offset) {
                return 0;
            }
            else if (curr->ycc_offset < addee_offset) {
                return -1;
            }
            else {
                return 1;
            }
        }
        else if (curr->ycc_seq_number < addee_seq_number) {
            return -1;
        }
        else {
            return 1;
        }
    }
    else if (curr->ycc_obj_id < addee_obj_id) {
        return -1;
    }
    else {
        return 1;
    }
}

static TSK_RETVAL_ENUM
    yaffscache_chunk_find_insertion_point(YAFFSFS_INFO *yfs, uint32_t obj_id, TSK_OFF_T offset, uint32_t seq_number, YaffsCacheChunk **chunk)
{
    YaffsCacheChunk *curr, *prev;

    // Have we seen this obj_id? If not, add an entry for it
    if(yfs->chunkMap->find(obj_id) == yfs->chunkMap->end()){
        fflush(stderr);
        YaffsCacheChunkGroup chunkGroup;
        chunkGroup.cache_chunks_head = NULL;
        chunkGroup.cache_chunks_tail = NULL;
        yfs->chunkMap->insert(std::make_pair(obj_id, chunkGroup));
    }

    curr = yfs->chunkMap->operator[](obj_id).cache_chunks_head;
    prev = NULL;

    if (chunk == NULL) {
        return TSK_ERR;
    }

    while(curr != NULL) {
        // Compares obj id, then seq num, then offset. -1 => current < new
        int cmp = yaffscache_chunk_compare(curr, obj_id, offset, seq_number);

        if (cmp == 0) {
            *chunk = curr;
            return TSK_OK;
        }
        else if (cmp == 1) {
            *chunk = prev;
            return TSK_STOP;
        }

        prev = curr;
        curr = curr->ycc_next;
    }

    *chunk = prev;
    return TSK_STOP;
}

/**
 * Add a chunk to the cache. 
 * @param yfs
 * @param offset Byte offset this chunk was found in (in the disk image)
 * @param seq_number Sequence number of this chunk
 * @param obj_id Object Id this chunk is associated with
 * @param parent_id Parent object ID that this chunk/object is associated with
 */
static TSK_RETVAL_ENUM
    yaffscache_chunk_add(YAFFSFS_INFO *yfs, TSK_OFF_T offset, uint32_t seq_number,
    uint32_t obj_id, uint32_t chunk_id, uint32_t parent_id)
{
    TSK_RETVAL_ENUM result;
    YaffsCacheChunk *prev;
    YaffsCacheChunk *chunk;
    if ((chunk = (YaffsCacheChunk*)tsk_malloc(sizeof(YaffsCacheChunk))) == NULL) {
        return TSK_ERR;
    }

    chunk->ycc_offset = offset;
    chunk->ycc_seq_number = seq_number;
    chunk->ycc_obj_id = obj_id;
    chunk->ycc_chunk_id = chunk_id;
    chunk->ycc_parent_id = parent_id;

    // Bit of a hack here. In some images, the root directory (obj_id = 1) lists iself as its parent
    // directory, which can cause issues later when we get directory contents. To prevent this,
    // if a chunk comes in with obj_id = 1 and parent_id = 1, manually set the parent ID to zero.
    if((obj_id == 1) && (parent_id == 1)){
        chunk->ycc_parent_id = 0;
    }

    // Find the chunk that should go right before the new chunk
    result = yaffscache_chunk_find_insertion_point(yfs, obj_id, offset, seq_number, &prev);

    if (result == TSK_ERR) {
        return TSK_ERR;
    }

    if (prev == NULL) {
        // No previous chunk - new chunk is the lowest we've seen and the new start of the list
        chunk->ycc_prev = NULL;
        chunk->ycc_next = yfs->chunkMap->operator[](obj_id).cache_chunks_head;
    }
    else {
        chunk->ycc_prev = prev;
        chunk->ycc_next = prev->ycc_next;
    }

    if (chunk->ycc_next != NULL) {
        // If we're not at the end, set the prev pointer on the next chunk to point to our new one
        chunk->ycc_next->ycc_prev = chunk;
    }
    else {
        yfs->chunkMap->operator[](obj_id).cache_chunks_tail = chunk;
    }

    if (chunk->ycc_prev != NULL) {
        // If we're not at the beginning, set the next pointer on the previous chunk to point at our new one
        chunk->ycc_prev->ycc_next = chunk;
    }
    else {
        yfs->chunkMap->operator[](obj_id).cache_chunks_head = chunk;
    }

    return TSK_OK;
}


/**
 * Get the file object from the cache.
 * @returns TSK_OK if it was found and TSK_STOP if we did not find it
 */
static TSK_RETVAL_ENUM
    yaffscache_object_find(YAFFSFS_INFO *yfs, uint32_t obj_id, YaffsCacheObject **obj)
{
    YaffsCacheObject *curr, *prev;
    curr = yfs->cache_objects;
    prev = NULL;

    if (obj == NULL) {
        return TSK_ERR;
    }

    while(curr != NULL) {
        if (curr->yco_obj_id == obj_id) {
            *obj = curr;
            return TSK_OK;
        }
        else if (curr->yco_obj_id > obj_id) {
            *obj = prev;
            return TSK_STOP;
        }

        prev = curr;
        curr = curr->yco_next;
    }

    *obj = prev;
    return TSK_STOP;
}

/**
 * Add an object to the cache if it does not already exist in there.
 * @returns TSK_ERR  on error, TSK_OK otherwise.
 */
static TSK_RETVAL_ENUM
    yaffscache_object_find_or_add(YAFFSFS_INFO *yfs, uint32_t obj_id, YaffsCacheObject **obj)
{
    YaffsCacheObject *prev;
    TSK_RETVAL_ENUM result;

    if (obj == NULL) {
        return TSK_ERR;
    }

    // Look for this obj_id in yfs->cache_objects
    // If not found, add it in the correct spot
    // yaffscache_object_find returns the last object with obj_id less than the one
    // we were searching for, so use that to insert the new one in the list
    result = yaffscache_object_find(yfs, obj_id, &prev);
    if (result == TSK_OK) {
        *obj = prev;
        return TSK_OK;
    }
    else if (result == TSK_STOP) {
        *obj = (YaffsCacheObject *) tsk_malloc(sizeof(YaffsCacheObject));
        (*obj)->yco_obj_id = obj_id;
        if (prev == NULL) {
            (*obj)->yco_next = yfs->cache_objects;
            yfs->cache_objects = *obj;
        }
        else {
            (*obj)->yco_next = prev->yco_next;
            prev->yco_next = (*obj);
        }
        return TSK_OK;
    }
    else {
        *obj = NULL;
        return TSK_ERR;
    }
}

static TSK_RETVAL_ENUM
    yaffscache_object_add_version(YaffsCacheObject *obj, YaffsCacheChunk *chunk)
{
    uint32_t ver_number;
    YaffsCacheChunk *header_chunk = NULL;
    YaffsCacheVersion *version;

    // Going to try ignoring unlinked/deleted headers (objID 3 and 4)
    if ((chunk->ycc_chunk_id == 0) && (chunk->ycc_parent_id != YAFFS_OBJECT_UNLINKED) 
        &&(chunk->ycc_parent_id != YAFFS_OBJECT_DELETED)) {
            header_chunk = chunk;
    }

    /* If this is the second version (since last header_chunk is not NULL) and no
    * header was added, get rid of this incomplete old version -- can't be
    * reasonably recovered.
    *
    * TODO: These chunks are still in the structure and can be walked,
    *       but I'm not sure how to represent this set of data chunks
    *       with no metadata under TSK. This is rare and we don't have
    *       a testcase for it now. Punting right now.
    *
    * Edit: Shouldn't get to this point anymore. Changes to 
    *       yaffscache_versions_insert_chunk make a version continue until it
    *       has a header block.
    */
    if (obj->yco_latest != NULL) {
        if (obj->yco_latest->ycv_header_chunk == NULL) {
            YaffsCacheVersion *incomplete = obj->yco_latest;

            if (tsk_verbose)
                tsk_fprintf(stderr, "yaffscache_object_add_version: "
                "removed an incomplete first version (no header)\n");

            obj->yco_latest = obj->yco_latest->ycv_prior;
            free(incomplete);
        }
    }

    if (obj->yco_latest != NULL) {
        ver_number = obj->yco_latest->ycv_version + 1;

        /* Until a new header is given, use the last seen header. */
        if (header_chunk == NULL) {
            header_chunk = obj->yco_latest->ycv_header_chunk;

            // If we haven't seen a good header yet and we have a deleted/unlinked one, use it
            if((header_chunk == NULL) && (chunk->ycc_chunk_id == 0)){
                header_chunk = chunk;
            }
        }
    }
    else {
        ver_number = 1;
    }

    if ((version = (YaffsCacheVersion *) tsk_malloc(sizeof(YaffsCacheVersion))) == NULL) {
        return TSK_ERR;
    }

    version->ycv_prior = obj->yco_latest;
    version->ycv_version = ver_number;
    version->ycv_seq_number = chunk->ycc_seq_number;
    version->ycv_header_chunk = header_chunk;
    version->ycv_first_chunk = chunk;
    version->ycv_last_chunk = chunk;

    obj->yco_latest = version;

    return TSK_OK;
}

/**
 * Add a chunk to its corresponding object in the cache. 
 */
static TSK_RETVAL_ENUM
    yaffscache_versions_insert_chunk(YAFFSFS_INFO *yfs, YaffsCacheChunk *chunk)
{
    YaffsCacheObject *obj;
    TSK_RETVAL_ENUM result;
    YaffsCacheVersion *version;

    // Building a list in yfs->cache_objects, sorted by obj_id
    result = yaffscache_object_find_or_add(yfs, chunk->ycc_obj_id, &obj);
    if (result != TSK_OK) {
        return TSK_ERR;
    }
    version = obj->yco_latest;

    /* First chunk in this object? */
    if (version == NULL) {
        yaffscache_object_add_version(obj, chunk);
    }
    else {
        /* Chunk in the same update? */
        if (chunk->ycc_seq_number == version->ycv_seq_number) {
            version->ycv_last_chunk = chunk;
            if ((chunk->ycc_chunk_id == 0) && (chunk->ycc_parent_id != YAFFS_OBJECT_UNLINKED) 
                &&(chunk->ycc_parent_id != YAFFS_OBJECT_DELETED)) {
                    version->ycv_header_chunk = chunk;
            }
            else if((chunk->ycc_chunk_id == 0) && (version->ycv_header_chunk == NULL)){
                version->ycv_header_chunk = chunk;
            }
        }
        // If there was no header for the last version, continue adding to it instead
        // of starting a new version. 
        else if(version->ycv_header_chunk == NULL){
            version->ycv_seq_number = chunk->ycc_seq_number;
            version->ycv_last_chunk = chunk;
            if ((chunk->ycc_chunk_id == 0) && (chunk->ycc_parent_id != YAFFS_OBJECT_UNLINKED) 
                &&(chunk->ycc_parent_id != YAFFS_OBJECT_DELETED)) {
                    version->ycv_header_chunk = chunk;
            }
            else if((chunk->ycc_chunk_id == 0) && (version->ycv_header_chunk == NULL)){
                version->ycv_header_chunk = chunk;
            }
        }
        else if(chunk->ycc_chunk_id == 0){   // Directories only have a header block
            // If we're looking at a new version of a directory where the previous version had the same name, 
            // leave everything in the same version. Multiple versions of the same directory aren't really giving us 
            // any information.
            YaffsHeader * newHeader;
            yaffsfs_read_header(yfs, &newHeader, chunk->ycc_offset);
            if((newHeader != NULL) && (newHeader->obj_type == YAFFS_TYPE_DIRECTORY)){
                // Read in the old header
                YaffsHeader * oldHeader;
                yaffsfs_read_header(yfs, &oldHeader, version->ycv_header_chunk->ycc_offset);
                if((oldHeader != NULL) && (oldHeader->obj_type == YAFFS_TYPE_DIRECTORY) &&
                    (0 == strncmp(oldHeader->name, newHeader->name, YAFFS_HEADER_NAME_LENGTH))){
                        version->ycv_seq_number = chunk->ycc_seq_number;
                        version->ycv_last_chunk = chunk;
                        version->ycv_header_chunk = chunk;
                }
                else{
                    // The older header either isn't a directory or it doesn't have the same name, so leave it
                    // as its own version
                    yaffscache_object_add_version(obj, chunk);
                }
            }
            else{
                //  Not a directory
                yaffscache_object_add_version(obj, chunk);
            }
        }
        else{
            //  Otherwise, add this chunk as the start of a new version
            yaffscache_object_add_version(obj, chunk);
        }
    }

    return TSK_OK;
}

static TSK_RETVAL_ENUM
    yaffscache_versions_compute(YAFFSFS_INFO *yfs)
{
    std::map<unsigned int,YaffsCacheChunkGroup>::iterator iter;
    for( iter = yfs->chunkMap->begin(); iter != yfs->chunkMap->end(); ++iter ) {
        YaffsCacheChunk *chunk_curr = yfs->chunkMap->operator[](iter->first).cache_chunks_head;

        while(chunk_curr != NULL) {
            if (yaffscache_versions_insert_chunk(yfs, chunk_curr) != TSK_OK) {
                return TSK_ERR;
            }

            chunk_curr = chunk_curr->ycc_next;
        }
    }

    return TSK_OK;
}

/**
 * Callback for yaffscache_find_children()
 * @param obj Object that is a child
 * @param version Version of the object
 * @param args Pointer to what was passed into yaffscache_find_children
 */
typedef TSK_RETVAL_ENUM yc_find_children_cb(YaffsCacheObject *obj, YaffsCacheVersion *version, void *args);

/**
 * Search the cache for objects that are children of the given address.
 * @param yfs
 * @param parent_inode Inode of folder/directory
 * @param cb Call back to call for each found child
 * @param args Pointer to structure that will be passed to cb
 * @returns TSK_ERR on error
 */
static TSK_RETVAL_ENUM
    yaffscache_find_children(YAFFSFS_INFO *yfs, TSK_INUM_T parent_inode, yc_find_children_cb cb, void *args)
{
    YaffsCacheObject *obj;

    uint32_t parent_id, version_num;
    if (yaffscache_inode_to_obj_id_and_version(parent_inode, &parent_id, &version_num) != TSK_OK) {
        return TSK_ERR;
    }

    /* Iterate over all objects and all versions of the objects to see if one is the child
     * of the given parent. */
    for (obj = yfs->cache_objects; obj != NULL; obj = obj->yco_next) {
        YaffsCacheVersion *version;
        for (version = obj->yco_latest; version != NULL; version = version->ycv_prior) {
            /* Is this an incomplete version? */
            if (version->ycv_header_chunk == NULL) {
                continue;
            }

            if (version->ycv_header_chunk->ycc_parent_id == parent_id) {
                TSK_RETVAL_ENUM result = cb(obj, version, args);
                if (result != TSK_OK)
                    return result;
            }
        }
    }

    return TSK_OK;
}

/**
 * Lookup an object based on its inode.
 * @param yfs
 * @param inode
 * @param version [out] Pointer to store version of the object that was found (if inode had a version of 0)
 * @param obj_ret [out] Pointer to store found object into
 * @returns TSK_ERR on error. 
 */
static TSK_RETVAL_ENUM
    yaffscache_version_find_by_inode(YAFFSFS_INFO *yfs, TSK_INUM_T inode, YaffsCacheVersion **version, YaffsCacheObject **obj_ret) {
        uint32_t obj_id, version_num;
        YaffsCacheObject *obj;
        YaffsCacheVersion *curr;

        if (version == NULL) {
            return TSK_ERR;
        }

        // convert inode to obj and version and find it in cache
        if (yaffscache_inode_to_obj_id_and_version(inode, &obj_id, &version_num) != TSK_OK) {
            *version = NULL;
            return TSK_ERR;
        }

        if (yaffscache_object_find(yfs, obj_id, &obj) != TSK_OK) {
            *version = NULL;
            return TSK_ERR;
        }

        if (version_num == 0) {
            if (obj_ret != NULL) {
                *obj_ret = obj;
            }
            *version = obj->yco_latest;
            return TSK_OK;
        }

        // Find the requested version in the list. 
        for(curr = obj->yco_latest; curr != NULL; curr = curr->ycv_prior) {
            if (curr->ycv_version == version_num) {
                if (obj_ret != NULL) {
                    *obj_ret = obj;
                }
                *version = curr;
                return TSK_OK;
            }
        }

        if (obj_ret != NULL) {
            *obj_ret = NULL;
        }
        *version = NULL;
        return TSK_ERR;
}

static void
    yaffscache_object_dump(FILE *fp, YaffsCacheObject *obj)
{
    YaffsCacheVersion *next_version = obj->yco_latest;
    YaffsCacheChunk *chunk = next_version->ycv_last_chunk;

    fprintf(fp, "Object %d\n", obj->yco_obj_id);
    while(chunk != NULL && chunk->ycc_obj_id == obj->yco_obj_id) {
        if (next_version != NULL && 
            chunk == next_version->ycv_last_chunk) {
                fprintf(fp, "  @%d: %p %p %p\n", 
                    next_version->ycv_version, 
                    next_version->ycv_header_chunk, 
                    next_version->ycv_first_chunk,
                    next_version->ycv_last_chunk);
                next_version = next_version->ycv_prior;
        }

        fprintf(fp, "    + %p %08x %08x %08llx\n",
            chunk,
            chunk->ycc_chunk_id,
            chunk->ycc_seq_number,
            chunk->ycc_offset);

        chunk = chunk->ycc_prev;
    }
}

static void
    yaffscache_objects_dump(FILE *fp, YAFFSFS_INFO *yfs)
{
    YaffsCacheObject *obj;

    for(obj = yfs->cache_objects; obj != NULL; obj = obj->yco_next)
        yaffscache_object_dump(fp, obj);
}

static void
    yaffscache_objects_stats(YAFFSFS_INFO *yfs, 
    unsigned int *obj_count,
    uint32_t *obj_first, uint32_t *obj_last,
    uint32_t *version_count,
    uint32_t *version_first, uint32_t *version_last)
{
    YaffsCacheObject *obj;
    YaffsCacheVersion *ver;

    /* deleted and unlinked special objects don't have headers */
    *obj_count = 2;
    *obj_first = 0xffffffff;
    *obj_last = 0;

    *version_count = 0;
    *version_first = 0xffffffff;
    *version_last = 0;

    for(obj = yfs->cache_objects; obj != NULL; obj = obj->yco_next) {
        *obj_count += 1;
        if (obj->yco_obj_id < *obj_first)
            *obj_first = obj->yco_obj_id;
        if (obj->yco_obj_id > *obj_last)
            *obj_last = obj->yco_obj_id;

        for(ver = obj->yco_latest; ver != NULL; ver = ver->ycv_prior) {
            *version_count += 1;
            if (ver->ycv_seq_number < *version_first)
                *version_first = ver->ycv_seq_number;
            if (ver->ycv_seq_number > *version_last)
                *version_last = ver->ycv_seq_number;
        }
    }
}

static void
    yaffscache_objects_free(YAFFSFS_INFO *yfs)
{
    if((yfs != NULL) && (yfs->cache_objects != NULL)){
        YaffsCacheObject *obj = yfs->cache_objects;
        while(obj != NULL) {
            YaffsCacheObject *to_free = obj;

            YaffsCacheVersion *ver = obj->yco_latest;
            while(ver != NULL) {
                YaffsCacheVersion *v_to_free = ver;
                ver = ver->ycv_prior;
                free(v_to_free);
            }

            obj = obj->yco_next;
            free(to_free);
        }
    }
}

static void
    yaffscache_chunks_free(YAFFSFS_INFO *yfs)
{
    if((yfs != NULL) && (yfs->chunkMap != NULL)){
        // Free the YaffsCacheChunks in each ChunkGroup
        std::map<unsigned int,YaffsCacheChunkGroup>::iterator iter;
        for( iter = yfs->chunkMap->begin(); iter != yfs->chunkMap->end(); ++iter ) {
            YaffsCacheChunk *chunk = yfs->chunkMap->operator[](iter->first).cache_chunks_head;
            while(chunk != NULL) {
                YaffsCacheChunk *to_free = chunk;
                chunk = chunk->ycc_next;
                free(to_free);
            }
        }

        // Free the map
        yfs->chunkMap->clear();
        delete yfs->chunkMap;
    }

}



/*
* Parsing and helper functions
*
*
*/

/* Function to parse config file
 *
 * @param img_info Image info for this image
 * @param map<string, int> Stores values from config file indexed on parameter name
 * @returns YAFFS_CONFIG_STATUS One of 	YAFFS_CONFIG_OK, YAFFS_CONFIG_FILE_NOT_FOUND, or YAFFS_CONFIG_ERROR
 */
static YAFFS_CONFIG_STATUS
yaffs_load_config_file(TSK_IMG_INFO * a_img_info, std::map<std::string, std::string> & results){
    size_t config_file_name_len;
    TSK_TCHAR * config_file_name;
    FILE* config_file;
    char buf[1001];

    // Ensure there is at least one image name
    if(a_img_info->num_img < 1){
        return YAFFS_CONFIG_ERROR;
    }

    // Construct the name of the config file from the first image name
    config_file_name_len = TSTRLEN(a_img_info->images[0]);
    config_file_name_len += TSTRLEN(YAFFS_CONFIG_FILE_SUFFIX);
    config_file_name = (TSK_TCHAR *) tsk_malloc(sizeof(TSK_TCHAR) * (config_file_name_len + 1));

    TSTRNCPY(config_file_name, a_img_info->images[0], TSTRLEN(a_img_info->images[0]) + 1);
    TSTRNCAT(config_file_name, YAFFS_CONFIG_FILE_SUFFIX, TSTRLEN(YAFFS_CONFIG_FILE_SUFFIX) + 1);

#ifdef TSK_WIN32
    HANDLE hWin;

    if ((hWin = CreateFile(config_file_name, GENERIC_READ,
            FILE_SHARE_READ, 0, OPEN_EXISTING, 0,
            0)) == INVALID_HANDLE_VALUE) {

        // For the moment, assume that the file just doesn't exist, which isn't an error
        free(config_file_name);
        return YAFFS_CONFIG_FILE_NOT_FOUND;
    }
    config_file = _fdopen(_open_osfhandle((intptr_t) hWin, _O_RDONLY), "r");
    if (config_file == NULL) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS);
        tsk_error_set_errstr(
                    "yaffs_load_config: Error converting Windows handle to C handle");
        free(config_file_name);
        CloseHandle(hWin);
        return YAFFS_CONFIG_ERROR;
    }
#else
    if (NULL == (config_file = fopen(config_file_name, "r"))) {
        free(config_file_name);
        return YAFFS_CONFIG_FILE_NOT_FOUND;
    }
#endif

    while(fgets(buf, 1000, config_file) != NULL){

        // Is it a comment?
        if((buf[0] == '#') || (buf[0] == ';')){
            continue;
        }

        // Is there a '=' ?
        if(strchr(buf, '=') == NULL){
            continue;
        }

        // Copy to strings while removing whitespace and converting to lower case
        std::string paramName("");
        std::string paramVal("");
        
        const char * paramNamePtr = strtok(buf, "=");
        while(*paramNamePtr != '\0'){
            if(! isspace((char)(*paramNamePtr))){
                paramName += tolower((char)(*paramNamePtr));
            }
            paramNamePtr++;
        }
    
        const char * paramValPtr = strtok(NULL, "=");
        while(*paramValPtr != '\0'){
            if(! isspace(*paramValPtr)){
                paramVal += tolower((char)(*paramValPtr));
            }
            paramValPtr++;
        }
        
        // Make sure this parameter is not already in the map
        if(results.find(paramName) != results.end()){
            // Duplicate parameter - return an error
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS);
            tsk_error_set_errstr(
                        "yaffs_load_config: Duplicate parameter name in config file (\"%s\"). %s", paramName.c_str(), YAFFS_HELP_MESSAGE);
            fclose(config_file);
            free(config_file_name);
            return YAFFS_CONFIG_ERROR;
        }

        // Add this entry to the map
        results[paramName] = paramVal;
    }

    fclose(config_file);
    free(config_file_name);
    return YAFFS_CONFIG_OK;
}

/*
 * Helper function for yaffs_validate_config
 * Tests that a string consists only of digits and has at least one digit
 * (Can modify later if we want negative fields to be valid)
 *
 * @param numStr String to test
 * @returns 1 on error, 0 on success
 */
static int
yaffs_validate_integer_field(std::string numStr){
    unsigned int i;

    // Test if empty
    if(numStr.length() == 0){
        return 1;
    }

    // Test each character
    for(i = 0;i < numStr.length();i++){
        if(isdigit(numStr[i]) == 0){
            return 1;
        }
    }

    return 0;
}

/*
 * Function to validate the contents of the config file
 * Currently testing:
 *  All YAFFS_CONFIG fields should be integers (if they exist)
 *  Either need all three of YAFFS_CONFIG_SEQ_NUM_STR, YAFFS_CONFIG_OBJ_ID_STR, YAFFS_CONFIG_CHUNK_ID_STR
 *   or none of them
 *
 * @param paramMap Holds mapping of parameter name to parameter value
 * @returns 1 on error (invalid parameters), 0 on success
 */
static int
yaffs_validate_config_file(std::map<std::string, std::string> & paramMap){
    int offset_field_count;

    // Make a list of all fields to test
    std::set<std::string> integerParams;
    integerParams.insert(YAFFS_CONFIG_SEQ_NUM_STR);
    integerParams.insert(YAFFS_CONFIG_OBJ_ID_STR);
    integerParams.insert(YAFFS_CONFIG_CHUNK_ID_STR);
    integerParams.insert(YAFFS_CONFIG_PAGE_SIZE_STR);
    integerParams.insert(YAFFS_CONFIG_SPARE_SIZE_STR);
    integerParams.insert(YAFFS_CONFIG_CHUNKS_PER_BLOCK_STR);

    // If the parameter is set, verify that the value is an int
    for(std::set<std::string>::iterator it = integerParams.begin();it != integerParams.end();it++){
        if((paramMap.find(*it) != paramMap.end()) && 
            (0 != yaffs_validate_integer_field(paramMap[*it]))){
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS);
            tsk_error_set_errstr(
                        "yaffs_validate_config_file: Empty or non-integer value for Yaffs2 parameter \"%s\". %s", (*it).c_str(), YAFFS_HELP_MESSAGE);
            return 1;
        }
    }

    // Check that we have all three spare offset fields, or none of the three
    offset_field_count = 0;
    if(paramMap.find(YAFFS_CONFIG_SEQ_NUM_STR) != paramMap.end()){
        offset_field_count++;
    }
    if(paramMap.find(YAFFS_CONFIG_OBJ_ID_STR) != paramMap.end()){
        offset_field_count++;
    }
    if(paramMap.find(YAFFS_CONFIG_CHUNK_ID_STR) != paramMap.end()){
        offset_field_count++;
    }

    if(! ((offset_field_count == 0) || (offset_field_count == 3))){
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS);
            tsk_error_set_errstr(
                        "yaffs_validate_config_file: Require either all three spare offset fields or none. %s", YAFFS_HELP_MESSAGE);
            return 1;
    }

    // Make sure there aren't any unexpected fields present
    for(std::map<std::string, std::string>::iterator it = paramMap.begin(); it != paramMap.end();it++){
        if(integerParams.find(it->first) == integerParams.end()){
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS);
            tsk_error_set_errstr(
                        "yaffs_validate_config_file: Found unexpected field in config file (\"%s\"). %s", it->first.c_str(), YAFFS_HELP_MESSAGE);
            return 1;
        }
    }

    return 0;
}

/*
* Function to attempt to determine the layout of the yaffs spare area.
* Results of the analysis (if the format could be determined) will be stored
* in yfs variables. 
*
* @param yfs File system being analyzed
* @param maxBlocksToTest Number of block groups to scan to detect spare area or 0 if there is no limit.
* @returns TSK_ERR if format could not be detected and TSK_OK if it could be.
*/
static TSK_RETVAL_ENUM 
yaffs_initialize_spare_format(YAFFSFS_INFO * yfs, TSK_OFF_T maxBlocksToTest){

    // Testing parameters - can all be changed
    unsigned int blocksToTest = 10;  // Number of blocks (64 chunks) to test
    unsigned int chunksToTest = 10;  // Number of chunks to test in each block 
    unsigned int minChunksRead = 10; // Minimum number of chunks we require to run the test (we might not get the full number we want to test for a very small file)

    unsigned int chunkSize = yfs->page_size + yfs->spare_size;
    unsigned int blockSize = yfs->chunks_per_block * chunkSize;

    TSK_FS_INFO *fs = &(yfs->fs_info);
    unsigned char *spareBuffer;

    unsigned int blockIndex;
    unsigned int chunkIndex;

    unsigned int currentOffset;

    unsigned char * allSpares;
    unsigned int allSparesLength;
    
    TSK_OFF_T maxBlocks;

    bool skipBlock;
    int goodOffset;
    unsigned int nGoodSpares;
    unsigned int nBlocksTested;

    int okOffsetFound = 0;   // Used as a flag for if we've found an offset that sort of works but doesn't seem great
    int goodOffsetFound = 0; // Flag to mark that we've found an offset that also passed secondary testing
    int bestOffset = 0;

    bool allSameByte; // Used in test that the spare area fields not be one repeated byte

    unsigned int i;

    int thisChunkBase;
    int lastChunkBase;

    // The spare area needs to be at least 16 bytes to run the test
    if(yfs->spare_size < 16){
        if(tsk_verbose && (! yfs->autoDetect)){
            tsk_fprintf(stderr,
                "yaffs_initialize_spare_format failed - given spare size (%d) is not large enough to contain needed fields\n", yfs->spare_size);
        }
        return TSK_ERR;
    }

    if ((spareBuffer = (unsigned char*) tsk_malloc(yfs->spare_size)) == NULL) {
        return TSK_ERR;
    }

    allSparesLength = yfs->spare_size * blocksToTest * chunksToTest;
    if ((allSpares = (unsigned char*) tsk_malloc(allSparesLength)) == NULL) {
        free(spareBuffer);
        return TSK_ERR;
    }

    // Initialize the pointers to one of the configurations we've seen (thought these defaults should not get used)
    yfs->spare_seq_offset = 0;
    yfs->spare_obj_id_offset = 4;
    yfs->spare_chunk_id_offset = 8;
    yfs->spare_nbytes_offset = 12;

    // Assume the data we want is 16 consecutive bytes in the order:
    //  seq num, obj id, chunk id, byte count
    //  (not sure we're guaranteed this but we wouldn't be able to deal with the alternative anyway)
    // Seq num is the important one. This number is constant in each block (block = 64 chunks), meaning
    //  all chunks in a block will share the same sequence number. The YAFFS2 descriptions would seem to
    //  indicate it should be different for each block, but this doesn't seem to always be the case.
    //  In particular we frequently see the 0x1000 seq number used over multiple blocks, but this isn't the only
    //  observed exception.

    // Calculate the number of blocks in the image
    maxBlocks = yfs->fs_info.img_info->size / (yfs->chunks_per_block * chunkSize);

    // If maxBlocksToTest = 0 (unlimited), set it to the total number of blocks
    // Also reduce the number of blocks to test if it is larger than the total number of blocks
    if ((maxBlocksToTest == 0) || (maxBlocksToTest > maxBlocks)){
        maxBlocksToTest = maxBlocks;
    }

    nGoodSpares = 0;
    nBlocksTested = 0;
    for (TSK_OFF_T blockIndex = 0;blockIndex < maxBlocksToTest;blockIndex++){

        // Read the last spare area that we want to test first
        TSK_OFF_T offset = (TSK_OFF_T)blockIndex * blockSize + (chunksToTest - 1) * chunkSize + yfs->page_size;
        ssize_t cnt = tsk_img_read(fs->img_info, offset, (char *) spareBuffer,
            yfs->spare_size);
        if ((cnt < 0) || ((unsigned int)cnt < yfs->spare_size)) {
            break;
        }

        // Is the spare all 0xff / 0x00?
        // If not, we know we should have all allocated chunks since YAFFS2 writes sequentially in a block
        //  - can't have an unallocated chunk followed by an allocated one
        // We occasionally see almost all null spare area with a few 0xff, which is not a valid spare.
        skipBlock = true;
        for (i = 0;i < yfs->spare_size;i++){
            if((spareBuffer[i] != 0xff) && (spareBuffer[i] != 0x00)){
                skipBlock = false;
                break;
            }
        }

        if (skipBlock){
            continue;
        }

        // If this block is potentialy valid (i.e., the spare contains something besides 0x00 and 0xff), copy all the spares into
        // the big array of extracted spare areas

        // Copy this spare area
        nGoodSpares++;
        for (i = 0;i < yfs->spare_size;i++){
            allSpares[nBlocksTested * yfs->spare_size * chunksToTest + (chunksToTest - 1) * yfs->spare_size + i] = spareBuffer[i];
        }

        // Copy all earlier spare areas in the block
        for (chunkIndex = 0;chunkIndex < chunksToTest - 1;chunkIndex++){
            offset = blockIndex * blockSize + chunkIndex * chunkSize + yfs->page_size;
            cnt = tsk_img_read(fs->img_info, offset, (char *) spareBuffer,
                yfs->spare_size);
            if ((cnt < 0) || ((unsigned int)cnt < yfs->spare_size)) {
                // We really shouldn't run out of data here since we already read in the furthest entry
                break; // Break out of chunksToTest loop
            }

            nGoodSpares++;
            for(i = 0;i < yfs->spare_size;i++){
                allSpares[nBlocksTested * yfs->spare_size * chunksToTest + chunkIndex * yfs->spare_size + i] = spareBuffer[i];
            }
        }

        // Record that we've found a potentially valid block
        nBlocksTested++;

        // If we've found enough potentailly valid blocks, break
        if (nBlocksTested >= blocksToTest){
            break;
        }
    }

    // Make sure we read enough data to reasonably perform the testing
    if (nGoodSpares < minChunksRead){

        if (tsk_verbose && (! yfs->autoDetect)){
            tsk_fprintf(stderr,
                "yaffs_initialize_spare_format failed - not enough potentially valid data could be read\n");
        }

        free(spareBuffer);
        free(allSpares);
        return TSK_ERR;
    }

    if (tsk_verbose && (! yfs->autoDetect)){
        tsk_fprintf(stderr,
            "yaffs_initialize_spare_format: Testing potential offsets for the sequence number in the spare area\n");
    }

    // Print out the collected spare areas if we're in verbose mode
    if(tsk_verbose && (! yfs->autoDetect)){
        for(blockIndex = 0;blockIndex < nBlocksTested;blockIndex++){
            for(chunkIndex = 0;chunkIndex < chunksToTest;chunkIndex++){
                for(i = 0;i < yfs->spare_size;i++){
                    fprintf(stderr, "%02x", allSpares[blockIndex * yfs->spare_size * chunksToTest + chunkIndex * yfs->spare_size + i]);
                }
                fprintf(stderr, "\n");
            }
        }
    }

    // Test all indices into the spare area (that leave enough space for all 16 bytes)
    for(currentOffset = 0;currentOffset <= yfs->spare_size - 16;currentOffset++){
        goodOffset = 1;
        for(blockIndex = 0;blockIndex < nBlocksTested;blockIndex++){
            for(chunkIndex = 1;chunkIndex < chunksToTest;chunkIndex++){

                lastChunkBase = blockIndex * yfs->spare_size * chunksToTest + (chunkIndex - 1) * yfs->spare_size;
                thisChunkBase = lastChunkBase + yfs->spare_size;

                // Seq num should not be all 0xff (we tested earlier that the chunk has been initialized)
                if((0xff == allSpares[thisChunkBase + currentOffset]) &&
                    (0xff == allSpares[thisChunkBase + currentOffset + 1]) &&
                    (0xff == allSpares[thisChunkBase + currentOffset + 2]) &&
                    (0xff == allSpares[thisChunkBase + currentOffset + 3])){
                        if(tsk_verbose && (! yfs->autoDetect)){
                            tsk_fprintf(stderr,
                                "yaffs_initialize_spare_format: Eliminating offset %d - invalid sequence number 0xffffffff\n", 
                                currentOffset);
                        }
                        goodOffset = 0;
                        break;
                }

                // Seq num should not be zero
                if((0 == allSpares[thisChunkBase + currentOffset]) &&
                    (0 == allSpares[thisChunkBase + currentOffset + 1]) &&
                    (0 == allSpares[thisChunkBase + currentOffset + 2]) &&
                    (0 == allSpares[thisChunkBase + currentOffset + 3])){
                        if(tsk_verbose && (! yfs->autoDetect)){
                            tsk_fprintf(stderr,
                                "yaffs_initialize_spare_format: Eliminating offset %d - invalid sequence number 0\n", 
                                currentOffset);
                        }
                        goodOffset = 0;
                        break;
                }

                // Seq num should match the previous one in the block
                if((allSpares[lastChunkBase + currentOffset] != allSpares[thisChunkBase + currentOffset]) ||
                    (allSpares[lastChunkBase + currentOffset + 1] != allSpares[thisChunkBase + currentOffset + 1]) ||
                    (allSpares[lastChunkBase + currentOffset + 2] != allSpares[thisChunkBase + currentOffset + 2]) ||
                    (allSpares[lastChunkBase + currentOffset + 3] != allSpares[thisChunkBase + currentOffset + 3])){
                        if(tsk_verbose && (! yfs->autoDetect)){
                            tsk_fprintf(stderr,
                                "yaffs_initialize_spare_format: Eliminating offset %d - did not match previous chunk sequence number\n", 
                                currentOffset);
                        }
                        goodOffset = 0;
                        break;
                }

                // Obj id should not be zero
                if((0 == allSpares[thisChunkBase + currentOffset + 4]) &&
                    (0 == allSpares[thisChunkBase + currentOffset + 5]) &&
                    (0 == allSpares[thisChunkBase + currentOffset + 6]) &&
                    (0 == allSpares[thisChunkBase + currentOffset + 7])){
                        if(tsk_verbose && (! yfs->autoDetect)){
                            tsk_fprintf(stderr,
                                "yaffs_initialize_spare_format: Eliminating offset %d - invalid object id 0\n", 
                                currentOffset);
                        }
                        goodOffset = 0;
                        break;
                }

                // All 16 bytes should not be the same
                // (It is theoretically possible that this could be valid, but incredibly unlikely)
                allSameByte = true;
                for(i = 1;i < 16;i++){
                    if(allSpares[thisChunkBase + currentOffset] != allSpares[thisChunkBase + currentOffset + i]){
                        allSameByte = false;
                        break;
                    }
                }
                if(allSameByte){
                    if(tsk_verbose && (! yfs->autoDetect)){
                        tsk_fprintf(stderr,
                            "yaffs_initialize_spare_format: Eliminating offset %d - all repeated bytes\n", 
                            currentOffset);
                    }
                    goodOffset = 0;
                    break;
                }

            } // End of loop over chunks

            if(!goodOffset){ // Break out of loop over blocks
                break;
            }
        }
        if(goodOffset){

            // Note that we've found an offset that is at least promising
            if((! goodOffsetFound) && (! okOffsetFound)){
                bestOffset = currentOffset;
            }
            okOffsetFound = 1;

            if(tsk_verbose && (! yfs->autoDetect)){
                tsk_fprintf(stderr,
                    "yaffs_initialize_spare_format: Found potential spare offsets:  %d (sequence number), %d (object id), %d (chunk id), %d (n bytes)\n",
                    currentOffset, currentOffset+4, currentOffset+8, currentOffset+12);
            }

            // Now do some more tests
            // Really need some more real-world test data to do this right.
            int possibleError = 0;

            // We probably don't want the first byte to always be 0xff
            int firstByteFF = 1;
            for(blockIndex = 0;blockIndex < nBlocksTested;blockIndex++){
                for(chunkIndex = 1;chunkIndex < chunksToTest;chunkIndex++){
                    if(allSpares[blockIndex * yfs->spare_size * chunksToTest + chunkIndex * yfs->spare_size + currentOffset] != 0xff){
                        firstByteFF = 0;
                    }
                }
            }

            if(firstByteFF){
                if(tsk_verbose && (! yfs->autoDetect)){
                    tsk_fprintf(stderr,
                        "yaffs_initialize_spare_format:  Previous data starts with all 0xff bytes. Looking for better offsets.\n");
                }
                possibleError = 1;
            }

            if(! possibleError){

                // If we already have a good offset, print this one out but don't record it
                if(! goodOffsetFound){

                    goodOffsetFound = 1;
                    bestOffset = currentOffset;

                    // Offset passed additional testing and we haven't seen an earlier good one, so go ahead and use it
                    if(tsk_verbose && (! yfs->autoDetect)){
                        tsk_fprintf(stderr,
                            "yaffs_initialize_spare_format:  Previous offsets appear good - will use as final offsets\n");
                    }

                }
                else{
                    // Keep using the old one
                    if(tsk_verbose && (! yfs->autoDetect)){
                        tsk_fprintf(stderr,
                            "yaffs_initialize_spare_format:  Previous offsets appear good but staying with earlier valid ones\n");
                    }
                }
            }
        }
    }

    free(spareBuffer);
    free(allSpares);

    if(okOffsetFound || goodOffsetFound){
        // Record everything
        yfs->spare_seq_offset = bestOffset;
        yfs->spare_obj_id_offset = bestOffset + 4;
        yfs->spare_chunk_id_offset = bestOffset + 8;
        yfs->spare_nbytes_offset = bestOffset + 12;

        if(tsk_verbose && (! yfs->autoDetect)){
            tsk_fprintf(stderr,
                "yaffs_initialize_spare_format: Final offsets: %d (sequence number), %d (object id), %d (chunk id), %d (n bytes)\n",
                bestOffset, bestOffset+4, bestOffset+8, bestOffset+12);
            tsk_fprintf(stderr,
                "If these do not seem valid: %s\n", YAFFS_HELP_MESSAGE);
        }
        return TSK_OK;
    }
    else{
        return TSK_ERR;
    }
}

/**
* yaffsfs_read_header( ... )
*
*/
static uint8_t 
    yaffsfs_read_header(YAFFSFS_INFO *yfs, YaffsHeader ** header, TSK_OFF_T offset)
{
    unsigned char *hdr;
    ssize_t cnt;
    YaffsHeader *head;
    TSK_FS_INFO *fs = &(yfs->fs_info);

    if ((hdr = (unsigned char*) tsk_malloc(yfs->page_size)) == NULL) {
        return 1;
    }

    cnt = tsk_img_read(fs->img_info, offset, (char *) hdr,
        yfs->page_size);
    if ((cnt < 0) || ((unsigned int)cnt < yfs->page_size)) {
        free(hdr);
        return 1;
    }

    if ((head = (YaffsHeader*) tsk_malloc( sizeof(YaffsHeader))) == NULL) {
        free(hdr);
        return 1;
    }

    memcpy(&head->obj_type, hdr, 4);
    memcpy(&head->parent_id, &hdr[4], 4);
    memcpy(head->name, (char*) &hdr[0xA], YAFFS_HEADER_NAME_LENGTH);
    memcpy(&head->file_mode, &hdr[0x10C], 4);
    memcpy(&head->user_id, &hdr[0x110], 4);
    memcpy(&head->group_id, &hdr[0x114], 4);
    memcpy(&head->atime, &hdr[0x118], 4);
    memcpy(&head->mtime, &hdr[0x11C], 4);
    memcpy(&head->ctime, &hdr[0x120], 4);
    memcpy(&head->file_size, &hdr[0x124], 4);
    memcpy(&head->equivalent_id, &hdr[0x128], 4);
    memcpy(head->alias, (char*) &hdr[0x12C], YAFFS_HEADER_ALIAS_LENGTH);

    //memcpy(&head->rdev_mode, &hdr[0x1CC], 4);
    //memcpy(&head->win_ctime, &hdr[0x1D0], 8);
    //memcpy(&head->win_atime, &hdr[0x1D8], 8);
    //memcpy(&head->win_mtime, &hdr[0x1E0], 8);
    //memcpy(&head->inband_obj_id, &hdr[0x1E8], 4);
    //memcpy(&head->inband_is_shrink, &hdr[0x1EC], 4);

    // NOTE: This isn't in Android 3.3 kernel but is in YAFFS2 git
    //memcpy(&head->file_size_high, &hdr[0x1F0], 4);

    free(hdr);

    *header = head;
    return 0;
}

/**
* Read and parse the YAFFS2 tags in the NAND spare bytes.
*
* @param info is a YAFFS fs handle
* @param spare YaffsSpare object to be populated
* @param offset, offset to read from
*
* @returns 0 on success and 1 on error
*/
static uint8_t 
    yaffsfs_read_spare(YAFFSFS_INFO *yfs, YaffsSpare ** spare, TSK_OFF_T offset)
{
    unsigned char *spr;
    ssize_t cnt;
    YaffsSpare *sp;
    TSK_FS_INFO *fs = &(yfs->fs_info);

    uint32_t seq_number;
    uint32_t object_id;
    uint32_t chunk_id;

    // Should have checked this by now, but just in case
    if((yfs->spare_seq_offset + 4 > yfs->spare_size) ||
        (yfs->spare_obj_id_offset + 4 > yfs->spare_size) ||
        (yfs->spare_chunk_id_offset + 4 > yfs->spare_size)){
            return 1;
    }

    if ((spr = (unsigned char*) tsk_malloc(yfs->spare_size)) == NULL) {
        return 1;
    }

    if (yfs->spare_size < 46) { // Why is this 46?
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("yaffsfs_read_spare: spare size is too small");
        free(spr);
        return 1;
    }

    cnt = tsk_img_read(fs->img_info, offset, (char*) spr, yfs->spare_size);
    if ((cnt < 0) || ((unsigned int)cnt < yfs->spare_size)) {
        // couldn't read sufficient bytes...
        if (spare) {
            free(spr);
            *spare = NULL;
        }
        return 1;
    }

    if ((sp = (YaffsSpare*) tsk_malloc(sizeof(YaffsSpare))) == NULL) {
        return 1;
    }

    memset(sp, 0, sizeof(YaffsSpare));

    /*
    * Complete read of the YAFFS2 spare
    */


    // The format of the spare area should have been determined earlier
    memcpy(&seq_number, &spr[yfs->spare_seq_offset], 4);
    memcpy(&object_id, &spr[yfs->spare_obj_id_offset], 4);
    memcpy(&chunk_id, &spr[yfs->spare_chunk_id_offset], 4);

    if ((YAFFS_SPARE_FLAGS_IS_HEADER & chunk_id) != 0) {

        sp->seq_number = seq_number;
        sp->object_id = object_id & ~YAFFS_SPARE_OBJECT_TYPE_MASK;
        sp->chunk_id = 0;

        sp->has_extra_fields = 1;
        sp->extra_parent_id = chunk_id & YAFFS_SPARE_PARENT_ID_MASK;
        sp->extra_object_type =
            (object_id & YAFFS_SPARE_OBJECT_TYPE_MASK)
            >> YAFFS_SPARE_OBJECT_TYPE_SHIFT;
    }
    else {
        sp->seq_number = seq_number;
        sp->object_id = object_id;
        sp->chunk_id = chunk_id;

        sp->has_extra_fields = 0;
    }

    free(spr);
    *spare = sp;

    return 0;
}

static uint8_t 
    yaffsfs_is_spare_valid(YAFFSFS_INFO *yfs, YaffsSpare *spare)
{
    if (spare == NULL) {
        return 1;
    }

    if ((spare->object_id > YAFFS_MAX_OBJECT_ID) ||
        (spare->seq_number < YAFFS_LOWEST_SEQUENCE_NUMBER) ||
        (spare->seq_number > YAFFS_HIGHEST_SEQUENCE_NUMBER)) {
            return 1;
    }

    return 0;
}

static uint8_t 
    yaffsfs_read_chunk(YAFFSFS_INFO *yfs,
    YaffsHeader **header, YaffsSpare **spare, TSK_OFF_T offset)
{
    TSK_OFF_T header_offset = offset;
    TSK_OFF_T spare_offset = offset + yfs->page_size; 

    if (header == NULL || spare == NULL) {
        return 1;
    }

    if (yaffsfs_read_header(yfs, header, header_offset) != 0) {
        return 1;
    }

    if (yaffsfs_read_spare(yfs, spare, spare_offset) != 0) {
        free(*header);
        *header = NULL;
        return 1;
    }

    return 0;
}

/**
 * Cycle through the entire image and populate the cache with objects as they are found.
 */
static uint8_t 
    yaffsfs_parse_image_load_cache(YAFFSFS_INFO * yfs)
{
    uint8_t status = TSK_OK;
    uint32_t nentries = 0;
    YaffsSpare *spare = NULL;

    uint8_t tempBuf[8];
    uint32_t parentID;

    if (yfs->cache_objects)
        return 0;

    for(TSK_OFF_T offset = 0;offset < yfs->fs_info.img_info->size;offset += yfs->page_size + yfs->spare_size){
        status = yaffsfs_read_spare( yfs, &spare, offset + yfs->page_size);
        if (status != TSK_OK) {
            break;
        }

        if (yaffsfs_is_spare_valid(yfs, spare) == TSK_OK) {


            if((spare->has_extra_fields) || (spare->chunk_id != 0)){
                yaffscache_chunk_add(yfs,
                    offset, 
                    spare->seq_number, 
                    spare->object_id, 
                    spare->chunk_id, 
                    spare->extra_parent_id);
            }
            else{
                // If we have a header block and didn't extract it already from the spare, get the parent ID from
                // the non-spare data
                if(8 == tsk_img_read(yfs->fs_info.img_info, offset, (char*) tempBuf, 8)){
                    memcpy(&parentID, &tempBuf[4], 4);

                    yaffscache_chunk_add(yfs,
                        offset, 
                        spare->seq_number, 
                        spare->object_id, 
                        spare->chunk_id, 
                        parentID);
                }
                else{
                    // Really shouldn't happen
                    fprintf(stderr, "Error reading header to get parent id at offset %x\n", offset);
                    yaffscache_chunk_add(yfs,
                        offset, 
                        spare->seq_number, 
                        spare->object_id, 
                        spare->chunk_id, 
                        0);
                }
            }
        }

        free(spare);
        spare = NULL;

        ++nentries;
    }

    if (tsk_verbose)
        fprintf(stderr, "yaffsfs_parse_image_load_cache: read %d entries\n", nentries);

    if (tsk_verbose)
        fprintf(stderr, "yaffsfs_parse_image_load_cache: started processing chunks for version cache...\n");
    fflush(stderr);

    // At this point, we have a list of chunks sorted by obj id, seq number, and offset
    // This makes the list of objects in cache_objects, which link to different versions
    yaffscache_versions_compute(yfs);

    if (tsk_verbose)
        fprintf(stderr, "yaffsfs_parse_image_load_cache: done version cache!\n");
    fflush(stderr);


    // Having multiple inodes point to the same object seems to cause trouble in TSK, especially in orphan file detection,
    //  so set the version number of the final one to zero.
    // While we're at it, find the highest obj_id and the highest version (before resetting to zero)
    TSK_INUM_T orphanParentID = yfs->fs_info.last_inum;
    YaffsCacheObject * currObj = yfs->cache_objects;
    YaffsCacheVersion * currVer;
    while(currObj != NULL){
        if(currObj->yco_obj_id > yfs->max_obj_id){
            yfs->max_obj_id = currObj->yco_obj_id;
        }

        currVer = currObj->yco_latest;
        if(currVer->ycv_version > yfs->max_version){
            yfs->max_version = currVer->ycv_version;
        }

        currVer->ycv_version = 0;
        currObj = currObj->yco_next;
    }

    // Use the max object id and version number to construct an upper bound on the inode
    TSK_INUM_T max_inum;
    yaffscache_obj_id_and_version_to_inode(yfs->max_obj_id, yfs->max_version, &max_inum);
    yfs->fs_info.last_inum = max_inum + 1; // One more for the orphan dir

    return TSK_OK;
}

// A version is allocated if:
//   1. This version is pointed to by yco_latest
//   2. This version didn't have a delete/unlinked header after the most recent copy of the normal header
static uint8_t yaffs_is_version_allocated(YAFFSFS_INFO * yfs, TSK_INUM_T inode){
    YaffsCacheObject * obj;
    YaffsCacheVersion * version;
    YaffsCacheChunk * curr;

    TSK_RETVAL_ENUM result = yaffscache_version_find_by_inode(yfs, inode, &version, &obj);
    if (result != TSK_OK) {
        if (tsk_verbose)
            tsk_fprintf(stderr, "yaffs_is_version_allocated: yaffscache_version_find_by_inode failed! (inode: %d)\n", inode);
        return 0;
    }

    if(obj->yco_latest == version){
        curr = obj->yco_latest->ycv_header_chunk;
        while(curr != NULL){
            // We're looking for a newer unlinked or deleted header. If one exists, then this object should be considered unallocated
            if((curr->ycc_parent_id == YAFFS_OBJECT_UNLINKED) || (curr->ycc_parent_id == YAFFS_OBJECT_DELETED)){
                return 0;
            }
            curr = curr ->ycc_next;
        }
        return 1;
    }
    else{
        return 0;
    }

}

/*
* TSK integration
*
*
*/

static uint8_t
    yaffs_make_directory(YAFFSFS_INFO *yaffsfs, TSK_FS_FILE *a_fs_file, 
    TSK_INUM_T inode, char *name)
{
    TSK_FS_FILE *fs_file = a_fs_file;


    fs_file->meta->type = TSK_FS_META_TYPE_DIR;
    fs_file->meta->mode = (TSK_FS_META_MODE_ENUM)0;
    fs_file->meta->nlink = 1;

    if((inode == YAFFS_OBJECT_UNLINKED) || (inode == YAFFS_OBJECT_DELETED) ||
        (inode == yaffsfs->fs_info.last_inum)){
            fs_file->meta->flags =
                (TSK_FS_META_FLAG_ENUM)(TSK_FS_META_FLAG_USED | TSK_FS_META_FLAG_ALLOC);
    }
    else{
        if(yaffs_is_version_allocated(yaffsfs, inode)){
            fs_file->meta->flags =
                (TSK_FS_META_FLAG_ENUM)(TSK_FS_META_FLAG_USED | TSK_FS_META_FLAG_ALLOC);
        }
        else{
            fs_file->meta->flags =
                (TSK_FS_META_FLAG_ENUM)(TSK_FS_META_FLAG_USED | TSK_FS_META_FLAG_UNALLOC);
        }
    }
    fs_file->meta->uid = fs_file->meta->gid = 0;
    fs_file->meta->mtime = fs_file->meta->atime = fs_file->meta->ctime =
        fs_file->meta->crtime = 0;
    fs_file->meta->mtime_nano = fs_file->meta->atime_nano =
        fs_file->meta->ctime_nano = fs_file->meta->crtime_nano = 0;

    if (fs_file->meta->name2 == NULL) {
        if ((fs_file->meta->name2 = (TSK_FS_META_NAME_LIST *)
            tsk_malloc(sizeof(TSK_FS_META_NAME_LIST))) == NULL) {
            return 1;
        }
        fs_file->meta->name2->next = NULL;
    }

    if (fs_file->meta->attr != NULL) {
        tsk_fs_attrlist_markunused(fs_file->meta->attr);
    }
    else {
        fs_file->meta->attr = tsk_fs_attrlist_alloc();
    }

    strncpy(fs_file->meta->name2->name, name,
        TSK_FS_META_NAME_LIST_NSIZE);

    fs_file->meta->size = 0;
    fs_file->meta->attr_state = TSK_FS_META_ATTR_EMPTY;
    fs_file->meta->addr = inode;
    return 0;
}

static uint8_t
    yaffs_make_regularfile( YAFFSFS_INFO * yaffsfs, TSK_FS_FILE * a_fs_file, 
    TSK_INUM_T inode, char * name )
{
    TSK_FS_FILE *fs_file = a_fs_file;

    fs_file->meta->type = TSK_FS_META_TYPE_REG;
    fs_file->meta->mode = (TSK_FS_META_MODE_ENUM)0;
    fs_file->meta->nlink =1;

    if(yaffs_is_version_allocated(yaffsfs, inode)){
        fs_file->meta->flags =
            (TSK_FS_META_FLAG_ENUM)(TSK_FS_META_FLAG_USED | TSK_FS_META_FLAG_ALLOC);
    }
    else{
        fs_file->meta->flags =
            (TSK_FS_META_FLAG_ENUM)(TSK_FS_META_FLAG_USED | TSK_FS_META_FLAG_UNALLOC);
    }

    fs_file->meta->uid = fs_file->meta->gid = 0;
    fs_file->meta->mtime = fs_file->meta->atime = fs_file->meta->ctime =
        fs_file->meta->crtime = 0;
    fs_file->meta->mtime_nano = fs_file->meta->atime_nano =
        fs_file->meta->ctime_nano = fs_file->meta->crtime_nano = 0;

    if (fs_file->meta->name2 == NULL) {
        if ((fs_file->meta->name2 = (TSK_FS_META_NAME_LIST *)
            tsk_malloc(sizeof(TSK_FS_META_NAME_LIST))) == NULL)
            return 1;
        fs_file->meta->name2->next = NULL;
    }

    if (fs_file->meta->attr != NULL) {
        tsk_fs_attrlist_markunused(fs_file->meta->attr);
    }
    else {
        fs_file->meta->attr = tsk_fs_attrlist_alloc();
    }

    fs_file->meta->addr = inode;
    strncpy(fs_file->meta->name2->name, name,
        TSK_FS_META_NAME_LIST_NSIZE);

    fs_file->meta->size = 0;
    fs_file->meta->attr_state = TSK_FS_META_ATTR_EMPTY;

    return 0;
}

/**
* \internal 
* Create YAFFS2 Deleted Object
*
* @ param yaffs file system
* fs_file to copy file information to
* return 1 on error, 0 on success
*/
static uint8_t
    yaffs_make_deleted( YAFFSFS_INFO * yaffsfs, TSK_FS_FILE * a_fs_file )
{
    TSK_FS_FILE *fs_file = a_fs_file;

    if (tsk_verbose)
        tsk_fprintf(stderr, "yaffs_make_deleted: Making virtual deleted node\n");

    if (yaffs_make_directory(yaffsfs, fs_file, YAFFS_OBJECT_DELETED, YAFFS_OBJECT_DELETED_NAME))
        return 1;

    return 0;
}

/**
* \internal 
* Create YAFFS2 Unlinked object
*
* @ param yaffs file system
* fs_file to copy file information to
* return 1 on error, 0 on success
*/
static uint8_t
    yaffs_make_unlinked( YAFFSFS_INFO * yaffsfs, TSK_FS_FILE * a_fs_file )
{
    TSK_FS_FILE * fs_file = a_fs_file;

    if (tsk_verbose)
        tsk_fprintf(stderr, "yaffs_make_unlinked: Making virtual unlinked node\n");

    if (yaffs_make_directory(yaffsfs, fs_file, YAFFS_OBJECT_UNLINKED, YAFFS_OBJECT_UNLINKED_NAME))
        return 1;

    return 0;
}

/**
* \internal 
* Create YAFFS2 orphan object
*
* @ param yaffs file system
* fs_file to copy file information to
* return 1 on error, 0 on success
*/
static uint8_t
    yaffs_make_orphan_dir( YAFFSFS_INFO * yaffsfs, TSK_FS_FILE * a_fs_file )
{
    TSK_FS_FILE * fs_file = a_fs_file;
    TSK_FS_NAME *fs_name = tsk_fs_name_alloc(256, 0);
    if (fs_name == NULL)
        return TSK_ERR;

    if (tsk_verbose)
        tsk_fprintf(stderr, "yaffs_make_orphan_dir: Making orphan dir node\n");

    if (tsk_fs_dir_make_orphan_dir_name(&(yaffsfs->fs_info), fs_name)) {
        tsk_fs_name_free(fs_name);
        return TSK_ERR;
    }

    if (yaffs_make_directory(yaffsfs, fs_file, yaffsfs->fs_info.last_inum, (char *)fs_name)){
        tsk_fs_name_free(fs_name);
        return 1;
    }
    tsk_fs_name_free(fs_name);
    return 0;
}

/* yaffsfs_inode_lookup - lookup inode, external interface
*
* Returns 1 on error and 0 on success
*
*/

static uint8_t
    yaffs_inode_lookup(TSK_FS_INFO *a_fs, TSK_FS_FILE * a_fs_file,
    TSK_INUM_T inum)
{
    YAFFSFS_INFO *yfs = (YAFFSFS_INFO *)a_fs;
    YaffsCacheObject *obj;
    YaffsCacheVersion *version;
    YaffsHeader *header = NULL;
    YaffsSpare *spare = NULL;
    TSK_RETVAL_ENUM result;
    uint8_t type;
    char *real_name;

    if (a_fs_file == NULL) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("yaffsfs_inode_lookup: fs_file is NULL");
        return 1;
    }

    if (a_fs_file->meta == NULL) {
        if ((a_fs_file->meta =
            tsk_fs_meta_alloc(YAFFS_FILE_CONTENT_LEN)) == NULL)
            return 1;
    }
    else {
        tsk_fs_meta_reset(a_fs_file->meta);
    }

    if (tsk_verbose)
        tsk_fprintf(stderr, "yaffs_inode_lookup: looking up %" PRIuINUM "\n",inum);

    switch(inum) {
    case YAFFS_OBJECT_UNLINKED:
        yaffs_make_unlinked(yfs, a_fs_file);
        return 0;

    case YAFFS_OBJECT_DELETED:
        yaffs_make_deleted(yfs, a_fs_file);
        return 0;
    }

    if(inum == yfs->fs_info.last_inum){
        yaffs_make_orphan_dir(yfs, a_fs_file);
        return 0;
    }

    result = yaffscache_version_find_by_inode(yfs, inum, &version, &obj);
    if (result != TSK_OK) {
        if (tsk_verbose)
            tsk_fprintf(stderr, "yaffs_inode_lookup: yaffscache_version_find_by_inode failed! (inode = %d)\n", inum);
        return 1;
    }

    if(version->ycv_header_chunk == NULL){
        return 1;
    }

    if (yaffsfs_read_chunk(yfs, &header, &spare, version->ycv_header_chunk->ycc_offset) != TSK_OK) {
        if (tsk_verbose)
            tsk_fprintf(stderr, "yaffs_inode_lookup: yaffsfs_read_chunk failed!\n");
        return 1;
    }

    type = header->obj_type;

    switch(inum) {
    case YAFFS_OBJECT_LOSTNFOUND:
        real_name = YAFFS_OBJECT_LOSTNFOUND_NAME;
        break;
    case YAFFS_OBJECT_UNLINKED:
        real_name = YAFFS_OBJECT_UNLINKED_NAME;
        break;
    case YAFFS_OBJECT_DELETED:
        real_name = YAFFS_OBJECT_DELETED_NAME;
        break;
    default:
        real_name = header->name;
        break;
    }

    switch(type) {
    case YAFFS_TYPE_FILE:
        if (tsk_verbose)
            tsk_fprintf(stderr, "yaffs_inode_lookup: is a file\n");
        yaffs_make_regularfile(yfs, a_fs_file, inum, real_name);
        break;

    case YAFFS_TYPE_DIRECTORY:
        if (tsk_verbose)
            tsk_fprintf(stderr, "yaffs_inode_lookup: is a directory\n");
        yaffs_make_directory(yfs, a_fs_file, inum, real_name);
        break;

    case YAFFS_TYPE_SOFTLINK:
        if (tsk_verbose)
            tsk_fprintf(stderr, "yaffs_inode_lookup: is a symbolic link\n");
        yaffs_make_regularfile(yfs, a_fs_file, inum, real_name);
        a_fs_file->meta->type = TSK_FS_META_TYPE_LNK;
        break;

    case YAFFS_TYPE_HARDLINK:
    case YAFFS_TYPE_UNKNOWN:
    default:
        if (tsk_verbose)
            tsk_fprintf(stderr, "yaffs_inode_lookup: is *** UNHANDLED *** (type %d, header at 0x%x)\n", type, version->ycv_header_chunk->ycc_offset);
        // We can still set a few things
        a_fs_file->meta->type = TSK_FS_META_TYPE_UNDEF;
        a_fs_file->meta->addr = inum;
        if(yaffs_is_version_allocated(yfs, inum)){
            a_fs_file->meta->flags =
                (TSK_FS_META_FLAG_ENUM)(TSK_FS_META_FLAG_USED | TSK_FS_META_FLAG_ALLOC);
        }
        else{
            a_fs_file->meta->flags =
                (TSK_FS_META_FLAG_ENUM)(TSK_FS_META_FLAG_USED | TSK_FS_META_FLAG_UNALLOC);
        }
        if (a_fs_file->meta->name2 == NULL) {
            if ((a_fs_file->meta->name2 = (TSK_FS_META_NAME_LIST *)
                tsk_malloc(sizeof(TSK_FS_META_NAME_LIST))) == NULL){
                    return 1;
            }
            a_fs_file->meta->name2->next = NULL;
        }
        strncpy(a_fs_file->meta->name2->name, real_name,
            TSK_FS_META_NAME_LIST_NSIZE);
        break;
    }

    /* Who owns this? I'm following the way FATFS does it by freeing + NULLing 
    * this and mallocing if used. 
    */
    if (a_fs_file->meta->link != NULL) {
        free(a_fs_file->meta->link);
        a_fs_file->meta->link = NULL;
    }

    if (type != YAFFS_TYPE_HARDLINK) {
        a_fs_file->meta->mode = (TSK_FS_META_MODE_ENUM)(header->file_mode & TWELVE_BITS_MASK); // chop at 12 bits;
        a_fs_file->meta->uid = header->user_id;
        a_fs_file->meta->gid = header->group_id;
        a_fs_file->meta->mtime = header->mtime;
        a_fs_file->meta->atime = header->atime;
        a_fs_file->meta->ctime = header->ctime;
    }

    if (type == YAFFS_TYPE_FILE) {
        a_fs_file->meta->size = header->file_size;
        // NOTE: This isn't in Android 3.3 kernel but is in YAFFS2 git
        //a_fs_file->meta->size |= ((TSK_OFF_T) header->file_size_high) << 32;
    }

    if (type == YAFFS_TYPE_HARDLINK) {
        // TODO: Store equivalent_id somewhere? */
    }

    if (type == YAFFS_TYPE_SOFTLINK) {
        a_fs_file->meta->link = (char*)tsk_malloc(YAFFS_HEADER_ALIAS_LENGTH);
        if (a_fs_file->meta->link == NULL) {
            free(header);
            free(spare);
            return 1;
        }

        memcpy(a_fs_file->meta->link, header->alias, YAFFS_HEADER_ALIAS_LENGTH);
    }

    free(header);
    free(spare);
    return 0;
}



/* yaffsfs_inode_walk - inode iterator
*
* flags used: TSK_FS_META_FLAG_USED, TSK_FS_META_FLAG_UNUSED,
*  TSK_FS_META_FLAG_ALLOC, TSK_FS_META_FLAG_UNALLOC, TSK_FS_META_FLAG_ORPHAN
*
*  Return 1 on error and 0 on success
*/

static uint8_t
    yaffsfs_inode_walk(TSK_FS_INFO *fs, TSK_INUM_T start_inum,
    TSK_INUM_T end_inum, TSK_FS_META_FLAG_ENUM flags,
    TSK_FS_META_WALK_CB a_action, void *a_ptr)
{
    YAFFSFS_INFO *yfs = (YAFFSFS_INFO *)fs;
    TSK_FS_FILE *fs_file;
    TSK_RETVAL_ENUM result;

    uint32_t start_obj_id;
    uint32_t start_ver_number;
    uint32_t end_obj_id;
    uint32_t end_ver_number;

    uint32_t obj_id;

    YaffsCacheObject *curr_obj;
    YaffsCacheVersion *curr_version;

    result = yaffscache_inode_to_obj_id_and_version(start_inum, &start_obj_id, &start_ver_number);

    result = yaffscache_inode_to_obj_id_and_version(end_inum, &end_obj_id, &end_ver_number);

    if (end_obj_id < start_obj_id) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("yaffsfs_inode_walk: end object id must be >= start object id: "
            "%" PRIx32 " must be >= %" PRIx32 "",
            end_obj_id, start_obj_id);
        return 1;
    }

    /* The ORPHAN flag is unsupported for YAFFS2 */
    if (flags & TSK_FS_META_FLAG_ORPHAN) {
        if (tsk_verbose){
            tsk_fprintf(stderr, "yaffsfs_inode_walk: ORPHAN flag unsupported by YAFFS2");
        }
    }

    if (((flags & TSK_FS_META_FLAG_ALLOC) == 0) &&
        ((flags & TSK_FS_META_FLAG_UNALLOC) == 0)) {
            flags = (TSK_FS_META_FLAG_ENUM)(flags | TSK_FS_META_FLAG_ALLOC | TSK_FS_META_FLAG_UNALLOC);
    }

    /* If neither of the USED or UNUSED flags are set, then set them
    * both
    */
    if (((flags & TSK_FS_META_FLAG_USED) == 0) &&
        ((flags & TSK_FS_META_FLAG_UNUSED) == 0)) {
            flags = (TSK_FS_META_FLAG_ENUM)(flags | TSK_FS_META_FLAG_USED | TSK_FS_META_FLAG_UNUSED);
    }

    if ((fs_file = tsk_fs_file_alloc(fs)) == NULL)
        return 1;
    if ((fs_file->meta =
        tsk_fs_meta_alloc(YAFFS_FILE_CONTENT_LEN)) == NULL)
        return 1;


    for (obj_id = start_obj_id; obj_id <= end_obj_id; obj_id++) {
        int retval;

        result = yaffscache_version_find_by_inode(yfs, obj_id, &curr_version, &curr_obj);
        if (result == TSK_OK) {

            TSK_INUM_T curr_inode;
            YaffsCacheVersion *version;

            // ALLOC, UNALLOC, or both are set at this point 
            if (flags & TSK_FS_META_FLAG_ALLOC) {
                // Allocated only - just look at current version
                if (yaffscache_obj_id_and_version_to_inode(obj_id, curr_obj->yco_latest->ycv_version, &curr_inode) != TSK_OK) {
                    tsk_fs_file_close(fs_file);
                    return 1;
                }

                // It's possible for the current version to be unallocated if the last header was a deleted or unlinked header
                if(yaffs_is_version_allocated(yfs, curr_inode)){
                    if (yaffs_inode_lookup(fs, fs_file, curr_inode) != TSK_OK) {
                        tsk_fs_file_close(fs_file);
                        return 1;
                    }

                    retval = a_action(fs_file, a_ptr);
                    if (retval == TSK_WALK_STOP) {
                        tsk_fs_file_close(fs_file);
                        return 0;
                    }
                    else if (retval == TSK_WALK_ERROR) {
                        tsk_fs_file_close(fs_file);
                        return 1;
                    }
                }
            }
            if (flags & TSK_FS_META_FLAG_UNALLOC){
                for (version = curr_obj->yco_latest; version != NULL; version = version->ycv_prior) {
                    if (yaffscache_obj_id_and_version_to_inode(obj_id, version->ycv_version, &curr_inode) != TSK_OK) {
                        tsk_fs_file_close(fs_file);
                        return 1;
                    }

                    if(! yaffs_is_version_allocated(yfs, curr_inode)){
                        if (yaffs_inode_lookup(fs, fs_file, curr_inode) != TSK_OK) {
                            tsk_fs_file_close(fs_file);
                            return 1;
                        }

                        retval = a_action(fs_file, a_ptr);
                        if (retval == TSK_WALK_STOP) {
                            tsk_fs_file_close(fs_file);
                            return 0;
                        }
                        else if (retval == TSK_WALK_ERROR) {
                            tsk_fs_file_close(fs_file);
                            return 1;
                        }
                    }
                }
            }

            curr_obj = curr_obj->yco_next;
        }
    }

    /*
    * Cleanup.
    */
    tsk_fs_file_close(fs_file);
    return 0;
}

static TSK_FS_BLOCK_FLAG_ENUM
    yaffsfs_block_getflags(TSK_FS_INFO *fs, TSK_DADDR_T a_addr)
{
    YAFFSFS_INFO *yfs = (YAFFSFS_INFO *)fs;
    TSK_FS_BLOCK_FLAG_ENUM flags = TSK_FS_BLOCK_FLAG_UNUSED;

    TSK_OFF_T offset = (a_addr * (fs->block_pre_size + fs->block_size + fs->block_post_size)) + yfs->page_size;
    YaffsSpare *spare = NULL;
    YaffsHeader *header = NULL;
    if (yaffsfs_read_spare(yfs, &spare, offset) != TSK_OK) {
        /* NOTE: Uh, how do we signal error? */
        return flags;
    }

    if (yaffsfs_is_spare_valid(yfs, spare) == TSK_OK) {
        /* XXX: Do we count blocks of older versions unallocated?
        *      If so, we need a smarter way to do this :/
        *
        *      Walk the object from this block and see if this
        *      block is used in the latest version. Could pre-
        *      calculate this at cache time as well.
        */


        if (spare->chunk_id == 0) {
            flags = (TSK_FS_BLOCK_FLAG_ENUM)(flags | TSK_FS_BLOCK_FLAG_META);
        } else {
            flags = (TSK_FS_BLOCK_FLAG_ENUM)(flags | TSK_FS_BLOCK_FLAG_CONT);
        }

        // Have obj id and offset
        // 1. Is the current version of this object allocated?
        // 2. If this is a header, is it the header of the current version?
        // 3. Is the chunk id too big given the current header?
        // 4. Is there a more recent version of this chunk id?
        YaffsCacheObject * obj = NULL;
        yaffscache_object_find(yfs, spare->object_id, &obj);

        // The result really shouldn't be NULL since we loaded every chunk
        if(obj != NULL){
            if(! yaffs_is_version_allocated(yfs, spare->object_id)){
                // If the current version isn't allocated, then no chunks in it are
                flags = (TSK_FS_BLOCK_FLAG_ENUM)(flags | TSK_FS_BLOCK_FLAG_UNALLOC);
            }
            else if (obj->yco_latest == NULL || obj->yco_latest->ycv_header_chunk == NULL) { 
                flags = (TSK_FS_BLOCK_FLAG_ENUM)(flags | TSK_FS_BLOCK_FLAG_UNALLOC); 
            }
            else if(spare->chunk_id == 0){
                if(obj->yco_latest->ycv_header_chunk->ycc_offset == offset - yfs->page_size){
                    // Have header chunk and it's the most recent header chunk
                    flags = (TSK_FS_BLOCK_FLAG_ENUM)(flags | TSK_FS_BLOCK_FLAG_ALLOC);
                }
                else{
                    // Have header chunk but isn't the most recent
                    flags = (TSK_FS_BLOCK_FLAG_ENUM)(flags | TSK_FS_BLOCK_FLAG_UNALLOC);
                }
            }
            else{
                // Read in the full header
                yaffsfs_read_header(yfs, &header, obj->yco_latest->ycv_header_chunk->ycc_offset);

                // chunk_id is 1-based, so for example chunk id 2 would be too big for a file
                //   500 bytes long
                if(header->file_size <= ((spare->chunk_id - 1) * (fs->block_size))){
                    flags = (TSK_FS_BLOCK_FLAG_ENUM)(flags | TSK_FS_BLOCK_FLAG_UNALLOC);
                }
                else{
                    // Since at this point we know there should be a chunk with this chunk id in the file, if
                    // this is the most recent version of the chunk assume it's part of the current version of the object.
                    YaffsCacheChunk * curr = obj->yco_latest->ycv_last_chunk;
                    while(curr != NULL){ // curr should really never make it to the beginning of the list

                        // Did we find our chunk?
                        if(curr->ycc_offset == offset - yfs->page_size){
                            flags = (TSK_FS_BLOCK_FLAG_ENUM)(flags | TSK_FS_BLOCK_FLAG_ALLOC);
                            break;
                        }

                        // Did we find a different chunk with our chunk id?
                        if(curr->ycc_chunk_id == spare->chunk_id){
                            flags = (TSK_FS_BLOCK_FLAG_ENUM)(flags | TSK_FS_BLOCK_FLAG_UNALLOC);
                            break;
                        }
                        curr = curr->ycc_prev;
                    }
                }
            }
        }

    } else {
        flags = (TSK_FS_BLOCK_FLAG_ENUM)(flags | TSK_FS_BLOCK_FLAG_UNUSED | TSK_FS_BLOCK_FLAG_UNALLOC);
    }

    free(spare);
    free(header);
    return flags;
}


/* yaffsfs_block_walk - block iterator
*
* flags: TSK_FS_BLOCK_FLAG_ALLOC, TSK_FS_BLOCK_FLAG_UNALLOC, TSK_FS_BLOCK_FLAG_CONT,
*  TSK_FS_BLOCK_FLAG_META
*
*  Return 1 on error and 0 on success
*/
static uint8_t
    yaffsfs_block_walk(TSK_FS_INFO *a_fs, TSK_DADDR_T a_start_blk,
    TSK_DADDR_T a_end_blk, TSK_FS_BLOCK_WALK_FLAG_ENUM a_flags,
    TSK_FS_BLOCK_WALK_CB a_action, void *a_ptr)
{
    TSK_FS_BLOCK *fs_block;
    TSK_DADDR_T addr;

    // clean up any error messages that are lying around
    tsk_error_reset();

    /*
    * Sanity checks.
    */
    if (a_start_blk < a_fs->first_block || a_start_blk > a_fs->last_block) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("yaffsfs_block_walk: start block: %" PRIuDADDR,
            a_start_blk);
        return 1;
    }
    if (a_end_blk < a_fs->first_block || a_end_blk > a_fs->last_block
        || a_end_blk < a_start_blk) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
            tsk_error_set_errstr("yaffsfs_block_walk: end block: %" PRIuDADDR ,
                a_end_blk);
            return 1;
    }

    /* Sanity check on a_flags -- make sure at least one ALLOC is set */
    if (((a_flags & TSK_FS_BLOCK_WALK_FLAG_ALLOC) == 0) &&
        ((a_flags & TSK_FS_BLOCK_WALK_FLAG_UNALLOC) == 0)) {
            a_flags = (TSK_FS_BLOCK_WALK_FLAG_ENUM)
                (a_flags | TSK_FS_BLOCK_WALK_FLAG_ALLOC |
                TSK_FS_BLOCK_WALK_FLAG_UNALLOC);
    }
    if (((a_flags & TSK_FS_BLOCK_WALK_FLAG_META) == 0) &&
        ((a_flags & TSK_FS_BLOCK_WALK_FLAG_CONT) == 0)) {
            a_flags = (TSK_FS_BLOCK_WALK_FLAG_ENUM)
                (a_flags | TSK_FS_BLOCK_WALK_FLAG_CONT | TSK_FS_BLOCK_WALK_FLAG_META);
    }


    if ((fs_block = tsk_fs_block_alloc(a_fs)) == NULL) {
        return 1;
    }

    for (addr = a_start_blk; addr <= a_end_blk; addr++) {
        int retval;
        int myflags;

        myflags = yaffsfs_block_getflags(a_fs, addr);

        // test if we should call the callback with this one
        if ((myflags & TSK_FS_BLOCK_FLAG_META)
            && (!(a_flags & TSK_FS_BLOCK_WALK_FLAG_META)))
            continue;
        else if ((myflags & TSK_FS_BLOCK_FLAG_CONT)
            && (!(a_flags & TSK_FS_BLOCK_WALK_FLAG_CONT)))
            continue;
        else if ((myflags & TSK_FS_BLOCK_FLAG_ALLOC)
            && (!(a_flags & TSK_FS_BLOCK_WALK_FLAG_ALLOC)))
            continue;
        else if ((myflags & TSK_FS_BLOCK_FLAG_UNALLOC)
            && (!(a_flags & TSK_FS_BLOCK_WALK_FLAG_UNALLOC)))
            continue;

        if (tsk_fs_block_get(a_fs, fs_block, addr) == NULL) {
            tsk_error_set_errstr2("yaffsfs_block_walk: block %" PRIuDADDR,
                addr);
            tsk_fs_block_free(fs_block);
            return 1;
        }

        retval = a_action(fs_block, a_ptr);
        if (retval == TSK_WALK_STOP) {
            break;
        }
        else if (retval == TSK_WALK_ERROR) {
            tsk_fs_block_free(fs_block);
            return 1;
        }
    }

    /*
    * Cleanup.
    */
    tsk_fs_block_free(fs_block);
    return 0;
}

static uint8_t
    yaffsfs_fscheck(TSK_FS_INFO * fs, FILE * hFile)
{
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_UNSUPFUNC);
    tsk_error_set_errstr("fscheck not implemented yet for YAFFS");
    return 1;
}


/**
* Print details about the file system to a file handle.
*
* @param fs File system to print details on
* @param hFile File handle to print text to
*
* @returns 1 on error and 0 on success
*/
static uint8_t
    yaffsfs_fsstat(TSK_FS_INFO * fs, FILE * hFile)
{
    YAFFSFS_INFO *yfs = (YAFFSFS_INFO *) fs;
    unsigned int obj_count, version_count;
    uint32_t obj_first, obj_last, version_first, version_last;

    // clean up any error messages that are lying around
    tsk_error_reset();

    tsk_fprintf(hFile, "FILE SYSTEM INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");

    tsk_fprintf(hFile, "File System Type: YAFFS2\n");
    tsk_fprintf(hFile, "Page Size: %u\n", yfs->page_size);
    tsk_fprintf(hFile, "Spare Size: %u\n", yfs->spare_size);
    tsk_fprintf(hFile, "Spare Offsets: Sequence number: %d, Object ID: %d, Chunk ID: %d, nBytes: %d\n",
        yfs->spare_seq_offset, yfs->spare_obj_id_offset, yfs->spare_chunk_id_offset, yfs->spare_nbytes_offset);

    tsk_fprintf(hFile, "\nMETADATA INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");


    yaffscache_objects_stats(yfs, 
        &obj_count, &obj_first, &obj_last,
        &version_count, &version_first, &version_last);

    tsk_fprintf(hFile, "Number of Allocated Objects: %u\n", obj_count);
    tsk_fprintf(hFile, "Object Id Range: %" PRIu32 " - %" PRIu32 "\n",
        obj_first, obj_last);
    tsk_fprintf(hFile, "Number of Total Object Versions: %u\n", version_count);
    tsk_fprintf(hFile, "Object Version Range: %" PRIu32 " - %" PRIu32 "\n",
        version_first, version_last);

    return 0;
}

/************************* istat *******************************/

typedef struct {
    FILE *hFile;
    int idx;
} YAFFSFS_PRINT_ADDR;

/* Callback for istat to print the block addresses */
static TSK_WALK_RET_ENUM
    print_addr_act(YAFFSFS_INFO * fs_file, TSK_OFF_T a_off, TSK_DADDR_T addr,
    char *buf, size_t size, TSK_FS_BLOCK_FLAG_ENUM flags, void *a_ptr)
{
    YAFFSFS_PRINT_ADDR *print = (YAFFSFS_PRINT_ADDR *) a_ptr;

    if (flags & TSK_FS_BLOCK_FLAG_CONT) {
        tsk_fprintf(print->hFile, "%" PRIuDADDR " ", addr);

        if (++(print->idx) == 8) {
            tsk_fprintf(print->hFile, "\n");
            print->idx = 0;
        }
    }

    return TSK_WALK_CONT;
}

/**
* Print details on a specific file to a file handle.
*
* @param fs File system file is located in
* @param hFile File handle to print text to
* @param inum Address of file in file system
* @param numblock The number of blocks in file to force print (can go beyond file size)
* @param sec_skew Clock skew in seconds to also print times in
*
* @returns 1 on error and 0 on success
*/
static uint8_t
    yaffsfs_istat(TSK_FS_INFO *fs, TSK_FS_ISTAT_FLAG_ENUM flags, FILE * hFile, TSK_INUM_T inum,
    TSK_DADDR_T numblock, int32_t sec_skew)
{
    TSK_FS_META *fs_meta;
    TSK_FS_FILE *fs_file;
    YAFFSFS_INFO *yfs = (YAFFSFS_INFO *)fs;
    char ls[12];
    YAFFSFS_PRINT_ADDR print;
    char timeBuf[32];
    YaffsCacheObject * obj = NULL;
    YaffsCacheVersion * version = NULL;
    YaffsHeader * header = NULL;

    yaffscache_version_find_by_inode(yfs, inum, &version, &obj);

    if ((fs_file = tsk_fs_file_open_meta(fs, NULL, inum)) == NULL) {
        return 1;
    }
    fs_meta = fs_file->meta;

    tsk_fprintf(hFile, "inode: %" PRIuINUM "\n", inum);
    tsk_fprintf(hFile, "%sAllocated\n",
        (fs_meta->flags & TSK_FS_META_FLAG_ALLOC) ? "" : "Not ");

    if (fs_meta->link)
        tsk_fprintf(hFile, "symbolic link to: %s\n", fs_meta->link);

    tsk_fprintf(hFile, "uid / gid: %" PRIuUID " / %" PRIuGID "\n",
        fs_meta->uid, fs_meta->gid);

    tsk_fs_meta_make_ls(fs_meta, ls, sizeof(ls));
    tsk_fprintf(hFile, "mode: %s\n", ls);

    tsk_fprintf(hFile, "size: %" PRIuOFF "\n", fs_meta->size);
    tsk_fprintf(hFile, "num of links: %d\n", fs_meta->nlink);

    if(version != NULL){
        yaffsfs_read_header(yfs, &header, version->ycv_header_chunk->ycc_offset);
        if(header != NULL){
            tsk_fprintf(hFile, "Name: %s\n", header->name);
        }
    }

    if (sec_skew != 0) {
        tsk_fprintf(hFile, "\nAdjusted Inode Times:\n");
        fs_meta->mtime -= sec_skew;
        fs_meta->atime -= sec_skew;
        fs_meta->ctime -= sec_skew;

        tsk_fprintf(hFile, "Accessed:\t%s\n",
            tsk_fs_time_to_str(fs_meta->atime, timeBuf));
        tsk_fprintf(hFile, "File Modified:\t%s\n",
            tsk_fs_time_to_str(fs_meta->mtime, timeBuf));
        tsk_fprintf(hFile, "Inode Modified:\t%s\n",
            tsk_fs_time_to_str(fs_meta->ctime, timeBuf));

        fs_meta->mtime += sec_skew;
        fs_meta->atime += sec_skew;
        fs_meta->ctime += sec_skew;

        tsk_fprintf(hFile, "\nOriginal Inode Times:\n");
    }
    else {
        tsk_fprintf(hFile, "\nInode Times:\n");
    }

    tsk_fprintf(hFile, "Accessed:\t%s\n",
        tsk_fs_time_to_str(fs_meta->atime, timeBuf));
    tsk_fprintf(hFile, "File Modified:\t%s\n",
        tsk_fs_time_to_str(fs_meta->mtime, timeBuf));
    tsk_fprintf(hFile, "Inode Modified:\t%s\n",
        tsk_fs_time_to_str(fs_meta->ctime, timeBuf));

    if(version != NULL){
        tsk_fprintf(hFile, "\nHeader Chunk:\n");
        tsk_fprintf(hFile, "%" PRIuDADDR "\n", (version->ycv_header_chunk->ycc_offset / (yfs->page_size + yfs->spare_size)));
    }

    if (numblock > 0) {
        TSK_OFF_T lower_size = numblock * fs->block_size;
        fs_meta->size = (lower_size < fs_meta->size)?(lower_size):(fs_meta->size);
    }
    tsk_fprintf(hFile, "\nData Chunks:\n");


    if (flags & TSK_FS_ISTAT_RUNLIST){
        const TSK_FS_ATTR *fs_attr_default =
            tsk_fs_file_attr_get_type(fs_file,
                TSK_FS_ATTR_TYPE_DEFAULT, 0, 0);
        if (fs_attr_default && (fs_attr_default->flags & TSK_FS_ATTR_NONRES)) {
            if (tsk_fs_attr_print(fs_attr_default, hFile)) {
                tsk_fprintf(hFile, "\nError creating run lists  ");
                tsk_error_print(hFile);
                tsk_error_reset();
            }
        }
    }
    else {
        print.idx = 0;
        print.hFile = hFile;

        if (tsk_fs_file_walk(fs_file, TSK_FS_FILE_WALK_FLAG_AONLY,
            (TSK_FS_FILE_WALK_CB)print_addr_act, (void *)&print)) {
            tsk_fprintf(hFile, "\nError reading file:  ");
            tsk_error_print(hFile);
            tsk_error_reset();
        }
        else if (print.idx != 0) {
            tsk_fprintf(hFile, "\n");
        }
    }

    tsk_fs_file_close(fs_file);

    return 0;
}

/* yaffsfs_close - close an yaffsfs file system */
static void
    yaffsfs_close(TSK_FS_INFO *fs)
{
    if(fs != NULL){
        YAFFSFS_INFO *yfs = (YAFFSFS_INFO *)fs;

        fs->tag = 0;

        // Walk and free the cache structures
        yaffscache_objects_free(yfs);
        yaffscache_chunks_free(yfs);

        //tsk_deinit_lock(&yaffsfs->lock);
        tsk_fs_free(fs);
	}
}

typedef struct _dir_open_cb_args {
    YAFFSFS_INFO *yfs;
    TSK_FS_DIR *dir;
    TSK_INUM_T parent_addr;
} dir_open_cb_args;

static TSK_RETVAL_ENUM
    yaffs_dir_open_meta_cb(YaffsCacheObject *obj, YaffsCacheVersion *version, void *args) {
        dir_open_cb_args *cb_args = (dir_open_cb_args *) args;
        YaffsCacheChunk *chunk = version->ycv_header_chunk;
        TSK_INUM_T curr_inode = 0;
        uint32_t obj_id = chunk->ycc_obj_id;
        uint32_t chunk_id = chunk->ycc_chunk_id;
        uint32_t vnum = version->ycv_version;
        YaffsHeader *header = NULL;
        TSK_FS_NAME * fs_name;
        char *file_ext;
        char version_string[64]; // Allow a max of 64 bytes in the version string

        yaffscache_obj_id_and_version_to_inode(obj_id, vnum, &curr_inode);

        if (chunk_id != 0) {
            return TSK_ERR;
        }

        if (tsk_verbose)
            fprintf(stderr, "dir_open_find_children_cb: %08" PRIxINUM " -> %08" PRIx32 ":%d\n", cb_args->parent_addr, obj_id, vnum);


        if (yaffsfs_read_header(cb_args->yfs, &header, chunk->ycc_offset) != TSK_OK) {
            return TSK_ERR;
        }

        if ((fs_name = tsk_fs_name_alloc(YAFFSFS_MAXNAMLEN + 64, 0)) == NULL) {
            free(header);
            return TSK_ERR;
        }

        switch (obj_id) {
        case YAFFS_OBJECT_LOSTNFOUND:
            strncpy(fs_name->name, YAFFS_OBJECT_LOSTNFOUND_NAME,
                fs_name->name_size - 64);
            break;
        case YAFFS_OBJECT_UNLINKED:
            strncpy(fs_name->name, YAFFS_OBJECT_UNLINKED_NAME,
                fs_name->name_size - 64);
            break;
        case YAFFS_OBJECT_DELETED:
            strncpy(fs_name->name, YAFFS_OBJECT_DELETED_NAME,
                fs_name->name_size - 64);
            break;
        default:
            strncpy(fs_name->name, header->name, fs_name->name_size - 64);
            break;
        }
        fs_name->name[fs_name->name_size - 65] = 0;

        // Only put object/version string onto unallocated versions
        if(! yaffs_is_version_allocated(cb_args->yfs, curr_inode)){ 
            // Also copy the extension so that it also shows up after the version string, which allows
            // easier searching by file extension. Max extension length is 5 characters after the dot,
            // and require at least one character before the dot
            file_ext = strrchr(fs_name->name, '.');
            if((file_ext != NULL) && (file_ext != fs_name->name) && (strlen(file_ext) < 7)){
               snprintf(version_string, 64, "#%d,%d%s", obj_id, vnum, file_ext);
            }
            else{
               snprintf(version_string, 64, "#%d,%d", obj_id, vnum);
            }
            strncat(fs_name->name, version_string, 64);
            fs_name->flags = TSK_FS_NAME_FLAG_UNALLOC;
        }
        else{
            fs_name->flags = TSK_FS_NAME_FLAG_ALLOC;
        }

        fs_name->meta_addr = curr_inode;

        switch (header->obj_type) {
        case YAFFS_TYPE_FILE:
            fs_name->type = TSK_FS_NAME_TYPE_REG;
            break;

        case YAFFS_TYPE_DIRECTORY:
            fs_name->type = TSK_FS_NAME_TYPE_DIR;
            break;

        case YAFFS_TYPE_SOFTLINK:
        case YAFFS_TYPE_HARDLINK:
            fs_name->type = TSK_FS_NAME_TYPE_LNK;
            break;

        case YAFFS_TYPE_SPECIAL:
            fs_name->type = TSK_FS_NAME_TYPE_UNDEF; // Could be a socket
            break;

        default:
            if (tsk_verbose)
                fprintf(stderr, "yaffs_dir_open_meta_cb: unhandled object type\n");
            fs_name->type = TSK_FS_NAME_TYPE_UNDEF;
            break;
        }

        free(header);

        if (tsk_fs_dir_add(cb_args->dir, fs_name)) {
            tsk_fs_name_free(fs_name);
            return TSK_ERR;
        }

        /* A copy is made in tsk_fs_dir_add, so we can free this one */
        tsk_fs_name_free(fs_name);

        return TSK_OK;
}

static TSK_RETVAL_ENUM
    yaffsfs_dir_open_meta(TSK_FS_INFO *a_fs, TSK_FS_DIR ** a_fs_dir,
    TSK_INUM_T a_addr)
{
    TSK_FS_DIR *fs_dir;
    TSK_FS_NAME *fs_name;
    YAFFSFS_INFO *yfs = (YAFFSFS_INFO *)a_fs;
    int should_walk_children = 0;
    uint32_t obj_id;
    uint32_t ver_number;

    if (a_addr < a_fs->first_inum || a_addr > a_fs->last_inum) { 
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("yaffs_dir_open_meta: Invalid inode value: %"
            PRIuINUM, a_addr);
        return TSK_ERR;
    }
    else if (a_fs_dir == NULL) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("yaffs_dir_open_meta: NULL fs_dir argument given");
        return TSK_ERR;
    }

    fs_dir = *a_fs_dir;

    if (fs_dir) {
        tsk_fs_dir_reset(fs_dir);
        fs_dir->addr = a_addr;
    }
    else if ((*a_fs_dir = fs_dir = tsk_fs_dir_alloc(a_fs, a_addr, 128)) == NULL) {
        return TSK_ERR;
    }

    if (tsk_verbose)
        fprintf(stderr,"yaffs_dir_open_meta: called for directory %" PRIu32 "\n", (uint32_t) a_addr);

    //  handle the orphan directory if its contents were requested
    if (a_addr == TSK_FS_ORPHANDIR_INUM(a_fs)) {
        return tsk_fs_dir_find_orphans(a_fs, fs_dir);
    }

    if ((fs_name = tsk_fs_name_alloc(YAFFSFS_MAXNAMLEN, 0)) == NULL) {
        return TSK_ERR;
    }


    if ((fs_dir->fs_file = 
        tsk_fs_file_open_meta(a_fs, NULL, a_addr)) == NULL) {
            tsk_error_errstr2_concat(" - yaffs_dir_open_meta");
            tsk_fs_name_free(fs_name);
            return TSK_ERR;
    }

    // extract obj_id and ver_number from inum
    yaffscache_inode_to_obj_id_and_version(a_addr, &obj_id, &ver_number);

    // Decide if we should walk the directory structure
    if (obj_id == YAFFS_OBJECT_DELETED ||
        obj_id == YAFFS_OBJECT_UNLINKED) {
            should_walk_children = 1;
    }
    else {
        YaffsCacheObject *obj;
        YaffsCacheVersion *versionFound;
        TSK_RETVAL_ENUM result = yaffscache_version_find_by_inode(yfs, a_addr, &versionFound, &obj);
        if (result != TSK_OK) {
            if (tsk_verbose)
                tsk_fprintf(stderr, "yaffsfs_dir_open_meta: yaffscache_version_find_by_inode failed! (inode: %d\n", a_addr);
            tsk_fs_name_free(fs_name);
            return TSK_ERR;
        }

        /* Only attach files onto the latest version of the directory */
        should_walk_children = (obj->yco_latest == versionFound);
    }

    // Search the cache for the children of this object and add them to fs_dir
    if (should_walk_children) {
        dir_open_cb_args args;
        args.yfs = yfs;
        args.dir = fs_dir;
        args.parent_addr = a_addr;
        yaffscache_find_children(yfs, a_addr, yaffs_dir_open_meta_cb, &args);
    }

    // add special entries to root directory
    if (obj_id == YAFFS_OBJECT_ROOT) {
        strncpy(fs_name->name, YAFFS_OBJECT_UNLINKED_NAME, fs_name->name_size);
        fs_name->meta_addr = YAFFS_OBJECT_UNLINKED;
        fs_name->type = TSK_FS_NAME_TYPE_DIR;
        fs_name->flags = TSK_FS_NAME_FLAG_ALLOC;
        if (tsk_fs_dir_add(fs_dir, fs_name)) {
            tsk_fs_name_free(fs_name);
            return TSK_ERR;
        }

        strncpy(fs_name->name, YAFFS_OBJECT_DELETED_NAME, fs_name->name_size);
        fs_name->meta_addr = YAFFS_OBJECT_DELETED;
        fs_name->type = TSK_FS_NAME_TYPE_DIR;
        fs_name->flags = TSK_FS_NAME_FLAG_ALLOC;
        if (tsk_fs_dir_add(fs_dir, fs_name)) {
            tsk_fs_name_free(fs_name);
            return TSK_ERR;
        }

        // orphan directory
        if (tsk_fs_dir_make_orphan_dir_name(a_fs, fs_name)) {
            tsk_fs_name_free(fs_name);
            return TSK_ERR;
        }
        fs_name->meta_addr = yfs->fs_info.last_inum;
        fs_name->type = TSK_FS_NAME_TYPE_DIR;
        fs_name->flags = TSK_FS_NAME_FLAG_ALLOC;
        if (tsk_fs_dir_add(fs_dir, fs_name)) {
            tsk_fs_name_free(fs_name);
            return TSK_ERR;
        }
    }

    tsk_fs_name_free(fs_name);
    return TSK_OK;
}

static TSK_FS_ATTR_TYPE_ENUM
    yaffsfs_get_default_attr_type(const TSK_FS_FILE * a_file)
{
    return TSK_FS_ATTR_TYPE_DEFAULT;
}

static uint8_t
    yaffsfs_load_attrs(TSK_FS_FILE *file)
{
    TSK_FS_ATTR *attr;
    TSK_FS_META *meta;
    TSK_FS_INFO *fs;
    YAFFSFS_INFO *yfs;
    TSK_FS_ATTR_RUN *data_run;
    TSK_DADDR_T file_block_count;
    YaffsCacheObject *obj;
    YaffsCacheVersion *version;
    TSK_RETVAL_ENUM result;
    TSK_LIST *chunks_seen = NULL;
    YaffsCacheChunk *curr;
    TSK_FS_ATTR_RUN *data_run_new;


    if (file == NULL || file->meta == NULL || file->fs_info == NULL)
    {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr
            ("yaffsfs_load_attrs: called with NULL pointers");
        return 1;
    }

    meta = file->meta;
    yfs = (YAFFSFS_INFO *)file->fs_info;
    fs = &yfs->fs_info;

    // see if we have already loaded the runs
    if ((meta->attr != NULL)
        && (meta->attr_state == TSK_FS_META_ATTR_STUDIED)) {
            return 0;
    }
    else if (meta->attr_state == TSK_FS_META_ATTR_ERROR) {
        return 1;
    }
    // not sure why this would ever happen, but...
    else if (meta->attr != NULL) {
        tsk_fs_attrlist_markunused(meta->attr);
    }
    else if (meta->attr == NULL) {
        meta->attr = tsk_fs_attrlist_alloc();
    }

    attr = tsk_fs_attrlist_getnew(meta->attr, TSK_FS_ATTR_NONRES);
    if (attr == NULL) {
        meta->attr_state = TSK_FS_META_ATTR_ERROR;
        return 1;
    }

    if (meta->size == 0) {
        data_run = NULL;
    }
    else {
        /* BC: I'm not entirely sure this is needed.  My guess is that
         * this was done instead of maintaining the head of the list of 
         * runs.  In theory, the tsk_fs_attr_add_run() method should handle
         * the fillers. */
        data_run = tsk_fs_attr_run_alloc();
        if (data_run == NULL) {
            tsk_fs_attr_run_free(data_run);
            meta->attr_state = TSK_FS_META_ATTR_ERROR;
            return 1;
        }

        data_run->offset = 0;
        data_run->addr = 0;
        data_run->len = (meta->size + fs->block_size - 1) / fs->block_size;
        data_run->flags = TSK_FS_ATTR_RUN_FLAG_FILLER;
    }
    

    // initialize the data run
    if (tsk_fs_attr_set_run(file, attr, data_run, NULL,
        TSK_FS_ATTR_TYPE_DEFAULT, TSK_FS_ATTR_ID_DEFAULT,
        meta->size, meta->size, roundup(meta->size, fs->block_size), (TSK_FS_ATTR_FLAG_ENUM)0, 0)) {
            meta->attr_state = TSK_FS_META_ATTR_ERROR;
            return 1;
    }

    // If the file has size zero, return now
    if(meta->size == 0){
        meta->attr_state = TSK_FS_META_ATTR_STUDIED;
        return 0;
    }


    /* Get the version for the given object. */
    result = yaffscache_version_find_by_inode(yfs, meta->addr, &version, &obj);
    if (result != TSK_OK || version == NULL) {
        if (tsk_verbose)
            tsk_fprintf(stderr, "yaffsfs_load_attrs: yaffscache_version_find_by_inode failed!\n");
        meta->attr_state = TSK_FS_META_ATTR_ERROR;
        return 1;
    }

    if (tsk_verbose)
        yaffscache_object_dump(stderr, obj);

    file_block_count = data_run->len;
    /* Cycle through the chunks for this version of this object */
    curr = version->ycv_last_chunk;
    while (curr != NULL && curr->ycc_obj_id == obj->yco_obj_id) {

        if (curr->ycc_chunk_id == 0) {
            if (tsk_verbose)
                tsk_fprintf(stderr, "yaffsfs_load_attrs: skipping header chunk\n");
        }
        else if (tsk_list_find(chunks_seen, curr->ycc_chunk_id)) {
            if (tsk_verbose)
                tsk_fprintf(stderr, "yaffsfs_load_attrs: skipping duplicate chunk\n");
        }
        else if (curr->ycc_chunk_id > file_block_count) {
            if (tsk_verbose)
                tsk_fprintf(stderr, "yaffsfs_load_attrs: skipping chunk past end\n");
        }
        /* We like this chunk */
        else {
            // add it to our internal list
            if (tsk_list_add(&chunks_seen, curr->ycc_chunk_id)) {
                meta->attr_state = TSK_FS_META_ATTR_ERROR;
                tsk_list_free(chunks_seen);
                chunks_seen = NULL;
                return 1;
            }

            data_run_new = tsk_fs_attr_run_alloc();
            if (data_run_new == NULL) {
                tsk_fs_attr_run_free(data_run_new);
                meta->attr_state = TSK_FS_META_ATTR_ERROR;
                return 1;
            }

            data_run_new->offset = (curr->ycc_chunk_id - 1);
            data_run_new->addr = curr->ycc_offset / (fs->block_pre_size + fs->block_size + fs->block_post_size);
            data_run_new->len = 1;
            data_run_new->flags = TSK_FS_ATTR_RUN_FLAG_NONE;

            if (tsk_verbose)
                tsk_fprintf(stderr, "yaffsfs_load_attrs: @@@ Chunk %d : %08x is at offset 0x%016llx\n",
                curr->ycc_chunk_id, curr->ycc_seq_number, curr->ycc_offset);

            tsk_fs_attr_add_run(fs, attr, data_run_new);
        }

        curr = curr->ycc_prev;
    }

    tsk_list_free(chunks_seen);
    meta->attr_state = TSK_FS_META_ATTR_STUDIED;
    return 0;
}

static uint8_t 
    yaffsfs_jentry_walk(TSK_FS_INFO *info, int entry,
    TSK_FS_JENTRY_WALK_CB cb, void *fn)
{
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_UNSUPFUNC);
    tsk_error_set_errstr("Journal support for YAFFS is not implemented");
    return 1;
}

static uint8_t 
    yaffsfs_jblk_walk(TSK_FS_INFO *info, TSK_DADDR_T daddr,
    TSK_DADDR_T daddrt, int entry, TSK_FS_JBLK_WALK_CB cb, void *fn)
{
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_UNSUPFUNC);
    tsk_error_set_errstr("Journal support for YAFFS is not implemented");
    return 1;
}

static uint8_t 
    yaffsfs_jopen(TSK_FS_INFO *info, TSK_INUM_T inum)
{
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_UNSUPFUNC);
    tsk_error_set_errstr("Journal support for YAFFS is not implemented");
    return 1;
}

/**
* \internal
* Open part of a disk image as a Yaffs/2 file system.
*
* @param img_info Disk image to analyze
* @param offset Byte offset where file system starts
* @param ftype Specific type of file system
* @param test Going to use this - 1 if we're doing auto-detect, 0 if not (display more verbose messages if the user specified YAFFS2)
* @returns NULL on error or if data is not an Yaffs/3 file system
*/
TSK_FS_INFO *
    yaffs2_open(TSK_IMG_INFO * img_info, TSK_OFF_T offset,
    TSK_FS_TYPE_ENUM ftype, uint8_t test)
{
    YAFFSFS_INFO *yaffsfs = NULL;
    TSK_FS_INFO *fs = NULL;
    const unsigned int psize = img_info->page_size;
    const unsigned int ssize = img_info->spare_size;
    YaffsHeader * first_header = NULL;
    TSK_FS_DIR *test_dir;
    std::map<std::string, std::string> configParams;
    YAFFS_CONFIG_STATUS config_file_status;

    // clean up any error messages that are lying around
    tsk_error_reset();

    if (TSK_FS_TYPE_ISYAFFS2(ftype) == 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("Invalid FS Type in yaffsfs_open");
        return NULL;
    }

    if (img_info->sector_size == 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("yaffs2_open: sector size is 0");
        return NULL;
    }

    

    if ((yaffsfs = (YAFFSFS_INFO *) tsk_fs_malloc(sizeof(YAFFSFS_INFO))) == NULL)
        return NULL;
    yaffsfs->cache_objects = NULL;
    yaffsfs->chunkMap = NULL;

    fs = &(yaffsfs->fs_info);

    fs->tag = TSK_FS_INFO_TAG;
    fs->ftype = ftype;
    fs->flags = (TSK_FS_INFO_FLAG_ENUM)0;
    fs->img_info = img_info;
    fs->offset = offset;
    fs->endian = TSK_LIT_ENDIAN;

    // Read config file (if it exists)
    config_file_status = yaffs_load_config_file(img_info, configParams);
    if(config_file_status == YAFFS_CONFIG_ERROR){
        // tsk_error was set by yaffs_load_config
        goto on_error;
    }
    else if(config_file_status == YAFFS_CONFIG_OK){
        // Validate the input
        // If it fails validation, return (tsk_error will be set up already)
        if(1 == yaffs_validate_config_file(configParams)){
            goto on_error;
        }
    }

    // If we read these fields from the config file, use those values. Otherwise use the defaults
    if(configParams.find(YAFFS_CONFIG_PAGE_SIZE_STR) != configParams.end()){
        yaffsfs->page_size = atoi(configParams[YAFFS_CONFIG_PAGE_SIZE_STR].c_str());
    }
    else{
        yaffsfs->page_size = psize == 0 ? YAFFS_DEFAULT_PAGE_SIZE : psize;
    }

    if(configParams.find(YAFFS_CONFIG_SPARE_SIZE_STR) != configParams.end()){
        yaffsfs->spare_size = atoi(configParams[YAFFS_CONFIG_SPARE_SIZE_STR].c_str());
    }
    else{
        yaffsfs->spare_size = ssize == 0 ? YAFFS_DEFAULT_SPARE_SIZE : ssize;
    }

    if(configParams.find(YAFFS_CONFIG_CHUNKS_PER_BLOCK_STR) != configParams.end()){
        yaffsfs->chunks_per_block = atoi(configParams[YAFFS_CONFIG_CHUNKS_PER_BLOCK_STR].c_str());
    }
    else{
        yaffsfs->chunks_per_block = 64;
    }

    // TODO: Why are 2 different memory allocation methods used in the same code?
    // This makes things unnecessary complex.
    yaffsfs->max_obj_id = 1;
    yaffsfs->max_version = 0;

    // Keep track of whether we're doing auto-detection of the file system
    if(test){
        yaffsfs->autoDetect = 1;
    }
    else{
        yaffsfs->autoDetect = 0;
    }

    // Determine the layout of the spare area
    // If it was specified in the config file, use those values. Otherwise do the auto-detection
    if(configParams.find(YAFFS_CONFIG_SEQ_NUM_STR) != configParams.end()){
        // In the validation step, we ensured that if one of the offsets was set, we have all of them
        yaffsfs->spare_seq_offset = atoi(configParams[YAFFS_CONFIG_SEQ_NUM_STR].c_str());
        yaffsfs->spare_obj_id_offset = atoi(configParams[YAFFS_CONFIG_OBJ_ID_STR].c_str());
        yaffsfs->spare_chunk_id_offset = atoi(configParams[YAFFS_CONFIG_CHUNK_ID_STR].c_str());

        // Check that the offsets are valid for the given spare area size (fields are 4 bytes long)
        if((yaffsfs->spare_seq_offset + 4 > yaffsfs->spare_size) ||
            (yaffsfs->spare_obj_id_offset + 4 > yaffsfs->spare_size) ||
            (yaffsfs->spare_chunk_id_offset + 4 > yaffsfs->spare_size)){
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS);
            tsk_error_set_errstr("yaffs2_open: Offset(s) in config file too large for spare area (size %d). %s", yaffsfs->spare_size, YAFFS_HELP_MESSAGE);
            goto on_error;
        }


        // nBytes isn't currently used, so just set to zero
        yaffsfs->spare_nbytes_offset = 0;
    }
    else{
        // Decide how many blocks to test. If we're not doing auto-detection, set to zero (no limit)
        unsigned int maxBlocksToTest;
        if(yaffsfs->autoDetect){
            maxBlocksToTest = YAFFS_DEFAULT_MAX_TEST_BLOCKS;
        }
        else{
            maxBlocksToTest = 0;
        }

        if(yaffs_initialize_spare_format(yaffsfs, maxBlocksToTest) != TSK_OK){
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_MAGIC);
            tsk_error_set_errstr("not a YAFFS file system (bad spare format). %s", YAFFS_HELP_MESSAGE);
            if (tsk_verbose)
                fprintf(stderr, "yaffsfs_open: could not find valid spare area format\n%s\n", YAFFS_HELP_MESSAGE);
            goto on_error;
        }
    }

    /*
    * Read the first record, make sure it's a valid header...
    *
    * Used for verification and autodetection of
    * the FS type.
    */
    if (yaffsfs_read_header(yaffsfs, &first_header, 0)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_MAGIC);
        tsk_error_set_errstr("not a YAFFS file system (first record). %s", YAFFS_HELP_MESSAGE);
        if (tsk_verbose)
            fprintf(stderr, "yaffsfs_open: invalid first record\n%s\n", YAFFS_HELP_MESSAGE);
        goto on_error;
    }
    free(first_header);
    first_header = NULL;

    fs->duname = "Chunk";

    /*
    * Calculate the meta data info
    */
    //fs->last_inum = 0xffffffff; // Will update this as we go
    fs->last_inum = 0;
    fs->root_inum = YAFFS_OBJECT_ROOT;
    fs->first_inum = YAFFS_OBJECT_FIRST;
    //fs->inum_count = fs->last_inum; // For now this will be the last_inum - 1 (after we calculate it)

    /*
    * Calculate the block info
    */
    fs->dev_bsize = img_info->sector_size;
    fs->block_size = yaffsfs->page_size;
    fs->block_pre_size = 0;
    fs->block_post_size = yaffsfs->spare_size;
    fs->block_count = img_info->size / (fs->block_pre_size + fs->block_size + fs->block_post_size);
    fs->first_block = 0;
    fs->last_block_act = fs->last_block = fs->block_count ? fs->block_count - 1 : 0;

    /* Set the generic function pointers */
    fs->inode_walk = yaffsfs_inode_walk;
    fs->block_walk = yaffsfs_block_walk;
    fs->block_getflags = yaffsfs_block_getflags;

    fs->get_default_attr_type = yaffsfs_get_default_attr_type;
    fs->load_attrs = yaffsfs_load_attrs;

    fs->file_add_meta = yaffs_inode_lookup;
    fs->dir_open_meta = yaffsfs_dir_open_meta;
    fs->fsstat = yaffsfs_fsstat;
    fs->fscheck = yaffsfs_fscheck;
    fs->istat = yaffsfs_istat;
    fs->name_cmp = tsk_fs_unix_name_cmp;

    fs->close = yaffsfs_close;

    /* Journal */
    fs->jblk_walk = yaffsfs_jblk_walk;
    fs->jentry_walk = yaffsfs_jentry_walk;
    fs->jopen = yaffsfs_jopen;

    /* Initialize the caches */
    if (tsk_verbose)
        fprintf(stderr, "yaffsfs_open: building cache...\n");

    /* Build cache */
    /* NOTE: The only modifications to the cache happen here, during at 
    *       the open. Should be fine with no lock, even if access to the
    *       cache is shared among threads.
    */
    //tsk_init_lock(&yaffsfs->lock);
    yaffsfs->chunkMap = new std::map<uint32_t, YaffsCacheChunkGroup>;
    yaffsfs_parse_image_load_cache(yaffsfs);

    if (tsk_verbose) {
        fprintf(stderr, "yaffsfs_open: done building cache!\n");
        //yaffscache_objects_dump(yaffsfs, stderr);
    }

    // Update the number of inums now that we've read in the file system
    fs->inum_count = fs->last_inum - 1;

    test_dir = tsk_fs_dir_open_meta(fs, fs->root_inum);
    if (test_dir == NULL) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_MAGIC);
        tsk_error_set_errstr("not a YAFFS file system (no root directory). %s", YAFFS_HELP_MESSAGE);
        if (tsk_verbose)
            fprintf(stderr, "yaffsfs_open: invalid file system\n%s\n", YAFFS_HELP_MESSAGE);
        goto on_error;
    }
    tsk_fs_dir_close(test_dir);

    return fs;

on_error:
    // yaffsfs_close frees all the cache objects
    yaffsfs_close(fs);

    return NULL;
}

