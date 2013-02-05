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
 *\file yaffs.c
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
 *      retreive the latest version of this object.
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

/*
 * Cache
 *
 *
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
    curr = yfs->cache_chunks_head;
    prev = NULL;

    if (chunk == NULL) {
        return TSK_ERR;
    }

    while(curr != NULL) {
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

static TSK_RETVAL_ENUM
yaffscache_chunk_add(YAFFSFS_INFO *yfs, TSK_OFF_T offset, uint32_t seq_number,
    uint32_t obj_id, uint32_t chunk_id, uint32_t parent_id)
{
    TSK_RETVAL_ENUM result;

    YaffsCacheChunk *chunk;
    if ((chunk = tsk_malloc(sizeof(YaffsCacheChunk))) == NULL) {
        return TSK_ERR;
    }

    chunk->ycc_offset = offset;
    chunk->ycc_seq_number = seq_number;
    chunk->ycc_obj_id = obj_id;
    chunk->ycc_chunk_id = chunk_id;
    chunk->ycc_parent_id = parent_id;

    YaffsCacheChunk *prev;
    result = yaffscache_chunk_find_insertion_point(yfs, obj_id, offset, seq_number, &prev);
    if (result == TSK_ERR) {
        return TSK_ERR;
    }

    if (prev == NULL) {
        chunk->ycc_prev = NULL;
        chunk->ycc_next = yfs->cache_chunks_head;
    }
    else {
        chunk->ycc_prev = prev;
        chunk->ycc_next = prev->ycc_next;
    }

    if (chunk->ycc_next != NULL) {
        chunk->ycc_next->ycc_prev = chunk;
    }
    else {
        yfs->cache_chunks_tail = chunk;
    }

    if (chunk->ycc_prev != NULL) {
        chunk->ycc_prev->ycc_next = chunk;
    }
    else {
        yfs->cache_chunks_head = chunk;
    }

    return TSK_OK;
}

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

static TSK_RETVAL_ENUM
yaffscache_object_find_or_add(YAFFSFS_INFO *yfs, uint32_t obj_id, YaffsCacheObject **obj)
{
    YaffsCacheObject *prev;
    TSK_RETVAL_ENUM result;

    if (obj == NULL) {
        return TSK_ERR;
    }

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

    if (chunk->ycc_chunk_id == 0)
        header_chunk = chunk;

    /* If this is the second version (since last header_chunk is NULL) and no
     * header was added, get rid of this incomplete old version -- can't be
     * reasonably recovered.
     *
     * TODO: These chunks are still in the structure and can be walked,
     *       but I'm not sure how to represent this set of data chunks
     *       with no metadata under TSK. This is rare and we don't have
     *       a testcase for it now. Punting right now.
     */
    if (obj->yco_latest != NULL) {
        if (obj->yco_latest->ycv_header_chunk == NULL) {
            if (tsk_verbose)
                tsk_fprintf(stderr, "yaffscache_object_add_version: "
                    "removed an incomplete first version (no header)\n");
            YaffsCacheVersion *incomplete = obj->yco_latest;
            obj->yco_latest = obj->yco_latest->ycv_prior;
            free(incomplete);
        }
    }

    if (obj->yco_latest != NULL) {
        ver_number = obj->yco_latest->ycv_version + 1;

        /* Until a new header is given, use the last seen header. */
        if (header_chunk == NULL) {
            header_chunk = obj->yco_latest->ycv_header_chunk;
        }
    }
    else {
        ver_number = 1;
    }

    YaffsCacheVersion *version;
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

static TSK_RETVAL_ENUM
yaffscache_versions_insert_chunk(YAFFSFS_INFO *yfs, YaffsCacheChunk *chunk)
{
    YaffsCacheObject *obj;
    TSK_RETVAL_ENUM result;

    result = yaffscache_object_find_or_add(yfs, chunk->ycc_obj_id, &obj);
    if (result != TSK_OK) {
        return TSK_ERR;
    }

    YaffsCacheVersion *version = obj->yco_latest;
    /* First chunk in this object? */
    if (version == NULL) {
        yaffscache_object_add_version(obj, chunk);
    }
    else {
        /* Chunk in the same update? */
        if (chunk->ycc_seq_number == version->ycv_seq_number) {
            version->ycv_last_chunk = chunk;
            if (chunk->ycc_chunk_id == 0) {
                version->ycv_header_chunk = chunk;
            }
        }
        /* Otherwise, either add this chunk as the start of a new version. */
        else {
          yaffscache_object_add_version(obj, chunk);
        }
    }

    return TSK_OK;
}

static TSK_RETVAL_ENUM
yaffscache_versions_compute(YAFFSFS_INFO *yfs)
{
    YaffsCacheChunk *chunk_curr = yfs->cache_chunks_head;

    while(chunk_curr != NULL) {
        if (yaffscache_versions_insert_chunk(yfs, chunk_curr) != TSK_OK) {
            return TSK_ERR;
        }

        chunk_curr = chunk_curr->ycc_next;
    }

    return TSK_OK;
}

typedef TSK_RETVAL_ENUM yc_find_children_cb(YaffsCacheObject *obj, YaffsCacheVersion *version, void *args);
static TSK_RETVAL_ENUM
yaffscache_find_children(YAFFSFS_INFO *yfs, uint32_t parent_inode, yc_find_children_cb cb, void *args)
{
    YaffsCacheObject *obj;
    YaffsCacheVersion *version;

    uint32_t parent_id, version_num;
    if (yaffscache_inode_to_obj_id_and_version(parent_inode, &parent_id, &version_num) != TSK_OK) {
        return TSK_ERR;
    }

    for(obj = yfs->cache_objects; obj != NULL; obj = obj->yco_next) {
        for(version = obj->yco_latest; version != NULL; version = version->ycv_prior) {
            /* Is this an incomplete version? */
            if (version->ycv_header_chunk == NULL)
                continue;

            if (version->ycv_header_chunk->ycc_parent_id == parent_id) {
                TSK_RETVAL_ENUM result = cb(obj, version, args);
                if (result != TSK_OK)
                    return result;
            }
        }
    }

    return TSK_OK;
}

static TSK_RETVAL_ENUM
yaffscache_version_find_by_inode(YAFFSFS_INFO *yfs, TSK_INUM_T inode, YaffsCacheVersion **version, YaffsCacheObject **obj_ret) {
    if (version == NULL) {
        return TSK_ERR;
    }

    uint32_t obj_id, version_num;
    if (yaffscache_inode_to_obj_id_and_version(inode, &obj_id, &version_num) != TSK_OK) {
        *version = NULL;
        return TSK_ERR;
    }

    YaffsCacheObject *obj;
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

    YaffsCacheVersion *curr;
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

static void
yaffscache_chunks_free(YAFFSFS_INFO *yfs)
{
    YaffsCacheChunk *chunk = yfs->cache_chunks_head;
    while(chunk != NULL) {
        YaffsCacheChunk *to_free = chunk;
        chunk = chunk->ycc_next;
        free(to_free);
    }
}



/*
 * Parsing and helper functions
 *
 *
 */

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
    if (cnt == -1 || cnt < yfs->page_size) {
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

    if ((spr = (unsigned char*) tsk_malloc(yfs->spare_size)) == NULL) {
        return 1;
    }

    if (yfs->spare_size < 46) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("yaffsfs_read_spare: spare size is too small");
        free(spr);
        return 1;
    }

    cnt = tsk_img_read(fs->img_info, offset, (char*) spr, yfs->spare_size);
    if (cnt == -1 || cnt < yfs->spare_size) {
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

    /*
     * NOTE: The layout of the tags in the spare was determined by looking at
     *       nanddump images and the YAFFS2 sourcecode.  It doesn't match
     *       older documentation, but appears to be correct for the dumps
     *       that we have obtained.  Is this going to change often? Am I
     *       just missing something?  I can't figure out what the first
     *       30 bytes are used for. The layout, at least, matches what I see 
     *       in the YAFFS2 and Android git repositories.
     */

    uint32_t seq_number;
    uint32_t object_id;
    uint32_t chunk_id;
    uint32_t n_bytes;

    memcpy(&seq_number, &spr[30], 4);
    memcpy(&object_id, &spr[34], 4);
    memcpy(&chunk_id, &spr[38], 4);
    memcpy(&n_bytes, &spr[42], 4);

    if ((YAFFS_SPARE_FLAGS_IS_HEADER & chunk_id) != 0) {
        sp->seq_number = seq_number;
        sp->object_id = object_id & ~YAFFS_SPARE_OBJECT_TYPE_MASK;
        sp->chunk_id = 0;
        sp->n_bytes = n_bytes;
        sp->extra_parent_id = chunk_id & YAFFS_SPARE_PARENT_ID_MASK;
        sp->extra_object_type =
            (object_id & YAFFS_SPARE_OBJECT_TYPE_MASK)
              >> YAFFS_SPARE_OBJECT_TYPE_SHIFT;
    }
    else {
        sp->seq_number = seq_number;
        sp->object_id = object_id;
        sp->chunk_id = chunk_id;
        sp->n_bytes = n_bytes;
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
 */
static uint8_t 
yaffsfs_cache_fs(YAFFSFS_INFO * yfs)
{
    uint8_t status = TSK_OK;
    size_t offset = 0;

    if (yfs->cache_objects)
        return 0;

    uint32_t nentries = 0;

    YaffsSpare *spare = NULL;
    offset = 0;
    while (1) {
        //if (tsk_verbose)
        //  fprintf(stderr, "yaffsfs_cache_fs: reading @ offset 0x%08lx\n", offset);

        status = yaffsfs_read_spare( yfs, &spare, offset + yfs->page_size);
        if (status != TSK_OK) {
            break;
        }

        if (yaffsfs_is_spare_valid(yfs, spare) == TSK_OK) {
            //if (tsk_verbose)
            //  fprintf(stderr, "yaffsfs_cache_fs: valid spare\n");

            yaffscache_chunk_add(yfs,
                    offset, 
                    spare->seq_number, 
                    spare->object_id, 
                    spare->chunk_id, 
                    spare->extra_parent_id);

            //if (tsk_verbose)
            //  fprintf(stderr, "yaffsfs_cache_fs: %08x %08x %08x\n", spare->object_id, spare->chunk_id, spare->seq_number);
        }

        free(spare);
        spare = NULL;

        ++nentries;
        offset += yfs->page_size + yfs->spare_size;
    }

    if (tsk_verbose)
        fprintf(stderr, "yaffsfs_cache_fs: read %d entries\n", nentries);

    if (tsk_verbose)
        fprintf(stderr, "yaffsfs_cache_fs: started processing chunks for version cache...\n");

    yaffscache_versions_compute(yfs);

    if (tsk_verbose)
        fprintf(stderr, "yaffsfs_cache_fs: done version cache!\n");

    return TSK_OK;
}


/*
 * TSK integration
 *
 *
 */

static uint8_t
yaffs_make_directory(YAFFSFS_INFO *yaffsfs, TSK_FS_FILE *a_fs_file, 
                     uint32_t inode, char *name)
{
    TSK_FS_FILE *fs_file = a_fs_file;
    fs_file->meta->type = TSK_FS_META_TYPE_DIR;
    fs_file->meta->mode = 0;
    fs_file->meta->nlink = 1;
    fs_file->meta->flags =
        (TSK_FS_META_FLAG_USED | TSK_FS_META_FLAG_ALLOC);
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

    strncpy(fs_file->meta->name2->name, name,
            TSK_FS_META_NAME_LIST_NSIZE);

    fs_file->meta->size = 0;
    fs_file->meta->attr_state = TSK_FS_META_ATTR_EMPTY;
    fs_file->meta->addr = inode;
    return 0;
}


static uint8_t
yaffs_make_regularfile( YAFFSFS_INFO * yaffsfs, TSK_FS_FILE * a_fs_file, 
			uint32_t inode, char * name )
{
    TSK_FS_FILE *fs_file = a_fs_file;

    fs_file->meta->type = TSK_FS_META_TYPE_REG;
    fs_file->meta->mode = 0;
    fs_file->meta->nlink =1;
    fs_file->meta->flags =
        (TSK_FS_META_FLAG_USED | TSK_FS_META_FLAG_ALLOC);

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

    YaffsCacheObject *obj;
    YaffsCacheVersion *version;
    TSK_RETVAL_ENUM result = yaffscache_version_find_by_inode(yfs, inum, &version, &obj);
    if (result != TSK_OK) {
        if (tsk_verbose)
            tsk_fprintf(stderr, "yaffs_inode_lookup: yaffscache_version_find_by_inode failed!\n");
        return 1;
    }

    YaffsHeader *header = NULL;
    YaffsSpare *spare = NULL;
    if (yaffsfs_read_chunk(yfs, &header, &spare, version->ycv_header_chunk->ycc_offset) != TSK_OK) {
        if (tsk_verbose)
            tsk_fprintf(stderr, "yaffs_inode_lookup: yaffsfs_read_chunk failed!\n");
        return 1;
    }

    uint8_t type = header->obj_type;

    char *real_name;
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
                tsk_fprintf(stderr, "yaffs_inode_lookup: is *** UNHANDLED ***\n");
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
        a_fs_file->meta->mode = header->file_mode;
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
        a_fs_file->meta->link = tsk_malloc(YAFFS_HEADER_ALIAS_LENGTH);
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
    result = yaffscache_inode_to_obj_id_and_version(start_inum, &start_obj_id, &start_ver_number);

    uint32_t end_obj_id;
    uint32_t end_ver_number;
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
        if (tsk_verbose)
            tsk_fprintf(stderr, "yaffsfs_inode_walk: ORPHAN flag unsupported by YAFFS2");
    }

    if (((flags & TSK_FS_META_FLAG_ALLOC) == 0) &&
            ((flags & TSK_FS_META_FLAG_UNALLOC) == 0)) {
        flags |= (TSK_FS_META_FLAG_ALLOC | TSK_FS_META_FLAG_UNALLOC);
    }

    /* If neither of the USED or UNUSED flags are set, then set them
     * both
     */
    if (((flags & TSK_FS_META_FLAG_USED) == 0) &&
            ((flags & TSK_FS_META_FLAG_UNUSED) == 0)) {
        flags |= (TSK_FS_META_FLAG_USED | TSK_FS_META_FLAG_UNUSED);
    }

    if ((fs_file = tsk_fs_file_alloc(fs)) == NULL)
        return 1;
    if ((fs_file->meta =
             tsk_fs_meta_alloc(YAFFS_FILE_CONTENT_LEN)) == NULL)
        return 1;

    uint32_t obj_id;
    for (obj_id = start_obj_id; obj_id <= end_obj_id; obj_id++) {
        int retval;

        YaffsCacheObject *curr_obj;
        YaffsCacheVersion *curr_version;
        result = yaffscache_version_find_by_inode(yfs, obj_id, &curr_version, &curr_obj);
        if (result != TSK_OK) {
            if (flags & TSK_FS_META_FLAG_UNALLOC) {
                fs_file->meta->flags = TSK_FS_META_FLAG_UNALLOC;
                fs_file->meta->addr = obj_id;

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
        else {
            TSK_INUM_T curr_inode;
            YaffsCacheVersion *version;

            if ((flags & TSK_FS_META_FLAG_UNUSED) == 0) {
                curr_inode = obj_id;
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
            else {
                for (version = curr_obj->yco_latest; version != NULL; version = version->ycv_prior) {
                    if (yaffscache_obj_id_and_version_to_inode(obj_id, version->ycv_version, &curr_inode) != TSK_OK) {
                        tsk_fs_file_close(fs_file);
                        return 1;
                    }

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
    YaffsSpare *spare;
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
        flags |= TSK_FS_BLOCK_FLAG_ALLOC;
        if (spare->chunk_id == 0) {
            flags |= TSK_FS_BLOCK_FLAG_META;
        } else {
            flags |= TSK_FS_BLOCK_FLAG_CONT;
        }
    } else {
        flags |= TSK_FS_BLOCK_FLAG_UNALLOC;
    }

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
        a_flags |=
            (TSK_FS_BLOCK_WALK_FLAG_ALLOC |
            TSK_FS_BLOCK_WALK_FLAG_UNALLOC);
    }
    if (((a_flags & TSK_FS_BLOCK_WALK_FLAG_META) == 0) &&
        ((a_flags & TSK_FS_BLOCK_WALK_FLAG_CONT) == 0)) {
        a_flags |=
            (TSK_FS_BLOCK_WALK_FLAG_CONT | TSK_FS_BLOCK_WALK_FLAG_META);
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
    time_t tmptime;
    char timeBuf[128];

    // clean up any error messages that are lying around
    tsk_error_reset();

    tsk_fprintf(hFile, "FILE SYSTEM INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");

    tsk_fprintf(hFile, "File System Type: YAFFS2\n");
    tsk_fprintf(hFile, "Page Size: %u\n", yfs->page_size);
    tsk_fprintf(hFile, "Spare Size: %u\n", yfs->spare_size);

    tsk_fprintf(hFile, "\nMETADATA INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");

    unsigned int obj_count, version_count;
    uint32_t obj_first, obj_last, version_first, version_last;
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
yaffsfs_istat(TSK_FS_INFO *fs, FILE * hFile, TSK_INUM_T inum,
    TSK_DADDR_T numblock, int32_t sec_skew)
{
    TSK_FS_META *fs_meta;
    TSK_FS_FILE *fs_file;
    char ls[12];
    YAFFSFS_PRINT_ADDR print;
    char timeBuf[32];

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

    if (numblock > 0) {
        TSK_OFF_T lower_size = numblock * fs->block_size;
        fs_meta->size = (lower_size < fs_meta->size)?(lower_size):(fs_meta->size);
    }
    tsk_fprintf(hFile, "\nBlocks:\n");

    print.idx = 0;
    print.hFile = hFile;

    if (tsk_fs_file_walk(fs_file, TSK_FS_FILE_WALK_FLAG_AONLY,
            (TSK_FS_FILE_WALK_CB) print_addr_act, (void *) &print)) {
        tsk_fprintf(hFile, "\nError reading file:  ");
        tsk_error_print(hFile);
        tsk_error_reset();
    }
    else if (print.idx != 0) {
        tsk_fprintf(hFile, "\n");
    }

    tsk_fs_file_close(fs_file);

    return 0;
}

/* yaffsfs_close - close an yaffsfs file system */
static void
yaffsfs_close(TSK_FS_INFO *fs)
{
    YAFFSFS_INFO *yfs = (YAFFSFS_INFO *)fs;

    fs->tag = 0;

    // TODO: Walk and free the cache structures
    yaffscache_objects_free(yfs);
    yaffscache_chunks_free(yfs);

    //tsk_deinit_lock(&yaffsfs->lock);

    tsk_fs_free(fs);
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

    yaffscache_obj_id_and_version_to_inode(obj_id, vnum, &curr_inode);

    if (chunk_id != 0) {
        return TSK_ERR;
    }

    if (tsk_verbose)
        fprintf(stderr, "dir_open_find_children_cb: %08" PRIxINUM " -> %08" PRIx32 ":%d\n", cb_args->parent_addr, obj_id, vnum);

    YaffsHeader *header = NULL;
    if (yaffsfs_read_header(cb_args->yfs, &header, chunk->ycc_offset) != TSK_OK) {
        return TSK_ERR;
    }

    TSK_FS_NAME * fs_name;
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

    char version_string[64];
    snprintf(version_string, 64, ":%d,%d", obj_id, vnum);
    strncat(fs_name->name, version_string, 31);

    fs_name->flags = TSK_FS_NAME_FLAG_ALLOC;
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

        default:
            if (tsk_verbose)
                fprintf(stderr, "yaffs_dir_open_meta_cb: unhandled object type\n");
            fs_name->type = TSK_FS_NAME_TYPE_REG;
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
    }
    else if ((*a_fs_dir = fs_dir = tsk_fs_dir_alloc(a_fs, a_addr, 128)) == NULL) {
        return TSK_ERR;
    }

    if (tsk_verbose)
        fprintf(stderr,"yaffs_dir_open_meta: called for directory %" PRIu32 "\n", (uint32_t) a_addr);

    if ((fs_name = tsk_fs_name_alloc(YAFFSFS_MAXNAMLEN, 0)) == NULL) {
        return TSK_ERR;
    }

    if ((fs_dir->fs_file = 
	    tsk_fs_file_open_meta(a_fs, NULL, a_addr)) == NULL) {
        tsk_error_errstr2_concat(" - yaffs_dir_open_meta");
        tsk_fs_name_free(fs_name);
        return TSK_ERR;
    }

    int should_walk_children = 0;

    uint32_t obj_id;
    uint32_t ver_number;
    yaffscache_inode_to_obj_id_and_version(a_addr, &obj_id, &ver_number);

    if (obj_id == YAFFS_OBJECT_DELETED ||
            obj_id == YAFFS_OBJECT_UNLINKED) {
        should_walk_children = 1;
    }
    else {
        YaffsCacheObject *obj;
        YaffsCacheVersion *version;
        TSK_RETVAL_ENUM result = yaffscache_version_find_by_inode(yfs, a_addr, &version, &obj);
        if (result != TSK_OK) {
            if (tsk_verbose)
                tsk_fprintf(stderr, "yaffs_inode_lookup: yaffscache_version_find_by_inode failed!\n");
            tsk_fs_name_free(fs_name);
            return TSK_ERR;
        }

        /* Only attach files onto the latest version of the directory */
        should_walk_children = (obj->yco_latest == version);
    }

    if (should_walk_children) {
        dir_open_cb_args args;
        args.yfs = yfs;
        args.dir = fs_dir;
        args.parent_addr = a_addr;
        yaffscache_find_children(yfs, a_addr, yaffs_dir_open_meta_cb, &args);
    }

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

    TSK_FS_ATTR_RUN *data_run = tsk_fs_attr_run_alloc();
    if (data_run == NULL) {
        tsk_fs_attr_run_free(data_run);
        meta->attr_state = TSK_FS_META_ATTR_ERROR;
        return 1;
    }

    data_run->offset = 0;
    data_run->addr = 0;
    data_run->len = (meta->size + fs->block_size - 1) / fs->block_size;
    data_run->flags = TSK_FS_ATTR_RUN_FLAG_FILLER;

    uint32_t file_block_count = data_run->len;

    // initialize the data run
    if (tsk_verbose)
        tsk_fprintf(stderr, "yaffsfs_load_attrs: before tsk_fs_attr_set_run\n");

    if (tsk_fs_attr_set_run(file, attr, data_run, NULL,
            TSK_FS_ATTR_TYPE_DEFAULT, TSK_FS_ATTR_ID_DEFAULT,
            meta->size, meta->size, roundup(meta->size, fs->block_size), 0, 0)) {
        meta->attr_state = TSK_FS_META_ATTR_ERROR;
        return 1;
    }

    if (tsk_verbose)
        tsk_fprintf(stderr, "yaffsfs_load_attrs: after tsk_fs_attr_set_run\n");

    /* Walk the version pointer back to the start adding single
     * block runs as we go.
     */
    YaffsCacheObject *obj;
    YaffsCacheVersion *version;
    TSK_RETVAL_ENUM result = yaffscache_version_find_by_inode(yfs, meta->addr, &version, &obj);
    if (result != TSK_OK || version == NULL) {
        if (tsk_verbose)
          tsk_fprintf(stderr, "yaffsfs_load_attrs: yaffscache_version_find_by_inode failed!\n");
        meta->attr_state = TSK_FS_META_ATTR_ERROR;
        return 1;
    }

    if (tsk_verbose)
        yaffscache_object_dump(stderr, obj);

    TSK_LIST *chunks_seen = NULL;
    YaffsCacheChunk *curr = version->ycv_last_chunk;
    while (curr != NULL && curr->ycc_obj_id == obj->yco_obj_id) {
        if (tsk_verbose)
            tsk_fprintf(stderr, "yaffsfs_load_attrs: Looking at %08x %08x %08x\n",
                    curr->ycc_obj_id, curr->ycc_chunk_id, curr->ycc_seq_number);

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
        else {
            if (tsk_list_add(&chunks_seen, curr->ycc_chunk_id)) {
                meta->attr_state = TSK_FS_META_ATTR_ERROR;
                tsk_list_free(chunks_seen);
                chunks_seen = NULL;
                return 1;
            }

            TSK_FS_ATTR_RUN *data_run_new = tsk_fs_attr_run_alloc();
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
 * @param test NOT USED
 * @returns NULL on error or if data is not an Yaffs/3 file system
 */
TSK_FS_INFO *
yaffs2_open(TSK_IMG_INFO * img_info, TSK_OFF_T offset,
	     TSK_FS_TYPE_ENUM ftype, uint8_t test)
{
    YAFFSFS_INFO *yaffsfs;
    TSK_FS_INFO *fs;
    const unsigned int psize = img_info->page_size;
    const unsigned int ssize = img_info->spare_size;

    // clean up any error messages that are lying around
    tsk_error_reset();

    if (TSK_FS_TYPE_ISYAFFS2(ftype) == 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("Invalid FS Type in yaffsfs_open");
        return NULL;
    }

    if ((yaffsfs = (YAFFSFS_INFO *) tsk_fs_malloc(sizeof(YAFFSFS_INFO))) == NULL)
        return NULL;

    yaffsfs->page_size = psize == 0 ? YAFFS_DEFAULT_PAGE_SIZE : psize;
    yaffsfs->spare_size = ssize == 0 ? YAFFS_DEFAULT_SPARE_SIZE : ssize;

    fs = &(yaffsfs->fs_info);

    fs->tag = TSK_FS_INFO_TAG;
    fs->ftype = ftype;
    fs->flags = 0;
    fs->img_info = img_info;
    fs->offset = offset;
    fs->endian = TSK_LIT_ENDIAN;

    /*
     * Read the first record, make sure it's a valid header...
     *
     * Used for verification and autodetection of
     * the FS type.
     */
    YaffsHeader * first_header = NULL;
    if (yaffsfs_read_header(yaffsfs, &first_header, 0)) {
	tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_MAGIC);
        tsk_error_set_errstr("not a YAFFS file system (first record)");
        if (tsk_verbose)
            fprintf(stderr, "yaffsfs_open: invalid first record\n");
        return NULL;
    }
    free(first_header);

    fs->duname = "Chunk";

    /*
     * Calculate the meta data info
     */
    fs->last_inum = 0xffffffff;
    fs->root_inum = YAFFS_OBJECT_ROOT;
    fs->first_inum = YAFFS_OBJECT_FIRST;
    fs->inum_count = fs->last_inum;

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
    yaffsfs->cache_objects = NULL;
    yaffsfs->cache_chunks_head = NULL;
    yaffsfs->cache_chunks_tail = NULL;
    yaffsfs_cache_fs(yaffsfs);

    if (tsk_verbose) {
        fprintf(stderr, "yaffsfs_open: done building cache!\n");
	//yaffscache_objects_dump(yaffsfs, stderr);
    }

    TSK_FS_DIR *test_dir = tsk_fs_dir_open_meta(fs, fs->root_inum);
    if (test_dir == NULL) {
	yaffsfs_close(fs);

	tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_MAGIC);
        tsk_error_set_errstr("not a YAFFS file system (no root directory)");
        if (tsk_verbose)
            fprintf(stderr, "yaffsfs_open: invalid file system\n");
        return NULL;
    }
    tsk_fs_dir_close(test_dir);

    return fs;
}
