/*
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2011 Brian Carrier.  All Rights reserved
 *
 * This software is distributed under the Common Public License 1.0
 */

/**
 * \file img_io.c
 * Contains the basic img reading API redirection functions.
 */

#include "tsk_img_i.h"

#define MIN(x,y) ( (x) < (y) ? (x) : (y) )

/**
 * \internal
 * Promotes the selected cache entry, since it has been recently requested.
 * This must be called while already under the cache lock.
 * @param a_img_info Disk image containing cache
 * @param ent Index of the cache entry to promote
 * @returns New index of the cache entry (currently always zero)
 */
static inline int
tsk_cache_promote(TSK_IMG_INFO * a_img_info, int ent)
{
	if (ent == 0)
		return 0;
	
	struct TSK_IMG_INFO_CACHE_ENTRY temp;
	memcpy(&temp, &(a_img_info->cache_info[ent]), sizeof(struct TSK_IMG_INFO_CACHE_ENTRY));
	memmove(&(a_img_info->cache_info[1]), &(a_img_info->cache_info[0]), sizeof(struct TSK_IMG_INFO_CACHE_ENTRY) * ent);
	memcpy(&(a_img_info->cache_info[0]), &temp, sizeof(struct TSK_IMG_INFO_CACHE_ENTRY));

	return 0;
}

/**
 * \internal
 * Ensures that the disk block at the specified offset is in the cache,
 * either by finding the already-cached block or by reading it from disk.
 * This must be called while already under the cache lock.
 * @param a_img_info Disk image to read from
 * @param a_off      Byte offset of the disk block; required to be a multiple of
 *                   TSK_IMG_INFO_CACHE_LEN
 * @param a_entry    Output: address of a pointer to a cache info entry that will
 *                   be set by this function. (Address should not be used if
 *                   the function returns an error.)
 * @returns          0 on error or 1 on success
 */
static inline int
tsk_get_cache_block(TSK_IMG_INFO * a_img_info,
	TSK_OFF_T a_off, struct TSK_IMG_INFO_CACHE_ENTRY ** a_entry)
{
	// we require that we're called with a page-aligned offset
	if ( ( a_off & (TSK_IMG_INFO_CACHE_LEN - 1) ) != 0 ) {
		fprintf(stderr, "Internal error: request cache page %" PRIuOFF "\n", a_off);
		exit(-1);
	}

	int ent;
	
	// find existing cache page
	for (ent = 0; ent < a_img_info->cache_used; ent++) {
		if (a_img_info->cache_info[ent].offset == a_off) {
			ent = tsk_cache_promote(a_img_info, ent);
			*a_entry = &(a_img_info->cache_info[ent]);
			return 1;
		}
	}
	
	// did not find existing cache page
	
	if (a_img_info->cache_used < TSK_IMG_INFO_CACHE_NUM) {
		// if we have not yet filled the cache, add a new cache page
		ent = (a_img_info->cache_used)++;
		a_img_info->cache_info[ent].page = ent;
	}
	else {
		// otherwise, use the last (lowest-priority) cache page
		ent = a_img_info->cache_used - 1;
	}
	
	a_img_info->cache_info[ent].offset = a_off;
	a_img_info->cache_info[ent].length = a_img_info->read(a_img_info, a_off,
		&(a_img_info->cache[a_img_info->cache_info[ent].page * TSK_IMG_INFO_CACHE_LEN]),
		TSK_IMG_INFO_CACHE_LEN);

	if (a_img_info->cache_info[ent].length <= 0) {
		a_img_info->cache_info[ent].length = 0;
		*a_entry = &(a_img_info->cache_info[ent]);
		return 0;
	}

	ent = tsk_cache_promote(a_img_info, ent);
	*a_entry = &(a_img_info->cache_info[ent]);
	return 1;
}

/**
 * \ingroup imglib
 * Reads data from an open disk image
 * @param a_img_info Disk image to read from
 * @param a_off Byte offset to start reading from
 * @param a_buf Buffer to read into
 * @param a_len Number of bytes to read into buffer
 * @returns -1 on error or number of bytes read
 */
ssize_t
tsk_img_read(TSK_IMG_INFO * a_img_info, TSK_OFF_T a_off,
    char *a_buf, size_t a_len)
{

	size_t len2;

    if (a_img_info == NULL) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_ARG);
        tsk_error_set_errstr("tsk_img_read: pointer is NULL");
        return -1;
    }

    /* cache_lock is used for both the cache in IMG_INFO and 
     * the shared variables in the img type specific INFO structs.
     * grab it now so that it is held before any reads.
     */
    tsk_take_lock(&(a_img_info->cache_lock));

	/* Error: read request starts after the end of the image file. */
    if (a_off >= a_img_info->size) {
        tsk_release_lock(&(a_img_info->cache_lock));
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_READ_OFF);
        tsk_error_set_errstr("tsk_img_read - %" PRIuOFF, a_off);
        return -1;
    }
    
	/* See if the requested length is going to be too long.
     * we'll use this length when checking the cache.
     * In other words, truncate the read request so that it
     * does not pass the end of the image file. */
    len2 = a_len;
    if (a_off + len2 > a_img_info->size)
        len2 = (size_t) (a_img_info->size - a_off);

	if (tsk_verbose > 2)
		tsk_fprintf(stderr, "tsk_img_read: offset %" PRIuOFF ", length %lx\n", a_off, len2);
	
	TSK_OFF_T block_addr; // block to read
	TSK_OFF_T block_offs; // offset within block
	size_t rlen; // remaining bytes to read
	size_t clen; // bytes to copy from the current cache block
	
	struct TSK_IMG_INFO_CACHE_ENTRY * cache_entry;
	
	rlen = len2;
	block_offs = a_off & (TSK_IMG_INFO_CACHE_LEN - 1);
	block_addr = a_off & ~(TSK_IMG_INFO_CACHE_LEN - 1);
	
	while (rlen > 0) {
		// get the current block from cache (possibly reading from disk)
		if (! tsk_get_cache_block(a_img_info, block_addr, & cache_entry)) {
			tsk_release_lock(&(a_img_info->cache_lock));
			return len2 - rlen;
		}

		// copy into the buffer the lesser of how much the block
		// holds and how much data we still need
		clen = MIN(MIN(TSK_IMG_INFO_CACHE_LEN, cache_entry->length) - block_offs, rlen);
		
		memcpy(a_buf,
			&(a_img_info->cache[cache_entry->page * TSK_IMG_INFO_CACHE_LEN]) + block_offs,
			clen);
		a_buf += clen;
		rlen -= clen;
		
		if ( (rlen > 0) && (cache_entry->length < TSK_IMG_INFO_CACHE_LEN) ) {
			// cache had a short read, but we requested data beyond this
			// return a short read
			tsk_release_lock(&(a_img_info->cache_lock));
			return len2 - rlen;			
		}
		
		// advance to the next block
		block_offs = 0;
		block_addr += TSK_IMG_INFO_CACHE_LEN;
	}

    tsk_release_lock(&(a_img_info->cache_lock));
    return len2;
}		
