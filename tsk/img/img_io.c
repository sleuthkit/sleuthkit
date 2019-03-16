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

// This function assumes that we hold the cache_lock even though we're not modyfying
// the cache.  This is because the lower-level read callbacks make the same assumption.
static ssize_t tsk_img_read_no_cache(TSK_IMG_INFO * a_img_info, TSK_OFF_T a_off,
    char *a_buf, size_t a_len)
{
    ssize_t nbytes;

    /* Some of the lower-level methods like block-sized reads.
        * So if the len is not that multiple, then make it. */
    if (a_len % a_img_info->sector_size) {
        char *buf2 = a_buf;

        size_t len_tmp;
        len_tmp = roundup(a_len, a_img_info->sector_size);
        if ((buf2 = (char *) tsk_malloc(len_tmp)) == NULL) {
            return -1;
        }
        nbytes = a_img_info->read(a_img_info, a_off, buf2, len_tmp);
        if ((nbytes > 0) && (nbytes < (ssize_t) a_len)) {
            memcpy(a_buf, buf2, nbytes);
        }
        else {
            memcpy(a_buf, buf2, a_len);
            nbytes = (ssize_t)a_len;
        }
        free(buf2);
    }
    else {
        nbytes = a_img_info->read(a_img_info, a_off, a_buf, a_len);
    }
    return nbytes;
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
#define CACHE_AGE   1000
    ssize_t read_count = 0;
    int cache_index = 0;
    int cache_next = 0;         // index to lowest age cache (to use next)
    size_t len2 = 0;

    if (a_img_info == NULL) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_ARG);
        tsk_error_set_errstr("tsk_img_read: a_img_info: NULL");
        return -1;
    }

    // Do not allow a_buf to be NULL.
    if (a_buf == NULL) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_ARG);
        tsk_error_set_errstr("tsk_img_read: a_buf: NULL");
        return -1;
    }

    // The function cannot handle negative offsets.
    if (a_off < 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_ARG);
        tsk_error_set_errstr("tsk_img_read: a_off: %" PRIuOFF, a_off);
        return -1;
    }

    // Protect a_off against overflowing when a_len is added since TSK_OFF_T
    // maps to an int64 we prefer it over size_t although likely checking
    // for ( a_len > SSIZE_MAX ) is better but the code does not seem to
    // use that approach.
    if ((TSK_OFF_T) a_len < 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_ARG);
        tsk_error_set_errstr("tsk_img_read: a_len: %zd", a_len);
        return -1;
    }

    /* cache_lock is used for both the cache in IMG_INFO and 
     * the shared variables in the img type specific INFO structs.
     * grab it now so that it is held before any reads.
     */
    tsk_take_lock(&(a_img_info->cache_lock));

    // if they ask for more than the cache length, skip the cache
    if ((a_len + (a_off % 512)) > TSK_IMG_INFO_CACHE_LEN) {
        read_count = tsk_img_read_no_cache(a_img_info, a_off, a_buf, a_len);
        tsk_release_lock(&(a_img_info->cache_lock));
        return read_count;
    }

    // TODO: why not just return 0 here (and be POSIX compliant)?
    // and why not check earlier for this condition?
    if (a_off >= a_img_info->size) {
        tsk_release_lock(&(a_img_info->cache_lock));
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_READ_OFF);
        tsk_error_set_errstr("tsk_img_read - %" PRIuOFF, a_off);
        return -1;
    }

    /* See if the requested length is going to be too long.
     * we'll use this length when checking the cache. */
    len2 = a_len;

    // Protect against INT64_MAX + INT64_MAX > value
    if (((TSK_OFF_T) len2 > a_img_info->size)
        || (a_off >= (a_img_info->size - (TSK_OFF_T)len2))) {
        len2 = (size_t) (a_img_info->size - a_off);
    }

    // check if it is in the cache
    for (cache_index = 0;
        cache_index < TSK_IMG_INFO_CACHE_NUM; cache_index++) {

        // Look into the in-use cache entries
        if (a_img_info->cache_len[cache_index] > 0) {

            // the read_count check makes sure we don't go back in after data was read
            if ((read_count == 0)
                && (a_img_info->cache_off[cache_index] <= a_off)
                && (a_img_info->cache_off[cache_index] +
                    a_img_info->cache_len[cache_index] >= a_off + len2)) {

                /*
                   if (tsk_verbose)
                   fprintf(stderr,
                   "tsk_img_read: Read found in cache %d\n",  cache_index );
                 */

                // We found it...
                memcpy(a_buf,
                    &a_img_info->cache[cache_index][a_off -
                        a_img_info->cache_off[cache_index]], len2);
                read_count = (ssize_t) len2;

                // reset its "age" since it was useful
                a_img_info->cache_age[cache_index] = CACHE_AGE;

                // we don't break out of the loop so that we update all ages
            }
            else {
                /* decrease its "age" since it was not useful.
                 * We don't let used ones go below 1 so that they are not
                 * confused with entries that have never been used. */
                a_img_info->cache_age[cache_index]--;

                // see if this is the most eligible replacement
                if ((a_img_info->cache_len[cache_next] > 0)
                    && (a_img_info->cache_age[cache_index] <
                        a_img_info->cache_age[cache_next]))
                    cache_next = cache_index;
            }
        }
        else {
            cache_next = cache_index;
        }
    }

    // if we didn't find it, then load it into the cache_next entry
    if (read_count == 0) {
        size_t read_size = 0;

        // round the offset down to a sector boundary
        a_img_info->cache_off[cache_next] = (a_off / 512) * 512;

        /*
           if (tsk_verbose)
           fprintf(stderr,
           "tsk_img_read: Loading data into cache %d (%" PRIuOFF
           ")\n", cache_next, a_img_info->cache_off[cache_next]);
         */

        // Read a full cache block or the remaining data.
        read_size = TSK_IMG_INFO_CACHE_LEN;

        if ((a_img_info->cache_off[cache_next] + (TSK_OFF_T)read_size) >
            a_img_info->size) {
            read_size =
                (size_t) (a_img_info->size -
                a_img_info->cache_off[cache_next]);
        }

        read_count = a_img_info->read(a_img_info,
            a_img_info->cache_off[cache_next],
            a_img_info->cache[cache_next], read_size);

        // if no error, then set the variables and copy the data
        // Although a read_count of -1 indicates an error,
        // since read_count is used in the calculation it may not be negative.
        // Also it does not make sense to copy data when the read_count is 0.
        if (read_count > 0) {
            TSK_OFF_T rel_off = 0;
            a_img_info->cache_age[cache_next] = CACHE_AGE;
            a_img_info->cache_len[cache_next] = read_count;

            // Determine the offset relative to the start of the cached data.
            rel_off = a_off - a_img_info->cache_off[cache_next];

            // Make sure we were able to read sufficient data into the cache.
            if (rel_off > (TSK_OFF_T) read_count) {
                len2 = 0;
            }
            // Make sure not to copy more than is available in the cache.
            else if ((rel_off + (TSK_OFF_T) len2) > (TSK_OFF_T) read_count) {
                len2 = (size_t) (read_count - rel_off);
            }
            // Only copy data when we have something to copy.
            if (len2 > 0) {
                memcpy(a_buf, &(a_img_info->cache[cache_next][rel_off]), len2);
            }
            read_count = (ssize_t) len2;
        }
        else {
            a_img_info->cache_len[cache_next] = 0;
            a_img_info->cache_age[cache_next] = 0;
            a_img_info->cache_off[cache_next] = 0;

            // Something went wrong so let's try skipping the cache
            read_count = tsk_img_read_no_cache(a_img_info, a_off, a_buf, a_len);
        }
    }

    tsk_release_lock(&(a_img_info->cache_lock));
    return read_count;
}
