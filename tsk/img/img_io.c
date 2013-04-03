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
    ssize_t retval = 0;
    int i;
    int cache_next = 0;         // index to lowest age cache (to use next)
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

    // if they ask for more than the cache length, skip the cache
    if ((a_len + a_off % 512) > TSK_IMG_INFO_CACHE_LEN) {
        ssize_t nbytes;

        /* Some of the lower-level methods like block-sized reads.
         * So if the len is not that multiple, then make it. */
        if (a_len % a_img_info->sector_size) {
            char *buf2 = a_buf;
            size_t len2;
            len2 = roundup(a_len, a_img_info->sector_size);
            if ((buf2 = (char *)tsk_malloc(len2)) == NULL) {
                tsk_release_lock(&(a_img_info->cache_lock));
                return -1;
            }
            nbytes = a_img_info->read(a_img_info, a_off, buf2, len2);
            if ((nbytes > 0) && (nbytes < (ssize_t)a_len)) {
                memcpy(a_buf, buf2, nbytes);
            }
            else {
                memcpy(a_buf, buf2, a_len);
                nbytes = a_len;
            }
            free(buf2);
        }
        else {
            nbytes = a_img_info->read(a_img_info, a_off, a_buf, a_len);
        }
        tsk_release_lock(&(a_img_info->cache_lock));
        return nbytes;
    }

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
    if (a_off + len2 > a_img_info->size)
        len2 = (size_t) (a_img_info->size - a_off);

    // check if it is in the cache
    for (i = 0; i < TSK_IMG_INFO_CACHE_NUM; i++) {

        // Look into the in-use cache entries
        if (a_img_info->cache_len[i] > 0) {

            // the retval check makes sure we don't go back in after data was read
            if ((retval == 0) && (a_img_info->cache_off[i] <= a_off) &&
                (a_img_info->cache_off[i] + a_img_info->cache_len[i] >=
                    a_off + len2)) {

                /*
                   if (tsk_verbose)
                   fprintf(stderr,
                   "tsk_img_read: Read found in cache %d\n", i);
                 */

                // We found it...
                memcpy(a_buf,
                    &a_img_info->cache[i][a_off -
                        a_img_info->cache_off[i]], len2);
                retval = (ssize_t) len2;

                // reset its "age" since it was useful
                a_img_info->cache_age[i] = CACHE_AGE;

                // we don't break out of the loop so that we update all ages
            }
            else {
                /* decrease its "age" since it was not useful.
                 * We don't let used ones go below 1 so that they are not
                 * confused with entries that have never been used. */
                a_img_info->cache_age[i]--;

                // see if this is the most eligible replacement
                if ((a_img_info->cache_len[cache_next] > 0)
                    && (a_img_info->cache_age[i] <
                        a_img_info->cache_age[cache_next]))
                    cache_next = i;
            }
        }
        else {
            cache_next = i;
        }
    }

    // if we didn't find it, then load it into the cache_next entry
    if (retval == 0) {
        size_t rlen;

        // round the offset down to a sector boundary
        a_img_info->cache_off[cache_next] = (a_off / 512) * 512;

        /*
           if (tsk_verbose)
           fprintf(stderr,
           "tsk_img_read: Loading data into cache %d (%" PRIuOFF
           ")\n", cache_next, a_img_info->cache_off[cache_next]);
         */

        // figure out the length to read into the cache
        rlen = TSK_IMG_INFO_CACHE_LEN;
        if (a_img_info->cache_off[cache_next] + rlen > a_img_info->size) {
            rlen =
                (size_t) (a_img_info->size -
                a_img_info->cache_off[cache_next]);
        }

        retval =
            a_img_info->read(a_img_info, a_img_info->cache_off[cache_next],
            a_img_info->cache[cache_next], rlen);

        // if no error, then set the variables and copy the data
        if (retval != -1) {
            a_img_info->cache_age[cache_next] = CACHE_AGE;
            a_img_info->cache_len[cache_next] = retval;

            // update the length we can actually copy (in case we did not get to read all that we wanted)
            if (a_off + len2 > a_img_info->cache_off[cache_next] + retval)
                len2 =
                    (size_t) (a_img_info->cache_off[cache_next] + retval -
                    a_off);

            memcpy(a_buf,
                &a_img_info->cache[cache_next][a_off -
                    a_img_info->cache_off[cache_next]], len2);
            retval = (ssize_t) len2;
        }
        else {
            a_img_info->cache_len[cache_next] = 0;
            a_img_info->cache_age[cache_next] = 0;
            a_img_info->cache_off[cache_next] = 0;
        }
    }

    tsk_release_lock(&(a_img_info->cache_lock));
    return retval;
}
