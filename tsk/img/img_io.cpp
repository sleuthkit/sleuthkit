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
#include "legacy_cache.h"

#include <chrono>
#include <memory>
#include <new>

class Timer {
public:
  size_t elapsed() const {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
      stop_time - start_time
    ).count();
  }

  void start() {
    start_time = std::chrono::high_resolution_clock::now();
  }

  void stop() {
    stop_time = std::chrono::high_resolution_clock::now();
  }
private:
  std::chrono::high_resolution_clock::time_point start_time, stop_time;
};

// This function assumes that we hold the cache_lock even though we're not modyfying
// the cache.  This is because the lower-level read callbacks make the same assumption.
static ssize_t img_read_no_cache(TSK_IMG_INFO * a_img_info, TSK_OFF_T a_off,
    char *a_buf, size_t a_len)
{
    ssize_t nbytes;

    IMG_INFO* iif = reinterpret_cast<IMG_INFO*>(a_img_info);

    /* Some of the lower-level methods like block-sized reads.
        * So if the len is not that multiple, then make it. */
    if (a_img_info->sector_size > 0 && a_len % a_img_info->sector_size) {
        size_t len_tmp;
        len_tmp = roundup(a_len, a_img_info->sector_size);

        std::unique_ptr<char[]> buf2(new(std::nothrow) char[len_tmp]);
        if (!buf2) {
            return -1;
        }

        nbytes = iif->read(a_img_info, a_off, buf2.get(), len_tmp);
        if (nbytes < 0) {
            return -1;
        }

        if (nbytes < (ssize_t) a_len) {
            memcpy(a_buf, buf2.get(), nbytes);
        }
        else {
            memcpy(a_buf, buf2.get(), a_len);
            nbytes = (ssize_t)a_len;
        }
    }
    else {
        nbytes = iif->read(a_img_info, a_off, a_buf, a_len);
    }

    return nbytes;
}

ssize_t tsk_img_read_no_cache(
  TSK_IMG_INFO* a_img_info,
  TSK_OFF_T a_off,
  char* a_buf,
  size_t a_len)
{
  IMG_INFO* iif = reinterpret_cast<IMG_INFO*>(a_img_info);

  Timer timer;
  Stats& stats = iif->stats;

  ssize_t read_count = 0;

  auto cache = static_cast<LegacyCache*>(iif->cache);
  cache->lock();
  timer.start();
  read_count = img_read_no_cache(a_img_info, a_off, a_buf, a_len);
  timer.stop();
  stats.miss_ns += timer.elapsed();
  ++stats.misses;
  stats.miss_bytes += read_count;
  cache->unlock();

  return read_count;
}

ssize_t
tsk_img_read_legacy(
    TSK_IMG_INFO* a_img_info,
    TSK_OFF_T a_off,
    char* a_buf,
    size_t a_len)
{
    IMG_INFO* iif = reinterpret_cast<IMG_INFO*>(a_img_info);

    Timer timer;
    Stats& stats = iif->stats;

#define CACHE_AGE   1000
    ssize_t read_count = 0;

    /* cache_lock is used for both the cache in IMG_INFO and
     * the shared variables in the img type specific INFO structs.
     * grab it now so that it is held before any reads.
     */
    auto cache = static_cast<LegacyCache*>(iif->cache);
    cache->lock();

    // if they ask for more than the cache length, skip the cache
    if (a_len + (a_off % 512) > TSK_IMG_INFO_CACHE_LEN) {
        timer.start();
        read_count = img_read_no_cache(a_img_info, a_off, a_buf, a_len);
        timer.stop();
        stats.miss_ns += timer.elapsed();
        ++stats.misses;
        stats.miss_bytes += read_count;
        cache->unlock();
        return read_count;
    }

    /* See if the requested length is going to be too long.
     * we'll use this length when checking the cache. */
    size_t len2 = a_len;

    // Protect against INT64_MAX + INT64_MAX > value
    if ((TSK_OFF_T) len2 > a_img_info->size
        || a_off >= a_img_info->size - (TSK_OFF_T)len2) {
        len2 = (size_t) (a_img_info->size - a_off);
    }

    int cache_next = 0;         // index to lowest age cache (to use next)

    timer.start();

    // check if it is in the cache
    for (int cache_index = 0; cache_index < TSK_IMG_INFO_CACHE_NUM; cache_index++) {

        // Look into the in-use cache entries
        if (cache->cache_len[cache_index] > 0) {

            // the read_count check makes sure we don't go back in after data was read
            if (read_count == 0
                && cache->cache_off[cache_index] <= a_off
                && cache->cache_off[cache_index] +
                    cache->cache_len[cache_index] >= a_off + len2) {

                /*
                   if (tsk_verbose)
                   fprintf(stderr,
                   "tsk_img_read: Read found in cache %d\n",  cache_index );
                 */

                // We found it...
                memcpy(a_buf,
                    &cache->cache[cache_index][a_off -
                        cache->cache_off[cache_index]], len2);
                read_count = (ssize_t) len2;

                // reset its "age" since it was useful
                cache->cache_age[cache_index] = CACHE_AGE;

                // we don't break out of the loop so that we update all ages

                ++stats.hits;
                stats.hit_bytes += read_count;
            }
            else {
                /* decrease its "age" since it was not useful.
                 * We don't let used ones go below 1 so that they are not
                 * confused with entries that have never been used. */
                cache->cache_age[cache_index]--;

                // see if this is the most eligible replacement
                if (cache->cache_len[cache_next] > 0
                    && cache->cache_age[cache_index] <
                        cache->cache_age[cache_next])
                    cache_next = cache_index;
            }
        }
        else {
            cache_next = cache_index;
        }
    }

    // if we didn't find it, then load it into the cache_next entry
    if (read_count == 0) {
        timer.start();

        size_t read_size = 0;

        // round the offset down to a sector boundary
        cache->cache_off[cache_next] = (a_off / 512) * 512;

        /*
           if (tsk_verbose)
           fprintf(stderr,
           "tsk_img_read: Loading data into cache %d (%" PRIdOFF
           ")\n", cache_next, a_img_info->cache_off[cache_next]);
         */

        // Read a full cache block or the remaining data.
        read_size = TSK_IMG_INFO_CACHE_LEN;

        if (cache->cache_off[cache_next] + (TSK_OFF_T)read_size >
            a_img_info->size) {
            read_size =
                (size_t) (a_img_info->size -
                cache->cache_off[cache_next]);
        }

        read_count = iif->read(a_img_info,
            cache->cache_off[cache_next],
            cache->cache[cache_next], read_size);

        // if no error, then set the variables and copy the data
        // Although a read_count of -1 indicates an error,
        // since read_count is used in the calculation it may not be negative.
        // Also it does not make sense to copy data when the read_count is 0.
        if (read_count > 0) {

            TSK_OFF_T rel_off = 0;
            cache->cache_age[cache_next] = CACHE_AGE;
            cache->cache_len[cache_next] = read_count;

            // Determine the offset relative to the start of the cached data.
            rel_off = a_off - cache->cache_off[cache_next];

            // Make sure we were able to read sufficient data into the cache.
            if (rel_off > (TSK_OFF_T) read_count) {
                len2 = 0;
            }
            // Make sure not to copy more than is available in the cache.
            else if (rel_off + (TSK_OFF_T) len2 > (TSK_OFF_T) read_count) {
                len2 = (size_t) (read_count - rel_off);
            }
            // Only copy data when we have something to copy.
            if (len2 > 0) {
                memcpy(a_buf, &(cache->cache[cache_next][rel_off]), len2);
            }
            read_count = (ssize_t) len2;
        }
        else {
            cache->cache_len[cache_next] = 0;
            cache->cache_age[cache_next] = 0;
            cache->cache_off[cache_next] = 0;

            // Something went wrong so let's try skipping the cache
            read_count = img_read_no_cache(a_img_info, a_off, a_buf, a_len);
        }

        timer.stop();
        stats.miss_ns += timer.elapsed();
        ++stats.misses;
        stats.miss_bytes += read_count;
    }
    else {
        timer.stop();
        stats.hit_ns += timer.elapsed();
    }

    cache->unlock();
    return read_count;
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
        tsk_error_set_errstr("tsk_img_read: a_off: %" PRIdOFF, a_off);
        return -1;
    }

    // TODO: why not just return 0 here (and be POSIX compliant)?
    if (a_off >= a_img_info->size) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_READ_OFF);
        tsk_error_set_errstr("tsk_img_read - %" PRIdOFF, a_off);
        return -1;
    }

    // FIXME: This check is ridiculous. It will fail only when you pass
    // in a buffer length that won't fit into 63 bits. You cannot allocate
    // a buffer that size, and anyway this is here only because no one was
    // sufficiently careful about the arithmetic below to avoid overflow.
    // The correct solution is to fix the arithemetic.
    //
    // Protect a_off against overflowing when a_len is added since TSK_OFF_T
    // maps to an int64 we prefer it over size_t although likely checking
    // for ( a_len > SSIZE_MAX ) is better but the code does not seem to
    // use that approach.

    if ((TSK_OFF_T) a_len < 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_ARG);
        tsk_error_set_errstr("tsk_img_read: a_len: %" PRIuSIZE, a_len);
        return -1;
    }

    return reinterpret_cast<IMG_INFO*>(a_img_info)->cache_read(a_img_info, a_off, a_buf, a_len);
}
