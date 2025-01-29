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
#include "img_cache.h"
#include "no_cache.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <functional>
#include <iterator>
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

ssize_t read_fully(char* buf, TSK_IMG_INFO* img, TSK_OFF_T off, size_t len) {
  IMG_INFO* iif = reinterpret_cast<IMG_INFO*>(img);
  size_t pos = 0;
  for (ssize_t r; pos < len; pos += r) {
    r = iif->read(img, off + pos, buf + pos, len - pos);
    if (r == -1) {
      return -1;
    }
  }
  return len;
}

ssize_t read_chunk_locking(
  TSK_IMG_INFO* img,
  TSK_OFF_T coff,
  size_t clen, char* buf,
  Cache& cache)
{
  if (read_fully(buf, img, coff, clen) == -1) {
    return -1;
  }
  std::scoped_lock lock{cache};
  reinterpret_cast<IMG_INFO*>(img)->cache_put(img, coff, buf);
  return clen;
}

Cache& cache_get(IMG_INFO* img) {
  return *reinterpret_cast<Cache*>(img->cache);
}

ssize_t tsk_img_read_lru_finer_lock(
  TSK_IMG_INFO* a_img_info,
  TSK_OFF_T a_off,
  char* a_buf,
  size_t a_len
)
{
  IMG_INFO* iif = reinterpret_cast<IMG_INFO*>(a_img_info);

  Timer timer;
  Stats& stats = iif->stats;

  Cache& cache = cache_get(iif);
  const size_t chunk_size = cache.chunk_size();

  // offset of src end, taking care not to overrun the end of the image
  const TSK_OFF_T send = a_off + std::min((TSK_OFF_T)a_len, a_img_info->size);
  // offset of chunk containing src end
  const TSK_OFF_T cend = send & ~(chunk_size - 1);

  // current src offset
  TSK_OFF_T soff = a_off;
  // current chunk offset
  TSK_OFF_T coff = a_off & ~(chunk_size - 1);

  std::unique_ptr<char[]> cbuf;
  if (coff < soff || cend < send) {
    // we will write at least one partial chunk, set up the chunk buffer
    cbuf.reset(new char[chunk_size]);
  }

  size_t clen, len, delta;
  char* dst = a_buf;
  const char* chunk;

  while (soff < send) {
    clen = std::min((TSK_OFF_T) chunk_size, a_img_info->size - coff);
    delta = soff - coff;
    len = std::min(clen - delta, (size_t)(send - soff));

    {
      std::scoped_lock lock{cache};
      timer.start();
      chunk = iif->cache_get(a_img_info, coff);
      if (chunk) {
        // cache hit: copy chunk to buffer
        std::memcpy(dst, chunk + delta, len);
        timer.stop();
        ++stats.hits;
        stats.hit_ns += timer.elapsed();
        stats.hit_bytes += len;
      }
    }

    if (!chunk) {
      // cache miss: read into buffer, copy chunk to cache
      timer.start();

      if (len < chunk_size) {
        // We're reading less than a complete chunk, so either the start
        // or the end of the read is not aligned to a chunk boundary.
        // Read full chunk into the temporary chunk buffer (because we
        // still want to cache a full chunk), then copy the portion we
        // want into dst.
        if (read_chunk_locking(a_img_info, coff, clen, cbuf.get(), cache) == -1) {
          return -1;
        }
        std::memcpy(dst, cbuf.get() + delta, len);
      }
      else {
        // read a complete chunk
        if (read_chunk_locking(a_img_info, coff, clen, dst, cache) == -1) {
          return -1;
        }
      }

      timer.stop();
      std::scoped_lock lock{cache};
      ++stats.misses;
      stats.miss_ns += timer.elapsed();
      stats.miss_bytes += len;
    }

    soff += len;
    coff += clen;
    dst += len;
  }

  return send - a_off;
}

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
  timer.start();
  ssize_t read_count = img_read_no_cache(a_img_info, a_off, a_buf, a_len);
  timer.stop();

  // update the stats
  auto cache = static_cast<NoCache*>(iif->cache);
  std::scoped_lock lock{cache->mutex};

  Stats& stats = iif->stats;
  stats.miss_ns += timer.elapsed();
  ++stats.misses;
  stats.miss_bytes += read_count;

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
