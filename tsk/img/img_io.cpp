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
#include "lru_cache.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <functional>
#include <iterator>
#include <memory>
#include <mutex>
#include <new>

#ifdef READ_STATS

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

class TskLock {
public:
  TskLock(tsk_lock_t* l): l(l) {}

  void lock() {
    tsk_take_lock(l);
  }

  void unlock() {
    tsk_release_lock(l);
  }

private:
  tsk_lock_t* l;
};

#endif

size_t cache_chunk_size(const TSK_IMG_CACHE* cache) {
  return cache->cache.chunk_size();
}

const char* cache_get(TSK_IMG_CACHE* cache, TSK_OFF_T off) {
  return cache->cache.get(off);
}

void cache_put(TSK_IMG_CACHE* cache, TSK_OFF_T off, const char* buf) {
  cache->cache.put(off, buf);
}

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

ssize_t read_chunk(
  TSK_IMG_INFO* img,
  TSK_OFF_T coff,
  size_t clen,
  char* buf)
{
  if (read_fully(buf, img, coff, clen) == -1) {
    return -1;
  }
  IMG_INFO* iif = reinterpret_cast<IMG_INFO*>(img);
  cache_put(iif->cache, coff, buf);
  return clen;
}

ssize_t tsk_img_read_cache(
  TSK_IMG_INFO* a_img_info,
  TSK_OFF_T a_off,
  char* a_buf,
  size_t a_len
)
{
  IMG_INFO* iif = reinterpret_cast<IMG_INFO*>(a_img_info);

#ifdef READ_STATS
  Timer timer;
  Stats& stats = iif->stats;
#endif

  const size_t chunk_size = cache_chunk_size(iif->cache);

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
#ifdef READ_STATS
      timer.start();
#endif
      chunk = cache_get(iif->cache, coff);
      if (chunk) {
        // cache hit: copy chunk to buffer
        std::memcpy(dst, chunk + delta, len);
#ifdef READ_STATS
        timer.stop();

        TskLock tskl(&iif->stats_lock);
        std::scoped_lock stats_lock{tskl};
        ++stats.hits;
        stats.hit_ns += timer.elapsed();
        stats.hit_bytes += len;
#endif
      }
    }

    if (!chunk) {
      // cache miss: read into buffer, copy chunk to cache
#ifdef READ_STATS
      timer.start();
#endif

      if (len < chunk_size) {
        // We're reading less than a complete chunk, so either the start
        // or the end of the read is not aligned to a chunk boundary.
        // Read full chunk into the temporary chunk buffer (because we
        // still want to cache a full chunk), then copy the portion we
        // want into dst.
        if (read_chunk(a_img_info, coff, clen, cbuf.get()) == -1) {
          return -1;
        }
        std::memcpy(dst, cbuf.get() + delta, len);
      }
      else {
        // read a complete chunk
        if (read_chunk(a_img_info, coff, clen, dst) == -1) {
          return -1;
        }
      }

#ifdef READ_STATS
      timer.stop();

      TskLock tskl(&iif->stats_lock);
      std::scoped_lock stats_lock{tskl};
      ++stats.misses;
      stats.miss_ns += timer.elapsed();
      stats.miss_bytes += len;
#endif
    }

    soff += len;
    coff += clen;
    dst += len;
  }

  return send - a_off;
}

ssize_t tsk_img_read_no_cache(
  TSK_IMG_INFO* a_img_info,
  TSK_OFF_T a_off,
  char* a_buf,
  size_t a_len)
{
  IMG_INFO* iif = reinterpret_cast<IMG_INFO*>(a_img_info);

#ifdef READ_STATS
  Timer timer;
  timer.start();
#endif

  ssize_t read_count;

  /* Some of the lower-level methods like block-sized reads.
   * So if the len is not that multiple, then make it. */
  if (a_img_info->sector_size > 0 && a_len % a_img_info->sector_size) {
    size_t len_tmp;
    len_tmp = roundup(a_len, a_img_info->sector_size);

    std::unique_ptr<char[]> buf2(new(std::nothrow) char[len_tmp]);
    if (!buf2) {
      return -1;
    }

    read_count = iif->read(a_img_info, a_off, buf2.get(), len_tmp);
    if (read_count < 0) {
      return -1;
    }

    if (read_count < (ssize_t) a_len) {
      std::memcpy(a_buf, buf2.get(), read_count);
    }
    else {
      std::memcpy(a_buf, buf2.get(), a_len);
      read_count = (ssize_t)a_len;
    }
  }
  else {
    read_count = iif->read(a_img_info, a_off, a_buf, a_len);
  }

#ifdef READ_STATS
  timer.stop();

  TskLock tskl(&iif->stats_lock);
  std::scoped_lock stats_lock{tskl};
  Stats& stats = iif->stats;
  stats.miss_ns += timer.elapsed();
  ++stats.misses;
  stats.miss_bytes += read_count;
#endif

  return read_count;
}

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
