#include "../libtsk.h"

#include "pool_compat.hpp"
#include "tsk_pool.hpp"

// Forward Declarations
extern "C" TSK_FS_ATTR_RUN *tsk_fs_attr_run_alloc();

ssize_t tsk_pool_read(TSK_POOL_INFO *a_pool, TSK_OFF_T a_off, char *a_buf,
                      size_t a_len) {
  const auto pool = static_cast<TSKPool *>(a_pool->impl);
  return pool->read(a_off, a_buf, a_len);
}

TSK_FS_ATTR_RUN *tsk_pool_unallocated_runs(const TSK_POOL_INFO *a_pool) {
  const auto pool = static_cast<TSKPool *>(a_pool->impl);
  const auto ranges = pool->unallocated_ranges();

  TSK_FS_ATTR_RUN *data_run_head = nullptr;
  TSK_FS_ATTR_RUN *data_run_last = nullptr;

  TSK_DADDR_T offset = 0;

  int count = 0;
  printf("Pool block size: %lld\n", pool->block_size());
  // Create the runs
  for (const auto &range : ranges) {
      count++;
      if (count < 10) {
          printf("Range start block: %lld, num blocks; %lld\n", range.start_block, range.num_blocks);
      }
    auto data_run = tsk_fs_attr_run_alloc();
    if (data_run == nullptr) {
      tsk_fs_attr_run_free(data_run_head);
      return nullptr;
    }

    data_run->addr = range.start_block;
    data_run->offset = offset;
    data_run->len = range.num_blocks;
    data_run->flags = TSK_FS_ATTR_RUN_FLAG_NONE;
    data_run->next = nullptr;
    if (count < 10) {
        printf("Run addr: %lld, offset: %lld, len: %lld\n\n", data_run->addr, data_run->offset, data_run->len);
    }

    offset += range.num_blocks;

    if (data_run_head == nullptr) {
      data_run_head = data_run;
    } else {
      data_run_last->next = data_run;
    }

    data_run_last = data_run;
  }

  return data_run_head;
}
