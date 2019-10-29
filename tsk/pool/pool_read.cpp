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

  // Create the runs
  for (const auto &range : ranges) {
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
