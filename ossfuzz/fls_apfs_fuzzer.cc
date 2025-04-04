// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <stddef.h>
#include <stdint.h>

#include <memory>

#include "tsk/tsk_tools_i.h"
#include "tsk/fs/tsk_fs.h"
#include "tsk/pool/tsk_pool.h"
#include "mem_img.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    mem_open(data, size);
    tsk_img_close
  };

  if (!img) {
    return 0;
  }

  std::unique_ptr<const TSK_POOL_INFO, decltype(&tsk_pool_close)> pool{
    tsk_pool_open_img_sing(img.get(), 0, TSK_POOL_TYPE_APFS),
    tsk_pool_close
  };

  if (!pool) {
    return 0;
  }

  // Pool start block is APFS container specific and is hard coded for now
  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> pool_img{
    pool->get_img_info(pool.get(), (TSK_DADDR_T) 106),
    tsk_img_close
  };

  if (!pool_img) {
    return 0;
  }

  std::unique_ptr<TSK_FS_INFO, decltype(&tsk_fs_close)> fs{
    tsk_fs_open_img_decrypt(pool_img.get(), 0, TSK_FS_TYPE_APFS_DETECT, ""),
    tsk_fs_close
  };

  if (fs) {
    tsk_fs_fls(fs.get(), TSK_FS_FLS_FULL, fs->root_inum, TSK_FS_DIR_WALK_FLAG_RECURSE, nullptr, 0);
  }

  return 0;
}
