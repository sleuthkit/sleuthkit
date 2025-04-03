// Copyright 2020 Google LLC
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
#include "mem_img.h"

#ifndef FSTYPE
#error Define FSTYPE as a valid value of TSK_FS_TYPE_ENUM.
#endif

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  TSK_FS_INFO *fs;

  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    mem_open(data, size),
    tsk_img_close
  };

  if (!img) {
    return 0;
  }

  std::unique_ptr<TSK_FS_INFO, decltype(&tsk_fs_close)> fs{
    tsk_fs_open_img(img.get(), 0, FSTYPE),
    tsk_fs_close
  };

  if (fs) {
    tsk_fs_fls(fs.get(), TSK_FS_FLS_FULL, fs->root_inum, TSK_FS_DIR_WALK_FLAG_RECURSE,
               nullptr, 0);
  }

  return 0;
}
