// Copyright 2026 Google LLC
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

// Image-layer and volume-system fuzz target.
//
// Threat model: an attacker supplies a disk image (or the segments of a split
// raw image) and the tool opens it. The image bytes are fully attacker
// controlled; the image/volume type selectors stand in for the investigator
// choosing a format on the command line.
//
// The historical fls/mmls targets bypassed this entire layer with an
// in-memory img backend (mem_img.h), so tsk/img/raw.c (cache + split
// handling), tsk/img/mult_files.c, tsk/img/img_open.cpp type detection,
// tsk/img/unsupported_types.c header probing and the BSD/encrypted-disk paths
// of tsk/vs/mm_open.c (detectDiskEncryption) never ran under fuzzing. This
// harness drives those paths through the real file-based entry points
// (tsk_img_open / tsk_vs_open).
//
// Note: deliberately no FuzzedDataProvider - the build compiles with
// -std=c++14 and the header's type traits require C++17. The two selector
// bytes are consumed manually instead.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <string>
#include <vector>

#include "tsk/tsk_tools_i.h"

namespace {

constexpr size_t kMaxPayload = 1u << 20;  // 1 MiB of image bytes is plenty
constexpr int kNumImgTypes = 4;
constexpr int kNumVsTypes = 6;

const TSK_IMG_TYPE_ENUM kImgTypes[kNumImgTypes] = {
    TSK_IMG_TYPE_DETECT,  // probe all supported image formats
    TSK_IMG_TYPE_RAW,     // raw single
    TSK_IMG_TYPE_RAW,     // raw split, 2 segments
    TSK_IMG_TYPE_RAW,     // raw split, 3 segments
};

const TSK_VS_TYPE_ENUM kVsTypes[kNumVsTypes] = {
    TSK_VS_TYPE_DETECT, TSK_VS_TYPE_DOS, TSK_VS_TYPE_BSD,
    TSK_VS_TYPE_SUN,    TSK_VS_TYPE_MAC, TSK_VS_TYPE_GPT,
};

TSK_WALK_RET_ENUM part_act(TSK_VS_INFO *, const TSK_VS_PART_INFO *, void *) {
  return TSK_WALK_CONT;
}

// Writes one image segment to a fresh temporary file and returns its name.
// Returns an empty string on failure.
std::string write_segment(const uint8_t *data, size_t size, int idx) {
  char pattern[64];
  snprintf(pattern, sizeof(pattern), "/tmp/sk_imgvs_%d_XXXXXX", idx);
  int fd = mkstemp(pattern);
  if (fd < 0) {
    return std::string();
  }
  if (size > 0 && write(fd, data, size) != (ssize_t)size) {
    close(fd);
    unlink(pattern);
    return std::string();
  }
  close(fd);
  return std::string(pattern);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 8) {
    return 0;
  }

  const int img_sel = data[0] % kNumImgTypes;
  const int vs_sel = data[1] % kNumVsTypes;
  const uint8_t *payload = data + 2;
  size_t payload_size = size - 2;
  if (payload_size > kMaxPayload) {
    payload_size = kMaxPayload;
  }

  int num_img = 1;
  if (img_sel >= 2) {
    num_img = img_sel - 1;  // 2 -> 2 segments, 3 -> 3 segments
  }

  std::vector<std::string> paths;
  for (int i = 0; i < num_img; ++i) {
    const size_t start = payload_size * i / num_img;
    const size_t end = payload_size * (i + 1) / num_img;
    std::string path =
        write_segment(payload + start, end - start, i);
    if (path.empty()) {
      break;
    }
    paths.push_back(std::move(path));
  }
  if (paths.empty()) {
    return 0;
  }

  // Pointers must reference the strings that outlive the call (paths), not
  // the loop-local above (libc++ SSO would otherwise point into a dead
  // stack object).
  std::vector<const char *> argv_img;
  argv_img.reserve(paths.size());
  for (const auto &p : paths) {
    argv_img.push_back(p.c_str());
  }

  TSK_IMG_INFO *img =
      tsk_img_open((int)paths.size(), argv_img.data(), kImgTypes[img_sel], 0);
  if (img != nullptr) {
    TSK_VS_INFO *vs = tsk_vs_open(img, 0, kVsTypes[vs_sel]);
    if (vs != nullptr) {
      if (vs->part_count > 0) {
        tsk_vs_part_walk(vs, 0, vs->part_count - 1, TSK_VS_PART_FLAG_ALL,
                         part_act, nullptr);
      }
      tsk_vs_close(vs);
    }
    tsk_img_close(img);
  }

  for (const auto &p : paths) {
    unlink(p.c_str());
  }
  return 0;
}
