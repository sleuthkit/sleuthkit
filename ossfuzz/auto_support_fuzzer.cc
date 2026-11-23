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

// "Is this image supported?" fuzz target.
//
// Threat model: the investigator points TSK at an attacker-supplied disk
// image and asks whether it is supported (the tsk-is-image-supported /
// logical imager front door). One fuzz input is one image file; the whole
// buffer is attacker controlled.
//
// Driving TskIsImageSupported sweeps every auto-detection front door in one
// target: volume-system detection incl. detectDiskEncryption
// (tsk/util/detect_encryption.c), pool detection, file-system detection for
// every supported type, and the TskAuto file walk (tsk/auto/auto.cpp) with
// per-file processing, none of which the historical per-type fls/mmls targets
// exercise (they force concrete types and never detect, never walk pools and
// never use the auto layer).

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <string>

#include "tsk/auto/tsk_is_image_supported.h"

namespace {

constexpr size_t kMaxPayload = 1u << 20;  // 1 MiB of image bytes is plenty

std::string write_image(const uint8_t *data, size_t size) {
  char pattern[64];
  snprintf(pattern, sizeof(pattern), "/tmp/sk_autosup_XXXXXX");
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

  std::string payload(reinterpret_cast<const char *>(data), size);
  if (payload.size() > kMaxPayload) {
    payload.resize(kMaxPayload);
  }

  std::string path = write_image(
      reinterpret_cast<const uint8_t *>(payload.data()), payload.size());
  if (path.empty()) {
    return 0;
  }

  const char *images[1] = {path.c_str()};
  TskIsImageSupported tskAuto;
  if (tskAuto.openImageUtf8(1, images, TSK_IMG_TYPE_DETECT, 0) == 0) {
    tskAuto.findFilesInImg();
    (void)tskAuto.isImageSupported();
    (void)tskAuto.isImageEncrypted();
  }
  tskAuto.closeImage();

  unlink(path.c_str());
  return 0;
}
