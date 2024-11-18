/*
 * The Sleuth Kit
 *
 *
 * Copyright (c) 2010, 2025 Basis Technology Corp.  All Rights reserved
 *
 * This software is distributed under the Common Public License 1.0
 */

#define CATCH_CONFIG_MAIN
#define CATCH_CONFIG_CONSOLE_WIDTH 80
#define CATCH_CONFIG_ENABLE_BENCHMARKING

#include "catch.hpp"

#include "tsk/libtsk.h"

#include <memory>



class Walker: public TskAuto {
public:
  virtual ~Walker() {}

  virtual TSK_FILTER_ENUM filterPool([[maybe_unused]] const TSK_POOL_INFO* p) override {
    return TSK_FILTER_CONT;
  }

  virtual TSK_FILTER_ENUM filterPoolVol([[maybe_unused]] const TSK_POOL_VOLUME_INFO* pv) override {
    return TSK_FILTER_CONT;
  }

  virtual TSK_FILTER_ENUM filterVs([[maybe_unused]] const TSK_VS_INFO* vs) override {
    return TSK_FILTER_CONT;
  }

  virtual TSK_FILTER_ENUM filterVol([[maybe_unused]] const TSK_VS_PART_INFO* vs_part) override {
    return TSK_FILTER_CONT;
  }
  
  virtual TSK_FILTER_ENUM filterFs([[maybe_unused]] TSK_FS_INFO* fs) override {
    return TSK_FILTER_CONT;
  }

  virtual TSK_RETVAL_ENUM processFile([[maybe_unused]] TSK_FS_FILE* file, [[maybe_unused]] const char*) override { 
    return TSK_OK;
  }
};

TEST_CASE("xxx") {
  const TSK_TCHAR* const images[] = { _TSK_T("../fsrip/testdata/img/TinyOSX.E01") };

  BENCHMARK("walk") {
    std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
      tsk_img_open(1, images, TSK_IMG_TYPE_EWF_EWF, 0),
      tsk_img_close
    };
    REQUIRE(img);

    Walker w;
    w.openImageHandle(img.get());
    return w.findFilesInImg();
  };
}
