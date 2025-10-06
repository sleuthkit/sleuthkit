/*
 * test_fatfs.cpp
 *
 * End-to-end functional tests for FAT filesystem support.
 *
 * Author: Taha Ebrahim
 */

#include "tsk/fs/tsk_fatfs.h"
#include "tsk/fs/tsk_fs.h"
#include "tsk/fs/tsk_fs_i.h"

#include "catch.hpp"

#include <tsk/libtsk.h>
#include <cstdlib>    // for std::getenv
#include <iostream>
#include <fstream>
#include <string>

TEST_CASE("test fatfs_open works as expected") {
    char* env = getenv("SLEUTHKIT_TEST_DATA_DIR");
    if (env == nullptr) {
        WARN("SLEUTHKIT_TEST_DATA_DIR is not set — skipping test");
        return;  
    }
    std::string path = std::string(env) + "/from_brian/5-fat-daylight/daylight.dd";
    const char *image_paths[] = {path.c_str()};

    TSK_IMG_INFO *img_info = tsk_img_open_utf8(
        1, image_paths, TSK_IMG_TYPE_RAW, 512);

    REQUIRE(img_info != nullptr);

    TSK_OFF_T offset = 0;

    SECTION("normal setup, expected workflow") {
        TSK_FS_INFO *fs_info = fatfs_open(img_info, offset, TSK_FS_TYPE_FAT12, 0, 0);
        REQUIRE(fs_info != nullptr);
        if (fs_info) {
            fs_info->close(fs_info);
        }
    }
    SECTION("test for whether FAT check works") {
        TSK_FS_INFO *fs = fatfs_open(img_info, offset, TSK_FS_TYPE_NTFS, 0, 0);
        REQUIRE(fs == nullptr); 

        // Check error set correctly
        REQUIRE(tsk_error_get_errno() == TSK_ERR_FS_ARG);
        REQUIRE(std::string(tsk_error_get_errstr()).find("Invalid FS Type") != std::string::npos);
    }
    SECTION("sector test") {
        img_info->sector_size=0;
        TSK_FS_INFO *fs = fatfs_open(img_info, offset, TSK_FS_TYPE_FAT12, 0, 0);
        REQUIRE(fs == nullptr); 
        // Check error set correctly
        REQUIRE(tsk_error_get_errno() == TSK_ERR_FS_ARG);
        REQUIRE(std::string(tsk_error_get_errstr()).find("sector size is 0") != std::string::npos);
    }
    if (img_info) {
        tsk_img_close(img_info);
    }   
}
TEST_CASE("walking works as expected") {
    char* env = getenv("SLEUTHKIT_TEST_DATA_DIR");
    if (env == nullptr) {
        WARN("SLEUTHKIT_TEST_DATA_DIR is not set — skipping test");
        return;  
    }
    std::string path = std::string(env) + "/from_brian/5-fat-daylight/daylight.dd";
    const char *image_paths[] = {path.c_str()};

    TSK_IMG_INFO *img_info = tsk_img_open_utf8(
        1, image_paths, TSK_IMG_TYPE_RAW, 512);

    REQUIRE(img_info != nullptr);

    TSK_OFF_T offset = 0;
    TSK_FS_INFO *fs_info = fatfs_open(img_info, offset, TSK_FS_TYPE_FAT12, 0, 0);
    REQUIRE(fs_info != nullptr);

    auto callback = +[](const TSK_FS_BLOCK *fs_block, void *a_ptr) -> TSK_WALK_RET_ENUM {
        REQUIRE(fs_block != nullptr);
        (void)a_ptr;
        return TSK_WALK_CONT;
    };


    SECTION("normal setup, expected workflow") {
        REQUIRE(fatfs_block_walk(fs_info, 2, 3,
            TSK_FS_BLOCK_WALK_FLAG_NONE,
            callback, nullptr) == 0);
    }
    SECTION("start block after end block check") {
        REQUIRE(fatfs_block_walk(fs_info, 3, 2,
            TSK_FS_BLOCK_WALK_FLAG_NONE,
            callback, nullptr) == 0);
    }
    SECTION("invalid start block / end block check") {
        REQUIRE(fatfs_block_walk(fs_info, -1, 2,
            TSK_FS_BLOCK_WALK_FLAG_NONE,
            callback, nullptr) == 1);
    }
    SECTION("invalid start block / end block check") {
        REQUIRE(fatfs_block_walk(fs_info, 3, -1,
            TSK_FS_BLOCK_WALK_FLAG_NONE,
            callback, nullptr) == 1);
    }

    if (fs_info) {
        fs_info->close(fs_info);
    }
    if (img_info) {
        tsk_img_close(img_info);
    } 
    

} 