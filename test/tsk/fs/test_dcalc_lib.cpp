#include "catch.hpp"
#include "tsk/fs/tsk_fs_i.h"
#include "tsk/fs/tsk_fs.h"
#include "tsk/libtsk.h"
#include <cstdio>
#include <cstring>

// Helper to check if the ext2 image exists
static bool ext2_image_exists() {
    FILE *f = fopen("test/data/image_ext2.dd", "rb");
    if (f) { fclose(f); return true; }
    return false;
}

// Helper to open ext2 image and fs
static bool setup_ext2_image(TSK_IMG_INFO **img, TSK_FS_INFO **fs) {
    if (!ext2_image_exists()) {
        WARN("Ext2 test image not found, skipping filesystem tests");
        return false;
    }
    *img = tsk_img_open_sing(_TSK_T("test/data/image_ext2.dd"), TSK_IMG_TYPE_RAW, 0);
    if (!*img) {
        WARN("Could not open ext2 test image");
        return false;
    }
    *fs = tsk_fs_open_img(*img, 0, TSK_FS_TYPE_EXT2);
    if (!*fs) {
        tsk_img_close(*img);
        *img = nullptr;
        WARN("Could not open ext2 filesystem");
        return false;
    }
    return true;
}

static void cleanup_ext2_image(TSK_IMG_INFO *img, TSK_FS_INFO *fs) {
    if (fs) tsk_fs_close(fs);
    if (img) tsk_img_close(img);
}

// Test tsk_fs_blkcalc with ext2 fs - DD flag
TEST_CASE("dcalc_lib: tsk_fs_blkcalc with ext2 fs DD flag", "[dcalc_lib]") {
    TSK_IMG_INFO *img = nullptr;
    TSK_FS_INFO *fs = nullptr;
    if (!setup_ext2_image(&img, &fs)) return;
    
    TSK_FS_BLKCALC_FLAG_ENUM flags = TSK_FS_BLKCALC_DD;
    TSK_DADDR_T cnt = 1; 
    int8_t result = tsk_fs_blkcalc(fs, flags, cnt);
    REQUIRE(result == 0); 
    
    cleanup_ext2_image(img, fs);
}

// Test tsk_fs_blkcalc with ext2 fs - BLKLS flag
TEST_CASE("dcalc_lib: tsk_fs_blkcalc with ext2 fs BLKLS flag", "[dcalc_lib]") {
    TSK_IMG_INFO *img = nullptr;
    TSK_FS_INFO *fs = nullptr;
    if (!setup_ext2_image(&img, &fs)) return;
    
    TSK_FS_BLKCALC_FLAG_ENUM flags = TSK_FS_BLKCALC_BLKLS;
    TSK_DADDR_T cnt = 1; 
    int8_t result = tsk_fs_blkcalc(fs, flags, cnt);
    REQUIRE(result == 0); 
    
    cleanup_ext2_image(img, fs);
}

// Test tsk_fs_blkcalc with count too large 
TEST_CASE("dcalc_lib: tsk_fs_blkcalc with count too large returns block too large", "[dcalc_lib]") {
    TSK_IMG_INFO *img = nullptr;
    TSK_FS_INFO *fs = nullptr;
    if (!setup_ext2_image(&img, &fs)) return;
    
    TSK_FS_BLKCALC_FLAG_ENUM flags = TSK_FS_BLKCALC_DD;
    TSK_DADDR_T cnt = 1000000; 
    int8_t result = tsk_fs_blkcalc(fs, flags, cnt);
    REQUIRE(result == 1); 
    
    cleanup_ext2_image(img, fs);
}

// Test tsk_fs_blkcalc with zero count
TEST_CASE("dcalc_lib: tsk_fs_blkcalc with zero count", "[dcalc_lib]") {
    TSK_IMG_INFO *img = nullptr;
    TSK_FS_INFO *fs = nullptr;
    if (!setup_ext2_image(&img, &fs)) return;
    
    TSK_FS_BLKCALC_FLAG_ENUM flags = TSK_FS_BLKCALC_DD;
    TSK_DADDR_T cnt = 0;
    int8_t result = tsk_fs_blkcalc(fs, flags, cnt);
    REQUIRE(result == 0); 
    
    cleanup_ext2_image(img, fs);
}

// Test tsk_fs_blkcalc with invalid flag combination
TEST_CASE("dcalc_lib: tsk_fs_blkcalc with invalid flags returns error", "[dcalc_lib]") {
    TSK_IMG_INFO *img = nullptr;
    TSK_FS_INFO *fs = nullptr;
    if (!setup_ext2_image(&img, &fs)) return;
    
    // Test with no flags set
    TSK_FS_BLKCALC_FLAG_ENUM flags = (TSK_FS_BLKCALC_FLAG_ENUM)0;
    TSK_DADDR_T cnt = 0;
    int8_t result = tsk_fs_blkcalc(fs, flags, cnt);
    REQUIRE(result == 1); 
    
    cleanup_ext2_image(img, fs);
}

// Test tsk_fs_blkcalc with multiple flags set 
TEST_CASE("dcalc_lib: tsk_fs_blkcalc with multiple flags set", "[dcalc_lib]") {
    TSK_IMG_INFO *img = nullptr;
    TSK_FS_INFO *fs = nullptr;
    if (!setup_ext2_image(&img, &fs)) return;
    
    TSK_FS_BLKCALC_FLAG_ENUM flags = (TSK_FS_BLKCALC_FLAG_ENUM)(TSK_FS_BLKCALC_DD | TSK_FS_BLKCALC_BLKLS);
    TSK_DADDR_T cnt = 1;
    int8_t result = tsk_fs_blkcalc(fs, flags, cnt);
    REQUIRE(result == 1); 
    
    cleanup_ext2_image(img, fs);
}

// Test tsk_fs_blkcalc with all three flags set
TEST_CASE("dcalc_lib: tsk_fs_blkcalc with all flags set", "[dcalc_lib]") {
    TSK_IMG_INFO *img = nullptr;
    TSK_FS_INFO *fs = nullptr;
    if (!setup_ext2_image(&img, &fs)) return;

    TSK_FS_BLKCALC_FLAG_ENUM flags = (TSK_FS_BLKCALC_FLAG_ENUM)(TSK_FS_BLKCALC_DD | TSK_FS_BLKCALC_BLKLS | TSK_FS_BLKCALC_SLACK);
    TSK_DADDR_T cnt = 1;
    int8_t result = tsk_fs_blkcalc(fs, flags, cnt);
    REQUIRE(result == 1); 
    
    cleanup_ext2_image(img, fs);
}

// Test tsk_fs_blkcalc with DD and different count values
TEST_CASE("dcalc_lib: tsk_fs_blkcalc with different count values", "[dcalc_lib]") {
    TSK_IMG_INFO *img = nullptr;
    TSK_FS_INFO *fs = nullptr;
    if (!setup_ext2_image(&img, &fs)) return;
    
    TSK_FS_BLKCALC_FLAG_ENUM flags = TSK_FS_BLKCALC_DD;
    
    int8_t result = tsk_fs_blkcalc(fs, flags, 1);
    REQUIRE(result == 0);
    
    result = tsk_fs_blkcalc(fs, flags, 5);
    REQUIRE(result == 0);
    
    result = tsk_fs_blkcalc(fs, flags, 10);
    REQUIRE(result == 0);
    
    cleanup_ext2_image(img, fs);
}

// Test tsk_fs_blkcalc with BLKLS flag and different count values
TEST_CASE("dcalc_lib: tsk_fs_blkcalc BLKLS with different count values", "[dcalc_lib]") {
    TSK_IMG_INFO *img = nullptr;
    TSK_FS_INFO *fs = nullptr;
    if (!setup_ext2_image(&img, &fs)) return;
    
    TSK_FS_BLKCALC_FLAG_ENUM flags = TSK_FS_BLKCALC_BLKLS;
    
    int8_t result = tsk_fs_blkcalc(fs, flags, 1);
    REQUIRE(result == 0);
    
    result = tsk_fs_blkcalc(fs, flags, 3);
    REQUIRE(result == 0);
    
    result = tsk_fs_blkcalc(fs, flags, 7);
    REQUIRE(result == 0);
    
    cleanup_ext2_image(img, fs);
}