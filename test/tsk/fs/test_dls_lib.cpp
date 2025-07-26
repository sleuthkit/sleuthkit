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

static void cleanup_image(TSK_IMG_INFO *img, TSK_FS_INFO *fs) {
    if (fs) tsk_fs_close(fs);
    if (img) tsk_img_close(img);
}

// Test tsk_fs_blkls with NONE flag (default mode - output block data)
TEST_CASE("dls_lib: tsk_fs_blkls with NONE flag", "[dls_lib]") {
    TSK_IMG_INFO *img = nullptr;
    TSK_FS_INFO *fs = nullptr;
    if (!setup_ext2_image(&img, &fs)) return;
    
    TSK_FS_BLKLS_FLAG_ENUM flags = TSK_FS_BLKLS_NONE;
    TSK_DADDR_T bstart = fs->first_block;
    TSK_DADDR_T blast = fs->first_block + 2;
    TSK_FS_BLOCK_WALK_FLAG_ENUM block_flags = TSK_FS_BLOCK_WALK_FLAG_UNALLOC;
    
    uint8_t result = tsk_fs_blkls(fs, flags, bstart, blast, block_flags);
    REQUIRE(result == 0);
    
    cleanup_image(img, fs);
}

// Test tsk_fs_blkls with LIST flag
TEST_CASE("dls_lib: tsk_fs_blkls with LIST flag", "[dls_lib]") {
    TSK_IMG_INFO *img = nullptr;
    TSK_FS_INFO *fs = nullptr;
    if (!setup_ext2_image(&img, &fs)) return;
    
    TSK_FS_BLKLS_FLAG_ENUM flags = TSK_FS_BLKLS_LIST;
    TSK_DADDR_T bstart = fs->first_block;
    TSK_DADDR_T blast = fs->first_block + 5;
    TSK_FS_BLOCK_WALK_FLAG_ENUM block_flags = TSK_FS_BLOCK_WALK_FLAG_ALLOC;
    
    uint8_t result = tsk_fs_blkls(fs, flags, bstart, blast, block_flags);
    REQUIRE(result == 0);
    
    cleanup_image(img, fs);
}

// Test tsk_fs_blkls with SLACK flag
TEST_CASE("dls_lib: tsk_fs_blkls with SLACK flag", "[dls_lib]") {
    TSK_IMG_INFO *img = nullptr;
    TSK_FS_INFO *fs = nullptr;
    if (!setup_ext2_image(&img, &fs)) return;
    
    TSK_FS_BLKLS_FLAG_ENUM flags = TSK_FS_BLKLS_SLACK;
    TSK_DADDR_T bstart = 0;
    TSK_DADDR_T blast = 0;
    TSK_FS_BLOCK_WALK_FLAG_ENUM block_flags = TSK_FS_BLOCK_WALK_FLAG_NONE;
    
    uint8_t result = tsk_fs_blkls(fs, flags, bstart, blast, block_flags);
    REQUIRE(result == 0);
    
    cleanup_image(img, fs);
}

// Test tsk_fs_blkls with CAT flag
TEST_CASE("dls_lib: tsk_fs_blkls with CAT flag", "[dls_lib]") {
    TSK_IMG_INFO *img = nullptr;
    TSK_FS_INFO *fs = nullptr;
    if (!setup_ext2_image(&img, &fs)) return;
    
    TSK_FS_BLKLS_FLAG_ENUM flags = TSK_FS_BLKLS_CAT;
    TSK_DADDR_T bstart = fs->first_block;
    TSK_DADDR_T blast = fs->first_block + 1;
    TSK_FS_BLOCK_WALK_FLAG_ENUM block_flags = TSK_FS_BLOCK_WALK_FLAG_ALLOC;
    
    uint8_t result = tsk_fs_blkls(fs, flags, bstart, blast, block_flags);
    REQUIRE(result == 0);
    
    cleanup_image(img, fs);
}

// Test tsk_fs_blkls with different block walk flags
TEST_CASE("dls_lib: tsk_fs_blkls with different block walk flags", "[dls_lib]") {
    TSK_IMG_INFO *img = nullptr;
    TSK_FS_INFO *fs = nullptr;
    if (!setup_ext2_image(&img, &fs)) return;
    
    TSK_FS_BLKLS_FLAG_ENUM flags = TSK_FS_BLKLS_NONE;
    TSK_DADDR_T bstart = fs->first_block;
    TSK_DADDR_T blast = fs->first_block + 2;
    
    // Test with allocated blocks only
    TSK_FS_BLOCK_WALK_FLAG_ENUM block_flags = TSK_FS_BLOCK_WALK_FLAG_ALLOC;
    uint8_t result = tsk_fs_blkls(fs, flags, bstart, blast, block_flags);
    REQUIRE(result == 0);
    
    // Test with unallocated blocks only
    block_flags = TSK_FS_BLOCK_WALK_FLAG_UNALLOC;
    result = tsk_fs_blkls(fs, flags, bstart, blast, block_flags);
    REQUIRE(result == 0);
    
    // Test with content blocks only
    block_flags = TSK_FS_BLOCK_WALK_FLAG_CONT;
    result = tsk_fs_blkls(fs, flags, bstart, blast, block_flags);
    REQUIRE(result == 0);
    
    // Test with metadata blocks only
    block_flags = TSK_FS_BLOCK_WALK_FLAG_META;
    result = tsk_fs_blkls(fs, flags, bstart, blast, block_flags);
    REQUIRE(result == 0);
    
    // Test with AONLY flag
    block_flags = TSK_FS_BLOCK_WALK_FLAG_AONLY;
    result = tsk_fs_blkls(fs, flags, bstart, blast, block_flags);
    REQUIRE(result == 0);
    
    cleanup_image(img, fs);
}

// Test tsk_fs_blkls with combined block walk flags
TEST_CASE("dls_lib: tsk_fs_blkls with combined block walk flags", "[dls_lib]") {
    TSK_IMG_INFO *img = nullptr;
    TSK_FS_INFO *fs = nullptr;
    if (!setup_ext2_image(&img, &fs)) return;
    
    TSK_FS_BLKLS_FLAG_ENUM flags = TSK_FS_BLKLS_NONE;
    TSK_DADDR_T bstart = fs->first_block;
    TSK_DADDR_T blast = fs->first_block + 3;
    TSK_FS_BLOCK_WALK_FLAG_ENUM block_flags = (TSK_FS_BLOCK_WALK_FLAG_ENUM)(
        TSK_FS_BLOCK_WALK_FLAG_ALLOC | 
        TSK_FS_BLOCK_WALK_FLAG_UNALLOC | 
        TSK_FS_BLOCK_WALK_FLAG_CONT | 
        TSK_FS_BLOCK_WALK_FLAG_META
    );
    
    uint8_t result = tsk_fs_blkls(fs, flags, bstart, blast, block_flags);
    REQUIRE(result == 0);
    
    cleanup_image(img, fs);
}

// Test tsk_fs_blkls with different block ranges
TEST_CASE("dls_lib: tsk_fs_blkls with different block ranges", "[dls_lib]") {
    TSK_IMG_INFO *img = nullptr;
    TSK_FS_INFO *fs = nullptr;
    if (!setup_ext2_image(&img, &fs)) return;
    
    TSK_FS_BLKLS_FLAG_ENUM flags = TSK_FS_BLKLS_NONE;
    TSK_FS_BLOCK_WALK_FLAG_ENUM block_flags = TSK_FS_BLOCK_WALK_FLAG_ALLOC;
    
    // Test with single block
    TSK_DADDR_T bstart = fs->first_block;
    TSK_DADDR_T blast = fs->first_block;
    uint8_t result = tsk_fs_blkls(fs, flags, bstart, blast, block_flags);
    REQUIRE(result == 0);
    
    // Test with multiple blocks
    bstart = fs->first_block;
    blast = fs->first_block + 5;
    result = tsk_fs_blkls(fs, flags, bstart, blast, block_flags);
    REQUIRE(result == 0);
    
    // Test with middle range
    bstart = fs->first_block + 10;
    blast = fs->first_block + 15;
    result = tsk_fs_blkls(fs, flags, bstart, blast, block_flags);
    REQUIRE(result == 0);
    
    cleanup_image(img, fs);
}

// Test tsk_fs_blkls with all flags combined
TEST_CASE("dls_lib: tsk_fs_blkls with all flags combined", "[dls_lib]") {
    TSK_IMG_INFO *img = nullptr;
    TSK_FS_INFO *fs = nullptr;
    if (!setup_ext2_image(&img, &fs)) return;
    
    TSK_FS_BLKLS_FLAG_ENUM flags = (TSK_FS_BLKLS_FLAG_ENUM)(
        TSK_FS_BLKLS_CAT | TSK_FS_BLKLS_LIST | TSK_FS_BLKLS_SLACK
    );
    TSK_DADDR_T bstart = fs->first_block;
    TSK_DADDR_T blast = fs->first_block + 2;
    TSK_FS_BLOCK_WALK_FLAG_ENUM block_flags = TSK_FS_BLOCK_WALK_FLAG_ALLOC;
    
    uint8_t result = tsk_fs_blkls(fs, flags, bstart, blast, block_flags);
    REQUIRE(result == 0);
    
    cleanup_image(img, fs);
}

// Test tsk_fs_blkls with zero block range
TEST_CASE("dls_lib: tsk_fs_blkls with zero block range", "[dls_lib]") {
    TSK_IMG_INFO *img = nullptr;
    TSK_FS_INFO *fs = nullptr;
    if (!setup_ext2_image(&img, &fs)) return;
    
    TSK_FS_BLKLS_FLAG_ENUM flags = TSK_FS_BLKLS_NONE;
    TSK_DADDR_T bstart = 0;
    TSK_DADDR_T blast = 0;
    TSK_FS_BLOCK_WALK_FLAG_ENUM block_flags = TSK_FS_BLOCK_WALK_FLAG_ALLOC;
    
    uint8_t result = tsk_fs_blkls(fs, flags, bstart, blast, block_flags);
    REQUIRE(result == 0);
    
    cleanup_image(img, fs);
}

// Test tsk_fs_blkls with maximum block range
TEST_CASE("dls_lib: tsk_fs_blkls with maximum block range", "[dls_lib]") {
    TSK_IMG_INFO *img = nullptr;
    TSK_FS_INFO *fs = nullptr;
    if (!setup_ext2_image(&img, &fs)) return;
    
    TSK_FS_BLKLS_FLAG_ENUM flags = TSK_FS_BLKLS_NONE;
    TSK_DADDR_T bstart = fs->first_block;
    TSK_DADDR_T blast = fs->last_block;
    TSK_FS_BLOCK_WALK_FLAG_ENUM block_flags = TSK_FS_BLOCK_WALK_FLAG_ALLOC;
    
    uint8_t result = tsk_fs_blkls(fs, flags, bstart, blast, block_flags);
    REQUIRE(result == 0);
    
    cleanup_image(img, fs);
}

// Test tsk_fs_blkls with verbose mode
TEST_CASE("dls_lib: tsk_fs_blkls with verbose mode", "[dls_lib]") {
    TSK_IMG_INFO *img = nullptr;
    TSK_FS_INFO *fs = nullptr;
    if (!setup_ext2_image(&img, &fs)) return;
    
    tsk_verbose = 1;
    
    TSK_FS_BLKLS_FLAG_ENUM flags = TSK_FS_BLKLS_NONE;
    TSK_DADDR_T bstart = fs->first_block;
    TSK_DADDR_T blast = fs->first_block + 1;
    TSK_FS_BLOCK_WALK_FLAG_ENUM block_flags = TSK_FS_BLOCK_WALK_FLAG_ALLOC;
    
    uint8_t result = tsk_fs_blkls(fs, flags, bstart, blast, block_flags);
    REQUIRE(result == 0);
    
    tsk_verbose = 0;
    
    cleanup_image(img, fs);
}

// Test tsk_fs_blkls with LIST flag and verbose mode
TEST_CASE("dls_lib: tsk_fs_blkls LIST with verbose mode", "[dls_lib]") {
    TSK_IMG_INFO *img = nullptr;
    TSK_FS_INFO *fs = nullptr;
    if (!setup_ext2_image(&img, &fs)) return;
    
    tsk_verbose = 1;
    
    TSK_FS_BLKLS_FLAG_ENUM flags = TSK_FS_BLKLS_LIST;
    TSK_DADDR_T bstart = fs->first_block;
    TSK_DADDR_T blast = fs->first_block + 2;
    TSK_FS_BLOCK_WALK_FLAG_ENUM block_flags = TSK_FS_BLOCK_WALK_FLAG_ALLOC;
    
    uint8_t result = tsk_fs_blkls(fs, flags, bstart, blast, block_flags);
    REQUIRE(result == 0);
    
    tsk_verbose = 0;
    
    cleanup_image(img, fs);
}

// Test tsk_fs_blkls with SLACK flag and verbose mode
TEST_CASE("dls_lib: tsk_fs_blkls SLACK with verbose mode", "[dls_lib]") {
    TSK_IMG_INFO *img = nullptr;
    TSK_FS_INFO *fs = nullptr;
    if (!setup_ext2_image(&img, &fs)) return;
    
    tsk_verbose = 1;
    
    TSK_FS_BLKLS_FLAG_ENUM flags = TSK_FS_BLKLS_SLACK;
    TSK_DADDR_T bstart = 0;
    TSK_DADDR_T blast = 0;
    TSK_FS_BLOCK_WALK_FLAG_ENUM block_flags = TSK_FS_BLOCK_WALK_FLAG_NONE;
    
    uint8_t result = tsk_fs_blkls(fs, flags, bstart, blast, block_flags);
    REQUIRE(result == 0);
    
    tsk_verbose = 0;
    
    cleanup_image(img, fs);
} 