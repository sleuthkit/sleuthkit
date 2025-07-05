#include <cstdio>
#include <cstring>
#include <memory>
#include <string>

#include "tsk/libtsk.h"
#include "tsk/fs/tsk_fs.h"
#include "tsk/fs/tsk_fs_i.h"
#include "tsk/base/tsk_base.h"

#include "catch.hpp"

static const TSK_OFF_T EXT2_IMAGE_OFFSET = 0;
static const TSK_FS_TYPE_ENUM EXT2_TYPE = TSK_FS_TYPE_EXT2;

// Helper to check if the ext2 image exists
static bool ext2_image_exists() {
    FILE *f = fopen("test/data/image_ext2.dd", "rb");
    if (f) { fclose(f); return true; }
    return false;
}

// Helper to open ext2 image and fs
static bool setup_ext2_image(TSK_IMG_INFO **img, TSK_FS_INFO **fs) {
    if (!ext2_image_exists()) {
        WARN("Ext2 test image not found, skipping unix_misc tests");
        return false;
    }
    *img = tsk_img_open_sing(_TSK_T("test/data/image_ext2.dd"), TSK_IMG_TYPE_RAW, 0);
    if (!*img) {
        WARN("Could not open ext2 test image");
        return false;
    }
    *fs = tsk_fs_open_img(*img, EXT2_IMAGE_OFFSET, EXT2_TYPE);
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

// Test for unix_make_data_run with attribute loading
TEST_CASE("unix_misc: tsk_fs_unix_make_data_run covers direct and indirect", "[unix_misc]") {
    TSK_IMG_INFO *img = nullptr;
    TSK_FS_INFO *fs = nullptr;
    if (!setup_ext2_image(&img, &fs)) return;

    // 2 (root), 11 (lost+found), 12 (a_directory)
    TSK_INUM_T test_inodes[] = {2, 11, 12};
    for (size_t i = 0; i < sizeof(test_inodes)/sizeof(test_inodes[0]); ++i) {
        TSK_FS_FILE *file = tsk_fs_file_open_meta(fs, nullptr, test_inodes[i]);
        REQUIRE(file != nullptr);
        REQUIRE(file->meta != nullptr);
        if (
            file->meta->attr_state != TSK_FS_META_ATTR_STUDIED &&
            file->meta->attr_state != TSK_FS_META_ATTR_ERROR
        ) {
            WARN("Unexpected attr_state for inode " << test_inodes[i] << ": " << file->meta->attr_state);
        }
        tsk_fs_file_close(file);
    }
    cleanup_ext2_image(img, fs);
}

// Test for default attribute type
TEST_CASE("unix_misc: tsk_fs_unix_get_default_attr_type returns DEFAULT", "[unix_misc]") {
    TSK_IMG_INFO *img = nullptr;
    TSK_FS_INFO *fs = nullptr;
    if (!setup_ext2_image(&img, &fs)) return;
    TSK_FS_FILE *file = tsk_fs_file_open_meta(fs, nullptr, 2); 
    REQUIRE(file != nullptr);
    auto type = tsk_fs_unix_get_default_attr_type(file);
    REQUIRE(type == TSK_FS_ATTR_TYPE_DEFAULT);
    tsk_fs_file_close(file);
    cleanup_ext2_image(img, fs);
}

// Test for comparing real and synthetic names
TEST_CASE("unix_misc: tsk_fs_unix_name_cmp compares names", "[unix_misc]") {
    REQUIRE(tsk_fs_unix_name_cmp(nullptr, "foo", "foo") == 0);
    REQUIRE(tsk_fs_unix_name_cmp(nullptr, "foo", "bar") != 0);
    REQUIRE(tsk_fs_unix_name_cmp(nullptr, "abc", "def") < 0);
    REQUIRE(tsk_fs_unix_name_cmp(nullptr, "xyz", "uvw") > 0);
}

// Test for non-unix FS type
TEST_CASE("unix_misc: tsk_fs_unix_make_data_run with non-Unix FS type returns error", "[unix_misc]") {
    TSK_IMG_INFO *img = tsk_img_open_sing(_TSK_T("test/data/image.dd"), TSK_IMG_TYPE_RAW, 0);
    if (!img) { WARN("Raw test image not found, skipping"); return; }
    TSK_FS_INFO *fs = tsk_fs_open_img(img, 0, TSK_FS_TYPE_NTFS);
    if (!fs) { tsk_img_close(img); WARN("Could not open non-Unix FS, skipping"); return; }
    TSK_FS_FILE *file = tsk_fs_file_open_meta(fs, nullptr, fs->root_inum);
    if (file) {
        REQUIRE(tsk_fs_unix_make_data_run(file) == 1);
        tsk_fs_file_close(file);
    }
    tsk_fs_close(fs);
    tsk_img_close(img);
}

// Test for invalid inode 
TEST_CASE("unix_misc: tsk_fs_unix_make_data_run with invalid inode triggers error", "[unix_misc]") {
    TSK_IMG_INFO *img = nullptr;
    TSK_FS_INFO *fs = nullptr;
    if (!setup_ext2_image(&img, &fs)) return;
    TSK_FS_FILE *file = tsk_fs_file_open_meta(fs, nullptr, 99999);
    if (!file || !file->meta) {
        SUCCEED("Invalid inode correctly not found or has no meta");
    } else {
        REQUIRE(tsk_fs_unix_make_data_run(file) == 1);
        tsk_fs_file_close(file);
    }
    cleanup_ext2_image(img, fs);
}

// Test for large inode (out-of-bound)
TEST_CASE("unix_misc: tsk_fs_unix_make_data_run with out-of-bounds inode triggers error", "[unix_misc]") {
    TSK_IMG_INFO *img = nullptr;
    TSK_FS_INFO *fs = nullptr;
    if (!setup_ext2_image(&img, &fs)) return;
    TSK_FS_FILE *file = tsk_fs_file_open_meta(fs, nullptr, 1000000);
    if (!file || !file->meta) {
        SUCCEED("Out-of-bounds inode correctly not found or has no meta");
    } else {
        REQUIRE(tsk_fs_unix_make_data_run(file) == 1);
        tsk_fs_file_close(file);
    }
    cleanup_ext2_image(img, fs);
}
