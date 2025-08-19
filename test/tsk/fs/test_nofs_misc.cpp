/*
* test_nofs_misc.cpp

*Author: Pratik Singh @singhpratik5

* Unit tests for internal functions common to the "non-file system" file systems

*/

#include "catch.hpp"
#include "tsk/fs/tsk_fs_i.h"
#include "tsk/img/tsk_img.h"
#include "test/tsk/img/test_img.h"
#include <cstdio>
#include <cstring>
#include <string>
#include <memory>

// Helper to open fs
struct RawFsHandle {
    TSK_IMG_INFO* img = nullptr;
    TSK_FS_INFO* fs = nullptr;
    RawFsHandle() {
        auto img_path = prepend_test_data_dir(_TSK_T("image_ext2.dd"));
        fix_slashes_for_windows(img_path);
        img = tsk_img_open_sing(img_path.c_str(), TSK_IMG_TYPE_DETECT, 0);
        REQUIRE(img != nullptr);
        fs = rawfs_open(img, 0);
        REQUIRE(fs != nullptr);
    }
    ~RawFsHandle() {
        if (fs) tsk_fs_close(fs);
        if (img) tsk_img_close(img);
    }
};

// Test tsk_fs_nofs_make_data_run
TEST_CASE("tsk_fs_nofs_make_data_run returns 1 and sets error", "[nofs_misc]") {
    TSK_FS_FILE fs_file;
    memset(&fs_file, 0, sizeof(fs_file));
    uint8_t ret = tsk_fs_nofs_make_data_run(&fs_file);

    REQUIRE(ret == 1);
    REQUIRE(tsk_error_get_errno() == TSK_ERR_FS_UNSUPFUNC);
    REQUIRE(strstr(tsk_error_get_errstr(), "Illegal analysis method for") != nullptr);
}

// Test tsk_fs_nofs_get_default_attr_type
TEST_CASE("tsk_fs_nofs_get_default_attr_type returns default", "[nofs_misc]") {
    TSK_FS_FILE fs_file;
    memset(&fs_file, 0, sizeof(fs_file));
    REQUIRE(tsk_fs_nofs_get_default_attr_type(&fs_file) == TSK_FS_ATTR_TYPE_DEFAULT);
}

// Test tsk_fs_nofs_close
TEST_CASE("tsk_fs_nofs_close sets tag to 0", "[nofs_misc]") {
    RawFsHandle handle;
    handle.fs->tag = 123;
    int original_tag = handle.fs->tag;
    tsk_fs_nofs_close(handle.fs);
    REQUIRE(original_tag == 123);
    handle.fs = nullptr;
}

// Test tsk_fs_nofs_block_getflags
TEST_CASE("tsk_fs_nofs_block_getflags returns correct flags", "[nofs_misc]") {
    RawFsHandle handle;
    REQUIRE(tsk_fs_nofs_block_getflags(handle.fs, 0) == (TSK_FS_BLOCK_FLAG_ALLOC | TSK_FS_BLOCK_FLAG_CONT));
}

// callback for block walk
static TSK_WALK_RET_ENUM block_walk_cb(const TSK_FS_BLOCK*, void* ptr) {
    int* count = static_cast<int*>(ptr);
    (*count)++;
    return TSK_WALK_CONT;
}
static TSK_WALK_RET_ENUM block_walk_cb_stop(const TSK_FS_BLOCK*, void* ptr) {
    int* count = static_cast<int*>(ptr);
    (*count)++;
    return TSK_WALK_STOP;
}
static TSK_WALK_RET_ENUM block_walk_cb_error(const TSK_FS_BLOCK*, void*) {
    return TSK_WALK_ERROR;
}
// No-op callback for nullptr
static TSK_WALK_RET_ENUM block_walk_cb_noop(const TSK_FS_BLOCK*, void*) {
    return TSK_WALK_CONT;
}

// Test tsk_fs_nofs_block_walk: out-of-range start block
TEST_CASE("tsk_fs_nofs_block_walk returns 1 for out-of-range start block", "[nofs_misc]") {
    RawFsHandle handle;
    REQUIRE(tsk_fs_nofs_block_walk(handle.fs, handle.fs->first_block - 1, handle.fs->first_block, TSK_FS_BLOCK_WALK_FLAG_ALLOC, block_walk_cb, nullptr) == 1);
}

// Test tsk_fs_nofs_block_walk: out-of-range end block
TEST_CASE("tsk_fs_nofs_block_walk returns 1 for out-of-range end block", "[nofs_misc]") {
    RawFsHandle handle;
    REQUIRE(tsk_fs_nofs_block_walk(handle.fs, handle.fs->first_block, handle.fs->last_block + 1, TSK_FS_BLOCK_WALK_FLAG_ALLOC, block_walk_cb, nullptr) == 1);
}

// Test tsk_fs_nofs_block_walk: end block < start block
TEST_CASE("tsk_fs_nofs_block_walk returns 1 for end block < start block", "[nofs_misc]") {
    RawFsHandle handle;
    REQUIRE(tsk_fs_nofs_block_walk(handle.fs, handle.fs->first_block + 2, handle.fs->first_block, TSK_FS_BLOCK_WALK_FLAG_ALLOC, block_walk_cb, nullptr) == 1);
}

// Test tsk_fs_nofs_block_walk: no ALLOC flag
TEST_CASE("tsk_fs_nofs_block_walk returns 0 if no ALLOC flag", "[nofs_misc]") {
    RawFsHandle handle;
    REQUIRE(tsk_fs_nofs_block_walk(handle.fs, handle.fs->first_block, handle.fs->last_block, TSK_FS_BLOCK_WALK_FLAG_NONE, block_walk_cb_noop, nullptr) == 0);
}

// Test tsk_fs_nofs_block_walk: normal walk
TEST_CASE("tsk_fs_nofs_block_walk normal walk", "[nofs_misc]") {
    RawFsHandle handle;
    int count = 0;
    REQUIRE(tsk_fs_nofs_block_walk(handle.fs, handle.fs->first_block, handle.fs->first_block, TSK_FS_BLOCK_WALK_FLAG_ALLOC, block_walk_cb, &count) == 0);
    REQUIRE(count == 1);
}

// Test tsk_fs_nofs_block_walk: callback returns STOP
TEST_CASE("tsk_fs_nofs_block_walk callback returns STOP", "[nofs_misc]") {
    RawFsHandle handle;
    int count = 0;
    REQUIRE(tsk_fs_nofs_block_walk(handle.fs, handle.fs->first_block, handle.fs->first_block + 2, TSK_FS_BLOCK_WALK_FLAG_ALLOC, block_walk_cb_stop, &count) == 0);
    REQUIRE(count == 1);
}

// Test tsk_fs_nofs_block_walk: callback returns ERROR
TEST_CASE("tsk_fs_nofs_block_walk callback returns ERROR", "[nofs_misc]") {
    RawFsHandle handle;
    REQUIRE(tsk_fs_nofs_block_walk(handle.fs, handle.fs->first_block, handle.fs->first_block, TSK_FS_BLOCK_WALK_FLAG_ALLOC, block_walk_cb_error, nullptr) == 1);
}

// Test tsk_fs_nofs_inode_walk
TEST_CASE("tsk_fs_nofs_inode_walk returns 1 and sets error", "[nofs_misc]") {
    RawFsHandle handle;
    REQUIRE(tsk_fs_nofs_inode_walk(handle.fs, 0, 0, (TSK_FS_META_FLAG_ENUM)0, nullptr, nullptr) == 1);
    REQUIRE(tsk_error_get_errno() == TSK_ERR_FS_UNSUPFUNC);
}

// Test tsk_fs_nofs_file_add_meta
TEST_CASE("tsk_fs_nofs_file_add_meta returns 1 and sets error", "[nofs_misc]") {
    RawFsHandle handle;
    REQUIRE(tsk_fs_nofs_file_add_meta(handle.fs, nullptr, 0) == 1);
    REQUIRE(tsk_error_get_errno() == TSK_ERR_FS_UNSUPFUNC);
}

// Test tsk_fs_nofs_istat
TEST_CASE("tsk_fs_nofs_istat returns 1 and sets error", "[nofs_misc]") {
    RawFsHandle handle;
    REQUIRE(tsk_fs_nofs_istat(handle.fs, (TSK_FS_ISTAT_FLAG_ENUM)0, nullptr, 0, 0, 0) == 1);
    REQUIRE(tsk_error_get_errno() == TSK_ERR_FS_UNSUPFUNC);
}

// Test tsk_fs_nofs_dir_open_meta
TEST_CASE("tsk_fs_nofs_dir_open_meta returns TSK_ERR and sets error", "[nofs_misc]") {
    RawFsHandle handle;
    REQUIRE(tsk_fs_nofs_dir_open_meta(handle.fs, nullptr, 0, 0) == TSK_ERR);
    REQUIRE(tsk_error_get_errno() == TSK_ERR_FS_UNSUPFUNC);
}

// Test tsk_fs_nofs_jopen
TEST_CASE("tsk_fs_nofs_jopen returns 1 and sets error", "[nofs_misc]") {
    RawFsHandle handle;
    REQUIRE(tsk_fs_nofs_jopen(handle.fs, 0) == 1);
    REQUIRE(tsk_error_get_errno() == TSK_ERR_FS_UNSUPFUNC);
}

// Test tsk_fs_nofs_jentry_walk
TEST_CASE("tsk_fs_nofs_jentry_walk returns 1 and sets error", "[nofs_misc]") {
    RawFsHandle handle;
    REQUIRE(tsk_fs_nofs_jentry_walk(handle.fs, 0, nullptr, nullptr) == 1);
    REQUIRE(tsk_error_get_errno() == TSK_ERR_FS_UNSUPFUNC);
}

// Test tsk_fs_nofs_jblk_walk
TEST_CASE("tsk_fs_nofs_jblk_walk returns 1 and sets error", "[nofs_misc]") {
    RawFsHandle handle;
    REQUIRE(tsk_fs_nofs_jblk_walk(handle.fs, 0, 0, 0, nullptr, nullptr) == 1);
    REQUIRE(tsk_error_get_errno() == TSK_ERR_FS_UNSUPFUNC);
}

// Test tsk_fs_nofs_name_cmp
TEST_CASE("tsk_fs_nofs_name_cmp compares names", "[nofs_misc]") {
    RawFsHandle handle;
    REQUIRE(tsk_fs_nofs_name_cmp(handle.fs, "abc", "abc") == 0);
    REQUIRE(tsk_fs_nofs_name_cmp(handle.fs, "abc", "def") != 0);
} 
