#include "catch.hpp"
#include "tsk/fs/tsk_fs_i.h"

// Test null cur pointer
TEST_CASE("tsk_fs_load_file_action null cur pointer", "[fs_load]") {
    TSK_FS_LOAD_FILE buf_info = {};
    buf_info.cur = nullptr;
    char test_buf[100] = "test data";
    TSK_FS_FILE fs_file = {};
    
    TSK_WALK_RET_ENUM result = tsk_fs_load_file_action(
        &fs_file, 0, 0, test_buf, 10, TSK_FS_BLOCK_FLAG_UNUSED, &buf_info);
    
    REQUIRE(result == TSK_WALK_ERROR);
}

// Test buffer overflow conditions
TEST_CASE("tsk_fs_load_file_action buffer overflow", "[fs_load]") {
    char buffer[100] = {0};
    TSK_FS_LOAD_FILE buf_info = {};
    TSK_FS_FILE fs_file = {};
    char test_buf[100] = "test data";
    
    buf_info.cur = buffer;
    buf_info.base = buffer;
    buf_info.left = 50;
    buf_info.total = 5;
    
    TSK_WALK_RET_ENUM result = tsk_fs_load_file_action(
        &fs_file, 0, 0, test_buf, 10, TSK_FS_BLOCK_FLAG_UNUSED, &buf_info);
    
    REQUIRE(result == TSK_WALK_ERROR);
    
    buf_info.cur = buffer + 90;
    buf_info.total = 100;
    
    result = tsk_fs_load_file_action(
        &fs_file, 0, 0, test_buf, 15, TSK_FS_BLOCK_FLAG_UNUSED, &buf_info);
    
    REQUIRE(result == TSK_WALK_ERROR);
}