#include "catch.hpp"
#include "tsk/fs/tsk_fs_i.h"

// Test tsk_fs_file_alloc with null filesystem
TEST_CASE("tsk_fs_file_alloc handles null filesystem", "[fs_file]") {
    TSK_FS_FILE *fs_file = tsk_fs_file_alloc(nullptr);
    REQUIRE(fs_file != nullptr);
    REQUIRE(fs_file->fs_info == nullptr);
    REQUIRE(fs_file->tag == TSK_FS_FILE_TAG);
    REQUIRE(fs_file->meta == nullptr);
    REQUIRE(fs_file->name == nullptr);
    
    tsk_fs_file_close(fs_file);
}

// Test tsk_fs_file_alloc with valid filesystem
TEST_CASE("tsk_fs_file_alloc with valid filesystem", "[fs_file]") {
    TSK_FS_INFO fs_info = {};
    TSK_FS_FILE *fs_file = tsk_fs_file_alloc(&fs_info);
    REQUIRE(fs_file != nullptr);
    REQUIRE(fs_file->fs_info == &fs_info);
    REQUIRE(fs_file->tag == TSK_FS_FILE_TAG);
    REQUIRE(fs_file->meta == nullptr);
    REQUIRE(fs_file->name == nullptr);
    
    tsk_fs_file_close(fs_file);
}

// Test tsk_fs_file_close with null file
TEST_CASE("tsk_fs_file_close handles null file", "[fs_file]") {
    tsk_fs_file_close(nullptr);
}

// Test tsk_fs_file_close with invalid tag
TEST_CASE("tsk_fs_file_close with invalid tag", "[fs_file]") {
    TSK_FS_FILE fs_file = {};
    fs_file.tag = 0;
    
    tsk_fs_file_close(&fs_file);
}

// Test tsk_fs_file_close with valid file
TEST_CASE("tsk_fs_file_close with valid file", "[fs_file]") {
    TSK_FS_FILE *fs_file = tsk_fs_file_alloc(nullptr);
    REQUIRE(fs_file != nullptr);
    
    tsk_fs_file_close(fs_file);
}

// Test tsk_fs_file_attr_getsize with null file
TEST_CASE("tsk_fs_file_attr_getsize with null file", "[fs_file]") {
    int result = tsk_fs_file_attr_getsize(nullptr);
    REQUIRE(result == 0);
}

// Test tsk_fs_file_attr_getsize with file that has no attributes
TEST_CASE("tsk_fs_file_attr_getsize with no attributes", "[fs_file]") {
    TSK_FS_FILE fs_file = {};
    fs_file.meta = nullptr;
    
    int result = tsk_fs_file_attr_getsize(&fs_file);
    REQUIRE(result == 0);
}

// Test tsk_fs_file_attr_get_idx with null file
TEST_CASE("tsk_fs_file_attr_get_idx with null file", "[fs_file]") {
    const TSK_FS_ATTR *attr = tsk_fs_file_attr_get_idx(nullptr, 0);
    REQUIRE(attr == nullptr);
}

// Test tsk_fs_file_attr_get_idx with file that has no attributes
TEST_CASE("tsk_fs_file_attr_get_idx with no attributes", "[fs_file]") {
    TSK_FS_FILE fs_file = {};
    fs_file.meta = nullptr;
    
    const TSK_FS_ATTR *attr = tsk_fs_file_attr_get_idx(&fs_file, 0);
    REQUIRE(attr == nullptr);
}

// Test tsk_fs_file_attr_get with null file
TEST_CASE("tsk_fs_file_attr_get with null file", "[fs_file]") {
    const TSK_FS_ATTR *attr = tsk_fs_file_attr_get(nullptr);
    REQUIRE(attr == nullptr);
}

// Test tsk_fs_file_attr_get with file that has no attributes
TEST_CASE("tsk_fs_file_attr_get with no attributes", "[fs_file]") {
    TSK_FS_FILE fs_file = {};
    fs_file.meta = nullptr;
    
    const TSK_FS_ATTR *attr = tsk_fs_file_attr_get(&fs_file);
    REQUIRE(attr == nullptr);
}

// Test tsk_fs_file_attr_get_id with null file
TEST_CASE("tsk_fs_file_attr_get_id with null file", "[fs_file]") {
    const TSK_FS_ATTR *attr = tsk_fs_file_attr_get_id(nullptr, 0);
    REQUIRE(attr == nullptr);
}

// Test tsk_fs_file_attr_get_id with file that has no attributes
TEST_CASE("tsk_fs_file_attr_get_id with no attributes", "[fs_file]") {
    TSK_FS_FILE fs_file = {};
    fs_file.meta = nullptr;
    
    const TSK_FS_ATTR *attr = tsk_fs_file_attr_get_id(&fs_file, 0);
    REQUIRE(attr == nullptr);
}

// Test tsk_fs_file_walk_type with null file
TEST_CASE("tsk_fs_file_walk_type with null file", "[fs_file]") {
    uint8_t result = tsk_fs_file_walk_type(nullptr, TSK_FS_ATTR_TYPE_DEFAULT, 0, TSK_FS_FILE_WALK_FLAG_NONE, nullptr, nullptr);
    REQUIRE(result == 1);
}

// Test tsk_fs_file_walk_type with null action
TEST_CASE("tsk_fs_file_walk_type with null action", "[fs_file]") {
    TSK_FS_FILE fs_file = {};
    uint8_t result = tsk_fs_file_walk_type(&fs_file, TSK_FS_ATTR_TYPE_DEFAULT, 0, TSK_FS_FILE_WALK_FLAG_NONE, nullptr, nullptr);
    REQUIRE(result == 1);
}

// Test tsk_fs_file_walk with null file
TEST_CASE("tsk_fs_file_walk with null file", "[fs_file]") {
    uint8_t result = tsk_fs_file_walk(nullptr, TSK_FS_FILE_WALK_FLAG_NONE, nullptr, nullptr);
    REQUIRE(result == 1);
}

// Test tsk_fs_file_walk with null action
TEST_CASE("tsk_fs_file_walk with null action", "[fs_file]") {
    TSK_FS_FILE fs_file = {};
    uint8_t result = tsk_fs_file_walk(&fs_file, TSK_FS_FILE_WALK_FLAG_NONE, nullptr, nullptr);
    REQUIRE(result == 1);
}

// Test tsk_fs_file_read_type with null file
TEST_CASE("tsk_fs_file_read_type with null file", "[fs_file]") {
    char buf[100];
    ssize_t result = tsk_fs_file_read_type(nullptr, TSK_FS_ATTR_TYPE_DEFAULT, 0, 0, buf, 100, TSK_FS_FILE_READ_FLAG_NONE);
    REQUIRE(result == -1);
}

// Test tsk_fs_file_read with null file
TEST_CASE("tsk_fs_file_read with null file", "[fs_file]") {
    char buf[100];
    ssize_t result = tsk_fs_file_read(nullptr, 0, buf, 100, TSK_FS_FILE_READ_FLAG_NONE);
    REQUIRE(result == -1);
}

// Test tsk_fs_file_get_owner_sid with null file
TEST_CASE("tsk_fs_file_get_owner_sid with null file", "[fs_file]") {
    char *sid_str = nullptr;
    uint8_t result = tsk_fs_file_get_owner_sid(nullptr, &sid_str);
    REQUIRE(result == 1);
}

// Test tsk_fs_file_get_owner_sid with null sid_str parameter
TEST_CASE("tsk_fs_file_get_owner_sid with null sid_str", "[fs_file]") {
    TSK_FS_FILE fs_file = {};
    uint8_t result = tsk_fs_file_get_owner_sid(&fs_file, nullptr);
    REQUIRE(result == 1);
}

// Test tsk_fs_file_hash_calc with null file
TEST_CASE("tsk_fs_file_hash_calc with null file", "[fs_file]") {
    TSK_FS_HASH_RESULTS hash_results = {};
    uint8_t result = tsk_fs_file_hash_calc(nullptr, &hash_results, TSK_BASE_HASH_MD5);
    REQUIRE(result == 1);
}

// Test tsk_fs_file_hash_calc with null hash_results
TEST_CASE("tsk_fs_file_hash_calc with null hash_results", "[fs_file]") {
    TSK_FS_FILE fs_file = {};
    uint8_t result = tsk_fs_file_hash_calc(&fs_file, nullptr, TSK_BASE_HASH_MD5);
    REQUIRE(result == 1);
}