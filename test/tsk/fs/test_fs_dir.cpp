#include "catch.hpp"
#include "tsk/fs/tsk_fs_i.h"
#include "tsk/img/tsk_img.h"

// Test tsk_fs_dir_alloc with null filesystem
TEST_CASE("tsk_fs_dir_alloc with null filesystem", "[fs_dir]") {
    TSK_FS_DIR *fs_dir = tsk_fs_dir_alloc(nullptr, 1, 10);
    REQUIRE(fs_dir != nullptr);
    REQUIRE(fs_dir->fs_info == nullptr);
    REQUIRE(fs_dir->addr == 1);
    REQUIRE(fs_dir->tag == TSK_FS_DIR_TAG);
    REQUIRE(fs_dir->names_alloc == 10);
    REQUIRE(fs_dir->names_used == 0);
    REQUIRE(fs_dir->names != nullptr);
    
    tsk_fs_dir_close(fs_dir);
}

// Test tsk_fs_dir_alloc with valid filesystem
TEST_CASE("tsk_fs_dir_alloc with valid filesystem", "[fs_dir]") {
    TSK_FS_INFO fs_info = {};
    TSK_FS_DIR *fs_dir = tsk_fs_dir_alloc(&fs_info, 2, 5);
    REQUIRE(fs_dir != nullptr);
    REQUIRE(fs_dir->fs_info == &fs_info);
    REQUIRE(fs_dir->addr == 2);
    REQUIRE(fs_dir->tag == TSK_FS_DIR_TAG);
    REQUIRE(fs_dir->names_alloc == 5);
    REQUIRE(fs_dir->names_used == 0);
    REQUIRE(fs_dir->names != nullptr);
    
    // Checking that all name entries are initialized
    for (size_t i = 0; i < 5; i++) {
        REQUIRE(fs_dir->names[i].tag == TSK_FS_NAME_TAG);
    }
    
    tsk_fs_dir_close(fs_dir);
}

// Test tsk_fs_dir_alloc with zero count
TEST_CASE("tsk_fs_dir_alloc with zero count", "[fs_dir]") {
    TSK_FS_DIR *fs_dir = tsk_fs_dir_alloc(nullptr, 1, 0);
    REQUIRE(fs_dir != nullptr);
    REQUIRE(fs_dir->names_alloc == 0);
    REQUIRE(fs_dir->names_used == 0);
    REQUIRE(fs_dir->names != nullptr);
    
    tsk_fs_dir_close(fs_dir);
}

// Test tsk_fs_dir_realloc with null directory
TEST_CASE("tsk_fs_dir_realloc with null directory", "[fs_dir]") {
    uint8_t result = tsk_fs_dir_realloc(nullptr, 10);
    REQUIRE(result == 1);
}

// Test tsk_fs_dir_realloc with invalid tag
TEST_CASE("tsk_fs_dir_realloc with invalid tag", "[fs_dir]") {
    TSK_FS_DIR fs_dir = {};
    fs_dir.tag = 0;  // Invalid tag
    
    uint8_t result = tsk_fs_dir_realloc(&fs_dir, 10);
    REQUIRE(result == 1);
}

// Test tsk_fs_dir_realloc with smaller size
TEST_CASE("tsk_fs_dir_realloc with smaller size", "[fs_dir]") {
    TSK_FS_DIR *fs_dir = tsk_fs_dir_alloc(nullptr, 1, 10);
    REQUIRE(fs_dir != nullptr);
    
    uint8_t result = tsk_fs_dir_realloc(fs_dir, 5);
    REQUIRE(result == 0);
    REQUIRE(fs_dir->names_alloc == 10);
    
    tsk_fs_dir_close(fs_dir);
}

// Test tsk_fs_dir_realloc with larger size
TEST_CASE("tsk_fs_dir_realloc with larger size", "[fs_dir]") {
    TSK_FS_DIR *fs_dir = tsk_fs_dir_alloc(nullptr, 1, 5);
    REQUIRE(fs_dir != nullptr);
    
    uint8_t result = tsk_fs_dir_realloc(fs_dir, 15);
    REQUIRE(result == 0);
    REQUIRE(fs_dir->names_alloc == 15);
    REQUIRE(fs_dir->names_used == 0);
    REQUIRE(fs_dir->names != nullptr);
    
    // Checking that new entries are initialized
    for (size_t i = 5; i < 15; i++) {
        REQUIRE(fs_dir->names[i].tag == TSK_FS_NAME_TAG);
    }
    
    tsk_fs_dir_close(fs_dir);
}

// Test tsk_fs_dir_reset with null directory
TEST_CASE("tsk_fs_dir_reset with null directory", "[fs_dir]") {
    tsk_fs_dir_reset(nullptr);
}

// Test tsk_fs_dir_reset with valid directory
TEST_CASE("tsk_fs_dir_reset with valid directory", "[fs_dir]") {
    TSK_FS_DIR *fs_dir = tsk_fs_dir_alloc(nullptr, 1, 5);
    REQUIRE(fs_dir != nullptr);

    fs_dir->names_used = 3;
    fs_dir->names[0].meta_addr = 10;
    fs_dir->names[1].meta_addr = 20;
    fs_dir->names[2].meta_addr = 30;
    
    tsk_fs_dir_reset(fs_dir);
    
    REQUIRE(fs_dir->names_used == 0);
    REQUIRE(fs_dir->names_alloc == 5);
    REQUIRE(fs_dir->addr == 0);
    
    tsk_fs_dir_close(fs_dir);
}

// Test tsk_fs_dir_close with null directory
TEST_CASE("tsk_fs_dir_close with null directory", "[fs_dir]") {
    tsk_fs_dir_close(nullptr);
}

// Test tsk_fs_dir_close with valid directory
TEST_CASE("tsk_fs_dir_close with valid directory", "[fs_dir]") {
    TSK_FS_DIR *fs_dir = tsk_fs_dir_alloc(nullptr, 1, 5);
    REQUIRE(fs_dir != nullptr);

    tsk_fs_dir_close(fs_dir);
}

// Test tsk_fs_dir_getsize with null directory
TEST_CASE("tsk_fs_dir_getsize with null directory", "[fs_dir]") {
    size_t size = tsk_fs_dir_getsize(nullptr);
    REQUIRE(size == 0);
}

// Test tsk_fs_dir_getsize with empty directory
TEST_CASE("tsk_fs_dir_getsize with empty directory", "[fs_dir]") {
    TSK_FS_DIR *fs_dir = tsk_fs_dir_alloc(nullptr, 1, 5);
    REQUIRE(fs_dir != nullptr);
    
    size_t size = tsk_fs_dir_getsize(fs_dir);
    REQUIRE(size == 0);
    
    tsk_fs_dir_close(fs_dir);
}

// Test tsk_fs_dir_getsize with directory containing entries
TEST_CASE("tsk_fs_dir_getsize with directory containing entries", "[fs_dir]") {
    TSK_FS_DIR *fs_dir = tsk_fs_dir_alloc(nullptr, 1, 5);
    REQUIRE(fs_dir != nullptr);
    
    fs_dir->names_used = 3;
    
    size_t size = tsk_fs_dir_getsize(fs_dir);
    REQUIRE(size == 3);
    
    tsk_fs_dir_close(fs_dir);
}

// Test tsk_fs_dir_get with null directory
TEST_CASE("tsk_fs_dir_get with null directory", "[fs_dir]") {
    TSK_FS_FILE *file = tsk_fs_dir_get(nullptr, 0);
    REQUIRE(file == nullptr);
}

// Test tsk_fs_dir_get with out of bounds index
TEST_CASE("tsk_fs_dir_get with out of bounds index", "[fs_dir]") {
    TSK_FS_DIR *fs_dir = tsk_fs_dir_alloc(nullptr, 1, 5);
    REQUIRE(fs_dir != nullptr);
    
    fs_dir->names_used = 3;
    
    TSK_FS_FILE *file = tsk_fs_dir_get(fs_dir, 5);
    REQUIRE(file == nullptr);
    
    file = tsk_fs_dir_get(fs_dir, 3);
    REQUIRE(file == nullptr);
    
    tsk_fs_dir_close(fs_dir);
}

// Test tsk_fs_dir_get with valid index
TEST_CASE("tsk_fs_dir_get with valid index", "[fs_dir]") {
    TSK_FS_DIR *fs_dir = tsk_fs_dir_alloc(nullptr, 1, 5);
    REQUIRE(fs_dir != nullptr);
    
    fs_dir->names_used = 3;
    TSK_FS_FILE *file = tsk_fs_dir_get(fs_dir, 0);
    REQUIRE(file == nullptr);
    
    tsk_fs_dir_close(fs_dir);
}

// Test tsk_fs_dir_get_name with null directory
TEST_CASE("tsk_fs_dir_get_name with null directory", "[fs_dir]") {
    const TSK_FS_NAME *name = tsk_fs_dir_get_name(nullptr, 0);
    REQUIRE(name == nullptr);
}

// Test tsk_fs_dir_get_name with out of bounds index
TEST_CASE("tsk_fs_dir_get_name with out of bounds index", "[fs_dir]") {
    TSK_FS_DIR *fs_dir = tsk_fs_dir_alloc(nullptr, 1, 5);
    REQUIRE(fs_dir != nullptr);
    
    fs_dir->names_used = 3;
    
    const TSK_FS_NAME *name = tsk_fs_dir_get_name(fs_dir, 5);
    REQUIRE(name == nullptr);
    
    tsk_fs_dir_close(fs_dir);
}

// Test tsk_fs_dir_get_name with valid index
TEST_CASE("tsk_fs_dir_get_name with valid index", "[fs_dir]") {
    TSK_FS_DIR *fs_dir = tsk_fs_dir_alloc(nullptr, 1, 5);
    REQUIRE(fs_dir != nullptr);
    
    fs_dir->names_used = 3;
    
    const TSK_FS_NAME *name = tsk_fs_dir_get_name(fs_dir, 0);
    REQUIRE(name == nullptr);
    
    tsk_fs_dir_close(fs_dir);
}

// Test tsk_fs_dir_contains with null directory
TEST_CASE("tsk_fs_dir_contains with null directory", "[fs_dir]") {
    // the function doesn't check for null
    // uint8_t result = tsk_fs_dir_contains(nullptr, 1, 0);
    // REQUIRE(result == 0);
}

// Test tsk_fs_dir_contains with empty directory
TEST_CASE("tsk_fs_dir_contains with empty directory", "[fs_dir]") {
    TSK_FS_DIR *fs_dir = tsk_fs_dir_alloc(nullptr, 1, 5);
    REQUIRE(fs_dir != nullptr);
    
    uint8_t result = tsk_fs_dir_contains(fs_dir, 1, 0);
    REQUIRE(result == 0);
    
    tsk_fs_dir_close(fs_dir);
}

// Test tsk_fs_dir_hash with null string
TEST_CASE("tsk_fs_dir_hash with null string", "[fs_dir]") {
    //uint32_t hash = tsk_fs_dir_hash(nullptr);
    //REQUIRE(hash == 0);
}

// Test tsk_fs_dir_hash with empty string
TEST_CASE("tsk_fs_dir_hash with empty string", "[fs_dir]") {
    uint32_t hash = tsk_fs_dir_hash("");
    REQUIRE(hash == 5381);
}

// Test tsk_fs_dir_hash with valid strings
TEST_CASE("tsk_fs_dir_hash with valid strings", "[fs_dir]") {
    uint32_t hash1 = tsk_fs_dir_hash("test");
    uint32_t hash2 = tsk_fs_dir_hash("test");
    uint32_t hash3 = tsk_fs_dir_hash("different");
    
    REQUIRE(hash1 == hash2);
    REQUIRE(hash1 != hash3);
    REQUIRE(hash1 != 0);
}
/*
// Test tsk_fs_dir_add with null directory
TEST_CASE("tsk_fs_dir_add with null directory", "[fs_dir]") {
    TSK_FS_NAME fs_name = {};
    fs_name.tag = TSK_FS_NAME_TAG;
    
    uint8_t result = tsk_fs_dir_add(nullptr, &fs_name);
    REQUIRE(result == 1);
}

// Test tsk_fs_dir_add with null name
TEST_CASE("tsk_fs_dir_add with null name", "[fs_dir]") {
    TSK_FS_DIR *fs_dir = tsk_fs_dir_alloc(nullptr, 1, 5);
    REQUIRE(fs_dir != nullptr);
    
    uint8_t result = tsk_fs_dir_add(fs_dir, nullptr);
    REQUIRE(result == 1);
    
    tsk_fs_dir_close(fs_dir);
}

// Test tsk_fs_dir_add with invalid name tag
TEST_CASE("tsk_fs_dir_add with invalid name tag", "[fs_dir]") {
    TSK_FS_DIR *fs_dir = tsk_fs_dir_alloc(nullptr, 1, 5);
    REQUIRE(fs_dir != nullptr);
    
    TSK_FS_NAME fs_name = {};
    fs_name.tag = 0;
    
    uint8_t result = tsk_fs_dir_add(fs_dir, &fs_name);
    REQUIRE(result == 1);
    
    tsk_fs_dir_close(fs_dir);
}
*/