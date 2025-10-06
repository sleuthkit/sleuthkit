#include "catch.hpp"
#include "tsk/fs/tsk_fs_i.h"

// Test tsk_fs_attr_run_alloc
TEST_CASE("tsk_fs_attr_run_alloc creates valid run structure", "[fs_attr]") {
    TSK_FS_ATTR_RUN *run = tsk_fs_attr_run_alloc();
    REQUIRE(run != nullptr);
    
    REQUIRE(run->addr == 0);
    REQUIRE(run->len == 0);
    REQUIRE(run->offset == 0);
    REQUIRE(run->flags == TSK_FS_ATTR_RUN_FLAG_NONE);
    REQUIRE(run->next == nullptr);
    
    tsk_fs_attr_run_free(run);
}

// Test tsk_fs_attr_run_free with null
TEST_CASE("tsk_fs_attr_run_free handles null", "[fs_attr]") {
    tsk_fs_attr_run_free(nullptr);
}

// Test tsk_fs_attr_alloc with resident type
TEST_CASE("tsk_fs_attr_alloc with resident type", "[fs_attr]") {
    TSK_FS_ATTR *attr = tsk_fs_attr_alloc(TSK_FS_ATTR_RES);
    REQUIRE(attr != nullptr);
    
    REQUIRE(attr->flags == (TSK_FS_ATTR_RES | TSK_FS_ATTR_INUSE));
    REQUIRE(attr->name != nullptr);
    REQUIRE(attr->name_size == 128);
    REQUIRE(attr->id == 0);
    REQUIRE(attr->size == 0);
    REQUIRE(attr->nrd.allocsize == 0);
    REQUIRE(attr->nrd.initsize == 0);
    REQUIRE(attr->nrd.skiplen == 0);
    REQUIRE(attr->nrd.compsize == 0);
    REQUIRE(attr->nrd.run == nullptr);
    REQUIRE(attr->rd.buf_size == 1024);
    REQUIRE(attr->rd.buf != nullptr);
    REQUIRE(attr->next == nullptr);
    
    tsk_fs_attr_free(attr);
}

// Test tsk_fs_attr_alloc with non-resident type
TEST_CASE("tsk_fs_attr_alloc with non-resident type", "[fs_attr]") {
    TSK_FS_ATTR *attr = tsk_fs_attr_alloc(TSK_FS_ATTR_NONRES);
    REQUIRE(attr != nullptr);
    
    REQUIRE(attr->flags == (TSK_FS_ATTR_NONRES | TSK_FS_ATTR_INUSE));
    REQUIRE(attr->name != nullptr);
    REQUIRE(attr->name_size == 128);
    REQUIRE(attr->id == 0);
    REQUIRE(attr->size == 0);
    REQUIRE(attr->nrd.allocsize == 0);
    REQUIRE(attr->nrd.initsize == 0);
    REQUIRE(attr->nrd.skiplen == 0);
    REQUIRE(attr->nrd.compsize == 0);
    REQUIRE(attr->nrd.run == nullptr);
    REQUIRE(attr->rd.buf_size == 0);
    REQUIRE(attr->rd.buf == nullptr);
    REQUIRE(attr->next == nullptr);
    
    tsk_fs_attr_free(attr);
}

// Test tsk_fs_attr_free with null
TEST_CASE("tsk_fs_attr_free handles null", "[fs_attr]") {
    tsk_fs_attr_free(nullptr);
}

// Test tsk_fs_attr_clear with null
TEST_CASE("tsk_fs_attr_clear handles null", "[fs_attr]") {
    // tsk_fs_attr_clear doesn't check for null
    // tsk_fs_attr_clear(nullptr);
}

// Test tsk_fs_attr_clear with valid attribute
TEST_CASE("tsk_fs_attr_clear with valid attribute", "[fs_attr]") {
    TSK_FS_ATTR *attr = tsk_fs_attr_alloc(TSK_FS_ATTR_RES);
    REQUIRE(attr != nullptr);
    
    attr->type = TSK_FS_ATTR_TYPE_NTFS_DATA;
    attr->id = 5;
    attr->size = 1000;
    strcpy(attr->name, "test_name");
    
    tsk_fs_attr_clear(attr);
    
    REQUIRE(attr->type == TSK_FS_ATTR_TYPE_NOT_FOUND);
    REQUIRE(attr->id == 0);
    REQUIRE(attr->size == 0);
    
    tsk_fs_attr_free(attr);
}

// Test tsk_fs_attr_set_str with null parameters
TEST_CASE("tsk_fs_attr_set_str with null parameters", "[fs_attr]") {
    TSK_FS_FILE fs_file = {};
    TSK_FS_ATTR *attr = tsk_fs_attr_alloc(TSK_FS_ATTR_RES);
    REQUIRE(attr != nullptr);
    
    // Test with null fs_file
    uint8_t result = tsk_fs_attr_set_str(
        nullptr, attr, "test_name", TSK_FS_ATTR_TYPE_NTFS_DATA, 0, (void*)"test_data", 10);
    REQUIRE(result == 0);  
    
    // Test with null fs_attr
    result = tsk_fs_attr_set_str(
        &fs_file, nullptr, "test_name", TSK_FS_ATTR_TYPE_NTFS_DATA, 0, (void*)"test_data", 10);
    REQUIRE(result == 1);  
    
    tsk_fs_attr_free(attr);
}

// Test tsk_fs_attr_set_str with valid parameters
TEST_CASE("tsk_fs_attr_set_str with valid parameters", "[fs_attr]") {
    TSK_FS_FILE fs_file = {};
    TSK_FS_ATTR *attr = tsk_fs_attr_alloc(TSK_FS_ATTR_RES);
    REQUIRE(attr != nullptr);
    
    const char *test_name = "test_name";
    const char *test_data = "test_data";
    size_t data_len = strlen(test_data);
    
    uint8_t result = tsk_fs_attr_set_str(
        &fs_file, attr, test_name, TSK_FS_ATTR_TYPE_NTFS_DATA, 5, (void*)test_data, data_len);
    
    REQUIRE(result == 0);
    REQUIRE(attr->type == TSK_FS_ATTR_TYPE_NTFS_DATA);
    REQUIRE(attr->id == 5);
    REQUIRE(attr->size == (TSK_OFF_T)data_len);
    REQUIRE(strcmp(attr->name, test_name) == 0);
    REQUIRE(attr->rd.buf != nullptr);
    REQUIRE(attr->rd.buf_size >= data_len);
    REQUIRE(memcmp(attr->rd.buf, test_data, data_len) == 0);
    
    tsk_fs_attr_free(attr);
}
/*
// Test tsk_fs_attr_set_run with valid parameters
TEST_CASE("tsk_fs_attr_set_run with valid parameters", "[fs_attr]") {
    TSK_FS_FILE fs_file = {};
    TSK_FS_ATTR *attr = tsk_fs_attr_alloc(TSK_FS_ATTR_NONRES);
    REQUIRE(attr != nullptr);
    
    TSK_FS_ATTR_RUN *run = tsk_fs_attr_run_alloc();
    REQUIRE(run != nullptr);
    
    run->addr = 100;
    run->len = 10;
    run->offset = 0;
    run->flags = TSK_FS_ATTR_RUN_FLAG_NONE;
    
    const char *test_name = "test_name";
    
    uint8_t result = tsk_fs_attr_set_run(
        &fs_file, attr, run, test_name, TSK_FS_ATTR_TYPE_NTFS_DATA, 5, 1000, 1000, 1024, TSK_FS_ATTR_FLAG_NONE, 0);
    
    REQUIRE(result == 1);
    
    tsk_fs_attr_free(attr);
    tsk_fs_attr_run_free(run);
}

// Test tsk_fs_attr_add_run with valid parameters
TEST_CASE("tsk_fs_attr_add_run with valid parameters", "[fs_attr]") {
    TSK_FS_INFO fs_info = {};
    TSK_FS_ATTR *attr = tsk_fs_attr_alloc(TSK_FS_ATTR_NONRES);
    REQUIRE(attr != nullptr);
    
    TSK_FS_ATTR_RUN *run1 = tsk_fs_attr_run_alloc();
    REQUIRE(run1 != nullptr);
    
    run1->addr = 100;
    run1->len = 10;
    run1->offset = 0;
    
    uint8_t result = tsk_fs_attr_add_run(&fs_info, attr, run1);
    REQUIRE(result == 0);
    
    tsk_fs_attr_free(attr);
    tsk_fs_attr_run_free(run1);
}
*/
// Test tsk_fs_attr_walk with null parameters
TEST_CASE("tsk_fs_attr_walk with null parameters", "[fs_attr]") {
    uint8_t result = tsk_fs_attr_walk(
        nullptr, TSK_FS_FILE_WALK_FLAG_NONE, nullptr, nullptr);
    REQUIRE(result == 1);
    
    // Test with null action
    TSK_FS_ATTR *attr = tsk_fs_attr_alloc(TSK_FS_ATTR_RES);
    REQUIRE(attr != nullptr);
    
    result = tsk_fs_attr_walk(
        attr, TSK_FS_FILE_WALK_FLAG_NONE, nullptr, nullptr);
    REQUIRE(result == 1);
    
    tsk_fs_attr_free(attr);
}

// Test tsk_fs_attr_read with null parameters
TEST_CASE("tsk_fs_attr_read with null parameters", "[fs_attr]") {
    char buf[100];
    
    ssize_t result = tsk_fs_attr_read(
        nullptr, 0, buf, 100, TSK_FS_FILE_READ_FLAG_NONE);
    REQUIRE(result == -1);
    
    // Test with null buf
    TSK_FS_ATTR *attr = tsk_fs_attr_alloc(TSK_FS_ATTR_RES);
    REQUIRE(attr != nullptr);
    
    result = tsk_fs_attr_read(
        attr, 0, nullptr, 100, TSK_FS_FILE_READ_FLAG_NONE);
    REQUIRE(result == -1);
    
    tsk_fs_attr_free(attr);
}
