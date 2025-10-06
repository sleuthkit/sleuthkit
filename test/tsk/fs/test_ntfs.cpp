#include "catch.hpp"
#include "tsk/fs/tsk_fs_i.h"
#include "tsk/fs/tsk_ntfs.h"

// Test nt2unixtime with zero input
TEST_CASE("nt2unixtime_zero", "[ntfs]") {
    uint64_t ntdate = 0;
    uint32_t result = nt2unixtime(ntdate);
    REQUIRE(result == 0);
}

// Test nt2unixtime with maximum 32-bit value
TEST_CASE("nt2unixtime_max_32bit", "[ntfs]") {
    uint64_t ntdate = 0xffffffffULL;
    uint32_t result = nt2unixtime(ntdate);
    REQUIRE(result == 0); 
}

// Test nt2unixtime with value just above 32-bit range
TEST_CASE("nt2unixtime_above_32bit", "[ntfs]") {
    uint64_t ntdate = 0x100000000ULL;
    uint32_t result = nt2unixtime(ntdate);
    REQUIRE(result == 0); 
}

// Test nt2unixtime with maximum 64-bit value
TEST_CASE("nt2unixtime_max_64bit", "[ntfs]") {
    uint64_t ntdate = 0xffffffffffffffffULL;
    uint32_t result = nt2unixtime(ntdate);
    REQUIRE(result == 0); 
}

// Test nt2unixtime with value just below 32-bit range
TEST_CASE("nt2unixtime_below_32bit", "[ntfs]") {
    uint64_t ntdate = 0xffffffffULL - 1;
    uint32_t result = nt2unixtime(ntdate);
    REQUIRE(result == 0); 
}
/* Causing mem leak
// Test ntfs_dinode_lookup with null parameters
TEST_CASE("ntfs_dinode_lookup_null_params", "[ntfs]") {
    NTFS_INFO *ntfs = nullptr;
    char *buf = nullptr;
    TSK_INUM_T mftnum = 0;
    TSK_OFF_T mft_start_addr = 0;
    TSK_RETVAL_ENUM result = ntfs_dinode_lookup(ntfs, buf, mftnum, &mft_start_addr);
    REQUIRE(result == TSK_ERR);
}

// Test tsk_fs_block_walk with null parameters
TEST_CASE("ntfs_block_walk_null", "[ntfs]") {
    TSK_FS_INFO *fs = nullptr;
    TSK_DADDR_T start_blk = 0;
    TSK_DADDR_T end_blk = 0;
    TSK_FS_BLOCK_WALK_FLAG_ENUM flags = TSK_FS_BLOCK_WALK_FLAG_NONE;
    TSK_FS_BLOCK_WALK_CB action = nullptr;
    void *ptr = nullptr;
    uint8_t result = tsk_fs_block_walk(fs, start_blk, end_blk, flags, action, ptr);
    REQUIRE(result == TSK_ERR);
}
*/
// Test tsk_fs_close with null parameters
TEST_CASE("ntfs_close_null", "[ntfs]") {
    TSK_FS_INFO *fs = nullptr;
    tsk_fs_close(fs);
}

// Test tsk_fs_unix_get_default_attr_type with null parameters
TEST_CASE("ntfs_get_default_attr_type_null", "[ntfs]") {
    const TSK_FS_FILE *file = nullptr;
    TSK_FS_ATTR_TYPE_ENUM result = tsk_fs_unix_get_default_attr_type(file);
    REQUIRE(result == TSK_FS_ATTR_TYPE_DEFAULT);
}

// Test ntfs_attrname_lookup error branch only others failing
struct DummyAttrdef {
    uint32_t type;
    char label[128];
};

TEST_CASE("ntfs_attrname_lookup_attrdef_null_and_load_fails", "[ntfs]") {
    NTFS_INFO ntfs = {};
    ntfs.attrdef = nullptr;

    uint16_t type = 0x10;
    char name[128] = {0};
    int ret = ntfs_attrname_lookup((TSK_FS_INFO*)&ntfs, type, name, sizeof(name));
    REQUIRE(ret == 1);
}

// Test nt2unixtime with a valid timestamp from 2024
TEST_CASE("nt2unixtime_valid_2024", "[ntfs]") {
    uint64_t ntdate = 116444736000000000ULL + (54ULL * 36525ULL * 24ULL * 60ULL * 60ULL * 10000000ULL / 100ULL);
    uint32_t result = nt2unixtime(ntdate);
    REQUIRE(result > 0); 
}

// Test nt2unixtime with a valid timestamp from 2000
TEST_CASE("nt2unixtime_valid_2000", "[ntfs]") {
    uint64_t ntdate = 116444736000000000ULL + (30ULL * 36525ULL * 24ULL * 60ULL * 60ULL * 10000000ULL / 100ULL);
    uint32_t result = nt2unixtime(ntdate);
    REQUIRE(result > 0); 
}

// Test nt2unixtime with a valid timestamp from 1970
TEST_CASE("nt2unixtime_valid_1970", "[ntfs]") {
    uint64_t ntdate = 116444736000000000ULL + 10000000ULL;
    uint32_t result = nt2unixtime(ntdate);
    REQUIRE(result > 0); 
}
