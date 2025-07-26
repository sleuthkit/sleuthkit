#include <cstdint>
#include <cstdio>
#include <cstddef>
#include <cstring>

#include "tsk/libtsk.h"
#include "tsk/fs/tsk_fs.h"
#include "tsk/fs/tsk_fs_i.h"

#include "catch.hpp"

// Test for tsk_fs_type_toid function
TEST_CASE("tsk_fs_type_toid converts TSK_TCHAR strings to filesystem type IDs", "[fs_types]") {
    SECTION("recognizes common filesystem types") {
        TSK_TCHAR ntfs_str[] =  _TSK_T("ntfs");
        REQUIRE(tsk_fs_type_toid(ntfs_str) == TSK_FS_TYPE_NTFS);
        
        TSK_TCHAR fat12_str[] = _TSK_T("fat12");
        REQUIRE(tsk_fs_type_toid(fat12_str) == TSK_FS_TYPE_FAT12);
        
        TSK_TCHAR ext2_str[] = _TSK_T("ext2");
        REQUIRE(tsk_fs_type_toid(ext2_str) == TSK_FS_TYPE_EXT2);
        
        TSK_TCHAR exfat_str[] = _TSK_T("exfat");
        REQUIRE(tsk_fs_type_toid(exfat_str) == TSK_FS_TYPE_EXFAT);
    }
    
    SECTION("handles invalid filesystem types") {
        TSK_TCHAR unknown_str[] = _TSK_T("unknown");
        REQUIRE(tsk_fs_type_toid(unknown_str) == TSK_FS_TYPE_UNSUPP);
        
        TSK_TCHAR empty_str[] = _TSK_T("");
        REQUIRE(tsk_fs_type_toid(empty_str) == TSK_FS_TYPE_UNSUPP);
    }
    
    SECTION("truncates strings longer than 15 characters") {
        TSK_TCHAR fs_name_exceeds_limit[] = _TSK_T("ntfs_verylongname");
        REQUIRE(tsk_fs_type_toid(fs_name_exceeds_limit) == TSK_FS_TYPE_UNSUPP);
    }
}

// Test for tsk_fs_type_supported function
TEST_CASE("tsk_fs_type_supported returns bitwise OR of all supported types", "[fs_types]") {
    TSK_FS_TYPE_ENUM supported_types = tsk_fs_type_supported();
    
    REQUIRE(supported_types != 0);
    
    SECTION("includes common filesystem types") {
        REQUIRE((supported_types & TSK_FS_TYPE_NTFS) != 0);
        REQUIRE((supported_types & TSK_FS_TYPE_FAT12) != 0);
        REQUIRE((supported_types & TSK_FS_TYPE_FAT16) != 0);
        REQUIRE((supported_types & TSK_FS_TYPE_FAT32) != 0);
        REQUIRE((supported_types & TSK_FS_TYPE_EXFAT) != 0);
        REQUIRE((supported_types & TSK_FS_TYPE_EXT2) != 0);
        REQUIRE((supported_types & TSK_FS_TYPE_EXT3) != 0);
        REQUIRE((supported_types & TSK_FS_TYPE_EXT4) != 0);
        REQUIRE((supported_types & TSK_FS_TYPE_ISO9660) != 0);
        REQUIRE((supported_types & TSK_FS_TYPE_SWAP) != 0);
        REQUIRE((supported_types & TSK_FS_TYPE_RAW) != 0);
    }
    
    SECTION("excludes special types") {
        REQUIRE((supported_types & TSK_FS_TYPE_DETECT) == 0);
    }
    
    SECTION("contains all expected types when combined") {
        TSK_FS_TYPE_ENUM expected_types = static_cast<TSK_FS_TYPE_ENUM>(
            TSK_FS_TYPE_NTFS |
            TSK_FS_TYPE_FAT12 |
            TSK_FS_TYPE_FAT16 |
            TSK_FS_TYPE_FAT32 |
            TSK_FS_TYPE_EXFAT |
            TSK_FS_TYPE_EXT2 |
            TSK_FS_TYPE_EXT3 |
            TSK_FS_TYPE_EXT4 |
            TSK_FS_TYPE_ISO9660 |
            TSK_FS_TYPE_SWAP |
            TSK_FS_TYPE_RAW
        );
        REQUIRE((supported_types & expected_types) == expected_types);
    }
}

// Test for tsk_fs_type_toid_utf8 function
TEST_CASE("tsk_fs_type_toid_utf8 handles edge cases correctly", "[fs_types]") {
    SECTION("is case sensitive") {
        REQUIRE(tsk_fs_type_toid_utf8("NTFS") == TSK_FS_TYPE_UNSUPP);
        REQUIRE(tsk_fs_type_toid_utf8("Ntfs") == TSK_FS_TYPE_UNSUPP);
        REQUIRE(tsk_fs_type_toid_utf8("ntfs") == TSK_FS_TYPE_NTFS);
    }
    
    SECTION("recognizes legacy type names") {
        REQUIRE(tsk_fs_type_toid_utf8("linux-ext") == TSK_FS_TYPE_EXT_DETECT);
        REQUIRE(tsk_fs_type_toid_utf8("linux-ext2") == TSK_FS_TYPE_EXT2);
        REQUIRE(tsk_fs_type_toid_utf8("bsdi") == TSK_FS_TYPE_FFS1);
        REQUIRE(tsk_fs_type_toid_utf8("freebsd") == TSK_FS_TYPE_FFS1);
        REQUIRE(tsk_fs_type_toid_utf8("solaris") == TSK_FS_TYPE_FFS1B);
    }
    
    SECTION("handles null and empty strings") {
        REQUIRE(tsk_fs_type_toid_utf8("") == TSK_FS_TYPE_UNSUPP);
    }
}

// Test for tsk_fs_type_toname function 
TEST_CASE("tsk_fs_type_toname converts filesystem type IDs to names", "[fs_types]") {
    SECTION("returns correct names for valid type codes") {
        REQUIRE(strcmp(tsk_fs_type_toname(TSK_FS_TYPE_NTFS), "ntfs") == 0);
        REQUIRE(strcmp(tsk_fs_type_toname(TSK_FS_TYPE_FAT12), "fat12") == 0);
        REQUIRE(strcmp(tsk_fs_type_toname(TSK_FS_TYPE_EXT2), "ext2") == 0);
        REQUIRE(strcmp(tsk_fs_type_toname(TSK_FS_TYPE_EXFAT), "exfat") == 0);
    }
    
    SECTION("returns null for invalid type codes") {
        REQUIRE(tsk_fs_type_toname(TSK_FS_TYPE_UNSUPP) == nullptr);
        REQUIRE(tsk_fs_type_toname(TSK_FS_TYPE_DETECT) == nullptr);
        REQUIRE(tsk_fs_type_toname((TSK_FS_TYPE_ENUM)0xFFFFFFFF) == nullptr);
    }
} 
