#include "catch.hpp"
#include "tsk/fs/tsk_fs_i.h"
#include "tsk/fs/tsk_ffs.h"
#include <string>
#include <memory>
#include <cstdio>

// Helper to open FFS image and return TSK_FS_INFO*
class FfsTestFS {
public:
    FfsTestFS(const TSK_TCHAR* img_path) {
        if (!img_path) {
            return;
        }
        img = tsk_img_open_sing(img_path, TSK_IMG_TYPE_DETECT, 0);
        if (!img) {
            return;
        }
        fs = tsk_fs_open_img(img, 0, TSK_FS_TYPE_DETECT);
    }
    ~FfsTestFS() {
        if (fs) tsk_fs_close(fs);
        if (img) tsk_img_close(img);
    }
    TSK_FS_INFO* get() { return fs; }
    bool valid() const { return img != nullptr && fs != nullptr; }
private:
    TSK_IMG_INFO* img = nullptr;
    TSK_FS_INFO* fs = nullptr;
};
 
// Test get block flags for the first block
TEST_CASE("ffs_block_getflags_basic", "[ffs]") {
    FfsTestFS testfs(_TSK_T("test/data/image/image.dd"));
    if (!testfs.valid()) {
        WARN("Could not open FFS image. Skipping test.");
        return;
    }
    TSK_FS_INFO* fs = testfs.get();
    
    REQUIRE(fs != nullptr);
    REQUIRE(fs->last_block >= fs->first_block); 
    
    TSK_FS_BLOCK_FLAG_ENUM flags = ffs_block_getflags(fs, fs->first_block);
    REQUIRE((flags & (TSK_FS_BLOCK_FLAG_ALLOC | TSK_FS_BLOCK_FLAG_UNALLOC)) != 0);
}

// Test journal entry walk returns appropriate error for UFS fs
TEST_CASE("ffs_jentry_walk_unsupported", "[ffs]") {
    FfsTestFS testfs(_TSK_T("test/data/image/image.dd"));
    if (!testfs.valid()) {
        WARN("Could not open FFS image. Skipping test.");
        return;
    }
    TSK_FS_INFO* fs = testfs.get();
    
    uint8_t result = ffs_jentry_walk(fs, 0, nullptr, nullptr);
    REQUIRE(result == 1);
    REQUIRE(tsk_error_get_errno() == TSK_ERR_FS_UNSUPFUNC);
    REQUIRE(strcmp(tsk_error_get_errstr(), "UFS does not have a journal") == 0);
}

// Test jblk walk for UFS fs
TEST_CASE("ffs_jblk_walk_unsupported", "[ffs]") {
    FfsTestFS testfs(_TSK_T("test/data/image/image.iso"));
    if (!testfs.valid()) {
        WARN("Could not open FFS image. Skipping test.");
        return;
    }
    TSK_FS_INFO* fs = testfs.get();
    
    uint8_t result = ffs_jblk_walk(fs, 0, 1, 0, nullptr, nullptr);
    REQUIRE(result == 1); 
    REQUIRE(tsk_error_get_errno() == TSK_ERR_FS_UNSUPFUNC);
    REQUIRE(strcmp(tsk_error_get_errstr(), "UFS does not have a journal") == 0);
}

// Test that journal open for UFS 
TEST_CASE("ffs_jopen_unsupported", "[ffs]") {
    FfsTestFS testfs(_TSK_T("test/data/image/image.iso"));
    if (!testfs.valid()) {
        WARN("Could not open FFS image. Skipping test.");
        return;
    }
    TSK_FS_INFO* fs = testfs.get();
    
    uint8_t result = ffs_jopen(fs, 0);
    REQUIRE(result == 1);
    REQUIRE(tsk_error_get_errno() == TSK_ERR_FS_UNSUPFUNC);
    REQUIRE(strcmp(tsk_error_get_errstr(), "UFS does not have a journal") == 0);
} 