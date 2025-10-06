#include "catch.hpp"
#include "tsk/fs/tsk_fs_i.h"
#include "tsk/fs/tsk_fs.h"
#include <cstring>
#include <string>
#include <memory>

//Only one non-static function in tsk/fs/fls_lib.cpp

class FlsTestFS {
public:
    FlsTestFS(const TSK_TCHAR* img_path) {
        img = tsk_img_open_sing(img_path, TSK_IMG_TYPE_DETECT, 0);
        if (!img) return;
        fs = tsk_fs_open_img(img, 0, TSK_FS_TYPE_DETECT);
    }
    ~FlsTestFS() {
        if (fs) tsk_fs_close(fs);
        if (img) tsk_img_close(img);
    }
    TSK_FS_INFO* get() { return fs; }
    bool valid() const { return img && fs; }
private:
    TSK_IMG_INFO* img = nullptr;
    TSK_FS_INFO* fs = nullptr;
};

// Test tsk_fs_fls with a null prefix (tpre is nullptr)
TEST_CASE("tsk_fs_fls_null_tpre", "[fls]") {
    FlsTestFS testfs(_TSK_T("test/data/image/image.dd"));
    if (!testfs.valid()) {
        WARN("Could not open test image. Skipping test.");
        return;
    }
    uint8_t result = tsk_fs_fls(testfs.get(), (TSK_FS_FLS_FLAG_ENUM)0, 2, TSK_FS_DIR_WALK_FLAG_ALLOC, nullptr, 0);
    REQUIRE(result == 0);
}

// Test tsk_fs_fls with an empty string as prefix
TEST_CASE("tsk_fs_fls_empty_tpre", "[fls]") {
    FlsTestFS testfs(_TSK_T("test/data/image/image.dd"));
    if (!testfs.valid()) {
        WARN("Could not open test image. Skipping test.");
        return;
    }
    const TSK_TCHAR *empty = _TSK_T("");
    uint8_t result = tsk_fs_fls(testfs.get(), (TSK_FS_FLS_FLAG_ENUM)0, 2, TSK_FS_DIR_WALK_FLAG_ALLOC, empty, 0);
    REQUIRE(result == 0);
}

// Test tsk_fs_fls with a non-empty prefix string
TEST_CASE("tsk_fs_fls_nonempty_tpre", "[fls]") {
    FlsTestFS testfs(_TSK_T("test/data/image/image.dd"));
    if (!testfs.valid()) {
        WARN("Could not open test image. Skipping test.");
        return;
    }
    const TSK_TCHAR *pre = _TSK_T("prefix");
    uint8_t result = tsk_fs_fls(testfs.get(), (TSK_FS_FLS_FLAG_ENUM)0, 2, TSK_FS_DIR_WALK_FLAG_ALLOC, pre, 0);
    REQUIRE(result == 0);
}

// Test tsk_fs_fls with disk image file and the root inode
TEST_CASE("tsk_fs_fls_integration_image_dd", "[fls][integration]") {
    const TSK_TCHAR *img_path = _TSK_T("test/data/image/image.dd");
    TSK_IMG_INFO *img = tsk_img_open_sing(img_path, TSK_IMG_TYPE_DETECT, 0);
    if (!img) {
        WARN("Could not open test image: " << img_path << ". Skipping test.");
        return; // image not available
    }
    TSK_FS_INFO *fs = tsk_fs_open_img(img, 0, TSK_FS_TYPE_DETECT);
    if (!fs) {
        tsk_img_close(img);
        WARN("Could not open filesystem in image: " << img_path << ". Skipping test.");
        return;
    }
    TSK_INUM_T root_inum = 2;
    uint8_t result = tsk_fs_fls(fs, (TSK_FS_FLS_FLAG_ENUM)0, root_inum, (TSK_FS_DIR_WALK_FLAG_ENUM)0, nullptr, 0);
    REQUIRE(result == 0);
    tsk_fs_close(fs);
    tsk_img_close(img);
} 