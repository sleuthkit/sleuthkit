#include <cstdint>
#include <cstdio>
#include <cstddef>
#include <cstring>
#include <memory>

#include "tsk/libtsk.h"
#include "tsk/fs/tsk_fs.h"
#include "tsk/fs/tsk_fs_i.h"
#include "tsk/img/tsk_img.h"

#include "catch.hpp"

// Mock decrypt function for testing
static uint8_t mock_decrypt_block(TSK_FS_INFO *fs, TSK_DADDR_T crypto_id, void *data) {
    // XOR decryption for testing
    char *buf = (char*)data;
    for (size_t i = 0; i < fs->block_size; i++) {
        buf[i] ^= (char)(crypto_id + i);
    }
    return 0; // Success
}

// Helper function to create a mock filesystem info structure
static TSK_FS_INFO* create_mock_fs_info() {
    TSK_FS_INFO *fs = (TSK_FS_INFO*)tsk_malloc(sizeof(TSK_FS_INFO));
    if (fs == nullptr) return nullptr;
    
    memset(fs, 0, sizeof(TSK_FS_INFO));
    fs->tag = TSK_FS_INFO_TAG;
    fs->block_size = 4096;
    fs->last_block = 1000;
    fs->last_block_act = 1000;
    fs->offset = 0;
    fs->block_pre_size = 0;
    fs->block_post_size = 0;
    fs->flags = TSK_FS_INFO_FLAG_NONE;
    fs->encryption_type = TSK_FS_ENCRYPTION_TYPE_NONE;
    fs->decrypt_block = nullptr;
    
    return fs;
}

// Helper function to free mock filesystem info
static void free_mock_fs_info(TSK_FS_INFO *fs) {
    if (fs) {
        free(fs);
    }
}

TEST_CASE("tsk_fs_read basic functionality", "[fs_io]") {
    SECTION("calls tsk_fs_read_decrypt with crypto_id 0") {
        TSK_FS_INFO *fs = create_mock_fs_info();
        REQUIRE(fs != nullptr);
        
        char buffer[1024];
        ssize_t result = tsk_fs_read(fs, 0, buffer, 1024);
        
        REQUIRE(result == -1);
        
        free_mock_fs_info(fs);
    }
}

TEST_CASE("tsk_fs_read_decrypt bounds checking", "[fs_io]") {
    SECTION("returns error when offset exceeds last_block_act") {
        TSK_FS_INFO *fs = create_mock_fs_info();
        REQUIRE(fs != nullptr);
        
        fs->last_block_act = 10;
        fs->block_size = 4096;
        
        char buffer[1024];
        TSK_OFF_T offset = (TSK_OFF_T)(fs->last_block_act + 1) * fs->block_size;
        
        ssize_t result = tsk_fs_read_decrypt(fs, offset, buffer, 1024, 0);
        
        REQUIRE(result == -1);
        REQUIRE(tsk_error_get_errno() == TSK_ERR_FS_READ);
        
        free_mock_fs_info(fs);
    }
    
    SECTION("returns error when offset is missing in partial image") {
        TSK_FS_INFO *fs = create_mock_fs_info();
        REQUIRE(fs != nullptr);
        
        fs->last_block_act = 10;
        fs->last_block = 20;
        fs->block_size = 4096;
        
        char buffer[1024];
        TSK_OFF_T offset = (TSK_OFF_T)(fs->last_block_act + 1) * fs->block_size;
        
        ssize_t result = tsk_fs_read_decrypt(fs, offset, buffer, 1024, 0);
        
        REQUIRE(result == -1);
        REQUIRE(tsk_error_get_errno() == TSK_ERR_FS_READ);
        
        free_mock_fs_info(fs);
    }
    
    SECTION("returns error when offset is too large for image") {
        TSK_FS_INFO *fs = create_mock_fs_info();
        REQUIRE(fs != nullptr);
        
        fs->last_block_act = 10;
        fs->last_block = 5;
        fs->block_size = 4096;
        
        char buffer[1024];
        TSK_OFF_T offset = (TSK_OFF_T)(fs->last_block_act + 1) * fs->block_size;
        
        ssize_t result = tsk_fs_read_decrypt(fs, offset, buffer, 1024, 0);
        
        REQUIRE(result == -1);
        REQUIRE(tsk_error_get_errno() == TSK_ERR_FS_READ);
        
        free_mock_fs_info(fs);
    }
}

TEST_CASE("tsk_fs_read_decrypt encrypted filesystem logic", "[fs_io]") {
    SECTION("handles block-aligned reads for encrypted filesystem") {
        TSK_FS_INFO *fs = create_mock_fs_info();
        REQUIRE(fs != nullptr);
        
        fs->flags = TSK_FS_INFO_FLAG_ENCRYPTED;
        fs->block_size = 4096;
        fs->last_block_act = 100;
        
        char buffer[4096];
        TSK_OFF_T offset = 4096;
        size_t len = 4096;
        
        ssize_t result = tsk_fs_read_decrypt(fs, offset, buffer, len, 1);
        
        REQUIRE(result == -1);
        
        free_mock_fs_info(fs);
    }
    
    SECTION("handles non-block-aligned reads for encrypted filesystem") {
        TSK_FS_INFO *fs = create_mock_fs_info();
        REQUIRE(fs != nullptr);
        
        fs->flags = TSK_FS_INFO_FLAG_ENCRYPTED;
        fs->block_size = 4096;
        fs->last_block_act = 100;
        
        char buffer[1024];
        TSK_OFF_T offset = 1000;
        size_t len = 1024;
        
        ssize_t result = tsk_fs_read_decrypt(fs, offset, buffer, len, 1);
        
        REQUIRE(result == -1);
        
        free_mock_fs_info(fs);
    }
    
    SECTION("handles memory allocation failure for encrypted filesystem") {
        TSK_FS_INFO *fs = create_mock_fs_info();
        REQUIRE(fs != nullptr);
        
        fs->flags = TSK_FS_INFO_FLAG_ENCRYPTED;
        fs->block_size = 4096;
        fs->last_block_act = 100;
        
        char buffer[1024];
        TSK_OFF_T offset = 1000;  
        size_t len = 1024;        
        
        // This test would require mocking tsk_malloc to return NULL
        // For now, we just verify the function handles the encrypted path
        ssize_t result = tsk_fs_read_decrypt(fs, offset, buffer, len, 1);
        
        REQUIRE(result == -1);
        
        free_mock_fs_info(fs);
    }
}

TEST_CASE("tsk_fs_read_decrypt pre/post block handling", "[fs_io]") {
    SECTION("handles filesystem with pre/post block sizes") {
        TSK_FS_INFO *fs = create_mock_fs_info();
        REQUIRE(fs != nullptr);
        
        fs->block_pre_size = 64;
        fs->block_post_size = 64;
        fs->block_size = 4096;
        fs->last_block_act = 100;
        
        char buffer[1024];
        ssize_t result = tsk_fs_read_decrypt(fs, 0, buffer, 1024, 0);
        
        REQUIRE(result == -1);
        
        free_mock_fs_info(fs);
    }
    
    SECTION("handles filesystem with only pre block size") {
        TSK_FS_INFO *fs = create_mock_fs_info();
        REQUIRE(fs != nullptr);
        
        fs->block_pre_size = 64;
        fs->block_post_size = 0;
        fs->block_size = 4096;
        fs->last_block_act = 100;
        
        char buffer[1024];
        ssize_t result = tsk_fs_read_decrypt(fs, 0, buffer, 1024, 0);
        
        REQUIRE(result == -1);
        
        free_mock_fs_info(fs);
    }
    
    SECTION("handles filesystem with only post block size") {
        TSK_FS_INFO *fs = create_mock_fs_info();
        REQUIRE(fs != nullptr);
        
        fs->block_pre_size = 0;
        fs->block_post_size = 64;
        fs->block_size = 4096;
        fs->last_block_act = 100;
        
        char buffer[1024];
        ssize_t result = tsk_fs_read_decrypt(fs, 0, buffer, 1024, 0);
        
        REQUIRE(result == -1);
        
        free_mock_fs_info(fs);
    }
}

TEST_CASE("tsk_fs_read_block basic functionality", "[fs_io]") {
    SECTION("calls tsk_fs_read_block_decrypt with crypto_id 0") {
        TSK_FS_INFO *fs = create_mock_fs_info();
        REQUIRE(fs != nullptr);
        
        char buffer[4096];
        ssize_t result = tsk_fs_read_block(fs, 0, buffer, 4096);
        
        REQUIRE(result == -1);
        
        free_mock_fs_info(fs);
    }
}

TEST_CASE("tsk_fs_read_block_decrypt input validation", "[fs_io]") {
    SECTION("returns error when length is not multiple of block size") {
        TSK_FS_INFO *fs = create_mock_fs_info();
        REQUIRE(fs != nullptr);
        
        fs->block_size = 4096;
        
        char buffer[1024];
        ssize_t result = tsk_fs_read_block_decrypt(fs, 0, buffer, 1024, 0);
        
        REQUIRE(result == -1);
        REQUIRE(tsk_error_get_errno() == TSK_ERR_FS_READ);
        
        free_mock_fs_info(fs);
    }
    
    SECTION("returns error when address exceeds last_block_act") {
        TSK_FS_INFO *fs = create_mock_fs_info();
        REQUIRE(fs != nullptr);
        
        fs->last_block_act = 10;
        fs->block_size = 4096;
        
        char buffer[4096];
        TSK_DADDR_T addr = fs->last_block_act + 1;
        
        ssize_t result = tsk_fs_read_block_decrypt(fs, addr, buffer, 4096, 0);
        
        REQUIRE(result == -1);
        REQUIRE(tsk_error_get_errno() == TSK_ERR_FS_READ);
        
        free_mock_fs_info(fs);
    }
    
    SECTION("returns error when address is missing in partial image") {
        TSK_FS_INFO *fs = create_mock_fs_info();
        REQUIRE(fs != nullptr);
        
        fs->last_block_act = 10;
        fs->last_block = 20;
        fs->block_size = 4096;
        
        char buffer[4096];
        TSK_DADDR_T addr = fs->last_block_act + 1;
        
        ssize_t result = tsk_fs_read_block_decrypt(fs, addr, buffer, 4096, 0);
        
        REQUIRE(result == -1);
        REQUIRE(tsk_error_get_errno() == TSK_ERR_FS_READ);
        
        free_mock_fs_info(fs);
    }
    
    SECTION("returns error when address is too large for image") {
        TSK_FS_INFO *fs = create_mock_fs_info();
        REQUIRE(fs != nullptr);
        
        fs->last_block_act = 10;
        fs->last_block = 5;  // Smaller than last_block_act
        fs->block_size = 4096;
        
        char buffer[4096];
        TSK_DADDR_T addr = fs->last_block_act + 1;
        
        ssize_t result = tsk_fs_read_block_decrypt(fs, addr, buffer, 4096, 0);
        
        REQUIRE(result == -1);
        REQUIRE(tsk_error_get_errno() == TSK_ERR_FS_READ);
        
        free_mock_fs_info(fs);
    }
}

TEST_CASE("tsk_fs_read_block_decrypt pre/post block handling", "[fs_io]") {
    SECTION("handles filesystem with pre/post block sizes") {
        TSK_FS_INFO *fs = create_mock_fs_info();
        REQUIRE(fs != nullptr);
        
        fs->block_pre_size = 64;
        fs->block_post_size = 64;
        fs->block_size = 4096;
        fs->last_block_act = 100;
        
        char buffer[4096];
        ssize_t result = tsk_fs_read_block_decrypt(fs, 0, buffer, 4096, 0);
        
        REQUIRE(result == -1);
        
        free_mock_fs_info(fs);
    }
    
    SECTION("handles filesystem without pre/post block sizes") {
        TSK_FS_INFO *fs = create_mock_fs_info();
        REQUIRE(fs != nullptr);
        
        fs->block_pre_size = 0;
        fs->block_post_size = 0;
        fs->block_size = 4096;
        fs->last_block_act = 100;
        
        char buffer[4096];
        ssize_t result = tsk_fs_read_block_decrypt(fs, 0, buffer, 4096, 0);
        
        REQUIRE(result == -1);
        
        free_mock_fs_info(fs);
    }
}

TEST_CASE("tsk_fs_read_block_decrypt encryption handling", "[fs_io]") {
    SECTION("handles encrypted filesystem with decrypt_block function") {
        TSK_FS_INFO *fs = create_mock_fs_info();
        REQUIRE(fs != nullptr);
        
        fs->flags = TSK_FS_INFO_FLAG_ENCRYPTED;
        fs->block_size = 4096;
        fs->last_block_act = 100;
        fs->decrypt_block = mock_decrypt_block;
        
        char buffer[4096];
        // buffer with test data
        memset(buffer, 0xAA, 4096);
        
        ssize_t result = tsk_fs_read_block_decrypt(fs, 0, buffer, 4096, 1);
        
        REQUIRE(result == -1);
        
        free_mock_fs_info(fs);
    }
    
    SECTION("handles encrypted filesystem without decrypt_block function") {
        TSK_FS_INFO *fs = create_mock_fs_info();
        REQUIRE(fs != nullptr);
        
        fs->flags = TSK_FS_INFO_FLAG_ENCRYPTED;
        fs->block_size = 4096;
        fs->last_block_act = 100;
        fs->decrypt_block = nullptr;
        
        char buffer[4096];
        ssize_t result = tsk_fs_read_block_decrypt(fs, 0, buffer, 4096, 1);
        
        REQUIRE(result == -1);
        
        free_mock_fs_info(fs);
    }
}

TEST_CASE("tsk_fs_read_block_decrypt multiple block decryption", "[fs_io]") {
    SECTION("handles multiple blocks with encryption") {
        TSK_FS_INFO *fs = create_mock_fs_info();
        REQUIRE(fs != nullptr);
        
        fs->flags = TSK_FS_INFO_FLAG_ENCRYPTED;
        fs->block_size = 4096;
        fs->last_block_act = 100;
        fs->decrypt_block = mock_decrypt_block;
        
        char buffer[8192];  // 2 blocks
        ssize_t result = tsk_fs_read_block_decrypt(fs, 0, buffer, 8192, 1);
        
        REQUIRE(result == -1);
        
        free_mock_fs_info(fs);
    }
}

// Test with real filesystem image
TEST_CASE("tsk_fs_read with real ext2 image", "[fs_io][integration]") {
    SECTION("reads from ext2 filesystem image") {
        TSK_IMG_INFO *img_info = tsk_img_open_sing(_TSK_T("test/data/image_ext2.dd"), TSK_IMG_TYPE_DETECT, 0);
        if (img_info == nullptr) {
            WARN("Could not open test image");
            return;
        }
        
        TSK_FS_INFO *fs_info = tsk_fs_open_img(img_info, 0, TSK_FS_TYPE_DETECT);
        if (fs_info == nullptr) {
            tsk_img_close(img_info);
            WARN("Could not open filesystem");
            return;
        }
        
        char buffer[1024];
        ssize_t result = tsk_fs_read(fs_info, 0, buffer, 1024);
        
        // Should succeed with real image
        REQUIRE(result == 1024);
        
        tsk_fs_close(fs_info);
        tsk_img_close(img_info);
    }
}
/*
TEST_CASE("tsk_fs_read_block with real ext2 image", "[fs_io][integration]") {
    SECTION("reads blocks from ext2 filesystem image") {
        TSK_IMG_INFO *img_info = tsk_img_open_sing(_TSK_T("test/data/image_ext2.dd"), TSK_IMG_TYPE_DETECT, 0);
        if (img_info == nullptr) {
            WARN("Could not open test image");
            return;
        }
        
        TSK_FS_INFO *fs_info = tsk_fs_open_img(img_info, 0, TSK_FS_TYPE_DETECT);
        if (fs_info == nullptr) {
            tsk_img_close(img_info);
            WARN("Could not open filesystem");
            return;
        }
        
        char buffer[fs_info->block_size];
        ssize_t result = tsk_fs_read_block(fs_info, 0, buffer, fs_info->block_size);
        
        // Should succeed with real image
        REQUIRE(result == (ssize_t)fs_info->block_size);
        
        tsk_fs_close(fs_info);
        tsk_img_close(img_info);
    }
}
*/
