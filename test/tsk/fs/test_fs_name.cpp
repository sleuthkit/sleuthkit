#include <cstdint>
#include <cstdio>
#include <cstddef>
#include <cstring>
#include <ctime>

#include "tsk/libtsk.h"
#include "tsk/fs/tsk_fs.h"
#include "tsk/fs/tsk_fs_i.h"

#include "catch.hpp"

// Test for tsk_fs_name_alloc function
TEST_CASE("tsk_fs_name_alloc allocates and initializes TSK_FS_NAME structure", "[fs_name]") {
    SECTION("allocates structure with normal name lengths") {
        TSK_FS_NAME *fs_name = tsk_fs_name_alloc(64, 32);
        REQUIRE(fs_name != nullptr);
        REQUIRE(fs_name->tag == TSK_FS_NAME_TAG);
        REQUIRE(fs_name->name != nullptr);
        REQUIRE(fs_name->name_size == 64);
        REQUIRE(fs_name->shrt_name != nullptr);
        REQUIRE(fs_name->shrt_name_size == 32);
        REQUIRE(fs_name->type == TSK_FS_NAME_TYPE_UNDEF);
        REQUIRE(fs_name->flags == (TSK_FS_NAME_FLAG_ENUM)0);
        REQUIRE(fs_name->meta_addr == 0);
        REQUIRE(fs_name->meta_seq == 0);
        REQUIRE(fs_name->par_addr == 0);
        REQUIRE(fs_name->par_seq == 0);
        
        tsk_fs_name_free(fs_name);
    }
    
    SECTION("allocates structure with zero short name length") {
        TSK_FS_NAME *fs_name = tsk_fs_name_alloc(128, 0);
        REQUIRE(fs_name != nullptr);
        REQUIRE(fs_name->tag == TSK_FS_NAME_TAG);
        REQUIRE(fs_name->name != nullptr);
        REQUIRE(fs_name->name_size == 128);
        REQUIRE(fs_name->shrt_name == nullptr);
        REQUIRE(fs_name->shrt_name_size == 0);
        
        tsk_fs_name_free(fs_name);
    }
    
    SECTION("handles memory allocation failure") {
        TSK_FS_NAME *fs_name = tsk_fs_name_alloc(SIZE_MAX, SIZE_MAX);
        if (fs_name != nullptr) {
            tsk_fs_name_free(fs_name);
        }
    }
}

// Test for tsk_fs_name_free function
TEST_CASE("tsk_fs_name_free deallocates TSK_FS_NAME structure", "[fs_name]") {
    SECTION("frees valid structure") {
        TSK_FS_NAME *fs_name = tsk_fs_name_alloc(64, 32);
        REQUIRE(fs_name != nullptr);
        
        strcpy(fs_name->name, "test_name");
        strcpy(fs_name->shrt_name, "test");
        fs_name->meta_addr = 12345;
        fs_name->type = TSK_FS_NAME_TYPE_REG;
        
        tsk_fs_name_free(fs_name);
    }
    
    SECTION("handles null pointer") {
        tsk_fs_name_free(nullptr);
    }
    /*
    SECTION("handles structure with invalid tag") {
        TSK_FS_NAME *fs_name = tsk_fs_name_alloc(64, 32);
        REQUIRE(fs_name != nullptr);
        
        // Corrupt the tag
        fs_name->tag = 0;
        
        tsk_fs_name_free(fs_name);
    }
    */
}

// Test for tsk_fs_name_realloc function
TEST_CASE("tsk_fs_name_realloc resizes name buffer", "[fs_name]") {
    SECTION("expands name buffer when needed") {
        TSK_FS_NAME *fs_name = tsk_fs_name_alloc(32, 16);
        REQUIRE(fs_name != nullptr);
        
        // Initial name
        strcpy(fs_name->name, "short");
        REQUIRE(fs_name->name_size == 32);
        
        // Reallocate to larger size
        uint8_t result = tsk_fs_name_realloc(fs_name, 64);
        REQUIRE(result == 0);
        REQUIRE(fs_name->name_size == 64);
        REQUIRE(strcmp(fs_name->name, "short") == 0);
        
        tsk_fs_name_free(fs_name);
    }
    
    SECTION("does nothing when new size is smaller or equal") {
        TSK_FS_NAME *fs_name = tsk_fs_name_alloc(64, 32);
        REQUIRE(fs_name != nullptr);
        
        size_t original_size = fs_name->name_size;
        strcpy(fs_name->name, "test_name");
        
        uint8_t result = tsk_fs_name_realloc(fs_name, 32);
        REQUIRE(result == 0);
        REQUIRE(fs_name->name_size == original_size);
        REQUIRE(strcmp(fs_name->name, "test_name") == 0);
        
        tsk_fs_name_free(fs_name);
    }
    
    SECTION("handles null pointer") {
        uint8_t result = tsk_fs_name_realloc(nullptr, 64);
        REQUIRE(result == 1);
    }
    /*
    SECTION("handles structure with invalid tag") {
        TSK_FS_NAME *fs_name = tsk_fs_name_alloc(32, 16);
        REQUIRE(fs_name != nullptr);
        
        fs_name->tag = 0; // Corrupt tag
        
        uint8_t result = tsk_fs_name_realloc(fs_name, 64);
        REQUIRE(result == 1);
        
        tsk_fs_name_free(fs_name);
    }
    */
}

// Test for tsk_fs_name_reset function
TEST_CASE("tsk_fs_name_reset clears structure fields", "[fs_name]") {
    SECTION("resets all fields to default values") {
        TSK_FS_NAME *fs_name = tsk_fs_name_alloc(64, 32);
        REQUIRE(fs_name != nullptr);
        
        strcpy(fs_name->name, "test_name");
        strcpy(fs_name->shrt_name, "test");
        fs_name->meta_addr = 12345;
        fs_name->meta_seq = 67890;
        fs_name->par_addr = 11111;
        fs_name->par_seq = 22222;
        fs_name->type = TSK_FS_NAME_TYPE_REG;
        fs_name->flags = TSK_FS_NAME_FLAG_ALLOC;
        fs_name->date_added = 999999;
        
        tsk_fs_name_reset(fs_name);
        
        REQUIRE(fs_name->name[0] == '\0');
        REQUIRE(fs_name->shrt_name[0] == '\0');
        REQUIRE(fs_name->meta_addr == 0);
        REQUIRE(fs_name->meta_seq == 0);
        REQUIRE(fs_name->par_addr == 0);
        REQUIRE(fs_name->par_seq == 0);
        REQUIRE(fs_name->type == TSK_FS_NAME_TYPE_UNDEF);
        REQUIRE(fs_name->flags == (TSK_FS_NAME_FLAG_ENUM)0);
        
        tsk_fs_name_free(fs_name);
    }
    
    SECTION("handles null pointers in name fields") {
        TSK_FS_NAME *fs_name = tsk_fs_name_alloc(64, 0);
        REQUIRE(fs_name != nullptr);
        
        free(fs_name->shrt_name);
        fs_name->shrt_name = nullptr;
        fs_name->shrt_name_size = 0;
        
        tsk_fs_name_reset(fs_name);
        
        tsk_fs_name_free(fs_name);
    }
}

// Test for tsk_fs_name_copy function
TEST_CASE("tsk_fs_name_copy copies structure contents", "[fs_name]") {
    SECTION("copies all fields correctly") {
        TSK_FS_NAME *src = tsk_fs_name_alloc(64, 32);
        TSK_FS_NAME *dst = tsk_fs_name_alloc(32, 16);
        REQUIRE(src != nullptr);
        REQUIRE(dst != nullptr);
        
        strcpy(src->name, "source_name");
        strcpy(src->shrt_name, "src");
        src->meta_addr = 12345;
        src->meta_seq = 67890;
        src->par_addr = 11111;
        src->par_seq = 22222;
        src->type = TSK_FS_NAME_TYPE_DIR;
        src->flags = TSK_FS_NAME_FLAG_ALLOC;
        src->date_added = 999999;
        
        uint8_t result = tsk_fs_name_copy(dst, src);
        REQUIRE(result == 0);
        
        REQUIRE(strcmp(dst->name, "source_name") == 0);
        REQUIRE(strcmp(dst->shrt_name, "src") == 0);
        REQUIRE(dst->meta_addr == 12345);
        REQUIRE(dst->meta_seq == 67890);
        REQUIRE(dst->par_addr == 11111);
        REQUIRE(dst->par_seq == 22222);
        REQUIRE(dst->type == TSK_FS_NAME_TYPE_DIR);
        REQUIRE(dst->flags == TSK_FS_NAME_FLAG_ALLOC);
        REQUIRE(dst->date_added == 999999);
        
        tsk_fs_name_free(src);
        tsk_fs_name_free(dst);
    }
    
    SECTION("handles null source name") {
        TSK_FS_NAME *src = tsk_fs_name_alloc(64, 32);
        TSK_FS_NAME *dst = tsk_fs_name_alloc(32, 16);
        REQUIRE(src != nullptr);
        REQUIRE(dst != nullptr);
        
        free(src->name);
        src->name = nullptr;
        src->name_size = 0;
        
        strcpy(dst->name, "original");
        
        uint8_t result = tsk_fs_name_copy(dst, src);
        REQUIRE(result == 0);
        REQUIRE(dst->name[0] == '\0');
        
        tsk_fs_name_free(src);
        tsk_fs_name_free(dst);
    }
    
    SECTION("handles null short name") {
        TSK_FS_NAME *src = tsk_fs_name_alloc(64, 0);
        TSK_FS_NAME *dst = tsk_fs_name_alloc(32, 16);
        REQUIRE(src != nullptr);
        REQUIRE(dst != nullptr);
        
        strcpy(src->name, "test");
        strcpy(dst->shrt_name, "original");
        
        uint8_t result = tsk_fs_name_copy(dst, src);
        REQUIRE(result == 0);
        REQUIRE(dst->shrt_name[0] == '\0');
        
        tsk_fs_name_free(src);
        tsk_fs_name_free(dst);
    }
    
    SECTION("expands destination buffer when needed") {
        TSK_FS_NAME *src = tsk_fs_name_alloc(64, 32);
        TSK_FS_NAME *dst = tsk_fs_name_alloc(8, 8);
        REQUIRE(src != nullptr);
        REQUIRE(dst != nullptr);
        
        strcpy(src->name, "very_long_name_that_exceeds_destination");
        strcpy(src->shrt_name, "long_short");
        
        uint8_t result = tsk_fs_name_copy(dst, src);
        REQUIRE(result == 0);
        REQUIRE(strcmp(dst->name, "very_long_name_that_exceeds_destination") == 0);
        REQUIRE(strcmp(dst->shrt_name, "long_short") == 0);
        REQUIRE(dst->name_size >= strlen("very_long_name_that_exceeds_destination"));
        REQUIRE(dst->shrt_name_size >= strlen("long_short"));
        
        tsk_fs_name_free(src);
        tsk_fs_name_free(dst);
    }
    
    SECTION("handles null pointers") {
        TSK_FS_NAME *fs_name = tsk_fs_name_alloc(32, 16);
        REQUIRE(fs_name != nullptr);
        
        uint8_t result = tsk_fs_name_copy(nullptr, fs_name);
        REQUIRE(result == 1);
        
        result = tsk_fs_name_copy(fs_name, nullptr);
        REQUIRE(result == 1);
        
        tsk_fs_name_free(fs_name);
    }
}

// Test for tsk_fs_meta_make_ls function
TEST_CASE("tsk_fs_meta_make_ls creates ls-style permissions string", "[fs_name]") {
    SECTION("creates correct permissions for regular file") {
        TSK_FS_META meta;
        memset(&meta, 0, sizeof(meta));
        meta.type = TSK_FS_META_TYPE_REG;
        meta.mode = (TSK_FS_META_MODE_ENUM)(TSK_FS_META_MODE_IRUSR | TSK_FS_META_MODE_IWUSR | TSK_FS_META_MODE_IXUSR |
                   TSK_FS_META_MODE_IRGRP | TSK_FS_META_MODE_IXGRP |
                   TSK_FS_META_MODE_IROTH);
        
        char buf[16];
        uint8_t result = tsk_fs_meta_make_ls(&meta, buf, sizeof(buf));
        REQUIRE(result == 0);
        REQUIRE(strcmp(buf, "rrwxr-xr--") == 0);
    }
    
    SECTION("creates correct permissions for directory") {
        TSK_FS_META meta;
        memset(&meta, 0, sizeof(meta));
        meta.type = TSK_FS_META_TYPE_DIR;
        meta.mode = (TSK_FS_META_MODE_ENUM)(TSK_FS_META_MODE_IRUSR | TSK_FS_META_MODE_IWUSR | TSK_FS_META_MODE_IXUSR |
                   TSK_FS_META_MODE_IRGRP | TSK_FS_META_MODE_IWGRP | TSK_FS_META_MODE_IXGRP |
                   TSK_FS_META_MODE_IROTH | TSK_FS_META_MODE_IXOTH);
        
        char buf[16];
        uint8_t result = tsk_fs_meta_make_ls(&meta, buf, sizeof(buf));
        REQUIRE(result == 0);
        REQUIRE(strcmp(buf, "drwxrwxr-x") == 0);
    }
    
    SECTION("handles different file types") {
        TSK_FS_META meta;
        memset(&meta, 0, sizeof(meta));
        meta.mode = (TSK_FS_META_MODE_ENUM)(TSK_FS_META_MODE_IRUSR | TSK_FS_META_MODE_IWUSR);
        
        char buf[16];
        
        meta.type = TSK_FS_META_TYPE_FIFO;
        uint8_t result = tsk_fs_meta_make_ls(&meta, buf, sizeof(buf));
        REQUIRE(result == 0);
        REQUIRE(buf[0] == 'p');
        
        meta.type = TSK_FS_META_TYPE_CHR;
        result = tsk_fs_meta_make_ls(&meta, buf, sizeof(buf));
        REQUIRE(result == 0);
        REQUIRE(buf[0] == 'c');
        
        meta.type = TSK_FS_META_TYPE_BLK;
        result = tsk_fs_meta_make_ls(&meta, buf, sizeof(buf));
        REQUIRE(result == 0);
        REQUIRE(buf[0] == 'b');
        
        meta.type = TSK_FS_META_TYPE_LNK;
        result = tsk_fs_meta_make_ls(&meta, buf, sizeof(buf));
        REQUIRE(result == 0);
        REQUIRE(buf[0] == 'l');
        
        meta.type = TSK_FS_META_TYPE_SOCK;
        result = tsk_fs_meta_make_ls(&meta, buf, sizeof(buf));
        REQUIRE(result == 0);
        REQUIRE(buf[0] == 'h');
    }
    
    SECTION("handles buffer too small") {
        TSK_FS_META meta;
        memset(&meta, 0, sizeof(meta));
        meta.type = TSK_FS_META_TYPE_REG;
        
        char buf[8];
        uint8_t result = tsk_fs_meta_make_ls(&meta, buf, sizeof(buf));
        REQUIRE(result == 1);
    }
    
    SECTION("handles unknown file type") {
        TSK_FS_META meta;
        memset(&meta, 0, sizeof(meta));
        meta.type = (TSK_FS_META_TYPE_ENUM)99;
        
        char buf[16];
        uint8_t result = tsk_fs_meta_make_ls(&meta, buf, sizeof(buf));
        REQUIRE(result == 0);
        REQUIRE(buf[0] == '-');
    }
}

// Test for tsk_fs_time_to_str function
TEST_CASE("tsk_fs_time_to_str formats time correctly", "[fs_name]") {
    SECTION("formats valid time") {
        time_t test_time = 946684800; // 2000-01-01 00:00:00 UTC
        char buf[128];
        
        tsk_fs_time_to_str(test_time, buf);
        
        REQUIRE(strlen(buf) > 0);
        REQUIRE(strstr(buf, "2000") != nullptr);
    }
    
    SECTION("handles zero time") {
        time_t zero_time = 0;
        char buf[128];
        
        tsk_fs_time_to_str(zero_time, buf);
        
        REQUIRE(strlen(buf) > 0);
    }
    
    SECTION("handles negative time") {
        time_t negative_time = -1;
        char buf[128];
        
        tsk_fs_time_to_str(negative_time, buf);
        
        REQUIRE(strlen(buf) > 0);
    }
}

// Test for tsk_fs_time_to_str_subsecs function
TEST_CASE("tsk_fs_time_to_str_subsecs formats time with subseconds", "[fs_name]") {
    SECTION("formats time with subseconds") {
        time_t test_time = 946684800; // 2000-01-01 00:00:00 UTC
        unsigned int subsecs = 123456789; 
        char buf[128];
        
        tsk_fs_time_to_str_subsecs(test_time, subsecs, buf);
        
        REQUIRE(strlen(buf) > 0);
        REQUIRE(strstr(buf, "2000") != nullptr);
    }
    
    SECTION("handles zero time and subseconds") {
        time_t zero_time = 0;
        unsigned int zero_subsecs = 0;
        char buf[128];
        
        tsk_fs_time_to_str_subsecs(zero_time, zero_subsecs, buf);
        
        REQUIRE(strlen(buf) > 0);
    }
    
    SECTION("handles large subsecond values") {
        time_t test_time = 946684800;
        unsigned int large_subsecs = 999999999; // Max nanosecs.
        char buf[128];
        
        tsk_fs_time_to_str_subsecs(test_time, large_subsecs, buf);
        
        REQUIRE(strlen(buf) > 0);
    }
}

// Test for tsk_fs_name_type_str array
TEST_CASE("tsk_fs_name_type_str contains correct type characters", "[fs_name]") {
    SECTION("contains expected type characters") {
        REQUIRE(tsk_fs_name_type_str[TSK_FS_NAME_TYPE_UNDEF][0] == '-');
        REQUIRE(tsk_fs_name_type_str[TSK_FS_NAME_TYPE_FIFO][0] == 'p');
        REQUIRE(tsk_fs_name_type_str[TSK_FS_NAME_TYPE_CHR][0] == 'c');
        REQUIRE(tsk_fs_name_type_str[TSK_FS_NAME_TYPE_DIR][0] == 'd');
        REQUIRE(tsk_fs_name_type_str[TSK_FS_NAME_TYPE_BLK][0] == 'b');
        REQUIRE(tsk_fs_name_type_str[TSK_FS_NAME_TYPE_REG][0] == 'r');
        REQUIRE(tsk_fs_name_type_str[TSK_FS_NAME_TYPE_LNK][0] == 'l');
        REQUIRE(tsk_fs_name_type_str[TSK_FS_NAME_TYPE_SOCK][0] == 's');
        REQUIRE(tsk_fs_name_type_str[TSK_FS_NAME_TYPE_SHAD][0] == 'h');
        REQUIRE(tsk_fs_name_type_str[TSK_FS_NAME_TYPE_WHT][0] == 'w');
        REQUIRE(tsk_fs_name_type_str[TSK_FS_NAME_TYPE_VIRT][0] == 'v');
        REQUIRE(tsk_fs_name_type_str[TSK_FS_NAME_TYPE_VIRT_DIR][0] == 'V');
    }
    
    SECTION("all entries are null-terminated") {
        for (int i = 0; i < TSK_FS_NAME_TYPE_STR_MAX; i++) {
            REQUIRE(tsk_fs_name_type_str[i][1] == '\0');
        }
    }
} 
