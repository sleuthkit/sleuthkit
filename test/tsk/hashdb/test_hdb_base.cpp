/*
 * File Name: test_hdb_base.cpp
 * 
 * Unit tests for hdb_base.cpp
 *
 * Author: Pratik Singh (@singhpratik5)
 */

#include "tsk/base/tsk_os.h"
#include "tsk/hashdb/tsk_hashdb_i.h"
#include "catch.hpp"
#include <memory>
#include <cstring>

// Helper function to cleanup TSK_HDB_INFO
void hdb_info_cleanup(TSK_HDB_INFO *hdb_info) {
    if (hdb_info) {
        hdb_info_base_close(hdb_info);
        free(hdb_info);
    }
}

// Helper function to create a minimal TSK_HDB_INFO for testing
TSK_HDB_INFO* create_test_hdb_info(const TSK_TCHAR *db_path) {
    TSK_HDB_INFO *hdb_info = (TSK_HDB_INFO*)tsk_malloc(sizeof(TSK_HDB_INFO));
    if (!hdb_info) {
        return nullptr;
    }
    memset(hdb_info, 0, sizeof(TSK_HDB_INFO));
    
    if (hdb_info_base_open(hdb_info, db_path) != 0) {
        free(hdb_info);
        return nullptr;
    }
    
    return hdb_info;
}

// ========================================================================
// Tests for hdb_base_get_db_path
// ========================================================================

TEST_CASE("hdb_base_get_db_path returns database path") {
    SECTION("Unix path") {
        std::unique_ptr<TSK_HDB_INFO, decltype(&hdb_info_cleanup)> hdb_info{
            create_test_hdb_info(_TSK_T("/path/to/database.db")),
            &hdb_info_cleanup
        };
        
        REQUIRE(hdb_info.get() != nullptr);
        const TSK_TCHAR *result = hdb_base_get_db_path(hdb_info.get());
        REQUIRE(result != nullptr);
        CHECK(TSTRCMP(result, _TSK_T("/path/to/database.db")) == 0);
    }
    
#ifdef TSK_WIN32
    SECTION("Windows path") {
        std::unique_ptr<TSK_HDB_INFO, decltype(&hdb_info_cleanup)> hdb_info{
            create_test_hdb_info(_TSK_T("C:\\Users\\test\\database.db")),
            &hdb_info_cleanup
        };
        
        REQUIRE(hdb_info.get() != nullptr);
        const TSK_TCHAR *result = hdb_base_get_db_path(hdb_info.get());
        REQUIRE(result != nullptr);
        CHECK(TSTRCMP(result, _TSK_T("C:\\Users\\test\\database.db")) == 0);
    }
#endif
}

// ========================================================================
// Tests for hdb_base_get_display_name
// ========================================================================

TEST_CASE("hdb_base_get_display_name returns display name") {
    SECTION("Simple filename") {
        std::unique_ptr<TSK_HDB_INFO, decltype(&hdb_info_cleanup)> hdb_info{
            create_test_hdb_info(_TSK_T("/path/to/database.db")),
            &hdb_info_cleanup
        };
        
        REQUIRE(hdb_info.get() != nullptr);
        const char *result = hdb_base_get_display_name(hdb_info.get());
        REQUIRE(result != nullptr);
        CHECK(strcmp(result, "database.db") == 0);
    }
    
    SECTION("Filename with .idx extension") {
        std::unique_ptr<TSK_HDB_INFO, decltype(&hdb_info_cleanup)> hdb_info{
            create_test_hdb_info(_TSK_T("/path/to/database.idx")),
            &hdb_info_cleanup
        };
        
        REQUIRE(hdb_info.get() != nullptr);
        const char *result = hdb_base_get_display_name(hdb_info.get());
        REQUIRE(result != nullptr);
        CHECK(strcmp(result, "database") == 0);
    }
}

// ========================================================================
// Tests for hdb_base_uses_external_indexes
// ========================================================================

TEST_CASE("hdb_base_uses_external_indexes returns false") {
    uint8_t result = hdb_base_uses_external_indexes();
    CHECK(result == 0);
}

// ========================================================================
// Tests for hdb_base_get_index_path
// ========================================================================

TEST_CASE("hdb_base_get_index_path returns database path") {
    SECTION("MD5 hash type") {
        std::unique_ptr<TSK_HDB_INFO, decltype(&hdb_info_cleanup)> hdb_info{
            create_test_hdb_info(_TSK_T("/path/to/database.db")),
            &hdb_info_cleanup
        };
        
        REQUIRE(hdb_info.get() != nullptr);
        const TSK_TCHAR *result = hdb_base_get_index_path(hdb_info.get(), TSK_HDB_HTYPE_MD5_ID);
        REQUIRE(result != nullptr);
        CHECK(TSTRCMP(result, _TSK_T("/path/to/database.db")) == 0);
    }
    
    SECTION("SHA1 hash type") {
        std::unique_ptr<TSK_HDB_INFO, decltype(&hdb_info_cleanup)> hdb_info{
            create_test_hdb_info(_TSK_T("/path/to/database.db")),
            &hdb_info_cleanup
        };
        
        REQUIRE(hdb_info.get() != nullptr);
        const TSK_TCHAR *result = hdb_base_get_index_path(hdb_info.get(), TSK_HDB_HTYPE_SHA1_ID);
        REQUIRE(result != nullptr);
        CHECK(TSTRCMP(result, _TSK_T("/path/to/database.db")) == 0);
    }
    
    SECTION("SHA256 hash type") {
        std::unique_ptr<TSK_HDB_INFO, decltype(&hdb_info_cleanup)> hdb_info{
            create_test_hdb_info(_TSK_T("/path/to/database.db")),
            &hdb_info_cleanup
        };
        
        REQUIRE(hdb_info.get() != nullptr);
        const TSK_TCHAR *result = hdb_base_get_index_path(hdb_info.get(), TSK_HDB_HTYPE_SHA2_256_ID);
        REQUIRE(result != nullptr);
        CHECK(TSTRCMP(result, _TSK_T("/path/to/database.db")) == 0);
    }
}

// ========================================================================
// Tests for hdb_base_has_index
// ========================================================================

TEST_CASE("hdb_base_has_index always returns true") {
    std::unique_ptr<TSK_HDB_INFO, decltype(&hdb_info_cleanup)> hdb_info{
        create_test_hdb_info(_TSK_T("/path/to/database.db")),
        &hdb_info_cleanup
    };
    
    REQUIRE(hdb_info.get() != nullptr);
    
    SECTION("MD5 hash type") {
        uint8_t result = hdb_base_has_index(hdb_info.get(), TSK_HDB_HTYPE_MD5_ID);
        CHECK(result == 1);
    }
    
    SECTION("SHA1 hash type") {
        uint8_t result = hdb_base_has_index(hdb_info.get(), TSK_HDB_HTYPE_SHA1_ID);
        CHECK(result == 1);
    }
    
    SECTION("SHA256 hash type") {
        uint8_t result = hdb_base_has_index(hdb_info.get(), TSK_HDB_HTYPE_SHA2_256_ID);
        CHECK(result == 1);
    }
    
    SECTION("Invalid hash type") {
        uint8_t result = hdb_base_has_index(hdb_info.get(), TSK_HDB_HTYPE_INVALID_ID);
        CHECK(result == 1);
    }
}

// ========================================================================
// Tests for hdb_base_make_index
// ========================================================================

TEST_CASE("hdb_base_make_index is a no-op returning success") {
    std::unique_ptr<TSK_HDB_INFO, decltype(&hdb_info_cleanup)> hdb_info{
        create_test_hdb_info(_TSK_T("/path/to/database.db")),
        &hdb_info_cleanup
    };
    
    REQUIRE(hdb_info.get() != nullptr);
    
    SECTION("MD5 hash type") {
        uint8_t result = hdb_base_make_index(hdb_info.get(), (TSK_TCHAR*)_TSK_T("md5"));
        CHECK(result == 0);
    }
    
    SECTION("SHA1 hash type") {
        uint8_t result = hdb_base_make_index(hdb_info.get(), (TSK_TCHAR*)_TSK_T("sha1"));
        CHECK(result == 0);
    }
    
    SECTION("NULL hash type") {
        uint8_t result = hdb_base_make_index(hdb_info.get(), nullptr);
        CHECK(result == 0);
    }
}

// ========================================================================
// Tests for hdb_base_open_index
// ========================================================================

TEST_CASE("hdb_base_open_index is a no-op returning success") {
    std::unique_ptr<TSK_HDB_INFO, decltype(&hdb_info_cleanup)> hdb_info{
        create_test_hdb_info(_TSK_T("/path/to/database.db")),
        &hdb_info_cleanup
    };
    
    REQUIRE(hdb_info.get() != nullptr);
    
    SECTION("MD5 hash type") {
        uint8_t result = hdb_base_open_index(hdb_info.get(), TSK_HDB_HTYPE_MD5_ID);
        CHECK(result == 0);
    }
    
    SECTION("SHA1 hash type") {
        uint8_t result = hdb_base_open_index(hdb_info.get(), TSK_HDB_HTYPE_SHA1_ID);
        CHECK(result == 0);
    }
    
    SECTION("Invalid hash type") {
        uint8_t result = hdb_base_open_index(hdb_info.get(), TSK_HDB_HTYPE_INVALID_ID);
        CHECK(result == 0);
    }
}

// ========================================================================
// Tests for hdb_base_lookup_str
// ========================================================================

// Dummy callback for lookup tests
static TSK_WALK_RET_ENUM test_lookup_callback(TSK_HDB_INFO *hdb_info, 
                                               const char *hash, 
                                               const char *name, 
                                               void *ptr) {
    (void)hdb_info;  // Suppressing unused parameter warning
    (void)hash;
    (void)name;
    (void)ptr;
    return TSK_WALK_CONT;
}

TEST_CASE("hdb_base_lookup_str returns unsupported error") {
    std::unique_ptr<TSK_HDB_INFO, decltype(&hdb_info_cleanup)> hdb_info{
        create_test_hdb_info(_TSK_T("/path/to/database.db")),
        &hdb_info_cleanup
    };
    
    REQUIRE(hdb_info.get() != nullptr);
    
    SECTION("MD5 hash lookup") {
        const char *hash = "d41d8cd98f00b204e9800998ecf8427e";
        int8_t result = hdb_base_lookup_str(hdb_info.get(), hash, 
                                            TSK_HDB_FLAG_QUICK, 
                                            test_lookup_callback, 
                                            nullptr);
        CHECK(result == -1);
        CHECK(tsk_error_get_errno() == TSK_ERR_HDB_UNSUPFUNC);
    }
    
    SECTION("SHA1 hash lookup") {
        const char *hash = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
        int8_t result = hdb_base_lookup_str(hdb_info.get(), hash, 
                                            TSK_HDB_FLAG_QUICK, 
                                            test_lookup_callback, 
                                            nullptr);
        CHECK(result == -1);
        CHECK(tsk_error_get_errno() == TSK_ERR_HDB_UNSUPFUNC);
    }
}

// ========================================================================
// Tests for hdb_base_lookup_bin
// ========================================================================

TEST_CASE("hdb_base_lookup_bin returns unsupported error") {
    std::unique_ptr<TSK_HDB_INFO, decltype(&hdb_info_cleanup)> hdb_info{
        create_test_hdb_info(_TSK_T("/path/to/database.db")),
        &hdb_info_cleanup
    };
    
    REQUIRE(hdb_info.get() != nullptr);
    
    SECTION("Binary MD5 hash lookup") {
        uint8_t hash[16] = {0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 
                           0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e};
        int8_t result = hdb_base_lookup_bin(hdb_info.get(), hash, 16,
                                           TSK_HDB_FLAG_QUICK, 
                                           test_lookup_callback, 
                                           nullptr);
        CHECK(result == -1);
        CHECK(tsk_error_get_errno() == TSK_ERR_HDB_UNSUPFUNC);
    }
    
    SECTION("Binary SHA1 hash lookup") {
        uint8_t hash[20] = {0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d,
                           0x32, 0x55, 0xbf, 0xef, 0x95, 0x60, 0x18, 0x90,
                           0xaf, 0xd8, 0x07, 0x09};
        int8_t result = hdb_base_lookup_bin(hdb_info.get(), hash, 20,
                                           TSK_HDB_FLAG_QUICK, 
                                           test_lookup_callback, 
                                           nullptr);
        CHECK(result == -1);
        CHECK(tsk_error_get_errno() == TSK_ERR_HDB_UNSUPFUNC);
    }
}

// ========================================================================
// Tests for hdb_base_lookup_verbose_str
// ========================================================================

TEST_CASE("hdb_base_lookup_verbose_str returns unsupported error") {
    std::unique_ptr<TSK_HDB_INFO, decltype(&hdb_info_cleanup)> hdb_info{
        create_test_hdb_info(_TSK_T("/path/to/database.db")),
        &hdb_info_cleanup
    };
    
    REQUIRE(hdb_info.get() != nullptr);
    
    SECTION("Verbose lookup") {
        const char *hash = "d41d8cd98f00b204e9800998ecf8427e";
        char result_buf[512];
        int8_t result = hdb_base_lookup_verbose_str(hdb_info.get(), hash, result_buf);
        CHECK(result == -1);
        CHECK(tsk_error_get_errno() == TSK_ERR_HDB_UNSUPFUNC);
    }
}

// ========================================================================
// Tests for hdb_base_accepts_updates
// ========================================================================

TEST_CASE("hdb_base_accepts_updates returns true") {
    uint8_t result = hdb_base_accepts_updates();
    CHECK(result == 1);
}

// ========================================================================
// Tests for hdb_base_add_entry
// ========================================================================

TEST_CASE("hdb_base_add_entry returns unsupported error") {
    std::unique_ptr<TSK_HDB_INFO, decltype(&hdb_info_cleanup)> hdb_info{
        create_test_hdb_info(_TSK_T("/path/to/database.db")),
        &hdb_info_cleanup
    };
    
    REQUIRE(hdb_info.get() != nullptr);
    
    SECTION("Add entry with all hash types") {
        uint8_t result = hdb_base_add_entry(hdb_info.get(),
                                           "test_file.txt",
                                           "d41d8cd98f00b204e9800998ecf8427e",
                                           "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                                           "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                                           "Test comment");
        CHECK(result == 1);
        CHECK(tsk_error_get_errno() == TSK_ERR_HDB_UNSUPFUNC);
    }
    
    SECTION("Add entry with minimal data") {
        uint8_t result = hdb_base_add_entry(hdb_info.get(),
                                           "file.dat",
                                           "d41d8cd98f00b204e9800998ecf8427e",
                                           nullptr,
                                           nullptr,
                                           nullptr);
        CHECK(result == 1);
        CHECK(tsk_error_get_errno() == TSK_ERR_HDB_UNSUPFUNC);
    }
}

// ========================================================================
// Tests for hdb_base_begin_transaction
// ========================================================================

TEST_CASE("hdb_base_begin_transaction returns unsupported error") {
    std::unique_ptr<TSK_HDB_INFO, decltype(&hdb_info_cleanup)> hdb_info{
        create_test_hdb_info(_TSK_T("/path/to/database.db")),
        &hdb_info_cleanup
    };
    
    REQUIRE(hdb_info.get() != nullptr);
    
    uint8_t result = hdb_base_begin_transaction(hdb_info.get());
    CHECK(result == 1);
    CHECK(tsk_error_get_errno() == TSK_ERR_HDB_UNSUPFUNC);
}

// ========================================================================
// Tests for hdb_base_commit_transaction
// ========================================================================

TEST_CASE("hdb_base_commit_transaction returns unsupported error") {
    std::unique_ptr<TSK_HDB_INFO, decltype(&hdb_info_cleanup)> hdb_info{
        create_test_hdb_info(_TSK_T("/path/to/database.db")),
        &hdb_info_cleanup
    };
    
    REQUIRE(hdb_info.get() != nullptr);
    
    uint8_t result = hdb_base_commit_transaction(hdb_info.get());
    CHECK(result == 1);
    CHECK(tsk_error_get_errno() == TSK_ERR_HDB_UNSUPFUNC);
}

// ========================================================================
// Tests for hdb_base_rollback_transaction
// ========================================================================

TEST_CASE("hdb_base_rollback_transaction returns unsupported error") {
    std::unique_ptr<TSK_HDB_INFO, decltype(&hdb_info_cleanup)> hdb_info{
        create_test_hdb_info(_TSK_T("/path/to/database.db")),
        &hdb_info_cleanup
    };
    
    REQUIRE(hdb_info.get() != nullptr);
    
    uint8_t result = hdb_base_rollback_transaction(hdb_info.get());
    CHECK(result == 1);
    CHECK(tsk_error_get_errno() == TSK_ERR_HDB_UNSUPFUNC);
}

// ========================================================================
// Tests for hdb_info_base_close
// ========================================================================

TEST_CASE("hdb_info_base_close handles cleanup") {
    SECTION("Close valid hdb_info") {
        TSK_HDB_INFO *hdb_info = create_test_hdb_info(_TSK_T("/path/to/database.db"));
        REQUIRE(hdb_info != nullptr);
        REQUIRE(hdb_info->db_fname != nullptr);
        
        // Close should free db_fname and set it to NULL
        hdb_info_base_close(hdb_info);
        CHECK(hdb_info->db_fname == nullptr);
        
        free(hdb_info);
    }
    
    SECTION("Close NULL hdb_info") {
        // Should handle NULL gracefully without crashing
        hdb_info_base_close(nullptr);
        // If we get here, test passed
        CHECK(true);
    }
}

// ========================================================================
// Tests for hdb_base_db_name_from_path
// ========================================================================

TEST_CASE("hdb_base_db_name_from_path extracts database name") {
    TSK_HDB_INFO *hdb_info = (TSK_HDB_INFO*)tsk_malloc(sizeof(TSK_HDB_INFO));
    REQUIRE(hdb_info != nullptr);
    memset(hdb_info, 0, sizeof(TSK_HDB_INFO));
    
    SECTION("Unix path with .idx extension") {
        const TSK_TCHAR *path = _TSK_T("/var/lib/hashdb/nsrl.idx");
        size_t path_len = TSTRLEN(path);
        hdb_info->db_fname = (TSK_TCHAR*)tsk_malloc((path_len + 1) * sizeof(TSK_TCHAR));
        TSTRNCPY(hdb_info->db_fname, path, path_len + 1);
        
        hdb_base_db_name_from_path(hdb_info);
        
        CHECK(strcmp(hdb_info->db_name, "nsrl") == 0);
        
        free(hdb_info->db_fname);
    }
    
    SECTION("Unix path without .idx extension") {
        const TSK_TCHAR *path = _TSK_T("/var/lib/hashdb/database.db");
        size_t path_len = TSTRLEN(path);
        hdb_info->db_fname = (TSK_TCHAR*)tsk_malloc((path_len + 1) * sizeof(TSK_TCHAR));
        TSTRNCPY(hdb_info->db_fname, path, path_len + 1);
        
        hdb_base_db_name_from_path(hdb_info);
        
        CHECK(strcmp(hdb_info->db_name, "database.db") == 0);
        
        free(hdb_info->db_fname);
    }
    
#ifdef TSK_WIN32
    SECTION("Windows path with backslashes") {
        const TSK_TCHAR *path = _TSK_T("C:\\Users\\Public\\database.idx");
        size_t path_len = TSTRLEN(path);
        hdb_info->db_fname = (TSK_TCHAR*)tsk_malloc((path_len + 1) * sizeof(TSK_TCHAR));
        TSTRNCPY(hdb_info->db_fname, path, path_len + 1);
        
        hdb_base_db_name_from_path(hdb_info);
        
        CHECK(strcmp(hdb_info->db_name, "database") == 0);
        
        free(hdb_info->db_fname);
    }
    
    SECTION("Windows path with forward slashes (cygwin)") {
        const TSK_TCHAR *path = _TSK_T("C:/Users/Public/database.idx");
        size_t path_len = TSTRLEN(path);
        hdb_info->db_fname = (TSK_TCHAR*)tsk_malloc((path_len + 1) * sizeof(TSK_TCHAR));
        TSTRNCPY(hdb_info->db_fname, path, path_len + 1);
        
        hdb_base_db_name_from_path(hdb_info);
        
        CHECK(strcmp(hdb_info->db_name, "database") == 0);
        
        free(hdb_info->db_fname);
    }
#endif
    
    SECTION("Path is just filename") {
        const TSK_TCHAR *path = _TSK_T("mydb.idx");
        size_t path_len = TSTRLEN(path);
        hdb_info->db_fname = (TSK_TCHAR*)tsk_malloc((path_len + 1) * sizeof(TSK_TCHAR));
        TSTRNCPY(hdb_info->db_fname, path, path_len + 1);
        
        hdb_base_db_name_from_path(hdb_info);
        
        CHECK(strcmp(hdb_info->db_name, "mydb") == 0);
        
        free(hdb_info->db_fname);
    }
    
    SECTION("Path ending with separator only") {
        const TSK_TCHAR *path = _TSK_T("/");
        size_t path_len = TSTRLEN(path);
        hdb_info->db_fname = (TSK_TCHAR*)tsk_malloc((path_len + 1) * sizeof(TSK_TCHAR));
        TSTRNCPY(hdb_info->db_fname, path, path_len + 1);
        
        hdb_base_db_name_from_path(hdb_info);
        
        // Should result in empty string
        CHECK(hdb_info->db_name[0] == '\0');
        
        free(hdb_info->db_fname);
    }
    
    SECTION(".idx extension is case insensitive") {
        const TSK_TCHAR *path = _TSK_T("/path/to/file.IDX");
        size_t path_len = TSTRLEN(path);
        hdb_info->db_fname = (TSK_TCHAR*)tsk_malloc((path_len + 1) * sizeof(TSK_TCHAR));
        TSTRNCPY(hdb_info->db_fname, path, path_len + 1);
        
        hdb_base_db_name_from_path(hdb_info);
        
        // Extension check is case-insensitive
        CHECK(strcmp(hdb_info->db_name, "file") == 0);
        
        free(hdb_info->db_fname);
    }
    
    SECTION("Multiple dots in filename") {
        const TSK_TCHAR *path = _TSK_T("/path/to/my.database.file.idx");
        size_t path_len = TSTRLEN(path);
        hdb_info->db_fname = (TSK_TCHAR*)tsk_malloc((path_len + 1) * sizeof(TSK_TCHAR));
        TSTRNCPY(hdb_info->db_fname, path, path_len + 1);
        
        hdb_base_db_name_from_path(hdb_info);
        
        CHECK(strcmp(hdb_info->db_name, "my.database.file") == 0);
        
        free(hdb_info->db_fname);
    }
    
    free(hdb_info);
}

// ========================================================================
// Tests for hdb_info_base_open
// ========================================================================

TEST_CASE("hdb_info_base_open initializes TSK_HDB_INFO") {
    SECTION("Successful initialization") {
        TSK_HDB_INFO *hdb_info = (TSK_HDB_INFO*)tsk_malloc(sizeof(TSK_HDB_INFO));
        REQUIRE(hdb_info != nullptr);
        memset(hdb_info, 0, sizeof(TSK_HDB_INFO));
        
        const TSK_TCHAR *path = _TSK_T("/path/to/database.db");
        uint8_t result = hdb_info_base_open(hdb_info, path);
        
        CHECK(result == 0);
        CHECK(hdb_info->db_fname != nullptr);
        CHECK(TSTRCMP(hdb_info->db_fname, path) == 0);
        CHECK(hdb_info->db_type == TSK_HDB_DBTYPE_INVALID_ID);
        CHECK(hdb_info->transaction_in_progress == 0);
        
        // Check function pointers are assigned
        CHECK(hdb_info->get_db_path != nullptr);
        CHECK(hdb_info->get_display_name != nullptr);
        CHECK(hdb_info->uses_external_indexes != nullptr);
        CHECK(hdb_info->get_index_path != nullptr);
        CHECK(hdb_info->has_index != nullptr);
        CHECK(hdb_info->make_index != nullptr);
        CHECK(hdb_info->open_index != nullptr);
        CHECK(hdb_info->lookup_str != nullptr);
        CHECK(hdb_info->lookup_raw != nullptr);
        CHECK(hdb_info->lookup_verbose_str != nullptr);
        CHECK(hdb_info->accepts_updates != nullptr);
        CHECK(hdb_info->add_entry != nullptr);
        CHECK(hdb_info->begin_transaction != nullptr);
        CHECK(hdb_info->commit_transaction != nullptr);
        CHECK(hdb_info->rollback_transaction != nullptr);
        CHECK(hdb_info->close_db != nullptr);
        
        hdb_info_base_close(hdb_info);
        free(hdb_info);
    }
    
    SECTION("Initialization with long path") {
        TSK_HDB_INFO *hdb_info = (TSK_HDB_INFO*)tsk_malloc(sizeof(TSK_HDB_INFO));
        REQUIRE(hdb_info != nullptr);
        memset(hdb_info, 0, sizeof(TSK_HDB_INFO));
        
        const TSK_TCHAR *path = _TSK_T("/very/long/path/to/some/deeply/nested/directory/structure/database.idx");
        uint8_t result = hdb_info_base_open(hdb_info, path);
        
        CHECK(result == 0);
        CHECK(hdb_info->db_fname != nullptr);
        CHECK(TSTRCMP(hdb_info->db_fname, path) == 0);
        CHECK(strcmp(hdb_info->db_name, "database") == 0);
        
        hdb_info_base_close(hdb_info);
        free(hdb_info);
    }
    
#ifdef TSK_WIN32
    SECTION("Initialization with Windows path") {
        TSK_HDB_INFO *hdb_info = (TSK_HDB_INFO*)tsk_malloc(sizeof(TSK_HDB_INFO));
        REQUIRE(hdb_info != nullptr);
        memset(hdb_info, 0, sizeof(TSK_HDB_INFO));
        
        const TSK_TCHAR *path = _TSK_T("C:\\Program Files\\HashDB\\database.db");
        uint8_t result = hdb_info_base_open(hdb_info, path);
        
        CHECK(result == 0);
        CHECK(hdb_info->db_fname != nullptr);
        CHECK(TSTRCMP(hdb_info->db_fname, path) == 0);
        
        hdb_info_base_close(hdb_info);
        free(hdb_info);
    }
#endif
}
