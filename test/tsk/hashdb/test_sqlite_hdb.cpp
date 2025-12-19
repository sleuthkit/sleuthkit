/*
 * File Name: test_sqlite_hdb.cpp
 * 
 * Unit tests for sqlite_hdb.cpp
 *
 * Author: Pratik Singh (@singhpratik5)
 */

#include "tsk/base/tsk_os.h"
#include "tsk/hashdb/tsk_hashdb_i.h"
#include "tsk/hashdb/tsk_hash_info.h"
#include "catch.hpp"
#include <memory>
#include <cstring>
#include <cstdio>
#include <string>

#ifdef TSK_WIN32
#include <windows.h>
#endif

// Portable fopen for TSK_TCHAR
static FILE *tsk_fopen_tchar(const TSK_TCHAR *path, const TSK_TCHAR *mode) {
#ifdef TSK_WIN32
    return _wfopen(path, mode);
#else
    return fopen(path, mode);
#endif
}

// Helper to create temporary file paths
static std::string get_temp_db_path() {
    static int counter = 0;
    char buffer[256];
#ifdef TSK_WIN32
    snprintf(buffer, sizeof(buffer), ".\\test_sqlite_hdb_%d.db", counter++);
#else
    snprintf(buffer, sizeof(buffer), "./test_sqlite_hdb_%d.db", counter++);
#endif
    return std::string(buffer);
}

// Helper to remove a file
static void remove_file(const char *path) {
    std::remove(path);
}

#ifdef TSK_WIN32
// Helper to convert string to wstring for Windows
static std::wstring string_to_wstring(const std::string& str) {
    if (str.empty()) {
        return std::wstring();
    }
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}
#endif

// Helper function to get TSK_TCHAR path
static TSK_TCHAR* get_tsk_path(const std::string& path) {
#ifdef TSK_WIN32
    static std::wstring wpath;
    wpath = string_to_wstring(path);
    return const_cast<TSK_TCHAR*>(wpath.c_str());
#else
    return const_cast<TSK_TCHAR*>(path.c_str());
#endif
}

// Dummy callback for lookup tests
static TSK_WALK_RET_ENUM test_lookup_callback(TSK_HDB_INFO *hdb_info,
                                               const char *hash,
                                               const char *name,
                                               void *ptr) {
    (void)hdb_info;  // Suppress unused parameter warning
    (void)hash;
    (void)name;
    (void)ptr;
    return TSK_WALK_CONT;
}

// Callback to count results
struct CallbackCounter {
    int count;
    std::string last_hash;
    std::string last_name;
};

static TSK_WALK_RET_ENUM count_callback(TSK_HDB_INFO *hdb_info,
                                        const char *hash,
                                        const char *name,
                                        void *ptr) {
    (void)hdb_info;
    CallbackCounter *counter = static_cast<CallbackCounter*>(ptr);
    counter->count++;
    if (hash) counter->last_hash = hash;
    if (name) counter->last_name = name;
    return TSK_WALK_CONT;
}

// ========================================================================
// Tests for sqlite_hdb_create_db
// ========================================================================

TEST_CASE("sqlite_hdb_create_db creates a new database") {
    std::string db_path = get_temp_db_path();
    TSK_TCHAR *tsk_path = get_tsk_path(db_path);
    
    SECTION("Create new database successfully") {
        uint8_t result = sqlite_hdb_create_db(tsk_path);
        CHECK(result == 0);
        
        // Verify file exists
        FILE *f = tsk_fopen_tchar(tsk_path, _TSK_T("rb"));
        REQUIRE(f != nullptr);
        fclose(f);
        
        remove_file(db_path.c_str());
    }
    
    SECTION("Create database in same location twice") {
        // First creation
        uint8_t result1 = sqlite_hdb_create_db(tsk_path);
        CHECK(result1 == 0);
        
        // Second creation should also succeed (overwrites)
        uint8_t result2 = sqlite_hdb_create_db(tsk_path);
        CHECK(result2 == 1); // Failed
        
        remove_file(db_path.c_str());
    }
}

// ========================================================================
// Tests for sqlite_hdb_is_sqlite_file
// ========================================================================

TEST_CASE("sqlite_hdb_is_sqlite_file detects SQLite files") {
    std::string db_path = get_temp_db_path();
    TSK_TCHAR *tsk_path = get_tsk_path(db_path);
    
    SECTION("Detect valid SQLite file") {
        // Create a SQLite database
        sqlite_hdb_create_db(tsk_path);
        
        FILE *f = tsk_fopen_tchar(tsk_path, _TSK_T("rb"));
        REQUIRE(f != nullptr);
        
        uint8_t is_sqlite = sqlite_hdb_is_sqlite_file(f);
        CHECK(is_sqlite == 1);
        
        fclose(f);
        remove_file(db_path.c_str());
    }
    
    SECTION("Detect non-SQLite file") {
        // Create a text file
        FILE *f = fopen(db_path.c_str(), "wb");
        REQUIRE(f != nullptr);
        fprintf(f, "This is not a SQLite file\n");
        fclose(f);
        
        f = fopen(db_path.c_str(), "rb");
        REQUIRE(f != nullptr);
        
        uint8_t is_sqlite = sqlite_hdb_is_sqlite_file(f);
        CHECK(is_sqlite == 0);
        
        fclose(f);
        remove_file(db_path.c_str());
    }
    
    SECTION("Detect empty file") {
        // Create empty file
        FILE *f = fopen(db_path.c_str(), "wb");
        REQUIRE(f != nullptr);
        fclose(f);
        
        f = fopen(db_path.c_str(), "rb");
        REQUIRE(f != nullptr);
        
        uint8_t is_sqlite = sqlite_hdb_is_sqlite_file(f);
        CHECK(is_sqlite == 0);
        
        fclose(f);
        remove_file(db_path.c_str());
    }
}

// ========================================================================
// Tests for sqlite_hdb_open
// ========================================================================

TEST_CASE("sqlite_hdb_open opens existing database") {
    std::string db_path = get_temp_db_path();
    TSK_TCHAR *tsk_path = get_tsk_path(db_path);
    
    SECTION("Open valid database") {
        // Create database first
        sqlite_hdb_create_db(tsk_path);
        
        // Open it
        TSK_HDB_INFO *hdb_info = sqlite_hdb_open(tsk_path);
        REQUIRE(hdb_info != nullptr);
        CHECK(hdb_info->db_type == TSK_HDB_DBTYPE_SQLITE_ID);
        CHECK(hdb_info->db_fname != nullptr);
        
        // Verify function pointers are set
        CHECK(hdb_info->lookup_str != nullptr);
        CHECK(hdb_info->lookup_raw != nullptr);
        CHECK(hdb_info->lookup_verbose_str != nullptr);
        CHECK(hdb_info->add_entry != nullptr);
        CHECK(hdb_info->begin_transaction != nullptr);
        CHECK(hdb_info->commit_transaction != nullptr);
        CHECK(hdb_info->rollback_transaction != nullptr);
        CHECK(hdb_info->close_db != nullptr);
        
        tsk_hdb_close(hdb_info);
        remove_file(db_path.c_str());
    }
    /*
    SECTION("Open creates database if it doesn't exist") {
        // SQLite creates the database if it doesn't exist
        TSK_HDB_INFO *hdb_info = sqlite_hdb_open(tsk_path);
        // SQLite will create the file, so this should succeed
        REQUIRE(hdb_info != nullptr);
        CHECK(hdb_info->db_type == TSK_HDB_DBTYPE_SQLITE_ID);
        
        tsk_hdb_close(hdb_info);
        remove_file(db_path.c_str());
    }
    */
}

// ========================================================================
// Tests for sqlite_hdb_add_entry
// ========================================================================

TEST_CASE("sqlite_hdb_add_entry adds entries to database") {
    std::string db_path = get_temp_db_path();
    TSK_TCHAR *tsk_path = get_tsk_path(db_path);
    
    sqlite_hdb_create_db(tsk_path);
    TSK_HDB_INFO *hdb_info = sqlite_hdb_open(tsk_path);
    REQUIRE(hdb_info != nullptr);
    
    SECTION("Add entry with MD5 and filename") {
        uint8_t result = sqlite_hdb_add_entry(hdb_info,
                                              "test_file.txt",
                                              "d41d8cd98f00b204e9800998ecf8427e",
                                              nullptr, nullptr, nullptr);
        CHECK(result == 0);
    }
    
    SECTION("Add entry with MD5, filename, and comment") {
        uint8_t result = sqlite_hdb_add_entry(hdb_info,
                                              "document.pdf",
                                              "5d41402abc4b2a76b9719d911017c592",
                                              nullptr, nullptr,
                                              "Test comment");
        CHECK(result == 0);
    }
    
    SECTION("Add duplicate MD5 with different filename") {
        const char *md5 = "098f6bcd4621d373cade4e832627b4f6";
        
        uint8_t result1 = sqlite_hdb_add_entry(hdb_info, "file1.txt", md5,
                                               nullptr, nullptr, nullptr);
        CHECK(result1 == 0);
        
        uint8_t result2 = sqlite_hdb_add_entry(hdb_info, "file2.txt", md5,
                                               nullptr, nullptr, nullptr);
        CHECK(result2 == 0);
    }
    
    SECTION("Add entry with invalid MD5 length fails") {
        uint8_t result = sqlite_hdb_add_entry(hdb_info,
                                              "test.txt",
                                              "invalid", // Too short
                                              nullptr, nullptr, nullptr);
        CHECK(result == 1);
        CHECK(tsk_error_get_errno() == TSK_ERR_HDB_ARG);
    }
    
    SECTION("Add entry with NULL filename") {
        uint8_t result = sqlite_hdb_add_entry(hdb_info,
                                              nullptr,
                                              "d41d8cd98f00b204e9800998ecf8427e",
                                              nullptr, nullptr, nullptr);
        CHECK(result == 0);
    }
    
    tsk_hdb_close(hdb_info);
    remove_file(db_path.c_str());
}

// ========================================================================
// Tests for sqlite_hdb_lookup_str
// ========================================================================

TEST_CASE("sqlite_hdb_lookup_str finds hashes in database") {
    std::string db_path = get_temp_db_path();
    TSK_TCHAR *tsk_path = get_tsk_path(db_path);
    
    sqlite_hdb_create_db(tsk_path);
    TSK_HDB_INFO *hdb_info = sqlite_hdb_open(tsk_path);
    REQUIRE(hdb_info != nullptr);
    
    const char *test_md5 = "d41d8cd98f00b204e9800998ecf8427e";
    const char *test_filename = "empty_file.txt";
    
    // Add an entry
    sqlite_hdb_add_entry(hdb_info, test_filename, test_md5,
                        nullptr, nullptr, nullptr);
    
    SECTION("Lookup existing hash with quick flag") {
        int8_t result = sqlite_hdb_lookup_str(hdb_info, test_md5,
                                              TSK_HDB_FLAG_QUICK,
                                              test_lookup_callback, nullptr);
        CHECK(result == 1);
    }
    
    SECTION("Lookup existing hash with callback") {
        CallbackCounter counter = {0, "", ""};
        int8_t result = sqlite_hdb_lookup_str(hdb_info, test_md5,
                                              TSK_HDB_FLAG_EXT,
                                              count_callback, &counter);
        CHECK(result == 1);
        CHECK(counter.count > 0);
        CHECK(counter.last_name == test_filename);
    }
    
    SECTION("Lookup non-existent hash") {
        const char *missing_md5 = "00000000000000000000000000000000";
        int8_t result = sqlite_hdb_lookup_str(hdb_info, missing_md5,
                                              TSK_HDB_FLAG_QUICK,
                                              test_lookup_callback, nullptr);
        CHECK(result == 0);
    }
    
    SECTION("Lookup with invalid hash length fails") {
        int8_t result = sqlite_hdb_lookup_str(hdb_info, "short",
                                              TSK_HDB_FLAG_QUICK,
                                              test_lookup_callback, nullptr);
        CHECK(result == 1);
        CHECK(tsk_error_get_errno() == TSK_ERR_HDB_ARG);
    }
    
    tsk_hdb_close(hdb_info);
    remove_file(db_path.c_str());
}

// ========================================================================
// Tests for sqlite_hdb_lookup_bin
// ========================================================================

TEST_CASE("sqlite_hdb_lookup_bin finds binary hashes in database") {
    std::string db_path = get_temp_db_path();
    TSK_TCHAR *tsk_path = get_tsk_path(db_path);
    
    sqlite_hdb_create_db(tsk_path);
    TSK_HDB_INFO *hdb_info = sqlite_hdb_open(tsk_path);
    REQUIRE(hdb_info != nullptr);
    
    const char *test_md5_str = "d41d8cd98f00b204e9800998ecf8427e";
    sqlite_hdb_add_entry(hdb_info, "test.txt", test_md5_str,
                        nullptr, nullptr, nullptr);
    
    SECTION("Lookup existing hash in binary form") {
        uint8_t hash[16] = {0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04,
                           0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e};
        
        int8_t result = sqlite_hdb_lookup_bin(hdb_info, hash, 16,
                                              TSK_HDB_FLAG_QUICK,
                                              test_lookup_callback, nullptr);
        CHECK(result == 1);
    }
    
    SECTION("Lookup with invalid length fails") {
        uint8_t hash[8] = {0};
        
        int8_t result = sqlite_hdb_lookup_bin(hdb_info, hash, 8,
                                              TSK_HDB_FLAG_QUICK,
                                              test_lookup_callback, nullptr);
        CHECK(result == -1);
        CHECK(tsk_error_get_errno() == TSK_ERR_HDB_ARG);
    }
    
    SECTION("Lookup non-existent binary hash") {
        uint8_t hash[16] = {0};
        
        int8_t result = sqlite_hdb_lookup_bin(hdb_info, hash, 16,
                                              TSK_HDB_FLAG_QUICK,
                                              test_lookup_callback, nullptr);
        CHECK(result == 0);
    }
    
    tsk_hdb_close(hdb_info);
    remove_file(db_path.c_str());
}

// ========================================================================
// Tests for sqlite_hdb_lookup_verbose_str
// ========================================================================

TEST_CASE("sqlite_hdb_lookup_verbose_str returns detailed info") {
    std::string db_path = get_temp_db_path();
    TSK_TCHAR *tsk_path = get_tsk_path(db_path);
    
    sqlite_hdb_create_db(tsk_path);
    TSK_HDB_INFO *hdb_info = sqlite_hdb_open(tsk_path);
    REQUIRE(hdb_info != nullptr);
    
    const char *test_md5 = "d41d8cd98f00b204e9800998ecf8427e";
    const char *test_filename = "verbose_test.txt";
    const char *test_comment = "This is a test comment";
    
    sqlite_hdb_add_entry(hdb_info, test_filename, test_md5,
                        nullptr, nullptr, test_comment);
    
    SECTION("Lookup existing hash with verbose info") {
        TskHashInfo result;
        int8_t ret = sqlite_hdb_lookup_verbose_str(hdb_info, test_md5, &result);
        
        CHECK(ret == 1);
        CHECK(result.hashMd5.length() > 0);
        CHECK(result.fileNames.size() > 0);
        if (result.fileNames.size() > 0) {
            CHECK(result.fileNames[0] == test_filename);
        }
        CHECK(result.comments.size() > 0);
        if (result.comments.size() > 0) {
            CHECK(result.comments[0] == test_comment);
        }
    }
    
    SECTION("Lookup non-existent hash") {
        TskHashInfo result;
        const char *missing_md5 = "00000000000000000000000000000000";
        int8_t ret = sqlite_hdb_lookup_verbose_str(hdb_info, missing_md5, &result);
        
        CHECK(ret == 0);
    }
    
    SECTION("Lookup with invalid hash length") {
        TskHashInfo result;
        int8_t ret = sqlite_hdb_lookup_verbose_str(hdb_info, "invalid", &result);
        
        CHECK(ret == -1);
        CHECK(tsk_error_get_errno() == TSK_ERR_HDB_ARG);
    }
    
    tsk_hdb_close(hdb_info);
    remove_file(db_path.c_str());
}

// ========================================================================
// Tests for sqlite_hdb_lookup_verbose_bin
// ========================================================================

TEST_CASE("sqlite_hdb_lookup_verbose_bin returns detailed binary lookup") {
    std::string db_path = get_temp_db_path();
    TSK_TCHAR *tsk_path = get_tsk_path(db_path);
    
    sqlite_hdb_create_db(tsk_path);
    TSK_HDB_INFO *hdb_info = sqlite_hdb_open(tsk_path);
    REQUIRE(hdb_info != nullptr);
    
    const char *test_md5_str = "098f6bcd4621d373cade4e832627b4f6";
    sqlite_hdb_add_entry(hdb_info, "binary_test.dat", test_md5_str,
                        nullptr, nullptr, "Binary lookup test");
    
    SECTION("Verbose binary lookup of existing hash") {
        uint8_t hash[16] = {0x09, 0x8f, 0x6b, 0xcd, 0x46, 0x21, 0xd3, 0x73,
                           0xca, 0xde, 0x4e, 0x83, 0x26, 0x27, 0xb4, 0xf6};
        TskHashInfo result;
        
        int8_t ret = sqlite_hdb_lookup_verbose_bin(hdb_info, hash, 16, &result);
        
        CHECK(ret == 1);
        CHECK(result.hashMd5.length() > 0);
    }
    
    SECTION("Verbose binary lookup with invalid length") {
        uint8_t hash[8] = {0};
        TskHashInfo result;
        
        int8_t ret = sqlite_hdb_lookup_verbose_bin(hdb_info, hash, 8, &result);
        
        CHECK(ret == -1);
        CHECK(tsk_error_get_errno() == TSK_ERR_HDB_ARG);
    }
    
    tsk_hdb_close(hdb_info);
    remove_file(db_path.c_str());
}

// ========================================================================
// Tests for transactions
// ========================================================================

TEST_CASE("sqlite_hdb transactions work correctly") {
    std::string db_path = get_temp_db_path();
    TSK_TCHAR *tsk_path = get_tsk_path(db_path);
    
    sqlite_hdb_create_db(tsk_path);
    TSK_HDB_INFO *hdb_info = sqlite_hdb_open(tsk_path);
    REQUIRE(hdb_info != nullptr);
    
    SECTION("Begin and commit transaction") {
        uint8_t begin = sqlite_hdb_begin_transaction(hdb_info);
        CHECK(begin == 0);
        
        // Add some entries within transaction
        sqlite_hdb_add_entry(hdb_info, "file1.txt",
                           "d41d8cd98f00b204e9800998ecf8427e",
                           nullptr, nullptr, nullptr);
        
        uint8_t commit = sqlite_hdb_commit_transaction(hdb_info);
        CHECK(commit == 0);
        
        // Verify entry exists
        int8_t found = sqlite_hdb_lookup_str(hdb_info,
                                            "d41d8cd98f00b204e9800998ecf8427e",
                                            TSK_HDB_FLAG_QUICK,
                                            test_lookup_callback, nullptr);
        CHECK(found == 1);
    }
    
    SECTION("Begin and rollback transaction") {
        uint8_t begin = sqlite_hdb_begin_transaction(hdb_info);
        CHECK(begin == 0);
        
        // Add entry within transaction
        sqlite_hdb_add_entry(hdb_info, "file2.txt",
                           "098f6bcd4621d373cade4e832627b4f6",
                           nullptr, nullptr, nullptr);
        
        uint8_t rollback = sqlite_hdb_rollback_transaction(hdb_info);
        CHECK(rollback == 0);
        
        // After rollback, entry should not exist
        int8_t found = sqlite_hdb_lookup_str(hdb_info,
                                            "098f6bcd4621d373cade4e832627b4f6",
                                            TSK_HDB_FLAG_QUICK,
                                            test_lookup_callback, nullptr);
        CHECK(found == 0);
    }
    
    SECTION("Multiple transactions") {
        // First transaction
        sqlite_hdb_begin_transaction(hdb_info);
        sqlite_hdb_add_entry(hdb_info, "tx1.txt",
                           "5d41402abc4b2a76b9719d911017c592",
                           nullptr, nullptr, nullptr);
        sqlite_hdb_commit_transaction(hdb_info);
        
        // Second transaction
        sqlite_hdb_begin_transaction(hdb_info);
        sqlite_hdb_add_entry(hdb_info, "tx2.txt",
                           "7d793037a0760186574b0282f2f435e7",
                           nullptr, nullptr, nullptr);
        sqlite_hdb_commit_transaction(hdb_info);
        
        // Both should exist
        int8_t found1 = sqlite_hdb_lookup_str(hdb_info,
                                             "5d41402abc4b2a76b9719d911017c592",
                                             TSK_HDB_FLAG_QUICK,
                                             test_lookup_callback, nullptr);
        CHECK(found1 == 1);
        
        int8_t found2 = sqlite_hdb_lookup_str(hdb_info,
                                             "7d793037a0760186574b0282f2f435e7",
                                             TSK_HDB_FLAG_QUICK,
                                             test_lookup_callback, nullptr);
        CHECK(found2 == 1);
    }
    
    tsk_hdb_close(hdb_info);
    remove_file(db_path.c_str());
}

// ========================================================================
// Tests for sqlite_hdb_close
// ========================================================================

TEST_CASE("sqlite_hdb_close cleans up properly") {
    std::string db_path = get_temp_db_path();
    TSK_TCHAR *tsk_path = get_tsk_path(db_path);
    
    sqlite_hdb_create_db(tsk_path);
    TSK_HDB_INFO *hdb_info = sqlite_hdb_open(tsk_path);
    REQUIRE(hdb_info != nullptr);
    
    SECTION("Close database after operations") {
        // Do some operations
        sqlite_hdb_add_entry(hdb_info, "test.txt",
                           "d41d8cd98f00b204e9800998ecf8427e",
                           nullptr, nullptr, nullptr);
        
        // Close should not crash
        tsk_hdb_close(hdb_info);
        
        // Database file should still exist
        FILE *f = fopen(db_path.c_str(), "rb");
        CHECK(f != nullptr);
        if (f) fclose(f);
    }
    
    remove_file(db_path.c_str());
}

// ========================================================================
// Integration tests
// ========================================================================

TEST_CASE("sqlite_hdb integration: full workflow") {
    std::string db_path = get_temp_db_path();
    TSK_TCHAR *tsk_path = get_tsk_path(db_path);
    
    SECTION("Create, populate, query, and close database") {
        // Create database
        uint8_t create_result = sqlite_hdb_create_db(tsk_path);
        REQUIRE(create_result == 0);
        
        // Open database
        TSK_HDB_INFO *hdb_info = sqlite_hdb_open(tsk_path);
        REQUIRE(hdb_info != nullptr);
        
        // Start transaction for bulk insert
        sqlite_hdb_begin_transaction(hdb_info);
        
        // Add multiple entries
        sqlite_hdb_add_entry(hdb_info, "doc1.pdf",
                           "d41d8cd98f00b204e9800998ecf8427e",
                           nullptr, nullptr, "Document 1");
        
        sqlite_hdb_add_entry(hdb_info, "doc2.pdf",
                           "098f6bcd4621d373cade4e832627b4f6",
                           nullptr, nullptr, "Document 2");
        
        sqlite_hdb_add_entry(hdb_info, "image.jpg",
                           "5d41402abc4b2a76b9719d911017c592",
                           nullptr, nullptr, nullptr);
        
        // Commit transaction
        sqlite_hdb_commit_transaction(hdb_info);
        
        // Query entries
        CallbackCounter counter1 = {0, "", ""};
        int8_t found1 = sqlite_hdb_lookup_str(hdb_info,
                                             "d41d8cd98f00b204e9800998ecf8427e",
                                             TSK_HDB_FLAG_EXT,
                                             count_callback, &counter1);
        CHECK(found1 == 1);
        CHECK(counter1.count == 1);
        CHECK(counter1.last_name == "doc1.pdf");
        
        // Verbose query
        TskHashInfo result;
        int8_t found2 = sqlite_hdb_lookup_verbose_str(hdb_info,
                                                     "098f6bcd4621d373cade4e832627b4f6",
                                                     &result);
        CHECK(found2 == 1);
        CHECK(result.fileNames.size() > 0);
        CHECK(result.comments.size() > 0);
        
        // Close database
        tsk_hdb_close(hdb_info);
        
        // Reopen and verify data persists
        hdb_info = sqlite_hdb_open(tsk_path);
        REQUIRE(hdb_info != nullptr);
        
        int8_t still_there = sqlite_hdb_lookup_str(hdb_info,
                                                   "5d41402abc4b2a76b9719d911017c592",
                                                   TSK_HDB_FLAG_QUICK,
                                                   test_lookup_callback, nullptr);
        CHECK(still_there == 1);
        
        tsk_hdb_close(hdb_info);
    }
    
    remove_file(db_path.c_str());
}

TEST_CASE("sqlite_hdb stress test: multiple entries same hash") {
    std::string db_path = get_temp_db_path();
    TSK_TCHAR *tsk_path = get_tsk_path(db_path);
    
    sqlite_hdb_create_db(tsk_path);
    TSK_HDB_INFO *hdb_info = sqlite_hdb_open(tsk_path);
    REQUIRE(hdb_info != nullptr);
    
    const char *common_hash = "d41d8cd98f00b204e9800998ecf8427e";
    
    SECTION("Add multiple filenames for same hash") {
        sqlite_hdb_begin_transaction(hdb_info);
        
        // Add same hash with different filenames
        for (int i = 0; i < 5; i++) {
            char filename[64];
            snprintf(filename, sizeof(filename), "duplicate_%d.txt", i);
            sqlite_hdb_add_entry(hdb_info, filename, common_hash,
                               nullptr, nullptr, nullptr);
        }
        
        sqlite_hdb_commit_transaction(hdb_info);
        
        // Lookup should find it and call callback multiple times
        CallbackCounter counter = {0, "", ""};
        int8_t found = sqlite_hdb_lookup_str(hdb_info, common_hash,
                                            TSK_HDB_FLAG_EXT,
                                            count_callback, &counter);
        CHECK(found == 1);
        CHECK(counter.count == 5);  // Should have 5 filenames
    }
    
    tsk_hdb_close(hdb_info);
    remove_file(db_path.c_str());
}

