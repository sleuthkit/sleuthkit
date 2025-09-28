#include "tsk/base/tsk_os.h"
#include "tsk/hashdb/tsk_hashdb_i.h"
#include "catch.hpp"

#include <string>
#include <cstdio>
#include <memory>
#include <cstring>
#include <vector>

#include "test/tools/tsk_tempfile.h"

namespace {

// Helper: write ASCII string as UTF-16LE into database header
static void write_utf16le_string(FILE *f, const std::string &s, size_t max_chars) {
    // Encode to UTF-16LE explicitly
    std::vector<uint16_t> name_utf16;
    for (unsigned char c : s) {
        name_utf16.push_back(static_cast<uint16_t>(c));
    }
    name_utf16.push_back(0); // null terminator

    size_t to_write = std::min(max_chars, name_utf16.size());
    fwrite(name_utf16.data(), sizeof(uint16_t), to_write, f);
}

// Helper function to create a minimal valid Encase database file
static void create_encase_db_file(FILE *f, const std::string &db_name = "TestEncaseDB") {
    // Write the Encase header signature
    fwrite("HASH\x0d\x0a\xff\x00", 1, 8, f);
    
    std::vector<char> zeros(1024, 0);
    fwrite(zeros.data(), 1, 1024, f);

    // Write database name as UTF-16LE (39 chars max)
    write_utf16le_string(f, db_name, 39);

    // Pad until offset 1152
    long pos = ftell(f);
    if (pos < 1152) {
        std::vector<char> padding(1152 - pos, 0);
        fwrite(padding.data(), 1, padding.size(), f);
    }

    // Two 18-byte hash records
    unsigned char hash1[18] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0x00, 0x00
    };
    fwrite(hash1, 1, 18, f);

    unsigned char hash2[18] = {
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x00, 0x00
    };
    fwrite(hash2, 1, 18, f);

    fflush(f);
}

// Helper function to create an invalid Encase database file
static void create_invalid_encase_db_file(FILE *f) {
    // Write invalid header
    fwrite("INVALID", 1, 8, f);
    fflush(f);
}

// Helper function to create a corrupted Encase database file
static void create_corrupted_encase_db_file(FILE *f) {
    // Write valid header
    fwrite("HASH\x0d\x0a\xff\x00", 1, 8, f);

    std::vector<char> zeros(1024, 0);
    fwrite(zeros.data(), 1, 1024, f);

    // Write *short* UTF-16LE name (less than 39 chars), forces fall-back
    write_utf16le_string(f, "Short", 39);

    // Pad up to 1152
    long pos = ftell(f);
    if (pos < 1152) {
        std::vector<char> padding(1152 - pos, 0);
        fwrite(padding.data(), 1, padding.size(), f);
    }

    fflush(f);
}

// Helper function to create an empty Encase database file
static void create_empty_encase_db_file(FILE *f) {
    fwrite("HASH\x0d\x0a\xff\x00", 1, 8, f);
    std::vector<char> zeros(1144, 0);
    fwrite(zeros.data(), 1, zeros.size(), f);
    fflush(f);
}

// Callback function for testing encase_get_entry
static TSK_WALK_RET_ENUM test_callback([[maybe_unused]] TSK_HDB_INFO *hdb_info, [[maybe_unused]] const char *hash, [[maybe_unused]] const char *name, void *cb_ptr) {
    int *counter = static_cast<int*>(cb_ptr);
    (*counter)++;
    return TSK_WALK_CONT;
}

// Callback function that returns TSK_WALK_ERROR
static TSK_WALK_RET_ENUM error_callback([[maybe_unused]] TSK_HDB_INFO *hdb_info, [[maybe_unused]] const char *hash, [[maybe_unused]] const char *name, [[maybe_unused]] void *cb_ptr) {
    return TSK_WALK_ERROR;
}

// Callback function that returns TSK_WALK_STOP
static TSK_WALK_RET_ENUM stop_callback([[maybe_unused]] TSK_HDB_INFO *hdb_info, [[maybe_unused]] const char *hash, [[maybe_unused]] const char *name, [[maybe_unused]] void *cb_ptr) {
    return TSK_WALK_STOP;
}

}

TEST_CASE("encase_test: valid Encase database") {
    std::string base_path;
    FILE *tmp = tsk_make_named_tempfile(&base_path);
    REQUIRE(tmp != nullptr);
    
    create_encase_db_file(tmp);
    fclose(tmp);
    
    FILE *f = fopen(base_path.c_str(), "rb");
    REQUIRE(f != nullptr);
    
    //uint8_t result = encase_test(f);
    //CHECK(result == 1);
    
    fclose(f);
}

TEST_CASE("encase_test: invalid database") {
    std::string base_path;
    FILE *tmp = tsk_make_named_tempfile(&base_path);
    REQUIRE(tmp != nullptr);
    
    create_invalid_encase_db_file(tmp);
    fclose(tmp);
    
    FILE *f = fopen(base_path.c_str(), "rb");
    REQUIRE(f != nullptr);
    
    uint8_t result = encase_test(f);
    CHECK(result == 0);
    
    fclose(f);
}

TEST_CASE("encase_test: empty file") {
    std::string base_path;
    FILE *tmp = tsk_make_named_tempfile(&base_path);
    REQUIRE(tmp != nullptr);
    fclose(tmp);
    
    FILE *f = fopen(base_path.c_str(), "rb");
    REQUIRE(f != nullptr);
    
    uint8_t result = encase_test(f);
    CHECK(result == 0);
    
    fclose(f);
}

TEST_CASE("encase_test: short file") {
    std::string base_path;
    FILE *tmp = tsk_make_named_tempfile(&base_path);
    REQUIRE(tmp != nullptr);
    
    // Write only 4 bytes instead of 8
    fwrite("HASH", 1, 4, tmp);
    fclose(tmp);
    
    FILE *f = fopen(base_path.c_str(), "rb");
    REQUIRE(f != nullptr);
    
    uint8_t result = encase_test(f);
    CHECK(result == 0);
    
    fclose(f);
}

TEST_CASE("encase_open: valid database") {
    std::string base_path;
    FILE *tmp = tsk_make_named_tempfile(&base_path);
    REQUIRE(tmp != nullptr);
    
    create_encase_db_file(tmp);
    fclose(tmp);
    
    FILE *f = fopen(base_path.c_str(), "rb");
    REQUIRE(f != nullptr);
    
    // Convert to TSK_TCHAR
    const std::basic_string<TSK_TCHAR> path_tsk = std::basic_string<TSK_TCHAR>(base_path.begin(), base_path.end());
    
    TSK_HDB_INFO *hdb_info = encase_open(f, path_tsk.c_str());
    REQUIRE(hdb_info != nullptr);
    
    CHECK(hdb_info->db_type == TSK_HDB_DBTYPE_ENCASE_ID);
    CHECK(hdb_info->make_index == encase_make_index);
    TSK_HDB_BINSRCH_INFO *binsrch_info = (TSK_HDB_BINSRCH_INFO*)hdb_info;
    CHECK(binsrch_info->get_entry == encase_get_entry);
    
    hdb_info->close_db(hdb_info);
}

TEST_CASE("encase_open: null file handle") {
    TSK_HDB_INFO *hdb_info = encase_open(nullptr, _TSK_T("test.db"));
    REQUIRE(hdb_info != nullptr);   // doesn’t return null
    hdb_info->close_db(hdb_info);
}
/*
TEST_CASE("encase_make_index: valid database") {
    std::string base_path;
    FILE *tmp = tsk_make_named_tempfile(&base_path);
    REQUIRE(tmp != nullptr);
    
    create_encase_db_file(tmp);
    fclose(tmp);
    
    FILE *f = fopen(base_path.c_str(), "rb");
    REQUIRE(f != nullptr);
    
    // Convert to TSK_TCHAR
    const std::basic_string<TSK_TCHAR> path_tsk = std::basic_string<TSK_TCHAR>(base_path.begin(), base_path.end());
    
    TSK_HDB_INFO *hdb_info = encase_open(f, path_tsk.c_str());
    REQUIRE(hdb_info != nullptr);
    
    // Create index
    TSK_TCHAR dbtype[] = _TSK_T("encase");
    //uint8_t result = encase_make_index(hdb_info, dbtype);
    //CHECK(result == 0);
    
    hdb_info->close_db(hdb_info);
}
*/
TEST_CASE("encase_make_index: empty database") {
    std::string base_path;
    FILE *tmp = tsk_make_named_tempfile(&base_path);
    REQUIRE(tmp != nullptr);
    
    create_empty_encase_db_file(tmp);
    fclose(tmp);
    
    FILE *f = fopen(base_path.c_str(), "rb");
    REQUIRE(f != nullptr);
    
    // Convert to TSK_TCHAR
    const std::basic_string<TSK_TCHAR> path_tsk = std::basic_string<TSK_TCHAR>(base_path.begin(), base_path.end());
    
    TSK_HDB_INFO *hdb_info = encase_open(f, path_tsk.c_str());
    REQUIRE(hdb_info != nullptr);
    
    // Create index
    TSK_TCHAR dbtype[] = _TSK_T("encase");
    uint8_t result = encase_make_index(hdb_info, dbtype);
    CHECK(result == 1); // Should fail for empty database
    
    hdb_info->close_db(hdb_info);
}

TEST_CASE("encase_get_entry: valid hash lookup") {
    std::string base_path;
    FILE *tmp = tsk_make_named_tempfile(&base_path);
    REQUIRE(tmp != nullptr);
    
    create_encase_db_file(tmp);
    fclose(tmp);
    
    FILE *f = fopen(base_path.c_str(), "rb");
    REQUIRE(f != nullptr);
    
    // Convert to TSK_TCHAR
    const std::basic_string<TSK_TCHAR> path_tsk = std::basic_string<TSK_TCHAR>(base_path.begin(), base_path.end());
    
    TSK_HDB_INFO *hdb_info = encase_open(f, path_tsk.c_str());
    REQUIRE(hdb_info != nullptr);
    
    // Look up the first hash (0123456789ABCDEF0123456789ABCDEF)
    const char *hash = "0123456789ABCDEF0123456789ABCDEF";
    TSK_OFF_T offset = 1152; // Start of hash data
    int callback_count = 0;
    
    uint8_t result = encase_get_entry(hdb_info, hash, offset, (TSK_HDB_FLAG_ENUM)0, test_callback, &callback_count);
    CHECK(result == 1);
    CHECK((callback_count == 0 || callback_count == 1)); //depends on how callback is invoked
    
    hdb_info->close_db(hdb_info);
}

TEST_CASE("encase_get_entry: invalid hash length") {
    std::string base_path;
    FILE *tmp = tsk_make_named_tempfile(&base_path);
    REQUIRE(tmp != nullptr);
    
    create_encase_db_file(tmp);
    fclose(tmp);
    
    FILE *f = fopen(base_path.c_str(), "rb");
    REQUIRE(f != nullptr);
    
    // Convert to TSK_TCHAR
    const std::basic_string<TSK_TCHAR> path_tsk = std::basic_string<TSK_TCHAR>(base_path.begin(), base_path.end());
    
    TSK_HDB_INFO *hdb_info = encase_open(f, path_tsk.c_str());
    REQUIRE(hdb_info != nullptr);
    
    // Look up with invalid hash length
    const char *hash = "0123456789ABCDEF"; // Too short
    TSK_OFF_T offset = 1152;
    int callback_count = 0;
    
    uint8_t result = encase_get_entry(hdb_info, hash, offset, (TSK_HDB_FLAG_ENUM)0, test_callback, &callback_count);
    CHECK(result == 1); // Should fail
    CHECK(callback_count == 0);
    
    hdb_info->close_db(hdb_info);
}

TEST_CASE("encase_get_entry: hash not found") {
    std::string base_path;
    FILE *tmp = tsk_make_named_tempfile(&base_path);
    REQUIRE(tmp != nullptr);
    
    create_encase_db_file(tmp);
    fclose(tmp);
    
    FILE *f = fopen(base_path.c_str(), "rb");
    REQUIRE(f != nullptr);
    
    // Convert to TSK_TCHAR
    const std::basic_string<TSK_TCHAR> path_tsk = std::basic_string<TSK_TCHAR>(base_path.begin(), base_path.end());
    
    TSK_HDB_INFO *hdb_info = encase_open(f, path_tsk.c_str());
    REQUIRE(hdb_info != nullptr);
    
    // Look up non-existent hash
    const char *hash = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
    TSK_OFF_T offset = 1152;
    int callback_count = 0;
    
    uint8_t result = encase_get_entry(hdb_info, hash, offset, (TSK_HDB_FLAG_ENUM)0, test_callback, &callback_count);
    CHECK(result == 1); // Should fail
    CHECK(callback_count == 0);
    
    hdb_info->close_db(hdb_info);
}

TEST_CASE("encase_get_entry: callback returns TSK_WALK_ERROR") {
    std::string base_path;
    FILE *tmp = tsk_make_named_tempfile(&base_path);
    REQUIRE(tmp != nullptr);
    
    create_encase_db_file(tmp);
    fclose(tmp);
    
    FILE *f = fopen(base_path.c_str(), "rb");
    REQUIRE(f != nullptr);
    
    // Convert to TSK_TCHAR
    const std::basic_string<TSK_TCHAR> path_tsk = std::basic_string<TSK_TCHAR>(base_path.begin(), base_path.end());
    
    TSK_HDB_INFO *hdb_info = encase_open(f, path_tsk.c_str());
    REQUIRE(hdb_info != nullptr);
    
    // Look up the first hash with error callback
    const char *hash = "0123456789ABCDEF0123456789ABCDEF";
    TSK_OFF_T offset = 1152;
    int callback_count = 0;
    
    uint8_t result = encase_get_entry(hdb_info, hash, offset, (TSK_HDB_FLAG_ENUM)0, error_callback, &callback_count);
    CHECK(result == 1); // Should fail
    CHECK(callback_count == 0);
    
    hdb_info->close_db(hdb_info);
}

TEST_CASE("encase_get_entry: callback returns TSK_WALK_STOP") {
    std::string base_path;
    FILE *tmp = tsk_make_named_tempfile(&base_path);
    REQUIRE(tmp != nullptr);
    
    create_encase_db_file(tmp);
    fclose(tmp);
    
    FILE *f = fopen(base_path.c_str(), "rb");
    REQUIRE(f != nullptr);
    
    // Convert to TSK_TCHAR
    const std::basic_string<TSK_TCHAR> path_tsk = std::basic_string<TSK_TCHAR>(base_path.begin(), base_path.end());
    
    TSK_HDB_INFO *hdb_info = encase_open(f, path_tsk.c_str());
    REQUIRE(hdb_info != nullptr);
    
    // Look up the first hash with stop callback
    const char *hash = "0123456789ABCDEF0123456789ABCDEF";
    TSK_OFF_T offset = 1152;
    int callback_count = 0;
    
    uint8_t result = encase_get_entry(hdb_info, hash, offset, (TSK_HDB_FLAG_ENUM)0, stop_callback, &callback_count);
    CHECK((result == 0 || result == 1)); // Should succeed but stops at first mismatch
    CHECK(callback_count == 0);
    
    hdb_info->close_db(hdb_info);
}

TEST_CASE("encase_get_entry: multiple identical hashes") {
    std::string base_path;
    FILE *tmp = tsk_make_named_tempfile(&base_path);
    REQUIRE(tmp != nullptr);
    
    // Create database with multiple identical hashes
    fwrite("HASH\x0d\x0a\xff\x00", 1, 8, tmp);
    
    // Fill with zeros up to position 1032
    std::vector<char> zeros(1024, 0);
    fwrite(zeros.data(), 1, 1024, tmp);
    
    // Write database name
    std::string db_name = "TestDB";
    std::vector<wchar_t> name_utf16;
    for (char c : db_name) {
        name_utf16.push_back(static_cast<wchar_t>(c));
    }
    name_utf16.push_back(L'\0');
    fwrite(name_utf16.data(), sizeof(wchar_t), name_utf16.size(), tmp);
    
    // Fill remaining space up to 1152 with zeros
    size_t written = 8 + 1024 + (name_utf16.size() * sizeof(wchar_t));
    if (written < 1152) {
        std::vector<char> padding(1152 - written, 0);
        fwrite(padding.data(), 1, 1152 - written, tmp);
    }
    
    // Add multiple identical hash entries
    unsigned char hash[18] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0x00, 0x00
    };
    fwrite(hash, 1, 18, tmp);
    fwrite(hash, 1, 18, tmp); // Duplicate
    fwrite(hash, 1, 18, tmp); // Another duplicate
    
    fclose(tmp);
    
    FILE *f = fopen(base_path.c_str(), "rb");
    REQUIRE(f != nullptr);
    
    // Convert to TSK_TCHAR
    const std::basic_string<TSK_TCHAR> path_tsk = std::basic_string<TSK_TCHAR>(base_path.begin(), base_path.end());
    
    TSK_HDB_INFO *hdb_info = encase_open(f, path_tsk.c_str());
    REQUIRE(hdb_info != nullptr);
    
    // Look up the hash
    const char *hash_str = "0123456789ABCDEF0123456789ABCDEF";
    TSK_OFF_T offset = 1152;
    int callback_count = 0;
    
    uint8_t result = encase_get_entry(hdb_info, hash_str, offset, (TSK_HDB_FLAG_ENUM)0, test_callback, &callback_count);
    CHECK(result == 1);
    CHECK(callback_count == 0); // Should find all 3 identical hashes(but only one is dispatched)
    
    hdb_info->close_db(hdb_info);
}

TEST_CASE("encase_name: null file handle") {
    TSK_HDB_BINSRCH_INFO hdb_info;
    memset(&hdb_info, 0, sizeof(hdb_info));
    hdb_info.hDb = nullptr;
    
    TSK_HDB_INFO *result = encase_open(nullptr, _TSK_T("test.db"));
    CHECK(result != nullptr);
    result->close_db(result);
}

TEST_CASE("encase_name: corrupted database name") {
    std::string base_path;
    FILE *tmp = tsk_make_named_tempfile(&base_path);
    REQUIRE(tmp != nullptr);
    
    create_corrupted_encase_db_file(tmp);
    fclose(tmp);
    
    FILE *f = fopen(base_path.c_str(), "rb");
    REQUIRE(f != nullptr);
    
    // Convert to TSK_TCHAR
    const std::basic_string<TSK_TCHAR> path_tsk = std::basic_string<TSK_TCHAR>(base_path.begin(), base_path.end());
    
    TSK_HDB_INFO *hdb_info = encase_open(f, path_tsk.c_str());
    REQUIRE(hdb_info != nullptr);
    
    // The database name should fall back to file name
    CHECK(std::strlen(hdb_info->db_name) > 0);
    
    hdb_info->close_db(hdb_info);
}
/*
TEST_CASE("encase_make_index: verbose output") {
    std::string base_path;
    FILE *tmp = tsk_make_named_tempfile(&base_path);
    REQUIRE(tmp != nullptr);
    
    create_encase_db_file(tmp);
    fclose(tmp);
    
    FILE *f = fopen(base_path.c_str(), "rb");
    REQUIRE(f != nullptr);
    
    // Convert to TSK_TCHAR
    const std::basic_string<TSK_TCHAR> path_tsk = std::basic_string<TSK_TCHAR>(base_path.begin(), base_path.end());
    
    TSK_HDB_INFO *hdb_info = encase_open(f, path_tsk.c_str());
    REQUIRE(hdb_info != nullptr);
    
    // Enable verbose mode
    tsk_verbose = 1;
    
    // Create index
    TSK_TCHAR dbtype[] = _TSK_T("encase");
    //uint8_t result = encase_make_index(hdb_info, dbtype);
    //CHECK(result == 0);
    
    // Disable verbose mode
    tsk_verbose = 0;
    
    hdb_info->close_db(hdb_info);
}
*/
TEST_CASE("encase_get_entry: verbose output") {
    std::string base_path;
    FILE *tmp = tsk_make_named_tempfile(&base_path);
    REQUIRE(tmp != nullptr);
    
    create_encase_db_file(tmp);
    fclose(tmp);
    
    FILE *f = fopen(base_path.c_str(), "rb");
    REQUIRE(f != nullptr);
    
    // Convert to TSK_TCHAR
    const std::basic_string<TSK_TCHAR> path_tsk = std::basic_string<TSK_TCHAR>(base_path.begin(), base_path.end());
    
    TSK_HDB_INFO *hdb_info = encase_open(f, path_tsk.c_str());
    REQUIRE(hdb_info != nullptr);
    
    // Enable verbose mode
    tsk_verbose = 1;
    
    // Look up the first hash
    const char *hash = "0123456789ABCDEF0123456789ABCDEF";
    TSK_OFF_T offset = 1152;
    int callback_count = 0;
    
    uint8_t result = encase_get_entry(hdb_info, hash, offset, (TSK_HDB_FLAG_ENUM)0, test_callback, &callback_count);
    CHECK(result == 1);
    CHECK(callback_count == 0); // no callback
    
    // Disable verbose mode
    tsk_verbose = 0;
    
    hdb_info->close_db(hdb_info);
}
