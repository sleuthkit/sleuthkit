/*
#include "tsk/base/tsk_os.h"
#include "tsk/hashdb/tsk_hashdb_i.h"
#include "catch.hpp"

#include <string>
#include <cstdio>
#include <memory>

#include "test/tools/tsk_tempfile.h"

// Portable fopen for TSK_TCHAR
static FILE *tsk_fopen_tchar(const TSK_TCHAR *path, const TSK_TCHAR *mode) {
#ifdef _WIN32
    return _wfopen(path, mode);
#else
    return fopen(path, mode);
#endif
}

namespace {

// Helper to write a minimal valid index file for idx-only databases.
static void write_minimal_index_file(FILE *f, const char *dbtype_str, const char *db_name,
                                     const char *hash_entry) {
    fprintf(f, "%s|%s\r\n", "00000000000000000000000000000000000000000", dbtype_str);
    fprintf(f, "%s|%s\r\n", "00000000000000000000000000000000000000001", db_name);

    if (hash_entry && *hash_entry) {
        fprintf(f, "%s|%016llu\r\n", hash_entry, 1ULL);
    }
    fflush(f);
}

struct HdbCloser {
    void operator()(TSK_HDB_INFO *p) const {
        if (p) {
            p->close_db(p);
        }
    }
};

// Simple callback that counts how many times it was invoked.
static TSK_WALK_RET_ENUM count_callback(TSK_HDB_INFO *, const char * , const char *, void *cb_ptr) {
    int *counter = static_cast<int*>(cb_ptr);
    (*counter)++;
    return TSK_WALK_CONT;
}

}

TEST_CASE("idxonly: open md5 index and perform quick and non-quick lookups") {
    std::string base_path;
    FILE *tmp = tsk_make_named_tempfile(&base_path);
    REQUIRE(tmp != nullptr);
    fclose(tmp);

    const std::basic_string<TSK_TCHAR> idx_path = std::basic_string<TSK_TCHAR>(base_path.begin(), base_path.end()) + _TSK_T("-md5.idx");

    FILE *idx = tsk_fopen_tchar(idx_path.c_str(), _TSK_T("w+"));
    REQUIRE(idx != nullptr);

    const char *db_name = "TestIdxOnlyMD5";
    const char *dbtype_str = "md5sum";
    const char *present_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; // 32 hex chars (MD5)
    write_minimal_index_file(idx, dbtype_str, db_name, present_hash);
    fclose(idx);

    // Open via public API in index-only mode
    std::unique_ptr<TSK_HDB_INFO, HdbCloser> hdb{
        tsk_hdb_open(const_cast<TSK_TCHAR*>(idx_path.c_str()), TSK_HDB_OPEN_IDXONLY)
    };
    REQUIRE(hdb != nullptr);

    REQUIRE(tsk_hdb_get_db_path(hdb.get()) == nullptr);

    REQUIRE(tsk_hdb_lookup_str(hdb.get(), present_hash, TSK_HDB_FLAG_QUICK, nullptr, nullptr) == 1);
    REQUIRE(tsk_hdb_lookup_str(hdb.get(), "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", TSK_HDB_FLAG_QUICK, nullptr, nullptr) == 0);

    int cb_count = 0;
    REQUIRE(tsk_hdb_lookup_str(hdb.get(), present_hash, (TSK_HDB_FLAG_ENUM)0, &count_callback, &cb_count) == 1);
    REQUIRE(cb_count == 1);
}

TEST_CASE("idxonly: open sha1 index and perform quick and non-quick lookups") {
    std::string base_path;
    FILE *tmp = tsk_make_named_tempfile(&base_path);
    REQUIRE(tmp != nullptr);
    fclose(tmp);

    const std::basic_string<TSK_TCHAR> idx_path = std::basic_string<TSK_TCHAR>(base_path.begin(), base_path.end()) + _TSK_T("-sha1.idx");

    FILE *idx = tsk_fopen_tchar(idx_path.c_str(), _TSK_T("w+"));
    REQUIRE(idx != nullptr);

    const char *db_name = "TestIdxOnlySHA1";
    const char *dbtype_str = "nsrl";
    const char *present_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; // 40 hex chars (SHA1)
    write_minimal_index_file(idx, dbtype_str, db_name, present_hash);
    fclose(idx);

    std::unique_ptr<TSK_HDB_INFO, HdbCloser> hdb{
        tsk_hdb_open(const_cast<TSK_TCHAR*>(idx_path.c_str()), TSK_HDB_OPEN_IDXONLY)
    };
    REQUIRE(hdb != nullptr);

    REQUIRE(tsk_hdb_get_db_path(hdb.get()) == nullptr);

    REQUIRE(tsk_hdb_lookup_str(hdb.get(), present_hash, TSK_HDB_FLAG_QUICK, nullptr, nullptr) == 1);
    const std::string absent_sha1(40, 'b');
    REQUIRE(tsk_hdb_lookup_str(hdb.get(), absent_sha1.c_str(), TSK_HDB_FLAG_QUICK, nullptr, nullptr) == 0);

    int cb_count = 0;
    REQUIRE(tsk_hdb_lookup_str(hdb.get(), present_hash, (TSK_HDB_FLAG_ENUM)0, &count_callback, &cb_count) == 1);
    REQUIRE(cb_count == 1);
}

TEST_CASE("idxonly: invalid extension fails to open") {
    std::string base_path;
    FILE *tmp = tsk_make_named_tempfile(&base_path);
    REQUIRE(tmp != nullptr);
    fclose(tmp);

    const std::basic_string<TSK_TCHAR> idx_path = std::basic_string<TSK_TCHAR>(base_path.begin(), base_path.end()) + _TSK_T("-sha256.idx"); // unsupported by idxonly

    FILE *idx = tsk_fopen_tchar(idx_path.c_str(), _TSK_T("w+"));
    REQUIRE(idx != nullptr);
    // extension should cause open to fail
    write_minimal_index_file(idx, "md5sum", "BadExt", nullptr);
    fclose(idx);

    TSK_HDB_INFO *hdb = tsk_hdb_open(const_cast<TSK_TCHAR*>(idx_path.c_str()), TSK_HDB_OPEN_IDXONLY);
    REQUIRE(hdb == nullptr);
}
*/
