/*
    File Name: test_hashkeeper.cpp
    Author: Pratik Singh (@singhpratik5)
    Testing: tsk/hashdb/hashkeeper.c (HK db)
*/

#include "tsk/base/tsk_os.h"
#include "tsk/hashdb/tsk_hashdb_i.h"
#include "catch.hpp"

#include <string>
#include <cstdio>
#include <memory>
#include <cstring>
#include <vector>
#include <stdexcept>

#include "test/tools/tsk_tempfile.h"

#ifdef TSK_WIN32
#include <windows.h>
#endif

namespace {

#ifdef TSK_WIN32
// Custom deleter for unique_ptr to close the FILE handle and remove the file.
struct SimpleFileDeleter {
    std::string path;
    void operator()(FILE* f) const {
        if (f) {
            fclose(f);
        }
        remove(path.c_str());
    }
};

// Creates a temporary file with a simple, pure-ASCII name in the current
// directory. This works around a known bug in the TSK library where it cannot
// handle standard Windows temporary paths that contain Unicode characters.
static std::unique_ptr<FILE, SimpleFileDeleter>
tsk_make_simple_tempfile(std::string& path_out) {
    path_out = "./hashkeeper_test_temp.db";
    remove(path_out.c_str()); // Clean up from any previous failed run
    FILE* f = fopen(path_out.c_str(), "w+b");
    if (!f) {
        return std::unique_ptr<FILE, SimpleFileDeleter>(nullptr, {path_out});
    }
    return std::unique_ptr<FILE, SimpleFileDeleter>(f, {path_out});
}

// Helper to convert a std::string path to the std::wstring that
// the hk_open function signature expects on Windows.
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


// Helper: write a correct HashKeeper header
static void write_hk_header(FILE *f) {
    fputs("\"file_id\",\"hashset_id\",\"file_name\",\"directory\",\"hash\",\"file_size\",\"date_modified\",\"time_modified\",\"time_zone\",\"comments\",\"date_accessed\",\"time_accessed\"\n", f);
}

// Helper: create a valid HashKeeper database file with 2-3 rows
static void create_hashkeeper_db_file(FILE *f) {
    write_hk_header(f);
    fputs("1,1,\"test1.txt\",\"C:\\Windows\\System32\",\"0123456789ABCDEF0123456789ABCDEF\",1024,\"2023-01-01\",\"12:00:00\",\"UTC\",\"Test file 1\",\"2023-01-01\",\"12:00:00\"\n", f);
    fputs("2,1,\"test2.txt\",\"C:\\Windows\",\"FEDCBA9876543210FEDCBA9876543210\",2048,\"2023-01-02\",\"13:00:00\",\"UTC\",\"Test file 2\",\"2023-01-02\",\"13:00:00\"\n", f);
    fflush(f);
}

// Helper: create malformed HK db (one good row, one malformed)
static void create_malformed_hashkeeper_db_file(FILE *f) {
    write_hk_header(f);
    fputs("1,1,\"test1.txt\",\"C:\\Windows\\System32\",\"0123456789ABCDEF0123456789ABCDEF\",1024,\"2023-01-01\",\"12:00:00\",\"UTC\",\"Test file 1\",\"2023-01-01\",\"12:00:00\"\n", f);
    fputs("malformed_entry\n", f);
    fflush(f);
}

// Helper: duplicate-hash HK db (same hash, different names)
static void create_same_hash_different_names_hashkeeper_db_file(FILE *f) {
    write_hk_header(f);
    fputs("1,1,\"test1.txt\",\"C:\\Windows\\System32\",\"0123456789ABCDEF0123456789ABCDEF\",1024,\"2023-01-01\",\"12:00:00\",\"UTC\",\"Test file 1\",\"2023-01-01\",\"12:00:00\"\n", f);
    fputs("2,1,\"test1_renamed.txt\",\"C:\\Windows\\System32\",\"0123456789ABCDEF0123456789ABCDEF\",1024,\"2023-01-01\",\"12:00:00\",\"UTC\",\"Test file 1 renamed\",\"2023-01-01\",\"12:00:00\"\n", f);
    fflush(f);
}

// Helper: header-only HK db
static void create_empty_hashkeeper_db_file(FILE *f) {
    write_hk_header(f);
    fflush(f);
}

// Helper: invalid (non-HK) file
static void create_invalid_hashkeeper_db_file(FILE *f) {
    fputs("Invalid header\n", f);
    fputs("1,1,test1.txt,C:\\\\Windows\\\\System32,0123456789ABCDEF0123456789ABCDEF,1024,2023-01-01,12:00:00,UTC,Test file 1,2023-01-01,12:00:00\n", f);
    fflush(f);
}

// Helper: find file offset of the line containing target hash (start-of-line offset)
static bool find_line_offset_for_hash(FILE *f, const char *hash, TSK_OFF_T *out_off) {
    if (!f || !hash || !out_off) return false;
    if (0 != fseeko(f, 0, SEEK_SET)) return false;
    char buf[TSK_HDB_MAXLEN];
    TSK_OFF_T offset = 0;
    if (nullptr == fgets(buf, sizeof(buf), f)) return false;
    offset += (TSK_OFF_T)strlen(buf);
    while (nullptr != fgets(buf, sizeof(buf), f)) {
        size_t len = strlen(buf);
        if (strstr(buf, hash) != nullptr) {
            *out_off = offset;
            return true;
        }
        offset += (TSK_OFF_T)len;
    }
    return false;
}

// Callbacks
static TSK_WALK_RET_ENUM test_lookup_callback(TSK_HDB_INFO *hdb_info, const char *hash, const char *name, void *ptr) {
    (void)hdb_info; (void)hash;
    std::vector<std::string> *found_names = static_cast<std::vector<std::string>*>(ptr);
    if (found_names) found_names->push_back(std::string(name));
    return TSK_WALK_CONT;
}

static TSK_WALK_RET_ENUM test_lookup_callback_stop(TSK_HDB_INFO *hdb_info, const char *hash, const char *name, void *ptr) {
    (void)hdb_info; (void)hash; (void)name; (void)ptr;
    return TSK_WALK_STOP;
}

static TSK_WALK_RET_ENUM test_lookup_callback_error(TSK_HDB_INFO *hdb_info, const char *hash, const char *name, void *ptr) {
    (void)hdb_info; (void)hash; (void)name; (void)ptr;
    return TSK_WALK_ERROR;
}

} // namespace

TEST_CASE("hk_test with valid HK db")
{
    std::unique_ptr<FILE, int (*)(FILE*)> f(tsk_make_tempfile(), &fclose);
    REQUIRE(f != nullptr);
    create_hashkeeper_db_file(f.get());
    CHECK(hk_test(f.get()) == 1);
}

TEST_CASE("hk_test with invalid db")
{
    std::unique_ptr<FILE, int (*)(FILE*)> f(tsk_make_tempfile(), &fclose);
    REQUIRE(f != nullptr);
    create_invalid_hashkeeper_db_file(f.get());
    CHECK(hk_test(f.get()) == 0);
}

TEST_CASE("hk_test with short header")
{
    std::unique_ptr<FILE, int (*)(FILE*)> f(tsk_make_tempfile(), &fclose);
    REQUIRE(f != nullptr);
    fputs("\"file_id\",\"hashset_id\"\n", f.get());
    fputs("1,1,\"test1.txt\",\"C:\\\\Windows\\\\System32\",\"0123456789ABCDEF0123456789ABCDEF\",1024,\"2023-01-01\",\"12:00:00\",\"UTC\",\"Test file 1\",\"2023-01-01\",\"12:00:00\"\n", f.get());
    fflush(f.get());
    CHECK(hk_test(f.get()) == 0);
}

TEST_CASE("hk_open basic")
{
#ifdef TSK_WIN32
    std::string path_s;
    auto f = tsk_make_simple_tempfile(path_s);
    std::wstring path_w = string_to_wstring(path_s);
    const TSK_TCHAR* path = path_w.c_str();
#else
    std::string path_s;
    std::unique_ptr<FILE, int (*)(FILE*)> f(tsk_make_named_tempfile(&path_s), &fclose);
    const TSK_TCHAR* path = path_s.c_str();
#endif
    REQUIRE(f != nullptr);
    create_hashkeeper_db_file(f.get());
    TSK_HDB_INFO *hdb = hk_open(f.get(), path);
    REQUIRE(hdb != nullptr);
    f.release(); // hdb now owns the file handle
    CHECK(hdb->db_type == TSK_HDB_DBTYPE_HK_ID);
    hdb->close_db(hdb);
}

// The following tests for hk_makeindex and hk_getentry will fail on MinGW
// because the TSK library has a hardcoded path to "C:\WINDOWS\System32\sort.exe"
// which is not present in the MSYS2/MinGW environment.
#if !(defined(__MINGW32__) || defined(__MINGW64__))

TEST_CASE("hk_makeindex ok / empty / malformed")
{
    // ok
    {
#ifdef TSK_WIN32
        std::string path_s;
        auto f = tsk_make_simple_tempfile(path_s);
        std::wstring path_w = string_to_wstring(path_s);
        const TSK_TCHAR* path = path_w.c_str();
#else
        std::string path_s;
        std::unique_ptr<FILE, int (*)(FILE*)> f(tsk_make_named_tempfile(&path_s), &fclose);
        const TSK_TCHAR* path = path_s.c_str();
#endif
        REQUIRE(f != nullptr);
        create_hashkeeper_db_file(f.get());
        TSK_HDB_INFO* hdb = hk_open(f.get(), path);
        REQUIRE(hdb != nullptr);
        f.release();
        TSK_TCHAR htype[] = _TSK_T("hk");
        CHECK(hk_makeindex(hdb, htype) == 0);
        hdb->close_db(hdb);
    }
    // empty → fail
    {
#ifdef TSK_WIN32
        std::string path_s;
        auto f = tsk_make_simple_tempfile(path_s);
        std::wstring path_w = string_to_wstring(path_s);
        const TSK_TCHAR* path = path_w.c_str();
#else
        std::string path_s;
        std::unique_ptr<FILE, int (*)(FILE*)> f(tsk_make_named_tempfile(&path_s), &fclose);
        const TSK_TCHAR* path = path_s.c_str();
#endif
        REQUIRE(f != nullptr);
        create_empty_hashkeeper_db_file(f.get());
        TSK_HDB_INFO* hdb = hk_open(f.get(), path);
        REQUIRE(hdb != nullptr);
        f.release();
        TSK_TCHAR htype[] = _TSK_T("hk");
        CHECK(hk_makeindex(hdb, htype) == 1);
        hdb->close_db(hdb);
    }
    // malformed but with at least one valid row → still ok
    {
#ifdef TSK_WIN32
        std::string path_s;
        auto f = tsk_make_simple_tempfile(path_s);
        std::wstring path_w = string_to_wstring(path_s);
        const TSK_TCHAR* path = path_w.c_str();
#else
        std::string path_s;
        std::unique_ptr<FILE, int (*)(FILE*)> f(tsk_make_named_tempfile(&path_s), &fclose);
        const TSK_TCHAR* path = path_s.c_str();
#endif
        REQUIRE(f != nullptr);
        create_malformed_hashkeeper_db_file(f.get());
        TSK_HDB_INFO* hdb = hk_open(f.get(), path);
        REQUIRE(hdb != nullptr);
        f.release();
        TSK_TCHAR htype[] = _TSK_T("hk");
        CHECK(hk_makeindex(hdb, htype) == 0);
        hdb->close_db(hdb);
    }
}

TEST_CASE("hk_getentry success and variations")
{
#ifdef TSK_WIN32
    std::string path_s;
    auto f = tsk_make_simple_tempfile(path_s);
    std::wstring path_w = string_to_wstring(path_s);
    const TSK_TCHAR* path = path_w.c_str();
#else
    std::string path_s;
    std::unique_ptr<FILE, int (*)(FILE*)> f(tsk_make_named_tempfile(&path_s), &fclose);
    const TSK_TCHAR* path = path_s.c_str();
#endif
    REQUIRE(f != nullptr);
    create_hashkeeper_db_file(f.get());

    TSK_OFF_T off = 0;
    REQUIRE(find_line_offset_for_hash(f.get(), "0123456789ABCDEF0123456789ABCDEF", &off));

    TSK_HDB_INFO *hdb = hk_open(f.get(), path);
    REQUIRE(hdb != nullptr);
    f.release();

    TSK_TCHAR htype[] = _TSK_T("hk");
    REQUIRE(hk_makeindex(hdb, htype) == 0);

    // normal callback
    {
        std::vector<std::string> names;
        CHECK(hk_getentry(hdb, "0123456789ABCDEF0123456789ABCDEF", off, TSK_HDB_FLAG_QUICK, test_lookup_callback, &names) == 0);
        REQUIRE(names.size() == 1);
        CHECK(names[0] == "C:\\Windows\\System32\\test1.txt");
    }

    // stop callback
    {
        std::vector<std::string> names;
        CHECK(hk_getentry(hdb, "0123456789ABCDEF0123456789ABCDEF", off, TSK_HDB_FLAG_QUICK, test_lookup_callback_stop, &names) == 0);
    }

    // error callback
    {
        std::vector<std::string> names;
        CHECK(hk_getentry(hdb, "0123456789ABCDEF0123456789ABCDEF", off, TSK_HDB_FLAG_QUICK, test_lookup_callback_error, &names) == 1);
    }

    // invalid hash length
    {
        std::vector<std::string> names;
        CHECK(hk_getentry(hdb, "0123456789ABCDEF", off, TSK_HDB_FLAG_QUICK, test_lookup_callback, &names) == 1);
    }

    // invalid offset
    {
        std::vector<std::string> names;
        CHECK(hk_getentry(hdb, "0123456789ABCDEF0123456789ABCDEF", 999999, TSK_HDB_FLAG_QUICK, test_lookup_callback, &names) == 1);
    }
    hdb->close_db(hdb);
}

TEST_CASE("hk_getentry same-hash different-names yields two callbacks")
{
#ifdef TSK_WIN32
    std::string path_s;
    auto f = tsk_make_simple_tempfile(path_s);
    std::wstring path_w = string_to_wstring(path_s);
    const TSK_TCHAR* path = path_w.c_str();
#else
    std::string path_s;
    std::unique_ptr<FILE, int (*)(FILE*)> f(tsk_make_named_tempfile(&path_s), &fclose);
    const TSK_TCHAR* path = path_s.c_str();
#endif
    REQUIRE(f != nullptr);
    create_same_hash_different_names_hashkeeper_db_file(f.get());

    TSK_OFF_T off = 0;
    REQUIRE(find_line_offset_for_hash(f.get(), "0123456789ABCDEF0123456789ABCDEF", &off));

    TSK_HDB_INFO *hdb = hk_open(f.get(), path);
    REQUIRE(hdb != nullptr);
    f.release();

    TSK_TCHAR htype[] = _TSK_T("hk");
    REQUIRE(hk_makeindex(hdb, htype) == 0);


    std::vector<std::string> names;
    CHECK(hk_getentry(hdb, "0123456789ABCDEF0123456789ABCDEF", off, TSK_HDB_FLAG_QUICK, test_lookup_callback, &names) == 0);
    CHECK(names.size() == 2);
    hdb->close_db(hdb);
}

#endif // #if !(defined(__MINGW32__) || defined(__MINGW64__))

