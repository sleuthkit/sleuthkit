/*
    File Name: test_md5sum.cpp
    Author: Pratik Singh (@singhpratik5)
    Testing: tsk/hashdb/md5sum.cpp
*/

#include "tsk/base/tsk_os.h"
#include "tsk/hashdb/tsk_hashdb_i.h"
#include "catch.hpp"

#include <string>
#include <cstdio>
#include <memory>
#include <cstring>
#include <vector>

#include "test/tools/tsk_tempfile.h"

// Windows-specific helpers to avoid Unicode temp path issues
#ifdef TSK_WIN32
#include <windows.h>
#endif

namespace {

static bool should_skip_index_tests() {
#ifdef TSK_WIN32
	const char* mingw = getenv("MINGW_PREFIX");
	const char* msys = getenv("MSYSTEM");
	// Check for MinGW compiler defines
#ifdef __MINGW32__
	return true;
#elif defined(__MINGW64__)
	return true;
#elif defined(__GNUC__) && defined(_WIN32)
	// GCC on Windows is likely MinGW
	return true;
#else
	return (mingw != nullptr) || (msys != nullptr);
#endif
#else
	return false;
#endif
}

#ifdef TSK_WIN32
struct SimpleFileDeleter {
	std::string path;
	void operator()(FILE* f) const {
		if (f) {
			fclose(f);
		}
		remove(path.c_str());
	}
};

static std::unique_ptr<FILE, SimpleFileDeleter>
	tsk_make_simple_tempfile(std::string& path_out) {
	path_out = "./md5sum_test_temp.db";
	remove(path_out.c_str());
	FILE* f = fopen(path_out.c_str(), "w+b");
	if (!f) {
		return std::unique_ptr<FILE, SimpleFileDeleter>(nullptr, {path_out});
	}
	return std::unique_ptr<FILE, SimpleFileDeleter>(f, {path_out});
}

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

// Helpers to create md5sum format files
// Format 1: "<32hex>  <name>" (spaces), or just the 32 hex chars on a line
static void create_md5sum_db_file_plain(FILE* f) {
	fputs("0123456789abcdef0123456789abcdef  file1.bin\n", f);
	fputs("0123456789abcdef0123456789abcdef  file1.bin\n", f); // duplicate name -> will be de-duped by getentry
	fputs("0123456789abcdef0123456789abcdef  file1_renamed.bin\n", f); // same hash, different name
	fputs("fedcba9876543210fedcba9876543210  other.bin\n", f);
	fflush(f);
}

// Variant with asterisk before name (binary mode style)
static void create_md5sum_db_file_star(FILE* f) {
	fputs("0123456789abcdef0123456789abcdef *star.bin\n", f);
	fflush(f);
}

// Format 2: "MD5 (NAME) = HASH"
static void create_md5sum_db_file_paren(FILE* f) {
	fputs("MD5 (paren1.bin) = 0123456789abcdef0123456789abcdef\n", f);
	fputs("MD5 (paren2.bin) = fedcba9876543210fedcba9876543210\n", f);
	fflush(f);
}

static void create_md5sum_db_file_empty(FILE* f) {
	// no valid entries
	fflush(f);
}

static void create_md5sum_db_file_invalid(FILE* f) {
	fputs("INVALID HEADER\n", f);
	fflush(f);
}

// Find offset to start of line containing the given hash
static bool find_line_offset_for_hash(FILE* f, const char* hash, TSK_OFF_T* out_off) {
	if (!f || !hash || !out_off) return false;
	if (0 != fseeko(f, 0, SEEK_SET)) return false;
	char buf[TSK_HDB_MAXLEN];
	TSK_OFF_T offset = 0;
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

// Callbacks for getentry
static TSK_WALK_RET_ENUM collect_names_cb(TSK_HDB_INFO* hdb_info, const char* hash, const char* name, void* ptr) {
	(void)hdb_info; (void)hash;
	std::vector<std::string>* names = static_cast<std::vector<std::string>*>(ptr);
	if (names) names->push_back(std::string(name ? name : ""));
	return TSK_WALK_CONT;
}

static TSK_WALK_RET_ENUM stop_cb(TSK_HDB_INFO* hdb_info, const char* hash, const char* name, void* ptr) {
	(void)hdb_info; (void)hash; (void)name; (void)ptr;
	return TSK_WALK_STOP;
}

static TSK_WALK_RET_ENUM error_cb(TSK_HDB_INFO* hdb_info, const char* hash, const char* name, void* ptr) {
	(void)hdb_info; (void)hash; (void)name; (void)ptr;
	return TSK_WALK_ERROR;
}

} // namespace

TEST_CASE("md5sum_test recognizes plain and paren formats")
{
	{
		std::unique_ptr<FILE, int (*)(FILE*)> f(tsk_make_tempfile(), &fclose);
		REQUIRE(f != nullptr);
		create_md5sum_db_file_plain(f.get());
		CHECK(md5sum_test(f.get()) == 1);
	}
	{
		std::unique_ptr<FILE, int (*)(FILE*)> f(tsk_make_tempfile(), &fclose);
		REQUIRE(f != nullptr);
		create_md5sum_db_file_paren(f.get());
		CHECK(md5sum_test(f.get()) == 1);
	}
	{
		std::unique_ptr<FILE, int (*)(FILE*)> f(tsk_make_tempfile(), &fclose);
		REQUIRE(f != nullptr);
		create_md5sum_db_file_invalid(f.get());
		CHECK(md5sum_test(f.get()) == 0);
	}
}

TEST_CASE("md5sum_open basic")
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
	create_md5sum_db_file_plain(f.get());

	TSK_HDB_INFO* hdb = md5sum_open(f.get(), path);
	REQUIRE(hdb != nullptr);
	f.release();
	CHECK(hdb->db_type == TSK_HDB_DBTYPE_MD5SUM_ID);
	hdb->close_db(hdb);
}

TEST_CASE("md5sum_makeindex ok / empty / mixed")
{
	if (should_skip_index_tests()) {
		REQUIRE(true);
		return;
	}
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
		create_md5sum_db_file_plain(f.get());
		TSK_HDB_INFO* hdb = md5sum_open(f.get(), path);
		REQUIRE(hdb != nullptr);
		f.release();
		TSK_TCHAR htype[] = _TSK_T("md5sum");
		CHECK(md5sum_makeindex(hdb, htype) == 0);
		hdb->close_db(hdb);
	}
	// empty -> fail
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
		create_md5sum_db_file_empty(f.get());
		TSK_HDB_INFO* hdb = md5sum_open(f.get(), path);
		REQUIRE(hdb != nullptr);
		f.release();
		TSK_TCHAR htype[] = _TSK_T("md5sum");
		CHECK(md5sum_makeindex(hdb, htype) == 1);
		hdb->close_db(hdb);
	}
	// mixed valid/invalid -> still ok (invalid lines ignored)
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
		create_md5sum_db_file_plain(f.get());
		fputs("badline\n", f.get());
		fflush(f.get());
		TSK_HDB_INFO* hdb = md5sum_open(f.get(), path);
		REQUIRE(hdb != nullptr);
		f.release();
		TSK_TCHAR htype[] = _TSK_T("md5sum");
		CHECK(md5sum_makeindex(hdb, htype) == 0);
		hdb->close_db(hdb);
	}
}

TEST_CASE("md5sum_getentry success and variations (plain format)")
{
	if (should_skip_index_tests()) {
		REQUIRE(true);
		return;
	}
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
	create_md5sum_db_file_plain(f.get());

	TSK_OFF_T off = 0;
	REQUIRE(find_line_offset_for_hash(f.get(), "0123456789abcdef0123456789abcdef", &off));

	TSK_HDB_INFO* hdb = md5sum_open(f.get(), path);
	REQUIRE(hdb != nullptr);
	f.release();

	TSK_TCHAR htype[] = _TSK_T("md5sum");
	REQUIRE(md5sum_makeindex(hdb, htype) == 0);

	{
		std::vector<std::string> names;
		CHECK(md5sum_getentry(hdb, "0123456789abcdef0123456789abcdef", off, TSK_HDB_FLAG_QUICK, collect_names_cb, &names) == 0);
		// Should collect two distinct names (duplicate suppressed)
		REQUIRE(names.size() == 2);
		CHECK((names[0] == "file1.bin" || names[1] == "file1.bin"));
		CHECK((names[0] == "file1_renamed.bin" || names[1] == "file1_renamed.bin"));
	}
	{
		std::vector<std::string> names;
		CHECK(md5sum_getentry(hdb, "0123456789abcdef0123456789abcdef", off, TSK_HDB_FLAG_QUICK, stop_cb, &names) == 0);
	}
	{
		std::vector<std::string> names;
		CHECK(md5sum_getentry(hdb, "0123456789abcdef0123456789abcdef", off, TSK_HDB_FLAG_QUICK, error_cb, &names) == 1);
	}
	{
		std::vector<std::string> names;
		CHECK(md5sum_getentry(hdb, "0123456789abcdef", off, TSK_HDB_FLAG_QUICK, collect_names_cb, &names) == 1);
	}
	{
		std::vector<std::string> names;
		CHECK(md5sum_getentry(hdb, "0123456789abcdef0123456789abcdef", 999999, TSK_HDB_FLAG_QUICK, collect_names_cb, &names) == 1);
	}
	hdb->close_db(hdb);
}

TEST_CASE("md5sum_getentry with paren format line")
{
	if (should_skip_index_tests()) {
		REQUIRE(true);
		return;
	}
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
	create_md5sum_db_file_paren(f.get());

	TSK_OFF_T off = 0;
	REQUIRE(find_line_offset_for_hash(f.get(), "0123456789abcdef0123456789abcdef", &off));

	TSK_HDB_INFO* hdb = md5sum_open(f.get(), path);
	REQUIRE(hdb != nullptr);
	f.release();

	TSK_TCHAR htype[] = _TSK_T("md5sum");
	REQUIRE(md5sum_makeindex(hdb, htype) == 0);

	std::vector<std::string> names;
	CHECK(md5sum_getentry(hdb, "0123456789abcdef0123456789abcdef", off, TSK_HDB_FLAG_QUICK, collect_names_cb, &names) == 0);
	REQUIRE(names.size() == 1);
	CHECK(names[0] == "paren1.bin");

	hdb->close_db(hdb);
}

TEST_CASE("md5sum_test recognizes star-format line")
{
	std::unique_ptr<FILE, int (*)(FILE*)> f(tsk_make_tempfile(), &fclose);
	REQUIRE(f != nullptr);
	create_md5sum_db_file_star(f.get());
	CHECK(md5sum_test(f.get()) == 1);
}