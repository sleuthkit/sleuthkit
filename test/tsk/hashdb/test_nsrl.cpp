/*
    File Name: test_nsrl.cpp
    Author: Pratik Singh (@singhpratik5)
    Testing: tsk/hashdb/nsrl.cpp (NSRL specific functions to read the database.)
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
	path_out = "./nsrl_test_temp.db";
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

// Helper functions to create NSRL format files
// Format 1: "SHA-1","FileName","FileSize","ProductCode","OpSystemCode","MD4","MD5","CRC32","SpecialCode"
static void create_nsrl_format1_db_file(FILE* f) {
	// Header line
	fputs("\"SHA-1\",\"FileName\",\"FileSize\",\"ProductCode\",\"OpSystemCode\",\"MD4\",\"MD5\",\"CRC32\",\"SpecialCode\"\n", f);
	// Data lines - SHA1 hashes must be exactly 40 hex characters and NOT all zeros
	fputs("\"A000000000000000000000000000000000000000\",\"file1.bin\",\"1024\",\"123\",\"456\",\"\",\"11111111111111111111111111111111\",\"00000000\",\"\"\n", f);
	fputs("\"A000000000000000000000000000000000000000\",\"file1_dup.bin\",\"2048\",\"123\",\"456\",\"\",\"11111111111111111111111111111111\",\"00000000\",\"\"\n", f);
	fputs("\"B111111111111111111111111111111111111111\",\"file2.bin\",\"4096\",\"789\",\"012\",\"\",\"22222222222222222222222222222222\",\"11111111\",\"\"\n", f);
	fflush(f);
}

// Format 2: "SHA-1","MD5","CRC32","FileName","FileSize","ProductCode","OpSystemCode","SpecialCode"
static void create_nsrl_format2_db_file(FILE* f) {
	// Header line
	fputs("\"SHA-1\",\"MD5\",\"CRC32\",\"FileName\",\"FileSize\",\"ProductCode\",\"OpSystemCode\",\"SpecialCode\"\n", f);
	// Data lines
	fputs("\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"11111111111111111111111111111111\",\"aaaaaaaa\",\"format2_file1.bin\",\"1024\",\"123\",\"456\",\"\"\n", f);
	fputs("\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"11111111111111111111111111111111\",\"aaaaaaaa\",\"format2_file1_dup.bin\",\"2048\",\"123\",\"456\",\"\"\n", f);
	fputs("\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"22222222222222222222222222222222\",\"bbbbbbbb\",\"format2_file2.bin\",\"4096\",\"789\",\"012\",\"\"\n", f);
	fflush(f);
}

static void create_nsrl_db_file_empty(FILE* f) {
	// Header only, no data
	fputs("\"SHA-1\",\"FileName\",\"FileSize\",\"ProductCode\",\"OpSystemCode\",\"MD4\",\"MD5\",\"CRC32\",\"SpecialCode\"\n", f);
	fflush(f);
}

static void create_nsrl_db_file_invalid(FILE* f) {
	fputs("INVALID HEADER\n", f);
	fflush(f);
}

static void create_nsrl_db_file_invalid_header_format(FILE* f) {
	// Wrong header format
	fputs("\"SHA-1\",\"WrongField\",\"FileSize\"\n", f);
	fflush(f);
}

static void create_nsrl_db_file_invalid_data(FILE* f) __attribute__((unused)); // Unused
static void create_nsrl_db_file_invalid_data(FILE* f) {
	// Valid header, invalid data
	fputs("\"SHA-1\",\"FileName\",\"FileSize\",\"ProductCode\",\"OpSystemCode\",\"MD4\",\"MD5\",\"CRC32\",\"SpecialCode\"\n", f);
	fputs("INVALID DATA LINE\n", f);
	fputs("\"11111111111111111111111111111111111111111\",\"file2.bin\",\"4096\",\"789\",\"012\",\"\",\"22222222222222222222222222222222\",\"11111111\",\"\"\n", f);
	fflush(f);
}
/* //Commenting out
static void create_nsrl_db_file_no_header(FILE* f) {
	// No header line
	fputs("\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"11111111111111111111111111111111\",\"aaaaaaaa\",\"file1.bin\",\"1024\",\"123\",\"456\",\"\"\n", f);
	fflush(f);
}
*/
static void create_nsrl_db_file_too_short(FILE* f) {
	// Line shorter than 45 characters
	fputs("\"SHA\"\n", f);
	fflush(f);
}

static void create_nsrl_db_file_wrong_prefix(FILE* f) {
	// Not starting with "SHA-1"
	fputs("\"MD5\",\"FileName\",\"FileSize\"\n", f);
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

TEST_CASE("nsrl_test recognizes format 1 and format 2 databases")
{
	// Format 1 database
	{
		std::unique_ptr<FILE, int (*)(FILE*)> f(tsk_make_tempfile(), &fclose);
		REQUIRE(f != nullptr);
		create_nsrl_format1_db_file(f.get());
		CHECK(nsrl_test(f.get()) == 1);
	}

	// Format 2 database
	{
		std::unique_ptr<FILE, int (*)(FILE*)> f(tsk_make_tempfile(), &fclose);
		REQUIRE(f != nullptr);
		create_nsrl_format2_db_file(f.get());
		CHECK(nsrl_test(f.get()) == 1);
	}

	// Invalid database
	{
		std::unique_ptr<FILE, int (*)(FILE*)> f(tsk_make_tempfile(), &fclose);
		REQUIRE(f != nullptr);
		create_nsrl_db_file_invalid(f.get());
		CHECK(nsrl_test(f.get()) == 0);
	}

	// Database with wrong prefix
	{
		std::unique_ptr<FILE, int (*)(FILE*)> f(tsk_make_tempfile(), &fclose);
		REQUIRE(f != nullptr);
		create_nsrl_db_file_wrong_prefix(f.get());
		CHECK(nsrl_test(f.get()) == 0);
	}

	// Database that's too short
	{
		std::unique_ptr<FILE, int (*)(FILE*)> f(tsk_make_tempfile(), &fclose);
		REQUIRE(f != nullptr);
		create_nsrl_db_file_too_short(f.get());
		CHECK(nsrl_test(f.get()) == 0);
	}

	// Empty file
	{
		std::unique_ptr<FILE, int (*)(FILE*)> f(tsk_make_tempfile(), &fclose);
		REQUIRE(f != nullptr);
		CHECK(nsrl_test(f.get()) == 0);
	}

	// Invalid header format
	{
		std::unique_ptr<FILE, int (*)(FILE*)> f(tsk_make_tempfile(), &fclose);
		REQUIRE(f != nullptr);
		create_nsrl_db_file_invalid_header_format(f.get());
		CHECK(nsrl_test(f.get()) == 0);
	}
}

TEST_CASE("nsrl_open basic")
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
	create_nsrl_format1_db_file(f.get());
	
    // Ensure data is written and file is at beginning
    fflush(f.get());
    rewind(f.get());
	
	TSK_HDB_INFO* hdb = nsrl_open(f.get(), path);
	REQUIRE(hdb != nullptr);
	f.release();
	CHECK(hdb->db_type == TSK_HDB_DBTYPE_NSRL_ID);
	hdb->close_db(hdb);
}

TEST_CASE("nsrl_open format 2")
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
	create_nsrl_format2_db_file(f.get());

	// Ensure data is written and file is at beginning
    fflush(f.get());
    rewind(f.get());
	
	TSK_HDB_INFO* hdb = nsrl_open(f.get(), path);
	REQUIRE(hdb != nullptr);
	f.release();
	CHECK(hdb->db_type == TSK_HDB_DBTYPE_NSRL_ID);
	hdb->close_db(hdb);
}

TEST_CASE("nsrl_makeindex format 1 with SHA1")
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
	create_nsrl_format1_db_file(f.get());
	
    // Ensure data is written and file is at beginning
    fflush(f.get());
    rewind(f.get());
	
	TSK_HDB_INFO* hdb = nsrl_open(f.get(), path);
	REQUIRE(hdb != nullptr);
	f.release();

	TSK_TCHAR htype[] = _TSK_T("nsrl-sha1");
	CHECK(nsrl_makeindex(hdb, htype) == 0);
	hdb->close_db(hdb);
}

TEST_CASE("nsrl_makeindex format 1 with MD5")
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
	create_nsrl_format1_db_file(f.get());
	
    // Ensure data is written and file is at beginning
    fflush(f.get());
    rewind(f.get());
	
	TSK_HDB_INFO* hdb = nsrl_open(f.get(), path);
	REQUIRE(hdb != nullptr);
	f.release();

	TSK_TCHAR htype[] = _TSK_T("nsrl-md5");
	CHECK(nsrl_makeindex(hdb, htype) == 0);
	hdb->close_db(hdb);
}

TEST_CASE("nsrl_makeindex format 2 with SHA1")
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
	create_nsrl_format2_db_file(f.get());
	
    // Ensure data is written and file is at beginning
    fflush(f.get());
    rewind(f.get());
	
	TSK_HDB_INFO* hdb = nsrl_open(f.get(), path);
	REQUIRE(hdb != nullptr);
	f.release();

	TSK_TCHAR htype[] = _TSK_T("nsrl-sha1");
	CHECK(nsrl_makeindex(hdb, htype) == 0);
	hdb->close_db(hdb);
}

TEST_CASE("nsrl_makeindex format 2 with MD5")
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
	create_nsrl_format2_db_file(f.get());

	// Ensure data is written and file is at beginning
	fflush(f.get());
	rewind(f.get());

	TSK_HDB_INFO* hdb = nsrl_open(f.get(), path);
	REQUIRE(hdb != nullptr);
	f.release();

	TSK_TCHAR htype[] = _TSK_T("nsrl-md5");
	CHECK(nsrl_makeindex(hdb, htype) == 0);
	hdb->close_db(hdb);
}

TEST_CASE("nsrl_makeindex empty database should fail")
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
	create_nsrl_db_file_empty(f.get());

	// Ensure data is written and file is at beginning
	fflush(f.get());
	rewind(f.get());

	TSK_HDB_INFO* hdb = nsrl_open(f.get(), path);
	REQUIRE(hdb != nullptr);
	f.release();


	TSK_TCHAR htype[] = _TSK_T("nsrl-sha1");
	CHECK(nsrl_makeindex(hdb, htype) == 1); // Should fail
	hdb->close_db(hdb);
}
/*
TEST_CASE("nsrl_makeindex handles invalid data lines gracefully")
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
	create_nsrl_db_file_invalid_data(f.get());

	// Ensure data is written and file is at beginning
	fflush(f.get());
	rewind(f.get());

	TSK_HDB_INFO* hdb = nsrl_open(f.get(), path);
	REQUIRE(hdb != nullptr);
	f.release();


	TSK_TCHAR htype[] = _TSK_T("nsrl-sha1");
	// Should succeed as invalid lines are skipped
	CHECK(nsrl_makeindex(hdb, htype) == 0);
	hdb->close_db(hdb);
}
*/
TEST_CASE("nsrl_getentry format 1 with SHA1")
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
	create_nsrl_format1_db_file(f.get());

	TSK_OFF_T off = 0;
	REQUIRE(find_line_offset_for_hash(f.get(), "A000000000000000000000000000000000000000", &off));

	// Ensure data is written and file is at beginning
	fflush(f.get());
	rewind(f.get());

	TSK_HDB_INFO* hdb = nsrl_open(f.get(), path);
	REQUIRE(hdb != nullptr);
	f.release();


	TSK_TCHAR htype[] = _TSK_T("nsrl-sha1");
	REQUIRE(nsrl_makeindex(hdb, htype) == 0);

	// Test successful lookup
	{
		std::vector<std::string> names;
		CHECK(nsrl_getentry(hdb, "A000000000000000000000000000000000000000", off, TSK_HDB_FLAG_QUICK, collect_names_cb, &names) == 0);
		REQUIRE(names.size() == 2);
		CHECK((names[0] == "file1.bin" || names[1] == "file1.bin"));
		CHECK((names[0] == "file1_dup.bin" || names[1] == "file1_dup.bin"));
	}

	// Test with wrong hash length
	{
		std::vector<std::string> names;
		CHECK(nsrl_getentry(hdb, "00000000000000000000000000000000", off, TSK_HDB_FLAG_QUICK, collect_names_cb, &names) == 1);
	}

	hdb->close_db(hdb);
}

TEST_CASE("nsrl_getentry format 1 with MD5")
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
	create_nsrl_format1_db_file(f.get());

	TSK_OFF_T off = 0;
	REQUIRE(find_line_offset_for_hash(f.get(), "11111111111111111111111111111111", &off));

	// Ensure data is written and file is at beginning
	fflush(f.get());
	rewind(f.get());

	TSK_HDB_INFO* hdb = nsrl_open(f.get(), path);
	REQUIRE(hdb != nullptr);
	f.release();


	TSK_TCHAR htype[] = _TSK_T("nsrl-md5");
	REQUIRE(nsrl_makeindex(hdb, htype) == 0);

	// Test successful lookup
	{
		std::vector<std::string> names;
		CHECK(nsrl_getentry(hdb, "11111111111111111111111111111111", off, TSK_HDB_FLAG_QUICK, collect_names_cb, &names) == 0);
		REQUIRE(names.size() == 2);
		CHECK((names[0] == "file1.bin" || names[1] == "file1.bin"));
		CHECK((names[0] == "file1_dup.bin" || names[1] == "file1_dup.bin"));
	}

	hdb->close_db(hdb);
}

TEST_CASE("nsrl_getentry format 2 with SHA1")
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
	create_nsrl_format2_db_file(f.get());

	TSK_OFF_T off = 0;
	REQUIRE(find_line_offset_for_hash(f.get(), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", &off));

	// Ensure data is written and file is at beginning
	fflush(f.get());
	rewind(f.get());

	TSK_HDB_INFO* hdb = nsrl_open(f.get(), path);
	REQUIRE(hdb != nullptr);
	f.release();


	TSK_TCHAR htype[] = _TSK_T("nsrl-sha1");
	REQUIRE(nsrl_makeindex(hdb, htype) == 0);

	// Test successful lookup
	{
		std::vector<std::string> names;
		CHECK(nsrl_getentry(hdb, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", off, TSK_HDB_FLAG_QUICK, collect_names_cb, &names) == 0);
		REQUIRE(names.size() == 2);
		CHECK((names[0] == "format2_file1.bin" || names[1] == "format2_file1.bin"));
		CHECK((names[0] == "format2_file1_dup.bin" || names[1] == "format2_file1_dup.bin"));
	}

	hdb->close_db(hdb);
}

TEST_CASE("nsrl_getentry format 2 with MD5")
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
	create_nsrl_format2_db_file(f.get());

	TSK_OFF_T off = 0;
	REQUIRE(find_line_offset_for_hash(f.get(), "11111111111111111111111111111111", &off));

	// Ensure data is written and file is at beginning
	fflush(f.get());
	rewind(f.get());

	TSK_HDB_INFO* hdb = nsrl_open(f.get(), path);
	REQUIRE(hdb != nullptr);
	f.release();


	TSK_TCHAR htype[] = _TSK_T("nsrl-md5");
	REQUIRE(nsrl_makeindex(hdb, htype) == 0);

	// Test successful lookup
	{
		std::vector<std::string> names;
		CHECK(nsrl_getentry(hdb, "11111111111111111111111111111111", off, TSK_HDB_FLAG_QUICK, collect_names_cb, &names) == 0);
		REQUIRE(names.size() == 2);
		CHECK((names[0] == "format2_file1.bin" || names[1] == "format2_file1.bin"));
		CHECK((names[0] == "format2_file1_dup.bin" || names[1] == "format2_file1_dup.bin"));
	}

	hdb->close_db(hdb);
}

TEST_CASE("nsrl_getentry with callbacks - stop and error")
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
	create_nsrl_format1_db_file(f.get());

	TSK_OFF_T off = 0;
	REQUIRE(find_line_offset_for_hash(f.get(), "A000000000000000000000000000000000000000", &off));

	// Ensure data is written and file is at beginning
	fflush(f.get());
	rewind(f.get());

	TSK_HDB_INFO* hdb = nsrl_open(f.get(), path);
	REQUIRE(hdb != nullptr);
	f.release();


	TSK_TCHAR htype[] = _TSK_T("nsrl-sha1");
	REQUIRE(nsrl_makeindex(hdb, htype) == 0);

	// Test stop callback
	{
		std::vector<std::string> names;
		CHECK(nsrl_getentry(hdb, "A000000000000000000000000000000000000000", off, TSK_HDB_FLAG_QUICK, stop_cb, &names) == 0);
	}

	// Test error callback
	{
		std::vector<std::string> names;
		CHECK(nsrl_getentry(hdb, "A000000000000000000000000000000000000000", off, TSK_HDB_FLAG_QUICK, error_cb, &names) == 1);
	}

	hdb->close_db(hdb);
}

TEST_CASE("nsrl_getentry with hash not found at offset")
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
	create_nsrl_format1_db_file(f.get());

	TSK_OFF_T off = 0;
	REQUIRE(find_line_offset_for_hash(f.get(), "A000000000000000000000000000000000000000", &off));

	// Ensure data is written and file is at beginning
	fflush(f.get());
	rewind(f.get());

	TSK_HDB_INFO* hdb = nsrl_open(f.get(), path);
	REQUIRE(hdb != nullptr);
	f.release();


	TSK_TCHAR htype[] = _TSK_T("nsrl-sha1");
	REQUIRE(nsrl_makeindex(hdb, htype) == 0);

	// Test with hash that doesn't match at offset
	{
		std::vector<std::string> names;
		CHECK(nsrl_getentry(hdb, "99999999999999999999999999999999999999999", off, TSK_HDB_FLAG_QUICK, collect_names_cb, &names) == 1);
	}

	hdb->close_db(hdb);
}

TEST_CASE("nsrl_getentry with invalid offset")
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
	create_nsrl_format1_db_file(f.get());

	// Ensure data is written and file is at beginning
	fflush(f.get());
	rewind(f.get());

	TSK_HDB_INFO* hdb = nsrl_open(f.get(), path);
	REQUIRE(hdb != nullptr);
	f.release();


	TSK_TCHAR htype[] = _TSK_T("nsrl-sha1");
	REQUIRE(nsrl_makeindex(hdb, htype) == 0);

	// Test with offset way beyond file end
	{
		std::vector<std::string> names;
		CHECK(nsrl_getentry(hdb, "A000000000000000000000000000000000000000", 999999, TSK_HDB_FLAG_QUICK, collect_names_cb, &names) == 1);
	}

	hdb->close_db(hdb);
}
