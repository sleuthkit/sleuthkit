/* 	
* Author: Taha Ebrahim @Taha-Ebrahim
* Creates named and unnamed temporary filesfor use in testing. It is primarily used on MinGW systems, 	
* where std::tmpfile() is unreliable 	
*/
#include "tsk_tempfile.h"

#include <cstdlib>
#include <ctime>
#include <cstring>
#include <string>

#ifdef _WIN32
#include <windows.h>
#define PATH_SEP '\\'
#else
#include <unistd.h>
#define PATH_SEP '/'
#endif

FILE* tsk_make_tempfile() {
#if defined(_WIN32) && defined(__MINGW32__)
    // MinGW-specific fallback — generate a unique filename and open manually
    std::string temp_dir;
    const char* env = std::getenv("TEMP");
    if (!env) env = std::getenv("TMP");
    temp_dir = env ? env : ".";

    std::string filename = "tsk_tempfile_" + std::to_string(std::time(nullptr)) +
                            "_" + std::to_string(GetTickCount64()) + ".txt";
    std::string full_path = temp_dir + PATH_SEP + filename;

    FILE* file = std::fopen(full_path.c_str(), "w+");
    return file;
#else
    // Use standard std::tmpfile for non-MinGW systems
    return std::tmpfile();
#endif
}

FILE* tsk_make_named_tempfile(std::string* out_path) {
    if (!out_path) return nullptr;

#if defined(_WIN32) && defined(__MINGW32__)
    char temp_path[MAX_PATH];
    char temp_file[MAX_PATH];

    // Get temp directory (usually C:\Users\<user>\AppData\Local\Temp)
    DWORD path_len = GetTempPathA(MAX_PATH, temp_path);
    if (path_len == 0 || path_len > MAX_PATH) return nullptr;

    // Create a unique temporary file name
    if (GetTempFileNameA(temp_path, "tsk", 0, temp_file) == 0) return nullptr;

    FILE* file = std::fopen(temp_file, "w+");
    if (file) *out_path = temp_file;
    return file;

#else
    char tmpl[] = "/tmp/tsk_tempfile_XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) return nullptr;

    FILE* file = fdopen(fd, "w+");
    if (file) *out_path = tmpl;
    else close(fd); // avoid leaking fd on failure
    return file;
#endif
}