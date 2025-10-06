#ifndef TEST_IMG_H
#define TEST_IMG_H

#include "tsk/base/tsk_os_cpp.h"  // for TSK_TCHAR, TSK_TSTRING
#include <cstdlib>                // for getenv / _wgetenv
#include <stdexcept>
#include <string>
#include <algorithm>

// Convenience wrapper for current build type
inline std::basic_string<TSK_TCHAR> prepend_test_data_dir(const TSK_TCHAR* relative_path) {
#ifdef TSK_WIN32
    const wchar_t* base = _wgetenv(L"srcdir");
    if (!base) throw std::runtime_error("srcdir not set");
    std::wstring full = base;
    full += L"/test/data/";
    full += relative_path;
#else
    const char* base = getenv("srcdir");
    if (!base) throw std::runtime_error("srcdir not set");
    std::string full = base;
    full += "/test/data/";
    full += relative_path;
#endif
    return full;
}

// Slash-fixing for Windows
#ifdef TSK_WIN32
inline void fix_slashes_for_windows(TSK_TSTRING &path) {
    std::replace(path.begin(), path.end(), _TSK_T('/'), _TSK_T('\\'));
}
#else
inline void fix_slashes_for_windows(TSK_TSTRING &) {}
#endif

#endif  // TEST_IMG_H
