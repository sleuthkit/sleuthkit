#ifndef MULT_FILES_H
#define MULT_FILES_H

#include "tsk_img_i.h"
#include "../base/tsk_os_cpp.h"

#include <functional>
#include <sstream>

#define TSK_TOSTRINGSTREAM std::basic_ostringstream<TSK_TCHAR>

std::function<TSK_TSTRING(size_t, TSK_TOSTRINGSTREAM&)> getSegmentPattern(const TSK_TCHAR* first);

#endif
