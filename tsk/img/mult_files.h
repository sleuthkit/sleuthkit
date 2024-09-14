#ifndef MULT_FILES_H
#define MULT_FILES_H

#include "tsk_img_i.h"

#include <functional>
#include <sstream>
#include <string>

#define TSK_STRING std::basic_string<TSK_TCHAR>
#define TSK_OSTRINGSTREAM std::basic_ostringstream<TSK_TCHAR>

std::function<TSK_STRING(size_t, TSK_OSTRINGSTREAM&)> getSegmentPattern(const TSK_TCHAR* first);

#endif
