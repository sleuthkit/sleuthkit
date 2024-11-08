#ifndef _TSK_OS_CPP_H
#define _TSK_OS_CPP_H

#include "tsk_os.h"

#include <string>

#ifdef TSK_WIN32
#define TSK_TSTRING std::wstring
#else
#define TSK_TSTRING std::string
#endif

#endif
