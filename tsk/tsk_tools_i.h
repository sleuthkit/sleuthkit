/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2007-2011 Brian Carrier.  All Rights reserved
 *
 * This software is distributed under the Common Public License 1.0
 */

#ifndef _TSK_TOOLS_I_H
#define _TSK_TOOLS_I_H

/* same as tsklib.h except that it includes the base_i.h file
 * instead of base.h so that we can get the _config defines.
 * This is to be used by the tools included with TSK (such as fls).
 */
#include "tsk/base/tsk_base_i.h"
#include "tsk/img/tsk_img.h"
#include "tsk/vs/tsk_vs.h"
#include "tsk/fs/tsk_fs.h"
#include "tsk/hashdb/tsk_hashdb.h"
#include "tsk/auto/tsk_auto.h"
#include "tsk/pool/tsk_pool.h"

#if defined(__cplusplus) && defined(TSK_WIN32)
#include <string>

/**
 * Convert a command line argument to UTF-8, e.g. a -k password. On Windows the tools parse
 * options from the wide command line, while the narrow argv that main() receives is in the
 * ANSI code page and cannot carry characters outside it.
 *
 * @param a_arg Wide argument (OPTARG)
 * @returns The argument as UTF-8, or an empty string if it could not be converted
 */
static inline std::string tsk_tool_arg_to_utf8(const TSK_TCHAR * a_arg)
{
    if (a_arg == NULL || a_arg[0] == L'\0') {
        return std::string();
    }
    int len = WideCharToMultiByte(CP_UTF8, 0, a_arg, -1, NULL, 0, NULL, NULL);
    if (len <= 0) {
        return std::string();
    }
    std::string utf8((size_t)len, '\0');
    if (WideCharToMultiByte(CP_UTF8, 0, a_arg, -1, &utf8[0], len, NULL, NULL) <= 0) {
        return std::string();
    }
    utf8.resize((size_t)len - 1);    // drop the terminator WideCharToMultiByte counted
    return utf8;
}
#endif

#endif
