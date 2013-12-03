/*
 *
 *  The Sleuth Kit
 *
 *  Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 *  Copyright (c) 2010-2012 Basis Technology Corporation. All Rights
 *  reserved.
 *
 *  This software is distributed under the Common Public License 1.0
 */

/**
 * \file TskUtilities.h
 * Contains common utility methods.
 */

#ifndef _TSK_UTILITIES_H
#define _TSK_UTILITIES_H

#include <string>

#include "tsk/framework/framework_i.h"

/**
 * Contains commonly needed utility methods.  Refer to the poco library
 * for other commonly needed methods.
 */
class TSK_FRAMEWORK_API TskUtilities
{
public:
    static std::string toUTF8(const std::wstring& utf16Str);
    static std::wstring toUTF16(const std::string& utf8Str);
    static void cleanUTF8(char *buf);
    static bool getHostIP(const std::string& host, std::string& host_ip);
    static std::string getProgDir();
    static std::string stripQuotes(const std::string& str);
};

#endif
