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
 * \file TskUtilities.cpp
 * Contains common utility methods.
 */

// TSK and TSK Framework includes
#include "TskUtilities.h"
#include "Services/TskServices.h"
#include <tsk3/base/tsk_base_i.h>

// Poco Includes
#include "Poco/UnicodeConverter.h"
#include "Poco/Net/DNS.h"
#include "Poco/Net/HostEntry.h"
#include "Poco/Net/NetException.h"

// C/C++ library includes
#include <sstream>

#if defined _WIN32 || defined _WIN64
#include <Windows.h>
#else
#error "Only Windows is currently supported"
#endif

/**
 * Convert a given UTF16 string to UTF8
 * @param utf16Str The UTF16 encoded string.
 * @returns A UTF8 encoded version of the input string.
 */
std::string TskUtilities::toUTF8(const std::wstring &utf16Str)
{
    std::string utf8Str;
    Poco::UnicodeConverter::toUTF8(utf16Str, utf8Str);
    return utf8Str;
}

/**
 * Convert a given UTF8 string to UTF16
 * @param utf8Str The UTF8 encoded string.
 * @returns A UTF16 encoded version of the input string.
 */
std::wstring TskUtilities::toUTF16(const std::string &utf8Str)
{
    std::wstring utf16Str;
    Poco::UnicodeConverter::toUTF16(utf8Str, utf16Str);
    return utf16Str;
}

void TskUtilities::cleanUTF8(char *buf)
{
    tsk_cleanupUTF8(buf, '^'); 
}

/**
 * Get the IP address for the given host name.
 * @param host The name of the host who's IP address you want.
 * @param host_ip This string will be filled in with the IP address.
 * @returns true on success, false otherwise.
 */
bool TskUtilities::getHostIP(const std::string& host, std::string & host_ip)
{
    try
    {
        Poco::Net::HostEntry hostEntry = Poco::Net::DNS::hostByName(host);

        if (hostEntry.addresses().empty())
        {
            LOGERROR(L"TskUtilities::getHostIP - No addresses found for host.\n");
            return false;
        }

        // Take the first address.
        host_ip = hostEntry.addresses()[0].toString();
        return true;
    }
    catch (Poco::Net::NetException& netEx)
    {
        std::wstringstream msg;
        msg << L"TskUtilities::getHostIP - Error resolving host name: " << host.c_str() 
            << L" : " << netEx.what() << std::endl;
        LOGERROR(msg.str());
        return false;
    }
}

/** Get the path of the directory where the currently executing program is 
 * installed.  
 *
 * @returns The path of the program directory.
 */
std::string TskUtilities::getProgDir()
{
    wchar_t progPath[256];
    wchar_t fullPath[256];
    HINSTANCE hInstance = GetModuleHandleW(NULL);

    GetModuleFileNameW(hInstance, fullPath, 256);
    for (int i = wcslen(fullPath)-1; i > 0; i--) {
        if (i > 256)
            break;

        if (fullPath[i] == '\\') {
            wcsncpy_s(progPath, fullPath, i+1);
            progPath[i+1] = '\0';
            break;
        }
    }

    return TskUtilities::toUTF8(std::wstring(progPath));
}

/** Strip matching leading and trailing double quotes from the input str.
 * If there is no matching quotes, the input str is returned.
 * @returns String without matching leading and trailing double quote.
 */
std::string TskUtilities::stripQuotes(const std::string& str)
{
    if (str.length() == 0)
        return str;
    std::string outStr;
    if (str[0] == '"' && str[str.length()-1] == '"') {
        outStr = str.substr(1, str.length()-2);
    } else
        outStr = str;
    return outStr;
}
