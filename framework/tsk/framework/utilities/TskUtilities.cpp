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
#include "tsk/framework/services/TskServices.h"
#include "tsk/base/tsk_base_i.h"

// Poco Includes
#include "Poco/UnicodeConverter.h"
#include "Poco/Net/DNS.h"
#include "Poco/Net/HostEntry.h"
#include "Poco/Net/NetException.h"
#include "Poco/Path.h"

// C/C++ library includes
#include <sstream>

#if defined _WIN32 || defined _WIN64
#include <Windows.h>
#endif

#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif

/**
 * Convert a given UTF16 string to UTF8
 * @param utf16Str The UTF16 encoded string.
 * @returns A UTF8 encoded version of the input string.
 */
std::string TskUtilities::toUTF8(const std::wstring &utf16Str)
{
    std::string utf8Str;
    char *utf8Buf;
    int utf8Size = utf16Str.size() * 5 + 1;
    utf8Buf = new char[utf8Size];
    UTF8 *ptr8;
    wchar_t *ptr16;

    ptr8 = (UTF8 *) utf8Buf;
    ptr16 = (wchar_t *) utf16Str.c_str();

    TSKConversionResult retval =
        tsk_UTF16WtoUTF8_lclorder((const wchar_t **)&ptr16, 
                                  (wchar_t *)&ptr16[utf16Str.size()+1],
                                  &ptr8,
                                  (UTF8 *) ((uintptr_t) ptr8 + utf8Size * sizeof(UTF8)), 
                                  TSKstrictConversion);
    if (retval != TSKconversionOK) 
    {
        return "";
    }
    utf8Str.assign(utf8Buf);
    delete [] utf8Buf;
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
    wchar_t *utf16Buf;
    int utf16Size = utf8Str.size() + 1;
    utf16Buf = new wchar_t[utf16Size];
    UTF8 *ptr8;
    wchar_t *ptr16;

    ptr16 = (wchar_t *) utf16Buf;
    ptr8 = (UTF8 *) utf8Str.data();

    TSKConversionResult retval =
        tsk_UTF8toUTF16W((const UTF8 **) &ptr8, 
                        (UTF8 *) & utf8Str.data()[utf8Str.size()], 
                        &ptr16,
                        (wchar_t *) ((uintptr_t) ptr16 + utf16Size * sizeof(wchar_t)), 
                        TSKstrictConversion);
    if (retval != TSKconversionOK) 
    {
        return L"";
    }
    utf16Str.assign(utf16Buf, ptr16 - utf16Buf);
    delete [] utf16Buf;
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
#ifdef TSK_WIN32
    wchar_t progPath[256];
    wchar_t fullPath[256];
    HINSTANCE hInstance = GetModuleHandleW(NULL);

    GetModuleFileNameW(hInstance, fullPath, 256);
    int i = wcslen(fullPath)-1;
    for (; i > 0; i--) {
        if (i > 256)
            break;

        if (fullPath[i] == '\\') {
            wcsncpy_s(progPath, fullPath, i+1);
            break;
        }
    }

    std::wstring progPathNoNull(progPath, i+1);
    return TskUtilities::toUTF8(progPathNoNull);

#elif __APPLE__
    char path[MAXPATHLEN+1];
    uint32_t path_len = MAXPATHLEN;
    if (_NSGetExecutablePath(path, &path_len) == 0) {
        Poco::Path p(path);
        return p.makeParent().toString();
    }
    return std::string("");
#else // NOT TSK_WIN32
    int size = 256;
    char* buf = 0;
    int ret = 0;
 
    while (1) {
        buf = (char*)realloc(buf, size*sizeof(char));
        if (!buf)
            return std::string("");
        ret = readlink("/proc/self/exe", buf, size);
        if (ret < 0) {
            free(buf);
            return std::string("");
        }
        if (ret < size) {
            std::string s(buf, ret);
            free(buf);
            Poco::Path path(s);
            return path.makeParent().toString();
        }
        size *= 2;
    }
    return std::string("");
#endif // NOT TSK_WIN32
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
