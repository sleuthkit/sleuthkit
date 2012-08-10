/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2012 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

#include <string.h>
#include <errno.h>
#include <share.h>
#include "string.h"
#include "Log.h"
#include "Utilities/TskUtilities.h"
#include "sys/stat.h"

// @@@ imports for directory creation and deletion
#include "windows.h"


Log::Log()
: m_logFile(NULL)
{
    m_filePath[0] = '\0';
}


/**
 * Opens a single log file with a default name, based on the time
 * that the log was opened.
 * @returns 1 on error and 0 on success.
 */
int Log::open()
{
    struct tm newtime;
    time_t aclock;

    time(&aclock);   // Get time in seconds
    localtime_s(&newtime, &aclock);   // Convert time to struct tm form 
    wchar_t filename[MAX_BUFF_LENGTH];
    _snwprintf_s(filename, MAX_BUFF_LENGTH, MAX_BUFF_LENGTH, L"log_%.4d-%.2d-%.2d-%.2d-%.2d-%.2d.txt",
        newtime.tm_year + 1900, newtime.tm_mon+1, newtime.tm_mday,  
        newtime.tm_hour, newtime.tm_min, newtime.tm_sec);

    return open(filename);
}
/**
 * Open the single log file at the path specified. All messages
 * will be printed to the log.
 * @param a_logFileFullPath Path to logfile to open.
 * @returns 1 on error and 0 on success.
 */
int Log::open(const wchar_t * a_logFileFullPath)
{
    close(); // if needed

    // open the log file for writing
    if ((m_logFile = _wfsopen(a_logFileFullPath, L"a", _SH_DENYWR)) == NULL) {
        wprintf(L"The file '%s' cannot be opened.\n", a_logFileFullPath);
        return 1;
    }

    wcsncpy_s(m_filePath, a_logFileFullPath,MAX_BUFF_LENGTH);

    return 0;
}

/**
 * Close the opened log file.
 * @returns 0 on success
 */
int Log::close()
{
    errno_t err = 0;
    if (m_logFile)
    {
        if (err = fclose(m_logFile))
            wprintf(L"The file '%s' was not closed.", m_logFile);

        m_logFile = NULL;
    }

    return err;
}

Log::~Log()
{
    close();
}


void Log::logf(Channel a_channel, char const *format, ...)
{
    va_list args;
    va_start(args, format);

    char buf[2048];
#ifdef TSK_WIN32
    vsnprintf_s(buf, 2048, _TRUNCATE, format, args);
#else
    buf[2047] = '\0';
    vsnprintf(buf, 2047, format, args);
#endif
    std::string msg(buf);
    log(a_channel, buf);
    va_end(args);
}

void Log::log(Channel a_channel, const std::string &a_msg)
{
    std::wstring msg_w = TskUtilities::toUTF16(a_msg);
    log(a_channel, msg_w);
}

void Log::log(Channel a_channel, const std::wstring &a_msg)
{
    wchar_t level[10];
    switch (a_channel)
    {
    case Error:
        wcsncpy_s(level, 10, L"[ERROR]", 7);
        break;
    case Warn:
        wcsncpy_s(level, 10, L"[WARN]", 6);
        break;
    case Info:
        wcsncpy_s(level, 10, L"[INFO]", 6);
        break;
    }

    struct tm newtime;
    time_t aclock;

    time(&aclock);   // Get time in seconds
    localtime_s(&newtime, &aclock);   // Convert time to struct tm form 
    char timeStr[64];
    _snprintf_s(timeStr, 64, "%.2d/%.2d/%.2d %.2d:%.2d:%.2d",
        newtime.tm_mon+1,newtime.tm_mday,newtime.tm_year % 100, 
        newtime.tm_hour, newtime.tm_min, newtime.tm_sec);

    if (m_logFile) {
        fwprintf(m_logFile, L"%S %s %s\n", timeStr, level, a_msg.data());
        fflush(m_logFile);
    }
    else {
        fwprintf(stderr, L"%S %s %s\n", timeStr, level, a_msg.data());
    }
}

/**
 * Return the path to the log file.
 * @returns path to log or NULL if log is going to STDERR
 */
const wchar_t * Log::getLogPath()
{
    if (m_logFile)
        return (const wchar_t * )&m_filePath;
    else
        return NULL;
}

