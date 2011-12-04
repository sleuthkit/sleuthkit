/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2011 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

#include <string.h>
#include <errno.h>
#include <share.h>
#include "string.h"
#include "Log.h"
#include "sys/stat.h"

// @@@ imports for directory creation and deletion
#include "windows.h"

Log::Log()
: m_logFile(NULL)
{
}

// return 1 on error, 0 on success
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

    /* BC: For some unknown reason, when we had this enabled, the carver
     * would miss files that it would otherwise find. Not sure why. It may have
     * to do with the carver producing so much data to stderr that this got in
     * its way...  Disabling since the log should be the primary source of debug
     * data anyway. */
    //fwprintf(stderr, L"%S %s %s\n", timeStr, level, a_msg);
    if (m_logFile) {
        fwprintf(m_logFile, L"%S %s %s\n", timeStr, level, a_msg.data());
        fflush(m_logFile);
    }
}

const wchar_t * Log::getLogPath()
{
    return (const wchar_t * )&m_filePath;
}

