/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2012 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

#include <string>
#include <cstring>
#include <errno.h>
#include <sstream>
#include "Log.h"
#include "tsk/framework/utilities/TskUtilities.h"
#include "sys/stat.h"
#include <time.h>
#include "Poco/FileStream.h"
#include "Poco/Exception.h"
#include "Poco/LineEndingConverter.h"
#include "Poco/LocalDateTime.h"
#include "Poco/DateTimeFormatter.h"

// @@@ imports for directory creation and deletion
//#include "windows.h"

// The threshold at which we will write a message to the log
// file for messages that repeat.
const int Log::REPEAT_THRESHOLD = 500;

Log::Log()
: m_filePath(""), m_outStream(), m_previousMessage(""), m_messageRepeatCount(0)
{
}


/**
 * Opens a single log file with a default name, based on the time
 * that the log was opened.
 * @returns 1 on error and 0 on success.
 */
int Log::open()
{
    struct tm *newtime;
    time_t aclock;

    time(&aclock);   // Get time in seconds
    newtime = localtime(&aclock);   // Convert time to struct tm form 
    wchar_t filename[MAX_BUFF_LENGTH];
    swprintf(filename, MAX_BUFF_LENGTH, L"log_%.4d-%.2d-%.2d-%.2d-%.2d-%.2d.txt",
        newtime->tm_year + 1900, newtime->tm_mon+1, newtime->tm_mday,  
        newtime->tm_hour, newtime->tm_min, newtime->tm_sec);

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
    return open(TskUtilities::toUTF8(a_logFileFullPath).c_str());
}

int Log::open(const char * a_logFileFullPath)
{
    close(); // if needed

    try {
        m_outStream.open(a_logFileFullPath, std::ios::app);
    } catch (const std::exception ex) {
        printf("The file '%s' cannot be opened. Exception: %s\n", a_logFileFullPath, ex.what());
        return 1;
    }

    m_filePath.assign(a_logFileFullPath);

    return 0;
}

/**
 * Close the opened log file.
 * @returns 0 on success
 */
int Log::close()
{
    m_outStream.close();
    if (m_outStream.bad()) {
        printf("The file '%s' was not closed.", m_filePath.c_str());
        return 1;
    }
    return 0;
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
    std::string level;
    switch (a_channel) {
    case Error:
        level.assign("[ERROR]");
        break;
    case Warn:
        level.assign("[WARN]");
        break;
    case Info:
        level.assign("[INFO]");
        break;
    }

    if (a_msg == m_previousMessage && m_messageRepeatCount < Log::REPEAT_THRESHOLD)
        m_messageRepeatCount++;
    else
    {
        if (m_messageRepeatCount > 0)
        {
            std::stringstream repeatMessage;
            repeatMessage << "The previous message was repeated "
                << m_messageRepeatCount << " times.";
            logMessage("[INFO]", repeatMessage.str());
        }
        m_previousMessage = a_msg;
        m_messageRepeatCount = 0;
        logMessage(level, a_msg);
    }
}

void Log::logMessage(const std::string& level, const std::string& msg)
{
    Poco::LocalDateTime now;

    std::ostream& outStream = m_outStream.good() ? m_outStream : std::cerr;

    outStream << Poco::DateTimeFormatter::format(now, "%m/%d/%y %H:%M:%S")
        << " " << level << " " << msg << Poco::LineEnding::NEWLINE_DEFAULT;
    outStream.flush();
}

void Log::log(Channel a_channel, const std::wstring &a_msg)
{
    log(a_channel, TskUtilities::toUTF8(a_msg).c_str());
}
/**
 * Return the path to the log file.
 * @returns path to log or NULL if log is going to STDERR
 */
const wchar_t * Log::getLogPathW()
{
    return (const wchar_t *)TskUtilities::toUTF16(m_filePath).c_str();
}
