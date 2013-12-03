/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2012 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

#ifndef _OSS_LOG_H
#define _OSS_LOG_H

#include "tsk/framework/framework_i.h"
#include <time.h>
#include <string>
#include <iostream>
#include <fstream>

// @@@ TODO: Resolve circular references between TskServices.h and this header by replacing macros with inline functions in TskServices.h

/**
 * \file Log.h
 * Interface and default logging infrastructure that enables applications and framework
 * to log to a single place.  
 */

/**
 * Macro that gets the log service and writes an error message in a
 * single statement. 
 * @param msg Message to log
 * @returns void
 */
#define LOGERROR(msg) TskServices::Instance().getLog().log(Log::Error, msg)

/**
 * Macro that gets the log service and writes a warning message in a
 * single statement. 
 * @param msg Message to log
 * @returns void
 */
#define LOGWARN(msg) TskServices::Instance().getLog().log(Log::Warn, msg)


/**
 * Macro that gets the log service and writes an info message in a
 * single statement. 
 * @param msg Message to log
 * @returns void
 */
#define LOGINFO(msg) TskServices::Instance().getLog().log(Log::Info, msg)


/**
 * Logging class to enable the framework, apps that use it, and modules to
 * log error and warning messages.  The default implementation writes
 * the log messages to a file if open() was called or prints the messages to
 * stderr if open() was never called. The class can be extended 
 * if you want logs to be saved in another way.
 * Can be registered with and retrieved from TskServices.
 *
 * Developers can either directly call the log() method with the logging
 * level, can call the logError(), etc. methods on the class or use the
 * LOGERROR() etc. macros, which will also get the Log service from TskServices.
 */
class TSK_FRAMEWORK_API Log
{
public:
    /** 
     * Defined logging levels.
     */
    enum Channel {
        Error, ///< Critical error that stops processing
        Warn,  ///< Unexpected results that could be recovered from
        Info    ///< General debugging information
    };

    Log();
    virtual ~Log();

    /**
     * Generate a log message with a given level (wide string).
     * @param a_channel Level of log to make
     * @param a_msg Message to record.
     */
    virtual void log(Channel a_channel, const std::wstring &a_msg);

    /**
     * Generate a log message with a given level (narrow string).
     * @param a_channel Level of log to make
     * @param a_msg Message to record.
     */
    virtual void log(Channel a_channel, const std::string &a_msg);

    /**
     * Generate a log message with a given level (printf-style arguments).
     * @param a_channel Level of log to make
     * @param format Message to record.
     */
    virtual void logf(Channel a_channel, char const *format, ...);


    /**
     * Log an error message.
     * @param msg Message to log
     */
    void logError(const std::wstring &msg) { log(Log::Error, msg); };

    /**
     * Log a warning message.
     * @param msg Message to log
     */
    void logWarn(const std::wstring &msg)  { log(Log::Warn,  msg); };

    /**
     * Log an info message.
     * @param msg Message to log
     */
    void logInfo(const std::wstring &msg)  { log(Log::Info,  msg); };

    int open(const wchar_t * a_logFileFullPath);
    int open(const char * a_outDir);
    int open();
    int close();
    const wchar_t * getLogPathW();
    const char * getLogPath() { return m_filePath.c_str(); }

protected:
    std::string m_filePath;
    std::ofstream m_outStream;
};
#endif
