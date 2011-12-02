/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2011 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

#ifndef _OSS_LOG_H
#define _OSS_LOG_H

#include "framework_i.h"
#include <time.h>
#include <string>

#define LOGERROR(msg) TskServices::Instance().getLog().logError(msg)
#define LOGWARN(msg) TskServices::Instance().getLog().logWarn(msg)
#define LOGINFO(msg) TskServices::Instance().getLog().logInfo(msg)

class TSK_FRAMEWORK_API Log
{
public:
    enum Channel {Error, Warn, Info};

    Log();
    virtual ~Log();
    virtual void log(Channel a_channel, const std::wstring &a_msg);

    void logError(const std::wstring &msg) { log(Log::Error, msg); };
    void logWarn(const std::wstring &msg)  { log(Log::Warn,  msg); };
    void logInfo(const std::wstring &msg)  { log(Log::Info,  msg); };

    int open(const wchar_t * a_outDir);
    int close();
    const wchar_t * getLogPath();

private:
    wchar_t m_filePath[MAX_BUFF_LENGTH];
    FILE * m_logFile;
};
#endif
