/*
** The Sleuth Kit
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2010-2019 Brian Carrier.  All Rights reserved
**
** This software is distributed under the Common Public License 1.0
**
*/

#pragma once

#include <string>

#include "MatchedRuleInfo.h"
#include "tsk/libtsk.h"

/**
* Defines the Report Utilities
*
*/
class ReportUtil {
public:
    static void initialize(const std::string &sessionDir);
    static void copyConfigFile(const std::wstring &configFilename);
    static void openReport(const std::string &alertFilename);
    static void openConsoleOutput(const std::string &consoleFileName);
    static void logOutputToFile(const char *buf);
    static void consoleOutput(FILE *fd, const char *msg, ...);
    static void printDebug(char *msg, const char *fmt, ...);
    static void printDebug(char *msg);
    static void closeReport();

    static void reportResult(const std::string &outputLocation, TSK_RETVAL_ENUM extractStatus,
        const MatchedRuleInfo *ruleMatchResult, TSK_FS_FILE *fs_file, const char *path, const std::string &extractedFilePath);

    static void SetPromptBeforeExit(bool flag);
    static void handleExit(int code);

    static std::wstring GetErrorStdStrW(DWORD a_err);
    static std::wstring GetLastErrorStdStrW();
    static std::string GetErrorStdStr(DWORD err);
};
