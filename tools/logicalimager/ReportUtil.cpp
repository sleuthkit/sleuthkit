/*
** The Sleuth Kit
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2010-2019 Brian Carrier.  All Rights reserved
**
** This software is distributed under the Common Public License 1.0
**
*/

/**
* \file ReportUtil.cpp
* Contains C++ code that implement the Report Util class.
*/

#include <iostream>
#include <conio.h>
#include <string>
#include <list>
#include <algorithm>
#include <locale>
#include <codecvt>
#include <direct.h>
#include <winsock2.h>
#include <locale.h>
#include <Wbemidl.h>
#include <shlwapi.h>
#include <fstream>
#include <winbase.h>
#include <comutil.h>

#include "ReportUtil.h"
#include "TskHelper.h"

static std::string sessionDirCopy;
static FILE *reportFile;
static FILE *consoleFile;
static bool promptBeforeExit = true;

void ReportUtil::initialize(const std::string &sessionDir) {
    sessionDirCopy = sessionDir;
    std::string consoleFileName = sessionDir + "/console.txt";
    ReportUtil::openConsoleOutput(consoleFileName);

    std::string reportFilename = sessionDir + "/SearchResults.txt";
    ReportUtil::openReport(reportFilename);
}

void ReportUtil::copyConfigFile(const std::wstring &configFilename) {
    // copy the config file into the output session directory
    std::ifstream src(TskHelper::toNarrow(configFilename), std::ios::binary);
    std::ofstream dst(sessionDirCopy + "/config.json", std::ios::binary);
    dst << src.rdbuf();
    dst.close();
    src.close();
}

/*
* Create the report file and print the header.
*
* @param reportFilename Name of the report file
*/
void ReportUtil::openReport(const std::string &reportFilename) {
    reportFile = fopen(reportFilename.c_str(), "w");
    if (!reportFile) {
        ReportUtil::consoleOutput(stderr, "ERROR: Failed to open report file %s\n", reportFilename.c_str());
        handleExit(1);
    }
    fprintf(reportFile, "VHD file/directory\tFile system offset\tFile metadata adddress\tExtraction status\tRule set name\tRule name\tDescription\tFilename\tPath\tExtractFilePath\tcrtime\tmtime\tatime\tctime\n");
}

void ReportUtil::openConsoleOutput(const std::string &consoleFileName) {
    consoleFile = fopen(consoleFileName.c_str(), "w");
    if (!consoleFile) {
        fprintf(stderr, "ERROR: Failed to open console file %s\n", consoleFileName.c_str());
        handleExit(1);
    }
}

void ReportUtil::logOutputToFile(const char *buf) {
    if (consoleFile) {
        fprintf(consoleFile, "%s", buf);
    }
}

void ReportUtil::consoleOutput(FILE *fd, const char *msg, ...) {
    char buf[2048];
    va_list args;

    va_start(args, msg);
    vsnprintf(buf, sizeof(buf), msg, args);
    fprintf(fd, "%s", buf);
    // output to console file
    logOutputToFile(buf);
    va_end(args);
}

void ReportUtil::printDebug(char *msg, const char *fmt, ...) {
    if (tsk_verbose) {
        std::string prefix("tsk_logical_imager: ");
        std::string message = prefix + msg + "\n";
        tsk_fprintf(stderr, message.c_str(), fmt);
    }
}

void ReportUtil::printDebug(char *msg) {
    printDebug(msg, "");
}

/*
* Write an file match result record to the report file. Also send a simple message to stdout, if shouldAlert is true.
* A report file record contains tab-separated fields:
*   - output VHD file/directory
*   - File system offset
*   - Metadata address
*   - extractStatus
*   - ruleSetName
*   - ruleName
*   - description
*   - name
*   - path
*   - ExtractFilePath
*   - crtime
*   - mtime
*   - atime
*   - ctime
*
* @param driveName Drive name
* @param extractStatus Extract status: TSK_OK if file was extracted, TSK_ERR otherwise
* @param ruleMatchResult The rule match result
* @param fs_file TSK_FS_FILE that matches
* @param path Parent path of fs_file
* @param extractedFilePath Extracted file path
*/
void ReportUtil::reportResult(const std::string &outputLocation, TSK_RETVAL_ENUM extractStatus, const MatchedRuleInfo *ruleMatchResult, TSK_FS_FILE *fs_file, const char *path, const std::string &extractedFilePath) {
    if (fs_file->name && (strcmp(fs_file->name->name, ".") == 0 || strcmp(fs_file->name->name, "..") == 0)) {
        // Don't report . and ..
        return;
    }
    if (extractStatus == TSK_ERR && (fs_file->meta == NULL || fs_file->meta->flags & TSK_FS_NAME_FLAG_UNALLOC)) {
        // Don't report unallocated files that failed extraction
        return;
    }
    // report file format is "VHD file<tab>File system offset<tab>file metadata address<tab>extractStatus<tab>ruleSetName<tab>ruleName<tab>description<tab>name<tab>path<tab>extracedFilePath<tab>crtime<tab>mtime<tab>atime<tab>ctime"
    std::string crtimeStr = (fs_file->meta ? std::to_string(fs_file->meta->crtime) : "0");
    std::string mtimeStr = (fs_file->meta ? std::to_string(fs_file->meta->mtime) : "0");
    std::string atimeStr = (fs_file->meta ? std::to_string(fs_file->meta->atime) : "0");
    std::string ctimeStr = (fs_file->meta ? std::to_string(fs_file->meta->ctime) : "0");
    fprintf(reportFile, "%s\t%" PRIdOFF "\t%" PRIuINUM "\t%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
        outputLocation.c_str(),
        fs_file->fs_info->offset,
        (fs_file->meta ? fs_file->meta->addr : 0),
        extractStatus,
        ruleMatchResult->getRuleSetName().c_str(),
        ruleMatchResult->getName().c_str(),
        ruleMatchResult->getDescription().c_str(),
        (fs_file->name ? fs_file->name->name : "name is null"),
        path,
        extractedFilePath.c_str(),
        crtimeStr.c_str(),
        mtimeStr.c_str(),
        atimeStr.c_str(),
        ctimeStr.c_str()
    );
    fflush(reportFile);

    std::string fullPath(path);
    if (fs_file->name) {
        fullPath += fs_file->name->name;
    }
    else {
        fullPath += "name is null";
    }

    if (ruleMatchResult->isShouldAlert()) {
        ReportUtil::consoleOutput(stdout, "Alert for %s: %s\n",
            ruleMatchResult->getRuleSetName().c_str(),
            fullPath.c_str());
    }
}

/*
* Close a file.
*/
void closeFile(FILE **file) {
    if (*file) {
        fclose(*file);
        *file = NULL;
    }
}

/*
* Close the report file.
*/
void ReportUtil::closeReport() {
    closeFile(&reportFile);
}

void ReportUtil::handleExit(int code) {
    closeFile(&reportFile);
    closeFile(&consoleFile);
    if (promptBeforeExit) {
        std::cout << std::endl << "Press any key to exit";
        (void)_getch();
    }
    exit(code);
}

/**
* GetErrorStdStr - returns readable error message for the given error code
*
* @param err error code
* @returns error message string
*/
std::string ReportUtil::GetErrorStdStr(DWORD err) {
    return TskHelper::toNarrow(ReportUtil::GetErrorStdStrW(err));
}

/**
* GetLastErrorStdStrW - returns readable widestring error message for the last error code as reported by GetLastError()
*
* @returns error message wide string
*/
std::wstring ReportUtil::GetLastErrorStdStrW() {
    DWORD error = GetLastError();
    return GetErrorStdStrW(error);
}

/**
* GetErrorStdStrW - returns readable widestring error message for the given error code
*
* @param err error code
* @returns error message wide string
*/
std::wstring ReportUtil::GetErrorStdStrW(DWORD a_err) {
    if (ERROR_SUCCESS != a_err) {
        LPVOID lpMsgBuf;
        DWORD bufLen = FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER |
            FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            a_err,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPWSTR)&lpMsgBuf,
            0, NULL);
        if (bufLen) {
            LPCWSTR lpMsgStr = (LPCWSTR)lpMsgBuf;
            std::wstring result(lpMsgStr, lpMsgStr + bufLen);
            size_t pos = result.find_last_not_of(L"\r\n");
            if (pos != std::wstring::npos) {
                result.resize(pos);
            }
            LocalFree(lpMsgBuf);
            return result;
        }
    }
    return std::wstring(L"no error");
}

void ReportUtil::SetPromptBeforeExit(bool flag) {
    promptBeforeExit = flag;
}