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
* \file TskFindFiles.cpp
* Contains C++ code that creates the Find Files class.
*/

#include <shlwapi.h>
#include <string>
#include <sstream>
#include <sstream>
#include <locale>
#include <iomanip>

#include "LogicalImagerRuleSet.h"
#include "tsk/tsk_tools_i.h"
#include "TskFindFiles.h"

/**
 * Create the Find Files object given the Logical Imager Configuration
 * @param config LogicalImagerRuleSet to use for finding files
 */
TskFindFiles::TskFindFiles(const LogicalImagerRuleSet *ruleSet, const char *alertFilePath) {
    m_logicialImagerRuleSet = ruleSet;
    m_alertFilePath.assign(alertFilePath);
    m_alertFile = fopen(alertFilePath, "w");
    if (!m_alertFile) {
        fprintf(stderr, "ERROR: Failed to open alert file %s\n", alertFilePath);
        exit(1);
    }
    fprintf(m_alertFile, "Extraction Status\tDescription\tFilename\tPath\n");
}

TskFindFiles::~TskFindFiles() {
    if (m_alertFile) {
        fclose(m_alertFile);
    }
}

/**
 * Print errors as they are encountered
 */
uint8_t TskFindFiles::handleError() {
    fprintf(stderr, "%s", tsk_error_get());
    return 0;
}

time_t getLatestTime(TSK_FS_META *meta) {
    if (meta) {
        return max(max(max(meta->atime, meta->crtime), meta->mtime), meta->ctime);
    }
    return 0;
}

std::string timeToString(time_t time) {
    struct tm * ptm;
    ptm = gmtime(&time);
    char buffer[80];
    strftime(buffer, 80, "%Y-%m-%d", ptm);
    return std::string(buffer);
}

void TskFindFiles::alert(TSK_RETVAL_ENUM extractStatus, const RuleMatchResult *matchResult, TSK_FS_FILE *fs_file, const char *path) {
    // alert file format is "extractStatus<tab>description<tab>name<tab>path"
    fprintf(m_alertFile, "%d\t%s\t%s\t%s\n",
        extractStatus,
        matchResult->getDescription().c_str(),
        (fs_file->name ? fs_file->name->name : "name is null"),
        path);
    fprintf(stdout, "%d\t%s\t%s\t%s\n",
        extractStatus,
        matchResult->getDescription().c_str(),
        (fs_file->name ? fs_file->name->name : "name is null"),
        path);
}

/**
* Process a file. If the file matches a rule specified in the LogicalImagerRuleSet,
* we collect it by reading the file content.
* @param fs_file File details
* @param path Full path of parent directory
* @returns TSK_OK or TSK_ERR. All error must have been registered.
*/
TSK_RETVAL_ENUM TskFindFiles::processFile(TSK_FS_FILE *fs_file, const char *path) {
    RuleMatchResult *matchResult = m_logicialImagerRuleSet->matches(fs_file, path);
    if (matchResult) {
        TSK_RETVAL_ENUM extractStatus = TSK_ERR;
        if (matchResult->isShouldSave()) {
            extractStatus = TskFindFiles::extractFile(fs_file);
        }
        // TODO: For verification only
        //fprintf(stdout, "processFile: extract=%d description=%s save=%d alert=%d name=%s\tsize=%" PRId64 "\tdate=%s\tpath=%s\n",
        //    (matchResult->isShouldSave() ? extractStatus : -1),
        //    matchResult->getDescription().c_str(),
        //    matchResult->isShouldSave(),
        //    matchResult->isShouldAlert(),
        //    (fs_file->name ? fs_file->name->name : "name is null"), 
        //    (fs_file->meta ? fs_file->meta->size : 0), 
        //    timeToString(getLatestTime(fs_file->meta)).c_str(), 
        //    path);

        if (matchResult->isShouldAlert()) {
            alert(extractStatus, matchResult, fs_file, path);
        }

        delete matchResult;
        return extractStatus;
    }
    return TSK_OK;
}

/**
 * Extract a file. tsk_img_writer_create must have been called prior to this method.
 * @param fs_file File details
 * @returns TSK_RETVAL_ENUM TSK_OK if file is extracted, TSK_ERR otherwise.
 */
TSK_RETVAL_ENUM TskFindFiles::extractFile(TSK_FS_FILE *fs_file) {
    TSK_OFF_T offset = 0;
    TSK_OFF_T bufferLen = 16 * 1024;
    TSK_OFF_T bytesRead;
    TSK_OFF_T bytesReadTotal = 0;
    char buffer[16 * 1024];

    while (true) {
        bytesRead = tsk_fs_file_read(fs_file, offset, buffer, bufferLen, TSK_FS_FILE_READ_FLAG_NONE);
        if (bytesRead == -1) {
            if (fs_file->meta && fs_file->meta->size == 0) {
                // ts_fs_file_read returns -1 with empty files, don't report it.
                return TSK_OK;  
            } else {
                // fprintf(stderr, "processFile: tsk_fs_file_read returns -1 filename=%s\toffset=%" PRId64 "\n", fs_file->name->name, offset);
                return TSK_ERR;
            }
        }
        offset += bytesRead;
        if (offset >= fs_file->meta->size) {
            break;
        }
    }
    return TSK_OK;
}