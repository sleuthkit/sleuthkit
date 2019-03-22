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
TskFindFiles::TskFindFiles(LogicalImagerRuleSet *ruleSet) {
    m_logicialImagerRuleSet = ruleSet;
}

/**
 * Print errors as they are encountered
 */
uint8_t TskFindFiles::handleError() {
    fprintf(stderr, "%s", tsk_error_get());
    return 0;
}

std::string timeToString(time_t time) {
    struct tm * ptm;
    ptm = gmtime(&time);
    char buffer[80];
    strftime(buffer, 80, "%Y-%m-%d", ptm);
    return std::string(buffer);
}

/**
* Process a file. If the file contains an extension which is specified in the LogicalImagerRuleSet,
* we collect it by reading the file content.
* @param fs_file file details
* @param path full path of parent directory
* @returns TSK_OK or TSK_ERR. All error must have been registered.
*/
TSK_RETVAL_ENUM TskFindFiles::processFile(TSK_FS_FILE *fs_file, const char *path) {
    // handle file only
    if (!isFile(fs_file))
        return TSK_OK;

    if (m_logicialImagerRuleSet->matches(fs_file, path)) {
        fprintf(stdout, "processFile: match name=%s\tsize=%" PRIu64 "\tmtime=%s\tpath=%s\n", 
            fs_file->name->name, fs_file->meta->size, timeToString(fs_file->meta->mtime).c_str(), path);

        TSK_OFF_T offset = 0;
        size_t bufferLen = 16 * 1024;
        size_t bytesRead;
        char buffer[16 * 1024];

        while (true) {
            bytesRead = tsk_fs_file_read(fs_file, offset, buffer, bufferLen, TSK_FS_FILE_READ_FLAG_NONE);
            if (bytesRead == -1) {
                fprintf(stderr, "processFile: tsk_fs_file_read returns -1\tfilename=%s\toffset=%" PRIu64 "\n", fs_file->name->name, offset);
                return TSK_ERR;
            }
            if (bytesRead < bufferLen) {
                break;
            }
            offset += bytesRead;
        }
    }
    return TSK_OK;
}