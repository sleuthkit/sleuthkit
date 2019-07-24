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
TskFindFiles::TskFindFiles(const LogicalImagerConfiguration *config) {
    m_logicialImagerConfiguration = config;
}

TskFindFiles::~TskFindFiles() {
}

/**
 * Print errors as they are encountered
 */
uint8_t TskFindFiles::handleError() {
    tsk_error_print(stderr);
    return 0;
}

/**
* Skip the processing of FAT orphans
* @param fs_info File system info
* @returns TSK_FILTER_CONT
*/
TSK_FILTER_ENUM
TskFindFiles::filterFs(TSK_FS_INFO * fs_info)
{
    // make sure that flags are set to get all files -- we need this to
    // find parent directory

    TSK_FS_DIR_WALK_FLAG_ENUM filterFlags = (TSK_FS_DIR_WALK_FLAG_ENUM)
        (TSK_FS_DIR_WALK_FLAG_ALLOC | TSK_FS_DIR_WALK_FLAG_UNALLOC);

    //check if to skip processing of FAT orphans
    if (TSK_FS_TYPE_ISFAT(fs_info->ftype)) {
        filterFlags = (TSK_FS_DIR_WALK_FLAG_ENUM)(filterFlags | TSK_FS_DIR_WALK_FLAG_NOORPHAN);
    }

    setFileFilterFlags(filterFlags);

    return TSK_FILTER_CONT;
}

/**
* Process a file. If the file matches a rule specified in the LogicalImagerRuleSet,
* we collect it by reading the file content.
* @param fs_file File details
* @param path Full path of parent directory
* @returns TSK_OK or TSK_ERR. All error must have been registered.
*/
TSK_RETVAL_ENUM TskFindFiles::processFile(TSK_FS_FILE *fs_file, const char *path) {
    return m_logicialImagerConfiguration->matches(fs_file, path);
}
