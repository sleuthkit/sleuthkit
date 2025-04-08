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
#include <iostream>

#include "LogicalImagerRuleSet.h"
#include "tsk/tsk_tools_i.h"
#include "tsk/fs/tsk_ntfs.h"
#include "TskFindFiles.h"
#include "TskHelper.h"
#include "ReportUtil.h"

/**
 * Create the Find Files object given the Logical Imager Configuration
 * @param config LogicalImagerRuleSet to use for finding files
 */
TskFindFiles::TskFindFiles(const LogicalImagerConfiguration *config, const std::string &driveName) :
    m_logicialImagerConfiguration(config), m_driveDisplayName(driveName)
 {
    m_fileCounter = 0;
    m_totalNumberOfFiles = 0;
    m_percentComplete = 0;
}

TskFindFiles::~TskFindFiles() {
    std::string title = "Analyzing drive " + m_driveDisplayName + " - Searching for files by attribute, 100% complete";
    SetConsoleTitleA(title.c_str());
}

/**
 * Print errors as they are encountered
 */
uint8_t TskFindFiles::handleError() {
    std::string str = tsk_error_get();
    str += "\n";
    ReportUtil::logOutputToFile(str.c_str());
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

    std::string title = "Analyzing drive " + m_driveDisplayName + " - Searching for files by attribute";
    if (TSK_FS_TYPE_ISNTFS(fs_info->ftype)) {
        NTFS_INFO *ntfs_info = (NTFS_INFO *)fs_info;
        if (ntfs_info->alloc_file_count == 0) {
            // we need to force the orphan finding process to get this count
            TSK_FS_DIR *fs_dir = tsk_fs_dir_open_meta(fs_info, fs_info->root_inum);
            if (fs_dir) {
                m_totalNumberOfFiles = ((NTFS_INFO*)fs_info)->alloc_file_count;
            }
            tsk_fs_dir_close(fs_dir);
        }
        title += ", 0% complete";
    }
    SetConsoleTitleA(title.c_str());

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

    /* Update progress - only apply to NTFS.
     * We can calculate progress for NTFS file systems because we have
     * modified TSK to keep track of the number of allocated files.
     * For NTFS, we increment the file counter for allocated files.
     */
    if (fs_file->fs_info && fs_file->fs_info->ftype == TSK_FS_TYPE_NTFS) {
        if (fs_file->meta && (fs_file->meta->flags & TSK_FS_META_FLAG_ALLOC && fs_file->meta->type == TSK_FS_META_TYPE_REG)) {
            m_fileCounter++;
        }
        if (0 == m_fileCounter % 5000) {
            if (m_totalNumberOfFiles > 0 && m_fileCounter <= m_totalNumberOfFiles) {
                m_percentComplete = (unsigned short)(((float)m_fileCounter / (float)m_totalNumberOfFiles) * 100);
                static unsigned short lastReportedPctComplete = 0;
                if ((m_percentComplete != lastReportedPctComplete)) {
                    std::string title = "Analyzing drive " + m_driveDisplayName + " - Searching for files by attribute, "
                        + TskHelper::intToStr((long)m_percentComplete) + std::string("% complete");
                    SetConsoleTitleA(title.c_str());
                    lastReportedPctComplete = m_percentComplete;
                }
            }
        }
    }

    return m_logicialImagerConfiguration->matches(fs_file, path);
}
