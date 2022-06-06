/*
** tsk_logical_imager
** The Sleuth Kit
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2010-2019 Brian Carrier.  All Rights reserved
**
** This software is distributed under the Common Public License 1.0
**
*/

/**
* \file TskFindFiles.h
* Contains the class definitions for TSK find files.
*/

#pragma once

#include <string>

#include "LogicalImagerRuleSet.h"
#include "LogicalImagerConfiguration.h"

class TskFindFiles : public TskAuto {
public:
    TskFindFiles(const LogicalImagerConfiguration *config, const std::string &driveName);
    ~TskFindFiles();
    virtual TSK_FILTER_ENUM filterFs(TSK_FS_INFO * fs_info);
    virtual TSK_RETVAL_ENUM processFile(TSK_FS_FILE *fs_file, const char *path);
    virtual uint8_t handleError();

private:
    const LogicalImagerConfiguration *m_logicialImagerConfiguration;
    size_t m_fileCounter;
    int m_totalNumberOfFiles;
    unsigned short m_percentComplete;
    const std::string m_driveDisplayName;
};