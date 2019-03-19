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

#include "LogicalImagerConfig.h"

class TskFindFiles : public TskAuto {
public:
    TskFindFiles(LogicalImagerConfig *config);
    virtual TSK_RETVAL_ENUM processFile(TSK_FS_FILE *fs_file, const char *path);
    virtual uint8_t handleError();

private:
    LogicalImagerConfig * m_logicialImagerConfig;
};