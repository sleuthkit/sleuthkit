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
* \file LogicalImagerConfiguration.h
* Contains the class definitions for the Logicial Imager Rule Configuration.
*/

#pragma once

#include <string>
#include <set>
#include <list>
#include <map>

#include "tsk/tsk_tools_i.h"
#include "LogicalImagerRuleSet.h"
#include "MatchedRuleInfo.h"
#include "json.h"

/**
* Implement the logical imager configuration.
*
*/
class LogicalImagerConfiguration
{
public:
    LogicalImagerConfiguration(const std::string &configFilename, LogicalImagerRuleSet::matchCallback callbackFunc);
    ~LogicalImagerConfiguration();

    TSK_RETVAL_ENUM matches(TSK_FS_FILE *fs_file, const char *path) const;
    const std::vector<std::pair<const MatchedRuleInfo *, std::list<std::string>>> getFullFilePaths() const;
    bool getCreateVHD() { return m_createVHD; }
    bool getFinalizeImagerWriter() { return m_finalizeImageWriter; }
    bool getPromptBeforeExit() { return m_promptBeforeExit; }
    std::string getVersion() { return m_version; }

private:
    LogicalImagerConfiguration(const LogicalImagerConfiguration &) = delete;

    std::vector<LogicalImagerRuleSet *> m_ruleSets;
    bool m_createVHD = false;
    bool m_finalizeImageWriter = false;
    bool m_promptBeforeExit = true;
    std::string m_version;
    LogicalImagerRuleSet::matchCallback m_callbackFunc;

    const std::string m_currentVersion = std::string("1.0");
};
