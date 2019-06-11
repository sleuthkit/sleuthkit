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
* Contains the class definitions for the Logicial Imager Rule Set.
*/

#pragma once

#include <string>
#include <set>
#include <list>
#include <map>

#include "tsk/tsk_tools_i.h"
#include "LogicalImagerRuleSet.h"
#include "RuleMatchResult.h"
#include "json.h"

/**
* Implement the logical imager configuration.
*
*/
class LogicalImagerConfiguration
{
public:
    LogicalImagerConfiguration(const std::string &configFilename);
    ~LogicalImagerConfiguration();

    TSK_RETVAL_ENUM matches(TSK_FS_FILE *fs_file, const char *path) const;
    const std::pair<const RuleMatchResult *, std::list<std::string>> getFullFilePaths() const;
    static TSK_RETVAL_ENUM extractFile(TSK_FS_FILE *fs_file);

    bool getFinalizeImagerWriter() { return m_finalizeImageWriter; }

private:
    LogicalImagerConfiguration(const LogicalImagerConfiguration &) = delete;

    std::vector<LogicalImagerRuleSet *> m_ruleSets;
    bool m_finalizeImageWriter = false;
};
