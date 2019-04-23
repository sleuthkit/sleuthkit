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
* \file LogicalImagerRuleSet.h
* Contains the class definitions for the Logicial Imager Rule Set.
*/

#pragma once

#include <string>
#include <set>
#include <list>
#include <map>

#include "tsk/tsk_tools_i.h"
#include "LogicalImagerRuleBase.h"
#include "RuleMatchResult.h"
#include "json.h"

/**
* Implement the logical imager rule set.
*
*/
class LogicalImagerRuleSet
{
public:
    LogicalImagerRuleSet(const std::string &configFilename, const std::string &alertFilename);
    ~LogicalImagerRuleSet();

    TSK_RETVAL_ENUM processFile(TSK_FS_FILE *fs_file, const char *path) const;
    TSK_RETVAL_ENUM matches(TSK_FS_FILE *fs_file, const char *path) const;
    const std::pair<const RuleMatchResult *, std::list<std::string>> getFullFilePaths() const;
    TSK_RETVAL_ENUM extractFile(TSK_FS_FILE *fs_file) const;
    void alert(TSK_RETVAL_ENUM extractStatus, const std::string &description, TSK_FS_FILE *fs_file, const char *path) const;

    bool getFinalizeImagerWriter() { return m_finalizeImageWriter; }
    void closeAlert() const;

private:
    void constructRuleSet(const std::string &ruleSetKey, nlohmann::json ruleSetValue);
    LogicalImagerRuleSet(const LogicalImagerRuleSet&) == delete;

    std::map<const RuleMatchResult *, std::vector<LogicalImagerRuleBase *>> m_rules;
    std::pair<const RuleMatchResult *, std::list<std::string>> m_fullFilePaths;
    bool m_finalizeImageWriter = false;
    std::string m_alertFilePath;
    FILE *m_alertFile;
};
