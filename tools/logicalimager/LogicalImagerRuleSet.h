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
    typedef TSK_RETVAL_ENUM(*matchCallback)(const RuleMatchResult *, TSK_FS_FILE *, const char *);

    LogicalImagerRuleSet();
    ~LogicalImagerRuleSet();

    bool matches(TSK_FS_FILE *fs_file, const char *path, matchCallback callbackFunc) const;
    const std::pair<const RuleMatchResult *, std::list<std::string>> getFullFilePaths() const;

    const std::vector<std::pair<const RuleMatchResult *, std::vector<LogicalImagerRuleBase *>>> getRules() {
        return m_rules;
    }

    void constructRuleSet(const nlohmann::json ruleSet, 
        std::vector<std::pair<const RuleMatchResult *, std::vector<LogicalImagerRuleBase *>>> &ourRules
    );

private:
    LogicalImagerRuleSet(const LogicalImagerRuleSet &) = delete;
    void constructRule(const std::string &ruleSetName, nlohmann::json rule);

    std::string m_ruleSetName;
    std::vector<std::pair<const RuleMatchResult *, std::vector<LogicalImagerRuleBase *>>> m_rules;
    std::pair<const RuleMatchResult *, std::list<std::string>> m_fullFilePaths;
};
