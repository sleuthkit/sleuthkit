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

/**
* Implement the logical imager rule set.
*
*/
class LogicalImagerRuleSet
{
public:
    LogicalImagerRuleSet(const std::string configFilename);
    ~LogicalImagerRuleSet();

    RuleMatchResult matches(TSK_FS_FILE *fs_file, const char *path) const;
    const std::list<std::string> getFilePaths() const;

private:
    // Internal for testing only
    void testFilePath();
    void testExtension();
    void testFilename();
    void testFileSize();
    void testFileDate();
    void testUserFolder();

    std::map<RuleMatchResult *, std::vector<LogicalImagerRuleBase *>> m_rules;
    std::list<std::string> m_filePaths;
};
