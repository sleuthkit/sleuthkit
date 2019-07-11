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
* \file LogicalImagerPathRule.h
* Contains the class definitions for the Logicial Imager Path Rule.
*/

#pragma once

#include <string>
#include <set>
#include <regex>
#include <list>

#include "tsk/tsk_tools_i.h"
#include "LogicalImagerRuleBase.h"

/**
* Implement the logical imager pathname rule.
*
*/
class LogicalImagerPathRule : public LogicalImagerRuleBase
{
public:
    LogicalImagerPathRule(const std::set<std::string> &extensions);
    ~LogicalImagerPathRule();

    bool matches(TSK_FS_FILE * /*fs_file*/, const char *path) const;

    static const char *getUserFolder() { return "[USER_FOLDER]"; }

private:
    bool LogicalImagerPathRule::matchUserFolder(std::string path) const;

    std::set<std::string> m_paths;
    std::list<std::regex> m_userFolderRegexes;
};
