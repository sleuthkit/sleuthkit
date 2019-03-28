/*
** The Sleuth Kit
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2010-2019 Brian Carrier.  All Rights reserved
**
** This software is distributed under the Common Public License 1.0
**
*/

#include <shlwapi.h>
#include <string>
#include <algorithm>

#include "LogicalImagerPathRule.h"

LogicalImagerPathRule::LogicalImagerPathRule(std::set<std::string> paths)
{
    for (auto it = std::begin(paths); it != std::end(paths); ++it) {
        m_paths.insert(LogicalImagerRuleBase::toLower(*it));
    }
}

LogicalImagerPathRule::~LogicalImagerPathRule()
{
}

/**
* Match a file's path against the logical imager path set
*
* @param fs_file TSK_FS_FILE containing the filename
* @param path parent path to fs_file
* @returns true if the path is in the rule
*          false otherwise
*/
bool LogicalImagerPathRule::matches(TSK_FS_FILE * /*fs_file*/, const char *path) const
{
    if (path == NULL)
        return false;

    std::string lowercasePath = LogicalImagerRuleBase::toLower(path);

    for (auto it = std::begin(m_paths); it != std::end(m_paths); ++it) {
        if (lowercasePath.find(*it) != std::string::npos) {
            return true;
        }
    }
    return false;
}
