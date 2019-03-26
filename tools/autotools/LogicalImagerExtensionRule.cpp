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

#include "LogicalImagerExtensionRule.h"

LogicalImagerExtensionRule::LogicalImagerExtensionRule(std::set<std::string> extensions)
{
    for (auto it = std::begin(extensions); it != std::end(extensions); ++it) {
        m_extensions.insert(LogicalImagerRuleBase::toLower(*it));
    }
}

LogicalImagerExtensionRule::~LogicalImagerExtensionRule()
{
}

/**
* Match a file's extension against the logical imager extension set
*
* @param fs_file TSK_FS_FILE containing the filename
* @param path parent path to fs_file
* @returns true if extension is in the rule
*          false otherwise
*/
bool LogicalImagerExtensionRule::matches(TSK_FS_FILE *fs_file, const char * /*path*/) const
{
    if (fs_file->name == NULL)
        return false;

    char *extension = PathFindExtensionA(fs_file->name->name);
    if (extension[0] == '.') {
        // skip the leading dot
        extension = &extension[1];
    }

    return m_extensions.find(LogicalImagerRuleBase::toLower(extension)) != m_extensions.end();
}