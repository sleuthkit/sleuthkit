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
#include <regex>

#include "LogicalImagerPathRule.h"
#include "TskHelper.h"

/* case insensitive user folder prefixes */
static char *userFolderRegexList[] = {
    "/?(documents and settings|users|home)/.*"
};
static std::string lowerCaseUserFolder;

LogicalImagerPathRule::LogicalImagerPathRule(const std::set<std::string> paths)
{
    for (auto it = std::begin(paths); it != std::end(paths); ++it) {
        m_paths.insert(TskHelper::toLower(*it));
    }
    lowerCaseUserFolder = TskHelper::toLower(getUserFolder());
}

LogicalImagerPathRule::~LogicalImagerPathRule()
{
}

bool endsWith(const std::string &str, const std::string &suffix) {
    return str.size() >= suffix.size() &&
        str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}

/**
* Match all user folder paths using regex_match
* @param rule Rule specified containing [USER_FOLDER] string
* @param path Path to be matched
* @returns true if there is a match, false otherwise
*/
bool LogicalImagerPathRule::matchUserFolder(const std::string &rule, const std::string path) const {
    for (int i = 0; i < sizeof(userFolderRegexList) / sizeof(userFolderRegexList[0]); ++i) {
        std::string newPattern(rule);
        newPattern.replace(newPattern.find(lowerCaseUserFolder), lowerCaseUserFolder.length(), userFolderRegexList[i]);
        if (endsWith(rule, "/")) {
            newPattern.append(".*");
        } else {
            newPattern.append("/.*");
        }
        std::regex pattern(newPattern);

        if (std::regex_match(path, pattern)) {
            return true;
        }
    }
    return false;
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

    const std::string lowercasePath = TskHelper::toLower(path);

    for (auto it = std::begin(m_paths); it != std::end(m_paths); ++it) {
        if (it->find(lowerCaseUserFolder) != std::string::npos) {
            if (matchUserFolder(*it, lowercasePath)) {
                return true;
            }
        } else if (lowercasePath.find(*it) != std::string::npos) {
            return true;
        }
    }
    return false;
}
