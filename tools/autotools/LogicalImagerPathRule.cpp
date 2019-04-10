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
static char *userFolderRegex = "/?(documents and settings|users|home)/[^/]+";
static std::string lowerCaseUserFolder;

bool endsWith(const std::string &str, const std::string &suffix) {
    return str.size() >= suffix.size() &&
        str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}

LogicalImagerPathRule::LogicalImagerPathRule(const std::set<std::string> &paths)
{
    lowerCaseUserFolder = TskHelper::toLower(getUserFolder());
    for (auto it = std::begin(paths); it != std::end(paths); ++it) {
        std::string lowerCasePath = TskHelper::toLower(*it);
        if (lowerCasePath.size() >= lowerCaseUserFolder.size() && 
            lowerCasePath.compare(0, lowerCaseUserFolder.size(), lowerCaseUserFolder) == 0) {
            // [USER_FOLDER] must be at the start of path
            // special case, add to regex
            std::string newPattern(lowerCasePath);
            newPattern.replace(newPattern.find(lowerCaseUserFolder), lowerCaseUserFolder.length(), userFolderRegex);
            if (endsWith(lowerCasePath, "/")) {
                newPattern.append(".*");
            } else {
                newPattern.append("/.*");
            }
            std::regex pattern(newPattern);
            m_userFolderRegexes.push_back(pattern);
        } else {
            m_paths.insert(TskHelper::toLower(*it));
        }
    }
}

LogicalImagerPathRule::~LogicalImagerPathRule()
{
}

/**
* Match all user folder paths using regex_match
* @param rule Rule specified containing [USER_FOLDER] string
* @param path Path to be matched
* @returns true if there is a match, false otherwise
*/
bool LogicalImagerPathRule::matchUserFolder(const std::string path) const {
    for (auto it = std::begin(m_userFolderRegexes); it != std::end(m_userFolderRegexes); ++it) {
        if (std::regex_match(path, *it)) {
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

    if (matchUserFolder(lowercasePath)) {
        return true;
    }

    for (auto it = std::begin(m_paths); it != std::end(m_paths); ++it) {
        if (lowercasePath.find(*it) != std::string::npos) {
            return true;
        }
    }
    return false;
}
