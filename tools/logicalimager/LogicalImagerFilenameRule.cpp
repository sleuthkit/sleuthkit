/*
** The Sleuth Kit
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2010-2019 Brian Carrier.  All Rights reserved
**
** This software is distributed under the Common Public License 1.0
**
*/

#include <string>
#include <algorithm>

#include "LogicalImagerFilenameRule.h"
#include "TskHelper.h"

/*
* Construct a filename rule.
*
* @param filenames A set of filename strings. The filename should not contain any parent path.
* The filenames is case-insensitive. It it normalize to lowercase.
*/
LogicalImagerFilenameRule::LogicalImagerFilenameRule(const std::set<std::string> &filenames) {
    for (auto it = std::begin(filenames); it != std::end(filenames); ++it) {
        validatePath(*it);
        m_filenames.insert(TskHelper::toLower(*it));
    }
}

LogicalImagerFilenameRule::~LogicalImagerFilenameRule() {
}

/**
* Match a filename against the logical imager filename set
*
* @param fs_file TSK_FS_FILE containing the filename
* @param path parent path to fs_file
* @returns true if filename matches this rule
*          false otherwise
*/
bool LogicalImagerFilenameRule::matches(TSK_FS_FILE *fs_file, const char * /*path*/) const {
    if (fs_file->name == NULL)
        return false;

    std::string lowercaseFilename = TskHelper::toLower(fs_file->name->name);

    for (auto it = std::begin(m_filenames); it != std::end(m_filenames); ++it) {
        if (lowercaseFilename == *it) {
            return true;
        }
    }
    return false;
}
