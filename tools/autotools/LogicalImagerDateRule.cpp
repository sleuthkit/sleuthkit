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

#include "LogicalImagerDateRule.h"

LogicalImagerDateRule::LogicalImagerDateRule(time_t min, time_t max) {
    m_min = min;
    m_max = max;
}

LogicalImagerDateRule::~LogicalImagerDateRule()
{
}

/**
* Is the file within the min and max date
*
* @param fs_file TSK_FS_FILE containing the filename
* @param path parent path to fs_file
* @returns true if extension is in the rule
*         false otherwise
*/
bool LogicalImagerDateRule::matches(TSK_FS_FILE * fs_file, const char * path) const
{
    if (fs_file->meta == NULL)
        return false;

    if (m_max == 0) {
        // no upper limit, check the min size
        if (fs_file->meta->mtime >= m_min)
            return true;
        else
            return false;
    } else {
        if (fs_file->meta->mtime >= m_min && fs_file->meta->mtime <= m_max) {
            return true;
        } else {
            return false;
        }
    }
}
