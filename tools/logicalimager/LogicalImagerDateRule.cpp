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
#include <ctime>
#include <stdio.h>
#include <iostream>

#include "LogicalImagerDateRule.h"

/*
* Construct a file date rule.
*
* @param min Minimum date in time_t
* @param max Maximum data in time_t
* @param minDays Minimum days for matching file minDays or newer
* minDays has higher priority over exact (min and max) dates
*/

LogicalImagerDateRule::LogicalImagerDateRule(time_t min, time_t max, int minDays) {
    m_min = min;
    m_max = max;
    m_minDays = minDays;
}

LogicalImagerDateRule::~LogicalImagerDateRule() {
}

/**
 * Get the latest time out of (atime, crtime, mtime and ctime) from the file meta
 *
 * @param meta TSK_FS_META of the file
 * @returns time_t of the latest time
 */
time_t LogicalImagerDateRule::getLatestTime(TSK_FS_META *meta) const {
    return max(max(max(meta->atime, meta->crtime), meta->mtime), meta->ctime);
}

/**
* Is the file latest time more than the minDays (match file minDays or newer)
* Is the file latest time within the min and max dates.
* Matching minDays takes priority over min and max dates.
*
* @param fs_file TSK_FS_FILE containing the filename
* @param path parent path to fs_file
* @returns true if the file matches this rule
*          false otherwise
*/
bool LogicalImagerDateRule::matches(TSK_FS_FILE *fs_file, const char * /* path */) const
{
    if (fs_file->meta == NULL)
        return false;

    time_t latest_time = getLatestTime(fs_file->meta);

    // m_minDays takes priority over explicit date
    if (m_minDays) {
        std::time_t now;
        std::tm localTime = {0};

        std::time(&now);
        gmtime_s(&localTime, &now);
        localTime.tm_mday -= m_minDays;
        std::time_t daysAgo = std::mktime(&localTime);
        if (daysAgo == -1) {
            std::cerr << "daysAgo failed, m_minDays = " << m_minDays << std::endl;
            return false;
        }

        if (latest_time > daysAgo)
            return true;
        else
            return false;
    }

    if (m_max == 0) {
        // no upper limit, check the min date
        if (latest_time > m_min)
            return true;
        else
            return false;
    } else {
        if (latest_time >= m_min && latest_time <= m_max) {
            return true;
        } else {
            return false;
        }
    }
}
