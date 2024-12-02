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
* \file LogicalImagerDateRule.h
* Contains the class definitions for the Logicial Imager File Date Rule.
*/

#pragma once

#include <string>
#include <set>

#include "tsk/tsk_tools_i.h"
#include "LogicalImagerRuleBase.h"

/**
* Implement the logical imager file date rule.
*
*/
class LogicalImagerDateRule : public LogicalImagerRuleBase
{
public:
    LogicalImagerDateRule(time_t min, time_t max, int minDays);
    LogicalImagerDateRule(int minDays) { m_minDays = minDays; }
    ~LogicalImagerDateRule();

    bool matches(TSK_FS_FILE *fs_file, const char * /*path*/) const;

private:
    time_t LogicalImagerDateRule::getLatestTime(TSK_FS_META *meta) const;

    time_t m_min;
    time_t m_max;
    int m_minDays;
};
