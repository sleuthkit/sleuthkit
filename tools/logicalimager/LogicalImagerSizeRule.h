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
* \file LogicalImagerSizeRule.h
* Contains the class definitions for the Logicial Imager File Size Rule.
*/

#pragma once

#include <string>
#include <set>

#include "tsk/tsk_tools_i.h"
#include "LogicalImagerRuleBase.h"

/**
* Implement the logical imager file size rule.
*
*/
class LogicalImagerSizeRule : public LogicalImagerRuleBase
{
public:
    LogicalImagerSizeRule(TSK_OFF_T min, TSK_OFF_T max);
    ~LogicalImagerSizeRule();

    bool matches(TSK_FS_FILE *fs_file, const char * /*path*/) const;

private:
    TSK_OFF_T m_min;
    TSK_OFF_T m_max;
};
