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
* \file LogicalImagerFilenameRule.h
* Contains the class definitions for the Logicial Imager Filename Rule.
*/

#pragma once

#include <string>
#include <set>

#include "tsk/tsk_tools_i.h"
#include "LogicalImagerRuleBase.h"

/**
* Implement the logical imager filename rule.
*
*/
class LogicalImagerFilenameRule : public LogicalImagerRuleBase
{
public:
    LogicalImagerFilenameRule(const std::set<std::string> &filenames);
    ~LogicalImagerFilenameRule();

    bool matches(TSK_FS_FILE *fs_file, const char * /*path*/) const;

private:
    std::set<std::string> m_filenames;
};
