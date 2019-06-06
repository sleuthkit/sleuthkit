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
* \file LogicalImagerRuleBase.h
* Contains the class definitions for the Logicial Imager Extension Rule.
*/

#pragma once

#include <string>
#include <set>

#include "tsk/tsk_tools_i.h"
#include "LogicalImagerRuleBase.h"

/**
* Implement the logical imager rule.
*
*/
class LogicalImagerExtensionRule : public LogicalImagerRuleBase
{
public:
    LogicalImagerExtensionRule(const std::set<std::string> &extensions);
    ~LogicalImagerExtensionRule();

    bool matches(TSK_FS_FILE *fs_file, const char * /*path*/) const;

private:
    std::set<std::string> m_extensions;
};
