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
* Contains the base class definitions for the Logicial Imager Rule.
*/

#pragma once

#include <string>
#include <algorithm>

#include "tsk/tsk_tools_i.h"

/**
* Implement the logical imager rule.
*
*/
class LogicalImagerRuleBase
{
public:
    LogicalImagerRuleBase();
    ~LogicalImagerRuleBase();

    virtual bool matches(TSK_FS_FILE *fs_file, const char *path) const = 0;
};
