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

    /**
    * Base method for matching a file and its path against derived classes.
    * Derived classes must implement the matches method.
    *
    * @param fs_file TSK_FS_FILE containing the filename
    * @param path parent path to fs_file
    * @returns true if the path is in the rule
    *          false otherwise
    */
    virtual bool matches(TSK_FS_FILE *fs_file, const char *path) const = 0;

    /**
    * Validate a path.
    * Path containing the backslash character is invalid.
    *
    * @param path parent path to a file
    * @throws std::logic_error if the path is invalid
    */
    void validatePath(const std::string &path) const;
};
