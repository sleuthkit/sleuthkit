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
* \file LogicalImagerRule.h
* Contains the class definitions for the Logicial Imager Rule.
*/

#pragma once

#include <string>
#include <set>

#include "tsk/tsk_tools_i.h"

/**
* Implement the logical imager rule.
*
*/
class LogicalImagerRule
{
public:
	LogicalImagerRule();
    ~LogicalImagerRule();

    BOOL addFolderNames(set<std::string> folderNames);
    BOOL addFileNames(set<std::string> fileNames);
    BOOL addExtensions(set<std::string> extensions);
    BOOL addMinMaxSize(int64_t min, int64_t max);

private:
};