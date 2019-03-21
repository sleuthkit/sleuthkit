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
* \file LogicalImagerConfig.h
* Contains the class definitions for the Logicial Imager Configuration.
*/

#pragma once

#include <string>
#include <set>
#include <map>

#include "tsk/tsk_tools_i.h"
#include "LogicalImagerExtensionRule.h"

/**
* Implement the logical imager configuration.
*
*/
class LogicalImagerConfig
{
public:
	LogicalImagerConfig(const std::string configFilename);
	~LogicalImagerConfig();

    bool matches(TSK_FS_FILE *fs_file, const char *path) const;

private:
	std::map<std::string, LogicalImagerRuleBase *> m_rules;
};