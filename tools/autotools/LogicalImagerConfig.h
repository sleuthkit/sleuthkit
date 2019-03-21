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

#include "tsk/tsk_tools_i.h"

/**
* Implement the logical imager configuration.
*
*/
class LogicalImagerConfig
{
public:
	LogicalImagerConfig(const std::string configFilename);
	~LogicalImagerConfig();

	bool hasExtension(const std::string extension);
	const std::set<std::string> getExtension();

private:
	std::set<std::string> m_extensions;
};