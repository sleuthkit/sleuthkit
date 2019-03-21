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
* \file LogicalImagerConfig.cpp
* Contains C++ code that creates the Logical Imager Configuration class.
*/

#include "LogicalImagerConfig.h"
#include "LogicalImagerExtensionRule.h"

#include <fstream>
#include <iostream>
#include <iterator>
#include <map>

/**
 * Create a logical imager configuration
 * 
 * @param configFilename Configuration filename containing the configuration of this logical imager.
 * For now, the configuration file defines file extensions (without the dot), one extension per line.
 * 
 */
LogicalImagerConfig::LogicalImagerConfig(const std::string configFilename)
{
	std::ifstream file(configFilename);

    // TODO: read the config yaml file and construct the m_rules map

    std::string extension_strs[] = {"jpg", "jpeg", "gif", "png"};
    std::set<std::string> extensions(extension_strs, extension_strs + sizeof(extension_strs)/sizeof(extension_strs[0]));
    LogicalImagerExtensionRule *extension_rule = new LogicalImagerExtensionRule(extensions);

    m_rules.insert(std::pair<std::string, LogicalImagerRuleBase *>(std::string("extension_rule"), extension_rule));
}

LogicalImagerConfig::~LogicalImagerConfig()
{
}

bool LogicalImagerConfig::matches(TSK_FS_FILE * fs_file, const char * path) const
{
    std::map<std::string, LogicalImagerRuleBase *>::const_iterator itr;
    bool result = false;

    for (itr = m_rules.begin(); itr != m_rules.end(); itr++) {
        result |= itr->second->matches(fs_file, path);
    }
    return result;
}
