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

#include <fstream>
#include <iostream>
#include <iterator>

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

	copy(std::istream_iterator<std::string>(file),
		std::istream_iterator<std::string>(),
		std::inserter(m_extensions, m_extensions.end()));
}

LogicalImagerConfig::~LogicalImagerConfig()
{
}

/**
 * Does the logical imager configuration contains an extension
 * 
 * @param extension Extension to search
 * @returns TRUE if extension is in the configuration
 *         FALSE otherwise
 */
bool LogicalImagerConfig::hasExtension(const std::string extension)
{
	return m_extensions.find(extension) != m_extensions.end();
}

/**
* Get a set of extensions defined in the configuration
*
* @returns A set of extensions
*
*/
const std::set<std::string> LogicalImagerConfig::getExtension()
{
	return m_extensions;
}
