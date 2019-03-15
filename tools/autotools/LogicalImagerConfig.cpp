#include "LogicalImagerConfig.h"

#include <fstream>
#include <iostream>
#include <iterator>

LogicalImagerConfig::LogicalImagerConfig()
{
}

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

bool LogicalImagerConfig::hasExtension(const std::string extension)
{
	return m_extensions.find(extension) != m_extensions.end();
}

const std::set<std::string> LogicalImagerConfig::getExtension()
{
	return m_extensions;
}
