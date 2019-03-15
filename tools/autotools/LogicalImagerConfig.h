#include <string>
#include <set>

#include "tsk/tsk_tools_i.h"

#pragma once

class LogicalImagerConfig
{
public:
	LogicalImagerConfig();
	LogicalImagerConfig(const std::string configFilename);
	~LogicalImagerConfig();

	bool hasExtension(const std::string extension);
	const std::set<std::string> getExtension();

private:
	std::set<std::string> m_extensions;
};