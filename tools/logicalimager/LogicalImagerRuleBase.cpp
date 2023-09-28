/*
** The Sleuth Kit
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2010-2019 Brian Carrier.  All Rights reserved
**
** This software is distributed under the Common Public License 1.0
**
*/

#include "LogicalImagerRuleBase.h"

LogicalImagerRuleBase::LogicalImagerRuleBase() {
}

LogicalImagerRuleBase::~LogicalImagerRuleBase() {
}

/**
* Validate a path.
* Path containing the backslash character is invalid.
*
* @param path parent path to a file
* @throws std::logic_error if the path is invalid
*/
void LogicalImagerRuleBase::validatePath(const std::string &path) const {
    if (path.find("\\") != std::string::npos) {
        throw std::logic_error("ERROR: Path cannot have backslash: " + path);
    }
}
