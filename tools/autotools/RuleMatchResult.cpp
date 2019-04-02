#include "RuleMatchResult.h"
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
* \file RuleMatchResult.cpp
* Contains C++ code that implement the Rule Match Resultt class.
*/

RuleMatchResult::RuleMatchResult(const std::string description, bool isMatch, bool shouldSave, bool shouldAlert) {
    m_isMatch = isMatch;
    m_description = description;
    m_shouldSave = shouldSave;
    m_shouldAlert = shouldAlert;
}
