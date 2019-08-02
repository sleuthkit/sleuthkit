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

#include "RuleMatchResult.h"

RuleMatchResult::RuleMatchResult(const std::string &ruleSetName, const std::string &name, 
    const std::string &description, bool shouldSave, bool shouldAlert) :
    m_ruleSetName(ruleSetName),
    m_name(name),
    m_description(description),
    m_shouldAlert(shouldAlert),
    m_shouldSave(shouldSave)
{
}
