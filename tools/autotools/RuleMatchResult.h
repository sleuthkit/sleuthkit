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
* \file RuleMatchResult.h
* Contains the class definitions for the Rule Match Result.
*/

#pragma once

#include <string>

/**
* Defines the rule match result
*
*/
class RuleMatchResult
{
public:
    RuleMatchResult(const std::string description, bool isMatch = false, bool shouldSave = true, bool shouldAlert = false);
    ~RuleMatchResult() {}

    bool isMatch() const { return m_isMatch; }
    const std::string getDescription() const { return m_description; }
    bool isShouldSave() const { return m_shouldSave; }
    bool isShouldAlert() const { return m_shouldAlert; }
    
private:
    bool m_isMatch;
    std::string m_description;
    bool m_shouldSave;
    bool m_shouldAlert;
};
