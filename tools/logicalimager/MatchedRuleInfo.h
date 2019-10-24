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
* \file MatchedRuleInfo.h
* Contains the class definitions for the Matched Rule Info.
*/

#pragma once

#include <string>

/**
* Defines the matched rule information
*
*/
class MatchedRuleInfo
{
public:
    MatchedRuleInfo(const std::string &ruleSetName, const std::string &name, 
        const std::string &description, bool shouldSave = true, bool shouldAlert = false);
    ~MatchedRuleInfo() {}

    const std::string getRuleSetName() const { return m_ruleSetName; }
    const std::string getName() const { return m_name; }
    const std::string getDescription() const { return m_description; }
    bool isShouldSave() const { return m_shouldSave; }
    bool isShouldAlert() const { return m_shouldAlert; }

private:
    std::string m_ruleSetName;
    std::string m_name;
    std::string m_description;
    bool m_shouldSave;
    bool m_shouldAlert;
};
