/*
 *  The Sleuth Kit
 *
 *  Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 *  Copyright (c) 2010-2012 Basis Technology Corporation. All Rights
 *  reserved.
 *
 *  This software is distributed under the Common Public License 1.0
 */

/**
 * \file TskSystemProperties.cpp
 * Contains the implementation of the TskSystemProperties class.
 */

// Include the class definition first to ensure it does not depend on subsequent includes in this file.
#include "TskSystemProperties.h"

#include "Services/TskServices.h" // @@@ TODO: Resolve need to include TskServices.h before Log.h (macros in Log.h cause circular references)
#include "Services/Log.h"
#include "Utilities/TskUtilities.h"
#include "Utilities/TskException.h"
#include <sstream>
#include "Poco/StringTokenizer.h"
#include "Poco/LocalDateTime.h"
#include "Poco/DateTimeFormatter.h"

const TskSystemProperties::PredefProp TskSystemProperties::predefinedProperties[] =
{
    PredefProp(PROG_DIR, "PROG_DIR", false),
    PredefProp(CONFIG_DIR, "CONFIG_DIR", false),
    PredefProp(MODULE_DIR, "MODULE_DIR", false),
    PredefProp(OUT_DIR, "OUT_DIR", true),
    PredefProp(PIPELINE_CONFIG_FILE, "PIPELINE_CONFIG_FILE", false),
    PredefProp(DB_HOST, "DB_HOST", false),
    PredefProp(DB_PORT, "DB_PORT", false),
    PredefProp(SESSION_ID, "SESSION_ID", false),
    PredefProp(CURRENT_TASK, "CURRENT_TASK", false),
    PredefProp(CURRENT_SEQUENCE_NUMBER, "CURRENT_SEQUENCE_NUMBER", false),
    PredefProp(NODE, "NODE", false),
    PredefProp(PID, "PID", false),
    PredefProp(START_TIME, "START_TIME", false),
    PredefProp(CURRENT_TIME, "CURRENT_TIME", false),
    PredefProp(UNIQUE_ID, "CURRENT_TIME", false),
};

TskSystemProperties::TskSystemProperties()
{
    for (std::size_t i = 0; i < END_PROPS; ++i)
    {
        predefPropNames.push_back(predefinedProperties[i].token);
        predefPropTokens.insert(predefinedProperties[i].token);

        if (predefinedProperties[i].required)
        {
            requiredProps.insert(predefinedProperties[i].id);
        }
    }
}

bool TskSystemProperties::isConfigured() const
{
    for (std::set<PredefinedProperty>::const_iterator prop = requiredProps.begin(); prop != requiredProps.end(); ++prop)
    {
        std::string value = getProperty(predefPropNames[*prop]);
        if (value.empty())
        {
            return false;
        }
    }

    return true;
}

void TskSystemProperties::setW(PredefinedProperty prop, const std::wstring &value)
{
    set(prop, TskUtilities::toUTF8(value));
}

void TskSystemProperties::setW(const std::wstring &name, const std::wstring &value)
{
    set(TskUtilities::toUTF8(name), TskUtilities::toUTF8(value));
}

void TskSystemProperties::set(PredefinedProperty prop, const std::string &value)
{
    if (prop < PROG_DIR || prop > END_PROPS)
    {
        throw TskException("TskSystemProperties::set passed out of range prop argument");
    }

    set(predefPropNames[prop], value);
}

void TskSystemProperties::set(const std::string &name, const std::string &value)
{
    if (name.empty())
    {
        throw TskException("TskSystemProperties::set passed empty name argument");
    }

    setProperty(name, value);
}

std::wstring TskSystemProperties::getW(PredefinedProperty prop) const
{
    return TskUtilities::toUTF16(get(prop));
}

std::wstring TskSystemProperties::getW(const std::wstring &name) const
{
    return TskUtilities::toUTF16(get(TskUtilities::toUTF8(name)));
}

std::string TskSystemProperties::get(PredefinedProperty prop) const
{
    if (prop < PROG_DIR || prop > END_PROPS)
    {
        throw TskException("TskSystemProperties::get passed out of range prop argument");
    }

    std::string value = get(predefPropNames[prop]);
    
    if (value.empty() && requiredProps.count(prop) != 0)
    {
        std::stringstream msg;
        msg << "TskSystemProperties::get called for unset required predefined system property " << predefPropNames[prop];
        throw TskException(msg.str());
    }
    
    return  value;
}

std::string TskSystemProperties::get(const std::string &name) const
{
    return expandMacros(getProperty(name));
}

std::wstring TskSystemProperties::expandMacrosW(const std::wstring &inputStr) const
{
    return TskUtilities::toUTF16(expandMacros(TskUtilities::toUTF8(inputStr)));
}

std::string TskSystemProperties::expandMacros(const std::string &inputStr) const
{
    std::string outputStr;
    expandMacros(inputStr, outputStr, 1);
    return outputStr;
}

void TskSystemProperties::expandMacros(const std::string &inputStr, std::string &outputStr, std::size_t depth) const
{
    if (depth > MAX_RECURSION_DEPTH)
    {
        std::wstringstream msg;
        msg << L"TskSystemProperties::expandMacros reached maximum depth (" << MAX_RECURSION_DEPTH << L") of recursion, cannot complete expansion of " << inputStr.c_str();
        LOGERROR(msg.str());
        return;
    }

    Poco::StringTokenizer tokenizer(inputStr, "#");
    for (Poco::StringTokenizer::Iterator token = tokenizer.begin(); token != tokenizer.end(); ++token)
    {
        if (predefPropTokens.count(*token) != 0)
        {
            if (*token == predefPropNames[CURRENT_TIME])
            {
                outputStr += Poco::DateTimeFormatter::format(Poco::LocalDateTime(), "%Y_%m_%d_%H_%M_%S");
            }
            else
            {
                expandMacros(getProperty(*token), outputStr, depth + 1);
            }
        }
        else
        {
            outputStr += *token;
        }
    }
}
