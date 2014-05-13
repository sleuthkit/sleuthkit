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

// TSK Framework includes
#include "tsk/framework/services/TskServices.h" // @@@ TODO: Resolve need to include TskServices.h before Log.h (macros in Log.h cause circular references)
#include "tsk/framework/services/Log.h"
#include "tsk/framework/utilities/TskUtilities.h"
#include "tsk/framework/utilities/TskException.h"

// Poco includes
#include "Poco/Path.h"
#include "Poco/StringTokenizer.h"
#include "Poco/LocalDateTime.h"
#include "Poco/DateTimeFormatter.h"

// C/C++ library includes
#include <sstream>
#include <assert.h>

namespace
{
    const std::string DEFAULT_PROG_DIR = Poco::Path::current();
    const std::string DEFAULT_CONFIG_DIR = std::string("#PROG_DIR#") + Poco::Path::separator() + std::string("Config");
    const std::string DEFAULT_MODULE_DIR = std::string("#PROG_DIR#") + Poco::Path::separator() + std::string("Modules");
    const std::string DEFAULT_SYSTEM_OUT_DIR = std::string("#OUT_DIR#") + Poco::Path::separator() + std::string("SystemOutput");
    const std::string DEFAULT_MODULE_OUT_DIR = std::string("#OUT_DIR#") + Poco::Path::separator() + std::string("ModuleOutput");
    const std::string DEFAULT_LOG_DIR = std::string("#SYSTEM_OUT_DIR#") + Poco::Path::separator() + std::string("Logs");
    const std::string DEFAULT_CARVE_DIR = std::string("#SYSTEM_OUT_DIR#") + Poco::Path::separator() + std::string("Carving");
    const std::string DEFAULT_UNALLOC_SECTORS_IMG_FILE_NAME = "unalloc.bin";
    const std::string DEFAULT_MAX_UNALLOC_SECTORS_IMG_FILE_SIZE = "0";
    const std::string DEFAULT_CARVE_EXTRACT_KEEP_INPUT_FILES = "false";
    const std::string DEFAULT_CARVE_EXTRACT_KEEP_OUTPUT_FILES = "false";
    const std::string DEFAULT_SCALPEL_CONFIG_FILE = std::string("#SCALPEL_DIR#") + Poco::Path::separator() + std::string("scalpel.conf");
    const std::string DEFAULT_PIPELINE_CONFIG_FILE = std::string("#CONFIG_DIR#") + Poco::Path::separator() + std::string("pipeline_config.xml");

    struct PredefProp
    {
        PredefProp(TskSystemProperties::PredefinedProperty propId, const std::string &macroToken, bool propRequired, const std::string &propDefaultValue) :
            id(propId), token(macroToken), required(propRequired), defaultValue(propDefaultValue) {}
        TskSystemProperties::PredefinedProperty id;
        std::string token;
        bool required;
        std::string defaultValue;
    };

    const PredefProp predefinedProperties[] =
    {
        PredefProp(TskSystemProperties::PROG_DIR, "PROG_DIR", false, ""),
        PredefProp(TskSystemProperties::CONFIG_DIR, "CONFIG_DIR", false, DEFAULT_CONFIG_DIR),
        PredefProp(TskSystemProperties::MODULE_DIR, "MODULE_DIR", false, DEFAULT_MODULE_DIR),
        PredefProp(TskSystemProperties::MODULE_CONFIG_DIR, "MODULE_CONFIG_DIR", false, DEFAULT_MODULE_DIR),    // default == MODULE_DIR
        PredefProp(TskSystemProperties::OUT_DIR, "OUT_DIR", true, ""),
        PredefProp(TskSystemProperties::SYSTEM_OUT_DIR, "SYSTEM_OUT_DIR", false, DEFAULT_SYSTEM_OUT_DIR),
        PredefProp(TskSystemProperties::MODULE_OUT_DIR, "MODULE_OUT_DIR", false, DEFAULT_MODULE_OUT_DIR),
        PredefProp(TskSystemProperties::LOG_DIR, "LOG_DIR", false, DEFAULT_LOG_DIR),
        PredefProp(TskSystemProperties::DB_HOST, "DB_HOST", false, ""),
        PredefProp(TskSystemProperties::DB_PORT, "DB_PORT", false, ""),
        PredefProp(TskSystemProperties::CARVE_DIR, "CARVE_DIR", false, DEFAULT_CARVE_DIR),
        PredefProp(TskSystemProperties::UNALLOC_SECTORS_IMG_FILE_NAME, "UNALLOC_SECTORS_IMG_FILE_NAME", false, DEFAULT_UNALLOC_SECTORS_IMG_FILE_NAME), 
        PredefProp(TskSystemProperties::MAX_UNALLOC_SECTORS_IMG_FILE_SIZE, "MAX_UNALLOC_SECTORS_IMG_FILE_SIZE", false, DEFAULT_MAX_UNALLOC_SECTORS_IMG_FILE_SIZE),
        PredefProp(TskSystemProperties::CARVE_EXTRACT_KEEP_INPUT_FILES, "CARVE_EXTRACT_KEEP_INPUT_FILES", false, DEFAULT_CARVE_EXTRACT_KEEP_INPUT_FILES), 
        PredefProp(TskSystemProperties::CARVE_EXTRACT_KEEP_OUTPUT_FILES, "CARVE_EXTRACT_KEEP_OUTPUT_FILES", false, DEFAULT_CARVE_EXTRACT_KEEP_OUTPUT_FILES),
        PredefProp(TskSystemProperties::SCALPEL_DIR, "SCALPEL_DIR", false, ""),
        PredefProp(TskSystemProperties::SCALPEL_CONFIG_FILE, "SCALPEL_CONFIG_FILE", false, DEFAULT_SCALPEL_CONFIG_FILE),
        PredefProp(TskSystemProperties::PIPELINE_CONFIG_FILE, "PIPELINE_CONFIG_FILE", false, DEFAULT_PIPELINE_CONFIG_FILE),
        PredefProp(TskSystemProperties::SESSION_ID, "SESSION_ID", false, ""),
        PredefProp(TskSystemProperties::CURRENT_TASK, "CURRENT_TASK", false, ""),
        PredefProp(TskSystemProperties::CURRENT_SEQUENCE_NUMBER, "CURRENT_SEQUENCE_NUMBER", false, ""),
        PredefProp(TskSystemProperties::NODE, "NODE", false, ""),
        PredefProp(TskSystemProperties::PID, "PID", false, ""),
        PredefProp(TskSystemProperties::START_TIME, "START_TIME", false, ""),
        PredefProp(TskSystemProperties::CURRENT_TIME, "CURRENT_TIME", false, ""),
        PredefProp(TskSystemProperties::UNIQUE_ID, "UNIQUE_ID", false, ""),
        PredefProp(TskSystemProperties::IMAGE_FILE, "IMAGE_FILE", false, "")
    };

    const std::size_t MAX_PATH_LENGTH = 1024;
    const std::size_t MAX_RECURSION_DEPTH = 10;
}

TskSystemProperties::TskSystemProperties()
{
    // Populate the lookup data structures. 
    for (std::size_t i = 0; i < END_PROPS; ++i)
    {
        predefProps[predefinedProperties[i].token] = predefinedProperties[i].id;
        predefPropNames[predefinedProperties[i].id] = predefinedProperties[i].token;
        predefPropTokens.insert(predefinedProperties[i].token);

        if (predefinedProperties[i].required)
        {
            requiredProps.insert(predefinedProperties[i].id);
        }

        predefPropDefaults[predefinedProperties[i].id] = predefinedProperties[i].defaultValue; 
    }
}

bool TskSystemProperties::isConfigured() const
{
    // Check whether all of the required predefined system properties are set.
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
    assert(prop >= PROG_DIR && prop < END_PROPS);
    if (prop < PROG_DIR || prop >= END_PROPS)
    {
        throw TskException("TskSystemProperties::set : passed out of range prop argument");
    }

    set(predefPropNames[prop], value);
}

void TskSystemProperties::set(const std::string &name, const std::string &value)
{
    assert(!name.empty());
    if (name.empty())
    {
        throw TskException("TskSystemProperties::set : passed empty name argument");
    }

    assert(name != "CURRENT_TIME");
    if (name == "CURRENT_TIME")
    {
        LOGWARN("TskSystemProperties::set : attempt to set read-only CURRENT_TIME system property");
        return;
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
    assert(prop >= PROG_DIR && prop < END_PROPS);
    if (prop < PROG_DIR || prop >= END_PROPS)
    {
        throw TskException("TskSystemProperties::get : passed out of range prop argument");
    }

    if (prop == CURRENT_TIME)
    {
        // CURRENT_TIME is always computed upon request.
        return Poco::DateTimeFormatter::format(Poco::LocalDateTime(), "%Y_%m_%d_%H_%M_%S");
    }

    std::string value = getProperty(predefPropNames[prop]);
        
    if (value.empty())
    {
        if (prop == PROG_DIR)
        {            
            // If PROG_DIR has not been set, set it to the location of the currently executing program.
            value = TskUtilities::getProgDir();
            const_cast<TskSystemProperties*>(this)->set(prop, value);
        }
        else if (prop == IMAGE_FILE)
        {
            // If IMAGE_FILE has not been set, attempt to retrieve it from the image database.
            const std::vector<std::string> imgNames = TskServices::Instance().getImgDB().getImageNames();
            if (!imgNames.empty())
            {
                value = imgNames[0];
                const_cast<TskSystemProperties*>(this)->set(prop, value);
            }
        }
        else
        {
            // Perhaps there is a default value.
            value = predefPropDefaults[prop];
        }
    }

    if (value.empty() && requiredProps.count(prop) != 0)
    {
        // The empty property is an unset required property.
        std::stringstream msg;
        msg << "TskSystemProperties::get : required predefined system property '" << predefPropNames[prop] << "' is not set";
        throw TskException(msg.str());
    }

    return  expandMacros(value);
}

std::string TskSystemProperties::get(const std::string &name) const
{
    if (predefProps.count(name) != 0)
    {
        return get(predefProps[name]);
    }

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
    assert(depth <= MAX_RECURSION_DEPTH);
    if (depth > MAX_RECURSION_DEPTH)
    {
        std::wstringstream msg;
        msg << L"TskSystemProperties::expandMacros : reached maximum depth (" << MAX_RECURSION_DEPTH << L") of recursion, cannot complete expansion of " << inputStr.c_str();
        LOGERROR(msg.str());
        return;
    }

    Poco::StringTokenizer tokenizer(inputStr, "#", Poco::StringTokenizer::TOK_IGNORE_EMPTY);
    for (Poco::StringTokenizer::Iterator token = tokenizer.begin(); token != tokenizer.end(); ++token)
    {
        if (predefPropTokens.count(*token) != 0)
        {
            expandMacros(get(*token), outputStr, depth + 1);
        }
        else
        {
            outputStr += *token;
        }
    }
}
