/*
 *
 *  The Sleuth Kit
 *
 *  Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 *  Copyright (c) 2010-2012 Basis Technology Corporation. All Rights
 *  reserved.
 *
 *  This software is distributed under the Common Public License 1.0
 */

/**
* \file TskSystemPropertiesImpl.cpp
* Contains an implementation of the TskSystemProperties class
* that uses the Poco Configuration package.
*/

#include "TskSystemPropertiesImpl.h"
#include "Services/TskServices.h"
#include "Poco/UnicodeConverter.h"
#include "Poco/Util/MapConfiguration.h"
#include "Poco/Util/XMLConfiguration.h"
#include "Utilities/TskException.h"
#include "Utilities/TskUtilities.h"
#include <sstream>

std::wstring TskSystemPropertiesImpl::get(std::wstring name) const
{
    std::wstring value;

    if (m_abstractConfig) 
    {
        std::string utf8Name;
        std::string utf8Value;

        Poco::UnicodeConverter::toUTF8(name, utf8Name);
        try 
        {
            utf8Value = m_abstractConfig->getString(utf8Name);
            Poco::UnicodeConverter::toUTF16(utf8Value, value);
            return value;
        } 
        catch (Poco::NotFoundException& ) 
        {
            // Log a message
            std::wstringstream msg;
            msg << L"TskSystemPropertiesImpl::get - No value found for: " << name;
            LOGWARN(msg.str());
        }
    } else 
    {
        // Log a message
        LOGERROR(L"TskSystemPropertiesImpl::get - Configuration not initialized.\n");
    }

    return value;
}

void TskSystemPropertiesImpl::set(std::wstring name, std::wstring value)
{
    if (m_abstractConfig) 
    {
        std::string utf8Name;
        std::string utf8Value;

        Poco::UnicodeConverter::toUTF8(name, utf8Name);
        Poco::UnicodeConverter::toUTF8(value, utf8Value);
        m_abstractConfig->setString(utf8Name, utf8Value);
    } else 
    {
        // Log a message
        LOGERROR(L"TskSystemPropertiesImpl::set - Configuration not initialized.\n");
    }
}

void TskSystemPropertiesImpl::initialize(Poco::Util::AbstractConfiguration & abstractConfig)
{
    m_abstractConfig = &abstractConfig;
}

void TskSystemPropertiesImpl::initialize(const std::wstring configfile) 
{
    // This gets wrapped in an AutoPtr and will be automatically
    // freed during destruction.
    Poco::Util::XMLConfiguration * pXMLConfig = 
        new Poco::Util::XMLConfiguration(TskUtilities::toUTF8(configfile));
    initialize(*pXMLConfig);
}

void TskSystemPropertiesImpl::initialize(const char *configfile) 
{
    // This gets wrapped in an AutoPtr and will be automatically
    // freed during destruction.
    Poco::Util::XMLConfiguration * pXMLConfig = 
        new Poco::Util::XMLConfiguration(configfile);
    initialize(*pXMLConfig);
}

void TskSystemPropertiesImpl::initialize()
{
    // This gets wrapped in an AutoPtr and will be automatically
    // freed during destruction.
    Poco::Util::MapConfiguration *pMapConfig =
        new Poco::Util::MapConfiguration();
    initialize(*pMapConfig);
}

