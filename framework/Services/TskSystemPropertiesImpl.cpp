/*
 *
 *  The Sleuth Kit
 *
 *  Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 *  Copyright (c) 2010-2011 Basis Technology Corporation. All Rights
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
#include "Utilities/TskException.h"
#include <sstream>

/* NOTE that the below comments are the only documentation about
 * the official properties.  Anything added to this list must be
 * documented. */

/** Root output directory that all modules can write to. Should be a
 * shared location if framework is being used in a distributed environment. */
const std::wstring TskSystemPropertiesImpl::OUT_DIR = L"OUT_DIR";

/// Directory where program using the framework is installed.  Used during search for modules. 
const std::wstring TskSystemPropertiesImpl::PROG_DIR = L"PROG_DIR";

/// Directory where configuration files and data can be found. 
const std::wstring TskSystemPropertiesImpl::CONFIG_DIR = L"CONFIG_DIR";

/// Directory where plug-in and executable modules can be found.
const std::wstring TskSystemPropertiesImpl::MODULE_DIR = L"MODULE_DIR";

/// Path to the pipeline config file being used. 
const std::wstring TskSystemPropertiesImpl::PIPELINE_CONFIG = L"PIPELINE_CONFIG_FILE";

/// Hostname of central database (if one is being used)
const std::wstring TskSystemPropertiesImpl::DB_HOST = L"DB_HOST";

/// port of central database (if one is being used)
const std::wstring TskSystemPropertiesImpl::DB_PORT = L"DB_PORT";

/** ID of this session.  The intended use of this is in a distributed
 * environment that is processing multiple images at the same time.  Each
 * image would have a unique session ID. */
const std::wstring TskSystemPropertiesImpl::SESSION_ID = L"SESSION_ID";

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

void TskSystemPropertiesImpl::initialize()
{
    // @@@ Need to make sure someone frees this....
    Poco::Util::MapConfiguration *pMapConfig =
        new Poco::Util::MapConfiguration();
    initialize(*pMapConfig);
}

