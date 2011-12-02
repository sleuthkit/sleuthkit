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
#include "Utilities/TskException.h"
#include <sstream>

const std::wstring TskSystemPropertiesImpl::OUTDIR = L"OUTDIR";
const std::wstring TskSystemPropertiesImpl::PROG_DIR = L"PROG_DIR";
const std::wstring TskSystemPropertiesImpl::CONFIG_DIR = L"CONFIG_DIR";
const std::wstring TskSystemPropertiesImpl::MODULE_DIR = L"MODULE_DIR";
const std::wstring TskSystemPropertiesImpl::PIPELINE_CONFIG = L"PIPELINE_CONFIG_FILE";
const std::wstring TskSystemPropertiesImpl::DB_HOST = L"DB_HOST";
const std::wstring TskSystemPropertiesImpl::DB_PORT = L"DB_PORT";
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
            msg << L"TskSystemPropertiesImpl::get - No value found for: " << name << std::endl;
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
