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
 * Contains the implementation of the TskSystemPropertiesImpl class.
 */

// Include the class definition first to ensure it does not depend on subsequent includes in this file.
#include "TskSystemPropertiesImpl.h"

#include "tsk/framework/services/Log.h"
#include "tsk/framework/services/TskServices.h"
#include "tsk/framework/utilities/TskUtilities.h"
#include "tsk/framework/utilities/TskException.h"
#include "Poco/Util/XMLConfiguration.h"
#include "Poco/Util/MapConfiguration.h"
#include <sstream>

void TskSystemPropertiesImpl::initialize(const std::wstring &configFile) 
{
    initialize(TskUtilities::toUTF8(configFile));
}

void TskSystemPropertiesImpl::initialize(const std::string &configfile) 
{
    try {
        m_abstractConfig = new Poco::Util::XMLConfiguration(configfile);
    }
    catch (Poco::FileNotFoundException& )
    {
        throw TskException("Configuration file not found : " + configfile);
    }
}

void TskSystemPropertiesImpl::initialize()
{
    m_abstractConfig = new Poco::Util::MapConfiguration();
}

void TskSystemPropertiesImpl::setProperty(const std::string &name, const std::string &value)
{
    if (!m_abstractConfig) 
    {
        throw TskException("TskSystemPropertiesImpl::set - Configuration not initialized.");
    } 

    m_abstractConfig->setString(name, value);
}

std::string TskSystemPropertiesImpl::getProperty(const std::string &name) const
{
    if (!m_abstractConfig) 
    {
        throw TskException("TskSystemPropertiesImpl::get - Configuration not initialized.");
    }

    try 
    {
        return m_abstractConfig->getString(name);
    } 
    catch (Poco::NotFoundException &) 
    {
        // Return empty string per documentation of base class interface.
        return "";
    }
}
