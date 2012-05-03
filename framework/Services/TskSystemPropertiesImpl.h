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
 * \file TskSystemPropertiesImpl.h
 * Contains an implementation of the TskSystemProperties class
 * that uses the Poco Configuration package.
 */

#ifndef _TSK_SYSTEMPROPERTIESIMPL_H
#define _TSK_SYSTEMPROPERTIESIMPL_H

#include <string>

#include "framework_i.h"
#include "TskSystemProperties.h"

#include "Poco/Util/AbstractConfiguration.h"

/**
 * An implementation of TskSystemProperties that uses Poco
 * AbstractConfiguration class to set and retrieve name/value
 * pairs from an XML file.
 */
class TSK_FRAMEWORK_API TskSystemPropertiesImpl : public TskSystemProperties
{
public:
    TskSystemPropertiesImpl() { 
        m_abstractConfig = (Poco::Util::AbstractConfiguration *)NULL; 
    };

    TskSystemPropertiesImpl(Poco::Util::AbstractConfiguration & abstractConfig) {
        m_abstractConfig = &abstractConfig; 
    };

    virtual ~TskSystemPropertiesImpl() {};

    std::wstring get(std::wstring name) const;

    void set(std::wstring name, std::wstring value);

    /**
     * Load the XML Config file
     * @param configfile Path to XML file
     */
    void initialize(const std::wstring configfile);

    /**
     * Load the XML Config file
     * @param configfile Path to XML file
     */
    void initialize(const char *configfile);

    /**
     * Use memory-based config settings only (no local file)
     */
    void initialize();
private:
    TskSystemPropertiesImpl(TskSystemPropertiesImpl const&) {};
    // Initialize with POCO AbstractConfiguration
    void initialize(Poco::Util::AbstractConfiguration & abstractConfig);

    Poco::AutoPtr<Poco::Util::AbstractConfiguration> m_abstractConfig;
};

#endif
