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
 * \file TskSystemPropertiesImpl.h
 * Contains an implementation of the TskSystemProperties class
 * that uses the Poco Configuration package.
 */

#ifndef _TSK_SYSTEMPROPERTIESIMPL_H
#define _TSK_SYSTEMPROPERTIESIMPL_H

#include "framework_i.h"
#include "TskSystemProperties.h"
#include "Poco/Util/AbstractConfiguration.h"
#include <string>

/**
 * An implementation of TskSystemProperties that uses Poco
 * AbstractConfiguration class to set and retrieve name/value
 * pairs from an XML file.
 */
class TSK_FRAMEWORK_API TskSystemPropertiesImpl : public TskSystemProperties
{
public:
    /**
     * Default constructor. The TskSystemPropertiesImpl must still be 
     * initialized with a call to one of the initialize() member functions
     * before the object can be used.
     */ 
    TskSystemPropertiesImpl() : m_abstractConfig(static_cast<Poco::Util::AbstractConfiguration*>(NULL)) {}

    /**
     * Initialize using a configuration file.
     *
     * @param configFile Path to the XML file to be used to initialize the
     * system properties.
     */
    void initialize(const std::wstring &configfile);

    /**
     * Initialize using a configuration file.
     *
     * @param configFile Path to the XML file to be used to initialize the
     * system properties.
     */
    void initialize(const std::string &configfile);

    /**
     * Initialize with no initial system property settings.
     */
    void initialize();

private:
    // Prohibit copying. 
    TskSystemPropertiesImpl(const TskSystemPropertiesImpl&);
    TskSystemPropertiesImpl& operator=(const TskSystemPropertiesImpl&);

    virtual void setProperty(const std::string &name, const std::string &value);
    virtual std::string getProperty(const std::string &name) const;

    Poco::AutoPtr<Poco::Util::AbstractConfiguration> m_abstractConfig;
};

#endif
