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
 * Contains the interface of the TskSystemPropertiesImpl class.
 */

#ifndef _TSK_SYSTEMPROPERTIESIMPL_H
#define _TSK_SYSTEMPROPERTIESIMPL_H

#include "tsk/framework/framework_i.h"
#include "TskSystemProperties.h"
#include "Poco/Util/AbstractConfiguration.h"
#include <string>

/**
 * An implementation of TskSystemProperties that uses Poco
 * AbstractConfiguration class to set and retrieve name/value
 * pairs from an XML file. Allows system property values to refer 
 * to other system property values (see the TskSystemProperties class 
 * description for more details).
 * 
 * The XML schema for this is that the name of the value is the tag and
 * the value is stored in the tag.  Here is an example:
 * 
 * \verbatim
 <?xml version="1.0" encoding="utf-8"?>
 <TSK_FRAMEWORK_CONFIG>
   <CONFIG_DIR>#PROG_DIR#/Config</CONFIG_DIR>
   <MODULE_DIR>#PROG_DIR#/Modules</MODULE_DIR>
 </TSK_FRAMEWORK_CONFIG>
 * \endverbatim
 * You can make up your own tags and the values will be inserted and 
 * available via the TskSystemProperties service. 
 */
class TSK_FRAMEWORK_API TskSystemPropertiesImpl : public TskSystemProperties
{
public:
    /**
     * Default constructor. The TskSystemPropertiesImpl object must then be 
     * initialized with a call to one of the initialize() member functions
     * before the object can be used.
     */ 
    TskSystemPropertiesImpl() : m_abstractConfig(static_cast<Poco::Util::AbstractConfiguration*>(NULL)) {}

    /**
     * Initialize using a configuration file.
     *
     * @param configfile Path to the XML file to be used to initialize the
     * system properties.
     */
    void initialize(const std::wstring &configfile);

    /**
     * Initialize using a configuration file.
     *
     * @param configfile Path to the XML file to be used to initialize the
     * system properties.
     */
    void initialize(const std::string &configfile);

    /**
     * Initialize with no initial system property settings.
     */
    void initialize();

private:
    // Prohibit copying by declaring copy control functions without implementations. 
    TskSystemPropertiesImpl(const TskSystemPropertiesImpl&);
    TskSystemPropertiesImpl& operator=(const TskSystemPropertiesImpl&);

    virtual void setProperty(const std::string &name, const std::string &value);
    virtual std::string getProperty(const std::string &name) const;

    /**
     * Manages a pointer to a Poco::Util::XMLConfiguration or
     * Poco::Util::MapConfiguration object that maps names to values. 
     */ 
    Poco::AutoPtr<Poco::Util::AbstractConfiguration> m_abstractConfig;
};

#endif
