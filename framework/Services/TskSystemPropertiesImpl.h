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
 * A singleton that wraps a Poco AbstractConfiguration
 * class to set and retrieve name/value pairs.
 */
class TSK_FRAMEWORK_API TskSystemPropertiesImpl : public TskSystemProperties
{
public:
    static const std::wstring OUTDIR;
    static const std::wstring PROG_DIR;
    static const std::wstring CONFIG_DIR;
    static const std::wstring MODULE_DIR;
    static const std::wstring PIPELINE_CONFIG;
    static const std::wstring DB_HOST;
    static const std::wstring DB_PORT;
    static const std::wstring SESSION_ID;

    /// Constructor
    TskSystemPropertiesImpl() { m_abstractConfig = (Poco::Util::AbstractConfiguration *)NULL; };
    TskSystemPropertiesImpl(Poco::Util::AbstractConfiguration & abstractConfig) { m_abstractConfig = &abstractConfig; };

    /// Destructor
    virtual ~TskSystemPropertiesImpl() {};

    /// Retrieve the string value associated with the given name.
    std::wstring get(std::wstring name) const;

    /// Associate a string value with a name.
    void set(std::wstring name, std::wstring value);

    /// Initialize with POCO AbstractConfiguration
    void initialize(Poco::Util::AbstractConfiguration & abstractConfig);

private:
    /// Copy Constructor
    TskSystemPropertiesImpl(TskSystemPropertiesImpl const&) {};

    Poco::Util::AbstractConfiguration * m_abstractConfig;
};

#endif