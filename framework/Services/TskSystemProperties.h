/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2011 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

/**
 * \file TskSystemProperties.h
 * Contains the interface for the TskSystemProperties class.
 */

#ifndef _TSK_SYSTEMPROPERTIES_H
#define _TSK_SYSTEMPROPERTIES_H

#include <string>

#include "framework_i.h"

#define TSK_SYS_PROP_GET(name) TskServices::Instance().getSystemProperties().get((name))
#define TSK_SYS_PROP_SET(name, value) TskServices::Instance().getSystemProperties().set((name), (value))

/**
 * An interface for setting and retrieving name/value pairs.
 */
class TSK_FRAMEWORK_API TskSystemProperties
{
public:
    /// Retrieve the string value associated with the given name.
    virtual std::wstring get(std::wstring name) const = 0;

    /// Associate a string value with a name.
    virtual void set(std::wstring name, std::wstring value) = 0;

protected:
    /// Default Constructor
    TskSystemProperties() {};

    /// Copy Constructor
    TskSystemProperties(TskSystemProperties const&) {};

    /// Destructor
    virtual ~TskSystemProperties() {};

};

#endif