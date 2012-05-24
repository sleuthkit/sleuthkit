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
* \file TskSystemProperties.cpp
* Contains the standard set of properties supported by the framework.
*/

#include "TskSystemProperties.h"

/* NOTE that the below comments are the only documentation about
 * the official properties.  Anything added to this list must be
 * documented. */

/** Root output directory that all modules can write to. Should be a
 * shared location if framework is being used in a distributed environment. */
const std::wstring TskSystemProperties::OUT_DIR = L"OUT_DIR";

/// Directory where program using the framework is installed.  Used during search for modules. 
const std::wstring TskSystemProperties::PROG_DIR = L"PROG_DIR";

/// Directory where configuration files and data can be found. 
const std::wstring TskSystemProperties::CONFIG_DIR = L"CONFIG_DIR";

/// Directory where plug-in and executable modules can be found.
const std::wstring TskSystemProperties::MODULE_DIR = L"MODULE_DIR";

/// Path to the pipeline config file being used. 
const std::wstring TskSystemProperties::PIPELINE_CONFIG = L"PIPELINE_CONFIG_FILE";

/// Hostname of central database (if one is being used)
const std::wstring TskSystemProperties::DB_HOST = L"DB_HOST";

/// port of central database (if one is being used)
const std::wstring TskSystemProperties::DB_PORT = L"DB_PORT";

/** ID of this session.  The intended use of this is in a distributed
 * environment that is processing multiple images at the same time.  Each
 * image would have a unique session ID. */
const std::wstring TskSystemProperties::SESSION_ID = L"SESSION_ID";
