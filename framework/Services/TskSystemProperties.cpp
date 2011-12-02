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
 * \file TskSystemProperties.cpp
 * Contains the implementation for the SystemProperties class.
 */

#include "Services/TskSystemProperties.h"

/**
 *
 */
SystemProperties::SystemProperties()
{
}

/**
 *
 */
SystemProperties::~SystemProperties()
{
}

/**
 *
 */
std::wstring SystemProperties::getDatabaseServerName() const
{
    return std::wstring(L"NOT_IMPLEMENTED");
}

/**
 *
 */
std::wstring SystemProperties::getOutputPath() const
{
    return std::wstring(L"NOT_IMPLEMENTED");
}

/**
 *
 */
std::wstring SystemProperties::getPipelineConfigPath() const
{
    return std::wstring(L"NOT_IMPLEMENTED");
}