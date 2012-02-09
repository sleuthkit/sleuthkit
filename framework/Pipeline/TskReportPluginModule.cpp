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
 * \file TskReportPluginModule.cpp
 * Contains the implementation for the TskReportPluginModule class.
 */

// System includes
#include <sstream>

// Framework includes
#include "TskReportPluginModule.h"
#include "Services/TskServices.h"
#include "Utilities/TskException.h"
#include "File/TskFileManagerImpl.h"

// Poco includes
#include "Poco/String.h"
#include "Poco/Path.h"

typedef TskModule::Status (*ReportFunc)();

/**
 * Constructor
 */
TskReportPluginModule::TskReportPluginModule()
{
}

/**
 * Destructor
 */
TskReportPluginModule::~TskReportPluginModule()
{
}

TskModule::Status TskReportPluginModule::report()
{
    if (!isLoaded())
    {
        std::wstringstream msg;
        msg << L"TskReportPluginModule::runWorker - Module not loaded: "
            << getPath().c_str();
        LOGERROR(msg.str());
        throw TskException("Module not loaded.");
    }

    try
    {
        ReportFunc report = (ReportFunc)getSymbol(TskPluginModule::REPORT_SYMBOL);
        return report();
    }
    catch (Poco::Exception& ex)
    {
        std::wstringstream errorMsg;
        errorMsg << L"TskReportPluginModule::run - Error: " << ex.displayText().c_str() << std::endl;
        LOGERROR(errorMsg.str());
        throw TskException("Module execution failed.");
    }
}

// Throw exception if the module does not have REPORT_SYMBOL
void TskReportPluginModule::checkInterface()
{
    if (!isLoaded())
        throw TskException("Module is not loaded");

    if (!hasSymbol(TskPluginModule::REPORT_SYMBOL)) {
        std::wstringstream msg;
        msg << L"TskReportPluginModule::checkInterface - Module does not contain the \""
            << TskPluginModule::REPORT_SYMBOL.c_str() << L"\" symbol : " << getPath().c_str();
        LOGERROR(msg.str());

        throw TskException("Module missing required symbol.");
    }
}
