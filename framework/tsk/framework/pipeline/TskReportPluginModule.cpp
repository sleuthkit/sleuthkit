/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2012 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

/**
 * \file TskReportPluginModule.cpp
 * Contains the implementation for the TskReportPluginModule class.
 */

// Include the class definition first to ensure it does not depend on subsequent includes in this file.
#include "TskReportPluginModule.h"

// TSK Framework includes
#include "tsk/framework/services/TskServices.h"
#include "tsk/framework/utilities/TskException.h"

// C/C++ includes
#include <sstream>

TskModule::Status TskReportPluginModule::report()
{
    const std::string MSG_PREFIX = "TskReportPluginModule::report : ";
    TskModule::Status status = TskModule::OK;
    try
    {
        if (!isLoaded())
        {
            std::stringstream msg;
            msg << MSG_PREFIX << "'" << getPath() << "' is not loaded";
            throw TskException(msg.str());
        }

        if (!hasSymbol(TskPluginModule::REPORT_SYMBOL)) 
        {
            std::stringstream msg;
            msg << MSG_PREFIX << "'" << getPath() << "' does not define the '" << TskPluginModule::REPORT_SYMBOL << "' symbol";
            throw TskException(msg.str());
        }

        typedef TskModule::Status (*ReportFunc)();
        ReportFunc report = (ReportFunc)getSymbol(TskPluginModule::REPORT_SYMBOL);
        status = report();
    }
    catch (TskException &ex) 
    {
        std::stringstream msg;
        msg << MSG_PREFIX << "TskException executing report function of " << getName() << ": " << ex.message();
        LOGERROR(msg.str());
        status = TskModule::FAIL;
    }
    catch (Poco::Exception &ex) 
    {
        std::stringstream msg;
        msg << MSG_PREFIX <<  "Poco::Exception executing report function of "  << getName() << ": " << ex.displayText();
        LOGERROR(msg.str());
        status = TskModule::FAIL;
    }
    catch (std::exception &ex) 
    {
        std::stringstream msg;
        msg << MSG_PREFIX <<  "std::exception executing report function of "  << getName() << ": " << ex.what();
        LOGERROR(msg.str());
        status = TskModule::FAIL;
    }
    catch (...)
    {
        std::stringstream msg;
        msg << MSG_PREFIX << "unrecognized exception executing report function of "  << getName();
        LOGERROR(msg.str());
        status = TskModule::FAIL;
    }

    return status;
}

void TskReportPluginModule::checkInterface()
{
    const std::string MSG_PREFIX = "TskReportPluginModule::checkInterface : ";

    if (!isLoaded())
    {
        std::stringstream msg;
        msg << MSG_PREFIX << getPath() << " is not loaded";
        LOGERROR(msg.str());
        throw TskException(msg.str());
    }

    if (!hasSymbol(TskPluginModule::REPORT_SYMBOL)) 
    {
        std::stringstream msg;
        msg << MSG_PREFIX << getPath() << " does not define the required '" << TskPluginModule::REPORT_SYMBOL << "' symbol";
        throw TskException(msg.str());
    }
}
