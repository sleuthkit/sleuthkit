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
 * \file TskFileAnalysisPluginModule.cpp
 * Contains the implementation for the TskFileAnalysisPluginModule class.
 */

// Include the class definition first to ensure it does not depend on subsequent includes in this file.
#include "TskFileAnalysisPluginModule.h"

// Framework includes
#include "tsk/framework/services/TskServices.h"
#include "tsk/framework/utilities/TskException.h"

// C/C++ library includes
#include <sstream>

TskModule::Status TskFileAnalysisPluginModule::run(TskFile *fileToAnalyze)
{
    const std::string MSG_PREFIX = "TskFileAnalysisPluginModule::run : ";
    TskModule::Status status = TskModule::OK;
    try
    {
        if (!isLoaded())
        {
            std::stringstream msg;
            msg << MSG_PREFIX << getPath() << " is not loaded";
            throw TskException(msg.str());
        }

        if (!hasSymbol(TskPluginModule::RUN_SYMBOL)) 
        {
            std::stringstream msg;
            msg << MSG_PREFIX << getPath() << " does not define the '" << TskPluginModule::RUN_SYMBOL << "' symbol";
            throw TskException(msg.str());
        }

        typedef TskModule::Status (*RunFunc)(TskFile*);
        RunFunc run = (RunFunc)getSymbol(TskPluginModule::RUN_SYMBOL);
        status = run(fileToAnalyze);
    }
    catch (TskException &ex) 
    {
        std::stringstream msg;
        msg << MSG_PREFIX << "TskException executing run function of " << getName() << ": " << ex.message();
        LOGERROR(msg.str());
        status = TskModule::FAIL;
    }
    catch (Poco::Exception &ex) 
    {
        std::stringstream msg;
        msg << MSG_PREFIX <<  "Poco::Exception executing run function of "  << getName() << ": " << ex.displayText();
        LOGERROR(msg.str());
        status = TskModule::FAIL;
    }
    catch (std::exception &ex) 
    {
        std::stringstream msg;
        msg << MSG_PREFIX <<  "std::exception executing run function of "  << getName() << ": " << ex.what();
        LOGERROR(msg.str());
        status = TskModule::FAIL;
    }
    catch (...)
    {
        std::stringstream msg;
        msg << MSG_PREFIX << "unrecognized exception executing run function of "  << getName();
        LOGERROR(msg.str());
        status = TskModule::FAIL;
    }

    return status;
}

void TskFileAnalysisPluginModule::checkInterface()
{
    const std::string MSG_PREFIX = "TskFileAnalysisPluginModule::checkInterface : ";

    if (!isLoaded())
    {
        std::stringstream msg;
        msg << MSG_PREFIX << getPath() << " is not loaded";
        LOGERROR(msg.str());
        throw TskException(msg.str());
    }

    if (!hasSymbol(TskPluginModule::RUN_SYMBOL)) 
    {
        std::stringstream msg;
        msg << MSG_PREFIX << getPath() << " does not define the required '" << TskPluginModule::RUN_SYMBOL << "' symbol";
        throw TskException(msg.str());
    }
}
