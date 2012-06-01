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

// System includes
#include <sstream>

// Framework includes
#include "TskFileAnalysisPluginModule.h"
#include "Services/TskServices.h"
#include "Utilities/TskException.h"
#include "File/TskFileManagerImpl.h"

// Poco includes
#include "Poco/String.h"
#include "Poco/Path.h"

typedef TskModule::Status (*RunFunc)(TskFile*);

/**
 * Constructor
 */
TskFileAnalysisPluginModule::TskFileAnalysisPluginModule()
{
}

/**
 * Destructor
 */
TskFileAnalysisPluginModule::~TskFileAnalysisPluginModule()
{
}

TskModule::Status TskFileAnalysisPluginModule::run(TskFile* fileToAnalyze)
{
    if (!isLoaded())
    {
        std::wstringstream msg;
        msg << L"TskFileAnalysisPluginModule::run - Module not loaded: "
            << getPath().c_str();
        LOGERROR(msg.str());
        throw TskException("Module not loaded.");
    }

    try
    {
        RunFunc run = (RunFunc)getSymbol(TskPluginModule::RUN_SYMBOL);
        return run(fileToAnalyze);
    }
    catch (Poco::Exception& ex)
    {
        std::wstringstream errorMsg;
        errorMsg << L"TskFileAnalysisPluginModule::run - Error: " << ex.displayText().c_str() << std::endl;
        LOGERROR(errorMsg.str());
        throw TskException("Module execution failed.");
    }
}

// Throw exception if the module does not have RUN_SYMBOL 
void TskFileAnalysisPluginModule::checkInterface()
{
    if (!isLoaded())
        throw TskException("Module is not loaded");

    if (!hasSymbol(TskPluginModule::RUN_SYMBOL)) {
        std::wstringstream msg;
        msg << L"TskFileAnalysisPluginModule::checkInterface - Module does not contain the \""
            << TskPluginModule::RUN_SYMBOL.c_str() << L"\" symbol : " << getPath().c_str();
        LOGERROR(msg.str());

        throw TskException("Module missing required symbol.");
    }
}
