/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2012 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

#ifndef _TSK_FILEANALYSISPLUGINMODULE_H
#define _TSK_FILEANALYSISPLUGINMODULE_H

#include "TskPluginModule.h"

#include "Poco/SharedLibrary.h"

/**
 * Supports the loading of custom dynamic libraries to perform
 * analysis on a single TskFile
 */
class TSK_FRAMEWORK_API TskFileAnalysisPluginModule: public TskPluginModule
{
public:
    // Default Constructor
    TskFileAnalysisPluginModule();

    // Destructor
    virtual ~TskFileAnalysisPluginModule();

    virtual Status run(TskFile* fileToAnalyze);

    /// Sets the path of the library to load and verifies
    /// that it implements the required interface.
    //virtual void setPath(const std::string& location);

    // Check the require interface for a plugin module. Throw exception if required interface is misssing.
    virtual void checkInterface();

private:
};

#endif
