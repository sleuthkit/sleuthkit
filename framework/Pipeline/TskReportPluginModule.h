/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2012 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

#ifndef _TSK_REPORTPLUGINMODULE_H
#define _TSK_REPORTPLUGINMODULE_H

#include "TskPluginModule.h"

#include "Poco/SharedLibrary.h"

/**
 * Supports the loading of custom dynamic libraries to perform
 * reporting and post-processing in a TskReportPipeline.
 */
class TSK_FRAMEWORK_API TskReportPluginModule: public TskPluginModule
{
public:
    // Default Constructor
    TskReportPluginModule();

    // Destructor
    virtual ~TskReportPluginModule();

    // Report module ignore fileToAnalyze
    virtual Status run(TskFile * fileToAnalyze) { return report(); };

    virtual Status report();

    // Check the require interface for a plugin module. Throw exception if required interface is misssing.
    virtual void checkInterface();

private:
};

#endif
