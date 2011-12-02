/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2011 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

#ifndef _TSK_REPORTPLUGINMODULE_H
#define _TSK_REPORTPLUGINMODULE_H

#include "TskPluginModule.h"

#include "Poco/SharedLibrary.h"

/**
 * A Plugin Module supports the loading of custom libraries to perform
 * reporting.
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
