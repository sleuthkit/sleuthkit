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

// TSK Framework includes
#include "TskPluginModule.h"

/**
 * Supports the use of custom dynamic libraries to perform
 * reporting and post-processing in a TskReportPipeline.
 */
class TSK_FRAMEWORK_API TskReportPluginModule: public TskPluginModule
{
public:
    // Doxygen comment in base class.
    virtual Status run(TskFile *fileToAnalyze) { return report(); };

    // Doxygen comment in base class.
    virtual Status report();

    // Doxygen comment in base class.
    virtual void checkInterface();
};

#endif
