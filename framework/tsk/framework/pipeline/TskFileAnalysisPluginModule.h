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

// TSK Framework includes
#include "TskPluginModule.h"

/**
 * Supports the loading of custom dynamic libraries to perform
 * analysis on a single TskFile
 */
class TSK_FRAMEWORK_API TskFileAnalysisPluginModule: public TskPluginModule
{
public:
    // Doxygen comment in base class.
    virtual Status run(TskFile *fileToAnalyze);

    // Doxygen comment in base class.
    virtual void checkInterface();
};

#endif
