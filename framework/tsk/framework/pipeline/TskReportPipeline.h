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
 * \file TskReportPipeline.h
 * Contains the interface for the TskReportPipeline class.
 */

#ifndef _TSK_REPORTPIPELINE_H
#define _TSK_REPORTPIPELINE_H

// TSK Framework includes
#include "TskPipeline.h"
#include "TskReportPluginModule.h"
#include "tsk/framework/utilities/TskException.h"

// C/C++ library includes
#include <string>

/**
 * Controls a series of reporting modules that are run
 * after all of the file-specific analysis modules are run.
 * The reporting pipeline can contain one or more TskModule
 * modules.
 */
class TSK_FRAMEWORK_API TskReportPipeline : public TskPipeline
{
public:
    // Doxygen comment in base class.
    virtual void run(const uint64_t fileId) 
    { 
        throw TskException("TskReportPipeline::run : not implemented"); 
    }

    // Doxygen comment in base class.
    virtual void run(TskFile *file) 
    { 
        throw TskException("TskReportPipeline::run : not implemented"); 
    }

    // Doxygen comment in base class.
    virtual void run();

    // Doxygen comment in base class.
    virtual TskPluginModule *createPluginModule() 
    { 
        return (new TskReportPluginModule());
    }
};

#endif
