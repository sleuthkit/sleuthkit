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
 * \file TskFileAnalysisPipeline.h
 * Contains the interface for the TskFileAnalysisPipeline class.
 */

#ifndef _TSK_FILEANALYSISPIPELINE_H
#define _TSK_FILEANALYSISPIPELINE_H


// TSK Framework includes
#include "TskPipeline.h"
#include "TskFileAnalysisPluginModule.h"

// C/C++ library includes
#include <string>

/**
 * Controls the processing of a file analysis pipeline.  
 */
class TSK_FRAMEWORK_API TskFileAnalysisPipeline : public TskPipeline
{
public:
    // Doxygen comment in base class.
    virtual void run(const uint64_t fileId);

    // Doxygen comment in base class.
    virtual void run(TskFile* file);

    // Doxygen comment in base class.
    virtual void run() 
    { 
        throw TskException("TskFileAnalysisPipeline::run : not implemented"); 
    }

    // Doxygen comment in base class.
    TskPluginModule *createPluginModule() 
    { 
        return (new TskFileAnalysisPluginModule());
    }
};

#endif
