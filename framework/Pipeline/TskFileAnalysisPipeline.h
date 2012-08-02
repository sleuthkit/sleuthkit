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
#include "TskModule.h"
#include "TskPipeline.h"
#include "TskPluginModule.h"
#include "TskFileAnalysisPluginModule.h"

// C/C++ library includes
#include <string>

/**
 * Controls the processing of a file analysis pipeline.  
 */
class TSK_FRAMEWORK_API TskFileAnalysisPipeline : public TskPipeline
{
public:
    void initialize(const std::string& pipelineConfig);
    virtual void run(const uint64_t fileId);
    virtual void run(TskFile* file);

    // Run through all the modules in the Pipeline for Reporting.
    virtual void run() {}; // NOP

    TskPluginModule * createPluginModule() 
    { 
        return (new TskFileAnalysisPluginModule()); 
    };
};

#endif
