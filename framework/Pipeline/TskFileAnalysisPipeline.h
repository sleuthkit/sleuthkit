/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2011 Basis Technology Corporation. All Rights
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

#include <string>
#include "TskModule.h"
#include "TskPipeline.h"
#include "TskPluginModule.h"
#include "TskFileAnalysisPluginModule.h"

/**
 * Controls the processing of a TskFile
 * through an ordered list of dynamically configured modules. The
 * pipeline can contain one or more instances of TskModule.
 */
class TSK_FRAMEWORK_API TskFileAnalysisPipeline : public TskPipeline
{
public:
    // Default constructor
    TskFileAnalysisPipeline();

    // Destructor
    ~TskFileAnalysisPipeline();

    // Initialize a Pipeline based on the given XML configuration string.
    void initialize(const std::string& pipelineConfig);

    // Run through all the modules in the Pipeline for the given file id.
    virtual void run(const uint64_t fileId);

    // Run through all the modules in the Pipeline for the given File object
    virtual void run(TskFile* file);

    // Run through all the modules in the Pipeline for Reporting.
    virtual void run() {}; // NOP

    // Create a module for the pipeline
    TskPluginModule * createPluginModule() { return (new TskFileAnalysisPluginModule()); };

};

#endif
