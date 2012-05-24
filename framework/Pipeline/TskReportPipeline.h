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

#include <string>
#include "TskPipeline.h"
#include "TskPluginModule.h"
#include "TskReportPluginModule.h"

/**
 * Controls a series of reporting modules that are run
 * after all of the file-specific analysis modules are run.
 * The reporting pipeline can contain one or more TskModule
 * modules.
 */
class TSK_FRAMEWORK_API TskReportPipeline : public TskPipeline
{
public:
    // Default constructor
    TskReportPipeline();

    // Destructor
    ~TskReportPipeline();

    // Initialize a Pipeline based on the given XML configuration string.
    void initialize(const std::string& pipelineConfig);

    // Run through all the modules in the Pipeline for the given file id.
    virtual void run(const uint64_t fileId) {}; // NOP

    // Run through all the modules in the Pipeline for the given File object
    virtual void run(TskFile* file) {}; // NOP

    // Run through all the modules in the Pipeline for Reporting.
    virtual void run();

    // Create a module for the pipeline
    TskPluginModule * createPluginModule() { return (new TskReportPluginModule()); };

};

#endif
