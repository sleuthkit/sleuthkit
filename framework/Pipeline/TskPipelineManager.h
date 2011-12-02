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
 * \file TskPipelineManager.h
 * Contains the interface for the TskPipelineManager class.
 */

#ifndef _TSK_PIPELINEMANAGER_H
#define _TSK_PIPELINEMANAGER_H

#include <string>
#include "TskPipeline.h"

/**
 * The TskPipelineManager class is responsible for creation of Pipelines.
 */
class TSK_FRAMEWORK_API TskPipelineManager
{
public:
    static const std::string FILE_ANALYSIS_PIPELINE;
    static const std::string REPORTING_PIPELINE;
    static const std::string PIPELINE_ELEMENT;
    static const std::string PIPELINE_TYPE;
    static const std::string DEFAULT_PIPELINE_CONFIG;

    // Default Constructor
    TskPipelineManager();

    // Destructor
    ~TskPipelineManager();

    // Create a new Pipeline of the given type
    TskPipeline * createPipeline(const std::string& pipelineType);

private:
    std::vector<TskPipeline *> m_pipelines;
};

#endif 