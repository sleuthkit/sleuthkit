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
 * \file TskPipelineManager.h
 * Contains the declarations for the TskPipelineManager class.
 */

#ifndef _TSK_PIPELINEMANAGER_H
#define _TSK_PIPELINEMANAGER_H

#include <string>
#include "TskPipeline.h"

/**
 * Responsible for creation and destruction of of TskPipeline objects.
 * This class is responsible for reading the pipeline configuration file.
 */
class TSK_FRAMEWORK_API TskPipelineManager
{
public:
    static const std::string FILE_ANALYSIS_PIPELINE;  ///< String to use when creating a file analysis pipeline type
    static const std::string REPORTING_PIPELINE;  ///< Deprecated: String to use when creating a post processing pipeline type
    static const std::string POST_PROCESSING_PIPELINE; ///< String to use when creating a post processing pipeline type
    static const std::string PIPELINE_ELEMENT; ///< Element in pipeline config XML file.
    static const std::string PIPELINE_TYPE; ///< Attribute in PIPELINE_ELEMENT for pipeline type in config XML file

    TskPipelineManager();
    ~TskPipelineManager();
    TskPipeline * createPipeline(const std::string& pipelineType);

private:
    std::vector<TskPipeline *> m_pipelines;  ///< List of allocated pipelines
};

#endif 
