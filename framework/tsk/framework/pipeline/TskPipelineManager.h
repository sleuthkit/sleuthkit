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
    /// Supported pipeline types
    enum PIPELINE_TYPE
    {
        FILE_ANALYSIS_PIPELINE, ///< A pipeline that operates on every file in the system
        POST_PROCESSING_PIPELINE ///< A pipeline that is run once file analysis is complete
    };

    static const std::string FILE_ANALYSIS_PIPELINE_STR;  ///< String to use in pipeline configuration file when creating a file analysis pipeline
    static const std::string POST_PROCESSING_PIPELINE_STR; ///< String to use in pipeline configuration file when creating a post processing pipeline
    static const std::string REPORTING_PIPELINE_STR; ///< Deprecated: String to use in pipeline configuration file when creating a post processing pipeline
    static const std::string PIPELINE_ELEMENT; ///< String to use in pipeline configuration file when creating a pipeline element
    static const std::string PIPELINE_TYPE_ATTRIBUTE; ///< Attribute in PIPELINE_ELEMENT for pipeline type in config XML file
    static const std::string PIPELINE_NAME_ATTRIBUTE; ///< Attribute in PIPELINE_ELEMENT for optional pipeline name in config XML file

    TskPipelineManager();
    ~TskPipelineManager();
    TskPipeline * createPipeline(const std::string& pipelineType);

    /**
     * Create a pipeline of the given type and optionally a given name.
     * @param type The type of pipeline to create
     * @param name An optional string to disambiguate the situation where there are multiple pipelines
     * of the same type.
     * @return Pointer to a pipeline object. This pointer is managed by TskPipelineManager which will free it
     * in its desctructor.
     */
    TskPipeline * createPipeline(const PIPELINE_TYPE type, const std::string& name="");

private:
    std::vector<TskPipeline *> m_pipelines;  ///< List of allocated pipelines

    std::string pipelineTypeToString(const PIPELINE_TYPE type);
};

#endif 
