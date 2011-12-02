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
 * \file TskPipeline.h
 * Contains the interface for the TskPipeline class.
 */

#ifndef _TSK_PIPELINE_H
#define _TSK_PIPELINE_H

#include <list>
#include <string>
#include "tsk3/base/tsk_os.h" // for uint64_t
#include "TskModule.h"
#include "TskPluginModule.h"

#include "Poco/DOM/Element.h"

/**
 * The Pipeline class controls the processing of a File
 * through an ordered list of dynamically configured modules.
 */
class TSK_FRAMEWORK_API TskPipeline
{
public:
    static const std::string MODULE_ELEMENT;
    static const std::string MODULE_TYPE_ATTR;
    static const std::string MODULE_ORDER_ATTR;
    static const std::string MODULE_LOCATION_ATTR;
    static const std::string MODULE_ARGS_ATTR;
    static const std::string MODULE_OUTPUT_ATTR;
    static const std::string MODULE_EXECUTABLE_TYPE;
    static const std::string MODULE_PLUGIN_TYPE;

    // Default constructor
    TskPipeline();

    // Copy constructor
    TskPipeline(TskPipeline& pipeline);

    // Destructor
    ~TskPipeline();

    // Validate a Pipeline based on the given XML configuration string.
    void validate(const std::string& pipelineConfig);

    // Initialize a Pipeline based on the given XML configuration string.
    void initialize(const std::string& pipelineConfig);

    // Does the Pipeline have any modules?
    bool isEmpty() const { return m_modules.size() == 0; }

    // Run through all the modules in the Pipeline for the given file id.
    virtual void run(const uint64_t fileId) = 0;

    // Run through all the modules in the Pipeline for the given File object
    virtual void run(TskFile* file) = 0;

    // Run through all the modules in the Pipeline, useful for processing entire ImgDB
    virtual void run() = 0;

    // Create a module for the pipeline
    virtual TskPluginModule * createPluginModule() = 0;

protected:
    std::vector<TskModule*> m_modules;

    bool excludeFile(const TskFile*);

private:
    bool m_hasExeModule;
    bool m_loadDll;

    TskModule * createModule(Poco::XML::Element * pElem);
};

#endif
