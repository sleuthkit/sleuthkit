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
 * \file TskPipeline.h
 * Contains the declarations for the TskPipeline class and the interface for methods
 * that are defined in the various implementations.
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
 * The Pipeline class controls the processing of data
 * through an ordered list of dynamic library or executable modules.
 * Different types of pipeline implementations exist for the different types of data. 
 * Pipelines are created by the TskPipelineManager class. 
 */
class TSK_FRAMEWORK_API TskPipeline
{
public:
    static const std::string MODULE_ELEMENT; ///< module element in XML config file
    static const std::string MODULE_TYPE_ATTR;  ///< attribute for module type in XML config file
    static const std::string MODULE_ORDER_ATTR; ///< attribute for module order in XML config file
    static const std::string MODULE_LOCATION_ATTR; ///< attribute for module location in XML config file
    static const std::string MODULE_ARGS_ATTR; ///< attribute for module arguments in XML config file
    static const std::string MODULE_OUTPUT_ATTR; ///< attribute for module output in XML config file
    static const std::string MODULE_EXECUTABLE_TYPE; ///< value of MODULE_TYPE_ATTR for executable modules
    static const std::string MODULE_PLUGIN_TYPE; ///< value of MODULE_TYPE_ATTR for library modules

    TskPipeline();
    ~TskPipeline();

    void validate(const std::string& pipelineConfig);
    void initialize(const std::string& pipelineConfig);
    bool isEmpty() const { 
        return m_modules.size() == 0; 
    }

    /**
     * Run a file analysis pipeline on a file with the given ID.
     * @param fileId Id of file to run pipeilne on.
     * @throws exceptions on errors 
     */
    virtual void run(const uint64_t fileId) = 0;

    /**
     * Run a file analysis pipeline on the given file object.
     * @param file TskFile object to run pipeilne on.
     * @throws exceptions on errors 
     */    
    virtual void run(TskFile* file) = 0;

    /**
     * Run a reporting / post-analysis pipeline.
     * @throws exceptions on errors     
     */    
    virtual void run() = 0;

    /**
     * Create a module for the given pipeline type.
     * @returns Plug-in module
     */
    virtual TskPluginModule * createPluginModule() = 0;

protected:
    std::vector<TskModule*> m_modules;
    bool m_hasExeModule;    ///< True if any module is an executable module

    bool excludeFile(const TskFile*);

private:
    // Disallow copying
    TskPipeline(const TskPipeline&);
    TskPipeline& operator=(const TskPipeline&);

    bool m_loadDll;     ///< True if dlls should be loaded during initialize

    TskModule * createModule(Poco::XML::Element * pElem);
};

#endif
