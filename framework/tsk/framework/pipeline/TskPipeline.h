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

// TSK includes
#include "tsk/base/tsk_os.h" // for uint64_t

// TSK Framework includes
#include "TskModule.h"
#include "TskPluginModule.h"

// Poco includes
#include "Poco/DOM/Element.h"
#include "Poco/Timespan.h"

// C/C++ library includes
#include <list>
#include <string>
#include <map>

/**
 * The Pipeline class controls the processing of data
 * through an ordered list of dynamic library or executable modules.
 * Different types of pipeline implementations exist for the different types of data. 
 * Pipelines are created by the TskPipelineManager class. 
 */
class TSK_FRAMEWORK_API TskPipeline
{
public:
    // DEVELOPERS: Changes to any of these elements and attributes require an update to $(TSK_HOME)\framework\docs\pipeline.dox 
    static const std::string MODULE_ELEMENT; ///< module element in XML config file
    static const std::string MODULE_TYPE_ATTR;  ///< attribute for module type in XML config file
    static const std::string MODULE_ORDER_ATTR; ///< attribute for module order in XML config file
    static const std::string MODULE_LOCATION_ATTR; ///< attribute for module location in XML config file
    static const std::string MODULE_ARGS_ATTR; ///< attribute for module arguments in XML config file
    static const std::string MODULE_OUTPUT_ATTR; ///< attribute for module output in XML config file
    static const std::string MODULE_EXECUTABLE_TYPE; ///< value of MODULE_TYPE_ATTR for executable modules
    static const std::string MODULE_PLUGIN_TYPE; ///< value of MODULE_TYPE_ATTR for library modules

    /**
     * Default constructor.
     */
    TskPipeline();

    /**
     * Destructor.
     */
    ~TskPipeline();

    /**
     * Validate a Pipeline based on the given XML configuration string. 
     * @param pipelineConfig String of config file for the specific type of pipeline. 
     * @throws TskException in case of error.
     */
    void validate(const std::string& pipelineConfig);

    /**
     * Parses the XML config file.  Modules are loaded if m_loadDll is set to true. 
     * @param pipelineConfig String of a config file for the specific type of pipeline.
     * @throws TskException in case of error.
     */
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

    /**
     * Logs the recorded execution times of the modules in the pipeline.
     */
    void logModuleExecutionTimes() const;

protected:
    /**
     * Determine whether a particular file should be processed.
     * @returns true if file should be excluded, false otherwise
     */
    bool excludeFile(const TskFile*);
    
    /**
     * Updates the recorded execution time of a module in the pipeline.
     * @param moduleId Module ID of the module.
     * @param executionTime Time increment to add to totasl execution time of the module.
     */
    void updateModuleExecutionTime(int moduleId, const Poco::Timespan::TimeDiff &executionTime);

    /**
     * Collection of modules in the pipeline.
     */
    std::vector<TskModule*> m_modules;

    bool m_hasExeModule;    ///< True if any module is an executable module

private:
    // Disallow copying
    TskPipeline(const TskPipeline&);
    TskPipeline& operator=(const TskPipeline&);

    /**
     * Creates a module of the type specified in the XML element.
     * @param pElem element type from XML file. 
     * @returns NULL on error 
     */
    TskModule * createModule(Poco::XML::Element * pElem);

    bool m_loadDll;     ///< True if dlls should be loaded during initialize
    
    /**
     * A mapping of module IDs to module names.
     */
    std::map<int, std::string> m_moduleNames;

    /**
     * A mapping of module IDs to cumulative module execution times.
     */
    std::map<int, Poco::Timespan> m_moduleExecTimes;
};

#endif
