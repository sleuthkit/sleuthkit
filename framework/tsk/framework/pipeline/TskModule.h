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
 * \file TskModule.h
 * Contains the interface for the Module class.
 */

#ifndef _TSK_MODULE_H
#define _TSK_MODULE_H

#include "tsk/framework/file/TskFile.h"

/**
 * Interface for classes that represent different types of modules
 * in the pipeline. Example module types include dynamic library
 * and executables. These modules perform some operation in the
 * context of a TskPipeline.
 */
class TSK_FRAMEWORK_API TskModule
{
public:
    /**
     * The TskModule class supports the use of a string macro that is expanded
     * to the path of the file currently under analysis. This macro is intended
     * to be used in the arguments strings passed to the initialization
     * functions of file analysis modules. "#CURRENT_FILE#" is the literal form
     * of the macro.
     */
    static const std::string CURRENT_FILE_MACRO;

    /// Standard values that module methods can return.
    enum Status
    {
        OK = 0, ///< Indicates that the module successfully analyzed the data or was able to decide that it should not analyze the data.
        FAIL, ///< Indicates that the module wanted to perform analysis on the data, but was unable to because of an error.  
        STOP  ///< Indicates that the module wants the pipeline to stop processing. 
    };

    // Default Constructor
    TskModule();

    // Virtual destructor since Module must be subclassed to be useful
    virtual ~TskModule();

    /**
     * Method that is used to run file analysis modules.
     * @returns Status of module
     */
    virtual Status run(TskFile* fileToAnalyze) = 0;

    /**
     * Method that is used to run report modules.
     * @returns Status of module
     */
    virtual Status report() { return TskModule::OK; };

    virtual void setPath(const std::string& location);

    /**
     * Returns the fully qualified path to the module.
     */
    virtual std::string getPath() const { return m_modulePath; }

    /// Set the arguments to be passed to the module.
    void setArguments(const std::string& args) { m_arguments = args; }

    /// Get the arguments
    std::string getArguments() const { return m_arguments; }

    /// Get the module name
    std::string getName() const { return m_name; }

    /// Get the module description
    std::string getDescription() const { return m_description; }

    /// Get the module version
    std::string getVersion() const { return m_version; }

    /// Set the module id
    void setModuleId(int moduleId) { m_moduleId = moduleId; }

    /// Get the module id
    int getModuleId() const { return m_moduleId; }

protected:
    std::string m_modulePath;
    std::string m_arguments;
    std::string m_name;
    std::string m_description;
    std::string m_version;
    int m_moduleId;

    static std::string expandArgumentMacros(const std::string &args, const TskFile *fileToAnalyze);

private:

};

#endif
