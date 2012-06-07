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

#include "File/TskFile.h"

/**
 * Interface for classes that represent different types of modules
 * in the pipeline. Example module types include dynamic library
 * and executables. These modules perform some operation in the
 * context of a TskPipeline.
 */
class TSK_FRAMEWORK_API TskModule
{
public:
    static const std::wstring FILE_MACRO;
    static const std::wstring OUT_MACRO;
    static const std::wstring SESSION_MACRO;
    static const std::wstring PROGDIR_MACRO;
    static const std::wstring MODDIR_MACRO;
    static const std::wstring TASK_MACRO;
    static const std::wstring NODE_MACRO;
    static const std::wstring SEQUENCE_MACRO;
    static const std::wstring PID_MACRO;
    static const std::wstring STARTTIME_MACRO;
    static const std::wstring CURTIME_MACRO;
    static const std::wstring UNIQUE_ID_MACRO;

    /// Standard values that module methods can return.
    enum Status
    {
        OK = 0, ///< Indicates that the module sucessfully analyzed the data or was able to decide that it should not analyze the data.
        FAIL, ///< Indicates that the module wanted to perform analysis on the data, but was unable to because of an error.  
        STOP  ///< Indicates that the module wants the pipeline to stop processing. 
    };

    // Default Constructor
    TskModule();

    // Virtual destructor since Module must be subclassed to be useful
    virtual ~TskModule();

    // This is where Module processing occurs and must be implemented by
    // subclasses.
    virtual Status run(TskFile* fileToAnalyze) = 0;

    // Override this for report modules.
    virtual Status report() { return TskModule::OK; };

    virtual void setPath(const std::string& location);

    virtual std::string getPath() const { return m_modulePath; }

    /// Set the arguments to be passed to the module.
    void setArguments(const std::string& args) { m_arguments = args; }

    /// Get the arguments
    std::string getArguments() const { return m_arguments; }

    /// Get the module name
    std::string getName() const { return m_name; }

    /// Set the module id
    void setModuleId(int moduleId) { m_moduleId = moduleId; }

    /// Get the module id
    int getModuleId() const { return m_moduleId; }

protected:
    std::string m_modulePath;
    std::string m_arguments;
    std::string m_name;
    int m_moduleId;

    std::string parameterSubstitution(const std::string& paramString, const TskFile* fileToAnalyze);

private:

};

#endif
