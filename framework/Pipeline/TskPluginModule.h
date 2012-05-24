/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2012 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

#ifndef _TSK_PLUGINMODULE_H
#define _TSK_PLUGINMODULE_H

#include "TskModule.h"

#include "Poco/SharedLibrary.h"

/**
 * Supports the loading of a custom dynamic library to perform
 * analysis in either a TskPipeline or TskReportPipeline.
 */
class TSK_FRAMEWORK_API TskPluginModule: public TskModule
{
public:
    // Default Constructor
    TskPluginModule();

    // Destructor
    virtual ~TskPluginModule();

    // Derived class must implement it's own run method
    virtual Status run(TskFile* fileToAnalyze) = 0;

    /// Sets the path of the library to load
    virtual void setPath(const std::string& location);

    // Initialize the module.
    void initialize();

    // Return true is the module is loaded.
    bool isLoaded() const;

    // Return a function entry with the given symbol in the module.
    void * getSymbol(const std::string symbol);

    // Return true is the module contains the function entry point.
    virtual bool hasSymbol(const std::string symbol);

    // Check the require interface for a plugin module. Throw exception if required interface is misssing.
    virtual void checkInterface() = 0;

protected:
    static const std::string RUN_SYMBOL;
    static const std::string REPORT_SYMBOL;
    static const std::string INITIALIZE_SYMBOL;
    static const std::string FINALIZE_SYMBOL;

private:
    Poco::SharedLibrary m_sharedLibrary;
};

#endif
