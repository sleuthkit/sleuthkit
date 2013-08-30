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

// TSK Framework includes
#include "TskModule.h"

// Poco includes
#include "Poco/SharedLibrary.h"

/**
 * Supports the loading of a custom dynamic library to perform
 * analysis in either a TskPipeline or TskReportPipeline.
 */
class TSK_FRAMEWORK_API TskPluginModule: public TskModule
{
public:
    /** 
     * Destructor that calls the finalize function of the module library and
     * unloads the library.
     */
    virtual ~TskPluginModule();

    /**
     * Loads the module library.
     *
     * @param location Either a relative or fully qualified path to the module 
     * library.
     */
    virtual void setPath(const std::string &location);

    /**
     * Calls the initialize function in the module library, if present.
     */
    TskModule::Status initialize();

    /**
     * Verifies that the required interface for a plugin module is defined by the module library. 
     * 
     * @return Throws TskException if the required interface is not defined.
     */
    virtual void checkInterface() = 0;

protected:
    static const std::string GET_COMPILER_SYMBOL;
    static const std::string GET_COMPILER_VERSION_SYMBOL;
    static const std::string GET_FRAMEWORK_VERSION_SYMBOL;
    static const std::string GET_BUILD_TYPE_SYMBOL;
    static const std::string NAME_SYMBOL;
    static const std::string DESCRIPTION_SYMBOL;
    static const std::string VERSION_SYMBOL;
    static const std::string RUN_SYMBOL;
    static const std::string REPORT_SYMBOL;
    static const std::string INITIALIZE_SYMBOL;
    static const std::string FINALIZE_SYMBOL;

    /** 
     * Checks whether or not the module library is loaded.
     *
     * @returns True if the module library is loaded.
     */ 
    bool isLoaded() const;

    /**
     * Checks whether or not the module library defines a particular symbol.
     *
     * @param symbol The symbol.
     * @returns True if the symbol is defined, false otherwise.
     */
    bool hasSymbol(const std::string symbol);

    /** 
     * Get a pointer to a function in the module library.
     *
     * @param symbol The symbol associated with the desired pointer.
     * @returns A pointer to the module library function corresponding to symbol.
     * Throws Poco::NotFoundException if symbol is not found.
     */
    void *getSymbol(const std::string symbol);

private:
    /**
     * Checks whether or not the module library was compiled with the same
     * framework library version (major and minor version number components), 
     * compiler, compiler version, and build target as the disk image 
     * processing system that is loading the module.
     */
   void validateLibraryVersionInfo();

    Poco::SharedLibrary m_sharedLibrary;
};

#endif
