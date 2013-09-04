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
 * \file TskPluginModule.cpp
 * Contains the implementation for the TskPluginModule class.
 */

// Include the class definition first to ensure it does not depend on subsequent includes in this file.
#include "TskPluginModule.h"

// Framework includes
#include "tsk/framework/services/TskServices.h"
#include "tsk/framework/utilities/TskException.h"
#include "tsk/framework/file/TskFileManagerImpl.h"
#include "tsk/framework/TskVersionInfo.h"

// Poco includes
#include "Poco/String.h"
#include "Poco/Path.h"
#include "Poco/Environment.h"

// C/C++ library includes
#include <sstream>
#include <string>

const std::string TskPluginModule::GET_COMPILER_SYMBOL = "getCompiler";
const std::string TskPluginModule::GET_COMPILER_VERSION_SYMBOL = "getCompilerVersion";
const std::string TskPluginModule::GET_FRAMEWORK_VERSION_SYMBOL = "getFrameWorkVersion";
const std::string TskPluginModule::GET_BUILD_TYPE_SYMBOL = "getBuildType";
const std::string TskPluginModule::NAME_SYMBOL = "name";
const std::string TskPluginModule::DESCRIPTION_SYMBOL = "description";
const std::string TskPluginModule::VERSION_SYMBOL = "version";
const std::string TskPluginModule::RUN_SYMBOL = "run";
const std::string TskPluginModule::REPORT_SYMBOL = "report";
const std::string TskPluginModule::INITIALIZE_SYMBOL = "initialize";
const std::string TskPluginModule::FINALIZE_SYMBOL = "finalize";

TskPluginModule::~TskPluginModule()
{
    if (m_sharedLibrary.isLoaded())
    {
        // Call finalize function if defined.
        if (m_sharedLibrary.hasSymbol(TskPluginModule::FINALIZE_SYMBOL))
        {
            typedef TskModule::Status (*FinalizeFunc)();
            FinalizeFunc fin = (FinalizeFunc)m_sharedLibrary.getSymbol(TskPluginModule::FINALIZE_SYMBOL);
            fin();
        }

        m_sharedLibrary.unload();
    }
}

void TskPluginModule::setPath(const std::string& location)
{
    try
    {
        if (location.empty()) 
        {
            throw TskException("TskPluginModule::setPath: location is empty or missing.");
        }

        std::string os = Poco::Environment::osName();        
        Poco::Path tempPath = location;
            
        // If on Linux or Mac, then prefix with "lib"
        if ((os.find("Linux") != std::string::npos) || (os.find("Darwin") != std::string::npos))
        {
            tempPath.setFileName("lib" + tempPath.getFileName());
        } 

        // Autogenerate filename extension if needed
        if (tempPath.getExtension().empty())
        {
            if (os.find("Linux") != std::string::npos)
            {
                tempPath.setExtension("so");
            } 
            else if (os.find("Darwin") != std::string::npos)
            {
                tempPath.setExtension("dylib");
            } 
            else if (os.find("Windows") != std::string::npos ||
                     os.find("CYGWIN")  != std::string::npos ||
                     os.find("MINGW")   != std::string::npos )
            {
                tempPath.setExtension("dll");
            } 
            else
            {
                throw TskException("TskPluginModule::setPath: OS unknown. Cannot resolve plugin extension.");
            }
        }

        // Search for location
        // Absolute (fully qualified) paths are not allowed.
        if (!tempPath.isAbsolute())
        {
            // See if we can find the executable in MODULE_DIR.
            std::string pathsToSearch = GetSystemProperty(TskSystemProperties::MODULE_DIR);

            bool found = Poco::Path::find(pathsToSearch, tempPath.toString(), tempPath);

            // Confirm existence of file at found location.
            Poco::File moduleFile(tempPath);
            if (found && moduleFile.exists())
            {
                std::wstringstream msg;
                msg << L"TskPluginModule::setPath - Module found at: "
                    << tempPath.toString().c_str();
                LOGINFO(msg.str());
            }
            else
            {
                std::stringstream msg;
                msg << "TskPluginModule::setPath - Module not found: "
                    << tempPath.toString().c_str();
                throw TskException(msg.str());
            }
        }
        else
        {
            std::stringstream msg;
            msg << "TskPluginModule::setPath: location (" << tempPath.toString() << ") is not relative to MODULE_DIR.";
            throw TskException(msg.str());
        }

        m_modulePath = tempPath.toString();

        // Load the library.
        m_sharedLibrary.load(m_modulePath);

        if (m_sharedLibrary.isLoaded())
        {
           validateLibraryVersionInfo();

           // TODO: Eliminate code duplication that follows.
           typedef const char* (*MetaDataFunc)();
           MetaDataFunc metaDataFunc = NULL;

            if (m_sharedLibrary.hasSymbol(TskPluginModule::NAME_SYMBOL))
            {
                metaDataFunc = (MetaDataFunc)m_sharedLibrary.getSymbol(TskPluginModule::NAME_SYMBOL);
                if (metaDataFunc)
                {
                    m_name = metaDataFunc();
                    metaDataFunc = NULL;
                }
            }

            if (m_sharedLibrary.hasSymbol(TskPluginModule::DESCRIPTION_SYMBOL))
            {
                metaDataFunc = (MetaDataFunc)m_sharedLibrary.getSymbol(TskPluginModule::DESCRIPTION_SYMBOL);
                if (metaDataFunc)
                {
                    m_description = metaDataFunc();
                    metaDataFunc = NULL;
                }
            }

            if (m_sharedLibrary.hasSymbol(TskPluginModule::VERSION_SYMBOL))
            {
                metaDataFunc = (MetaDataFunc)m_sharedLibrary.getSymbol(TskPluginModule::VERSION_SYMBOL);
                if (metaDataFunc)
                {
                    m_version = metaDataFunc();
                    metaDataFunc = NULL;
                }
            }
        }

        if (m_name.empty())
        {
            Poco::Path modulePath(m_modulePath);
            m_name = modulePath.getBaseName();
        }
    }
    catch (TskException& ex)
    {
        // Base class has already logged an error so we simply rethrow.
        throw ex;
    }
    catch(std::exception& ex)
    {
        // Log a message and throw a framework exception.
        std::wstringstream msg;
        msg << L"TskPluginModule::setPath - " << ex.what();
        LOGERROR(msg.str());

        throw TskException("Failed to set path: " + m_modulePath);
    }
}

TskModule::Status TskPluginModule::initialize()
{
    const std::string MSG_PREFIX = "TskPluginModule::initialize : ";
    TskModule::Status status = TskModule::FAIL;
    if (m_sharedLibrary.hasSymbol(TskPluginModule::INITIALIZE_SYMBOL))
    {
        try
        {
            std::string arguments = expandArgumentMacros(m_arguments, 0);
            typedef TskModule::Status (*InitializeFunc)(const char* args);
            InitializeFunc init = (InitializeFunc) m_sharedLibrary.getSymbol(TskPluginModule::INITIALIZE_SYMBOL);
            status = init(arguments.c_str());        
        }
        catch (TskException &ex) 
        {
            std::stringstream msg;
            msg << MSG_PREFIX << "TskException initializing " << getName() << ": " << ex.message();
            LOGERROR(msg.str());
            status = TskModule::FAIL;
        }
        catch (Poco::Exception &ex) 
        {
            std::stringstream msg;
            msg << MSG_PREFIX <<  "Poco::Exception initializing "  << getName() << ": " << ex.displayText();
            LOGERROR(msg.str());
            status = TskModule::FAIL;
        }
        catch (std::exception &ex) 
        {
            std::stringstream msg;
            msg << MSG_PREFIX <<  "std::exception initializing "  << getName() << ": " << ex.what();
            LOGERROR(msg.str());
            status = TskModule::FAIL;
        }
        catch (...)
        {
            std::stringstream msg;
            msg << MSG_PREFIX << "unrecognized exception initializing "  << getName();
            LOGERROR(msg.str());
            status = TskModule::FAIL;
        }
    }

    return status;
}

bool TskPluginModule::isLoaded() const
{
    return (m_sharedLibrary.isLoaded());
}

void *TskPluginModule::getSymbol(const std::string symbol)
{
    return (void*)m_sharedLibrary.getSymbol(symbol);
}

bool TskPluginModule::hasSymbol(const std::string symbol) 
{
    return (m_sharedLibrary.hasSymbol(symbol));
}

void TskPluginModule::validateLibraryVersionInfo()
{
   if (!hasSymbol(GET_FRAMEWORK_VERSION_SYMBOL) || !hasSymbol(GET_COMPILER_SYMBOL) || !hasSymbol(GET_COMPILER_VERSION_SYMBOL) || !hasSymbol(GET_BUILD_TYPE_SYMBOL))
   {
      throw TskException("version info interface not implemented");
   }

   int frameworkVersion = TskVersionInfo::getFrameworkVersion();
   typedef int (*GetFrameworkVersion)();
   GetFrameworkVersion getFrameworkVersion = (GetFrameworkVersion) m_sharedLibrary.getSymbol(TskPluginModule::GET_FRAMEWORK_VERSION_SYMBOL);
   int moduleFrameworkVersion = getFrameworkVersion();
   if (((frameworkVersion >> 16) & 0xFFFF)  != (( moduleFrameworkVersion >> 16) & 0xFFFF))
   {
      throw TskException("TskPluginModule::validateLibraryVersionInfo : framework version mismatch");
   }

   typedef TskVersionInfo::Compiler (*GetCompiler)();
   GetCompiler getCompiler = (GetCompiler) m_sharedLibrary.getSymbol(TskPluginModule::GET_COMPILER_SYMBOL);
   if (TskVersionInfo::getCompiler() != getCompiler())
   {
      throw TskException("TskPluginModule::validateLibraryVersionInfo : compiler mismatch");
   }

   typedef int (*GetCompilerVersion)();
   GetCompilerVersion getCompilerVersion = (GetCompilerVersion) m_sharedLibrary.getSymbol(TskPluginModule::GET_COMPILER_VERSION_SYMBOL);
   if (TskVersionInfo::getCompilerVersion() != getCompilerVersion())
   {
      throw TskException("TskPluginModule::validateLibraryVersionInfo : compiler version mismatch");
   }

   typedef TskVersionInfo::BuildType (*GetBuildType)();
   GetBuildType getBuildType = (GetBuildType) m_sharedLibrary.getSymbol(TskPluginModule::GET_BUILD_TYPE_SYMBOL);
   if (TskVersionInfo::getBuildType() != getBuildType())
   {
      throw TskException("TskPluginModule::validateLibraryVersionInfo : build target mismatch");
   }
}
