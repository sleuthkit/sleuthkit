/*
 *
 *  The Sleuth Kit
 *
 *  Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 *  Copyright (c) 2010-2012 Basis Technology Corporation. All Rights
 *  reserved.
 *
 *  This software is distributed under the Common Public License 1.0
 */

/**
 * \file TskModule.cpp
 * Contains the implementation for the TskModule base class.
 */

#include <sstream>

#include "TskModule.h"
#include "tsk/framework/services/TskServices.h"
#include "tsk/framework/services/TskSystemProperties.h"

#include "Poco/String.h"
#include "Poco/Environment.h"
#include "Poco/Path.h"
#include "Poco/File.h"

const std::string TskModule::CURRENT_FILE_MACRO = "#CURRENT_FILE#";

TskModule::TskModule() : m_moduleId(0)
{
}

TskModule::~TskModule()
{
}

/**
 * Sets the location of the module given an absolute or relative location.
 * For relative paths we look for the
 * module first in PROG_DIR, then MODULE_DIR, then the
 * current directory, and 
 * finally the system path. Will throw an exception if the module cannot 
 * be found.
 * @param location Absolute or relative path string for module.
 */
void TskModule::setPath(const std::string& location)
{
    if (location.empty()) 
    {
        throw TskException("TskModule::setPath: location is empty or missing.");
    }

    Poco::Path tempPath = location;

    if (!tempPath.isAbsolute())
    {
        // If this is a relative path, then see if we can find the
        // executable either in PROG_DIR, in MODULE_DIR, in the current directory,
        // or on the system path.        
        std::string pathsToSearch = GetSystemProperty(TskSystemProperties::PROG_DIR); 
        if (!pathsToSearch.empty())
            pathsToSearch += Poco::Path::pathSeparator();
        pathsToSearch += GetSystemProperty(TskSystemProperties::MODULE_DIR);
        if (!pathsToSearch.empty())
            pathsToSearch += Poco::Path::pathSeparator();
        pathsToSearch += ".";

        if (!Poco::Path::find(pathsToSearch, location, tempPath))
        {
            // if we didn't find them in the above paths, check on the path. 
            if (Poco::Environment::has("Path"))
            {
                std::string systemPath = Poco::Environment::get("Path");
            
                if (!systemPath.empty())
                {
                    Poco::Path::find(systemPath, location, tempPath);
                }
            }
        }
    }

    // Confirm existence of file at location.
    Poco::File moduleFile(tempPath);

    if (!moduleFile.exists())
    {
        std::stringstream msg;
        msg << "TskModule::setPath - Module not found: "
            << tempPath.toString().c_str();
        throw TskException(msg.str());
    }
    else {
        std::wstringstream msg;
        msg << L"TskModule::setPath - Module found at: "
            << tempPath.toString().c_str();
        LOGINFO(msg.str());
    }

    m_modulePath = tempPath.toString();
}

std::string TskModule::expandArgumentMacros(const std::string &args, const TskFile *fileToAnalyze)
{
    std::string outputStr = args;

    if (fileToAnalyze)
    {
        Poco::replaceInPlace(outputStr, TskModule::CURRENT_FILE_MACRO, fileToAnalyze->getPath());
    }

    return ExpandSystemPropertyMacros(outputStr);
}
