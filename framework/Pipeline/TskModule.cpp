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
#include "Services/TskServices.h"
#include "Utilities/TskException.h"
#include "Utilities/TskUtilities.h"
#include "Services/TskSystemProperties.h"

#include "Poco/String.h"
#include "Poco/StringTokenizer.h"
#include "Poco/Environment.h"
#include "Poco/Path.h"
#include "Poco/File.h"
#include "Poco/FileStream.h"
#include "Poco/Process.h"
#include "Poco/PipeStream.h"
#include "Poco/StreamCopier.h"
#include "Poco/DateTimeFormatter.h"
#include "Poco/DateTimeFormat.h"


/* Note that the comment next to the macro name serves as the primary documenattion for the supported macros */
const std::wstring TskModule::FILE_MACRO = L"@FILE";    ///< The file id currently being processed by the pipeline
const std::wstring TskModule::OUT_MACRO = L"@OUT";  ///< The path to the preferred output folder (as supplied by the program that configured the pipeline).
const std::wstring TskModule::SESSION_MACRO = L"@SESSION";  ///< The session id assigned by to this job (as assigned by the program that configured the pipeline).
const std::wstring TskModule::PROGDIR_MACRO = L"@PROGDIR";  ///< The path to the directory where the program that is using the pipeline is installed.
const std::wstring TskModule::MODDIR_MACRO = L"@MODDIR";  ///< The path to the module directory has been configured to be. 
const std::wstring TskModule::TASK_MACRO = L"@TASK";    ///< The name of the currently executing task (e.g. FileAnalysis, Carving etc.)
const std::wstring TskModule::NODE_MACRO = L"@NODE";    ///< The name of the computer on which the task is running.
const std::wstring TskModule::SEQUENCE_MACRO = L"@SEQUENCE";    ///< The job sequence number
const std::wstring TskModule::PID_MACRO = L"@PID";  ///< The process id of the program that is using the pipeline.
const std::wstring TskModule::STARTTIME_MACRO = L"@STARTTIME";  ///< The time at which the program that is using the pipeline started.
const std::wstring TskModule::CURTIME_MACRO = L"@CURTIME";  ///< The current time.
const std::wstring TskModule::UNIQUE_ID_MACRO = L"@UNIQUE_ID";  ///< A combination of task name, node name, process id and start time separated by underscores. This is useful if you want to redirect output to a shared location. A unique file name will eliminate potential file sharing conflicts.

TskModule::TskModule() : m_modulePath(""), m_arguments(""), m_name(""), m_moduleId(0)
{
}

TskModule::~TskModule()
{
}

/**
 * Determines the fully qualified path to a module given either an
 * absolute or relative location string. For relative paths we look for the
 * module first in PROG_DIR, then MODULE_DIR, then the
 * current directory, and 
 * finally the system path. Will throw an exception if the module cannot 
 * be found.
 * @param location Absolute or relative path string.
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
        
        std::string pathsToSearch = TskUtilities::toUTF8(TSK_SYS_PROP_GET(TskSystemProperties::PROG_DIR));
        if (!pathsToSearch.empty())
            pathsToSearch += Poco::Path::pathSeparator();
        pathsToSearch += TskUtilities::toUTF8(TSK_SYS_PROP_GET(TskSystemProperties::MODULE_DIR));
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
        std::wstringstream msg;
        msg << L"TskModule::setPath - Module not found: "
            << tempPath.toString().c_str();
        LOGERROR(msg.str());
        throw TskException("Module not found.");
    }
    else {
        std::wstringstream msg;
        msg << L"TskModule::setPath - Module found at: "
            << tempPath.toString().c_str();
        LOGINFO(msg.str());
    }

    m_modulePath = tempPath.toString();
    m_name = tempPath.getBaseName();
}

/**
 * Perform parameter substitution on given string.
 */
std::string TskModule::parameterSubstitution(const std::string& paramString, const TskFile* fileToAnalyze)
{
    std::string resultString = paramString;

    if (fileToAnalyze)
    {
        // Replace all occurences of FILE_MACRO with the file name.
        Poco::replaceInPlace(resultString, TskUtilities::toUTF8(TskModule::FILE_MACRO), fileToAnalyze->getPath());
    }

    // Replace all occurences of OUT_MACRO with the output directory.
    if (resultString.find(TskUtilities::toUTF8(TskModule::OUT_MACRO)) != string::npos)
        Poco::replaceInPlace(resultString, 
                         TskUtilities::toUTF8(TskModule::OUT_MACRO), 
                         TskUtilities::toUTF8(TSK_SYS_PROP_GET(TskSystemProperties::OUT_DIR)));

    // Replace all occurences of PROGDIR_MACRO with the program directory.
    if (resultString.find(TskUtilities::toUTF8(TskModule::PROGDIR_MACRO)) != string::npos)
        Poco::replaceInPlace(resultString, 
                         TskUtilities::toUTF8(TskModule::PROGDIR_MACRO), 
                         TskUtilities::toUTF8(TSK_SYS_PROP_GET(TskSystemProperties::PROG_DIR)));

    if (resultString.find(TskUtilities::toUTF8(TskModule::MODDIR_MACRO)) != string::npos)
        Poco::replaceInPlace(resultString, 
                         TskUtilities::toUTF8(TskModule::MODDIR_MACRO), 
                         TskUtilities::toUTF8(TSK_SYS_PROP_GET(TskSystemProperties::MODULE_DIR)));

    // Replace all occurences of SESSION_MACRO with the session id.
    if (resultString.find(TskUtilities::toUTF8(TskModule::SESSION_MACRO)) != string::npos)
        Poco::replaceInPlace(resultString, 
                         TskUtilities::toUTF8(TskModule::SESSION_MACRO), 
                         TskUtilities::toUTF8(TSK_SYS_PROP_GET(TskSystemProperties::SESSION_ID)));

    // Replace all occurences of TASK_MACRO with the task name.
    if (resultString.find(TskUtilities::toUTF8(TskModule::TASK_MACRO)) != string::npos)
        Poco::replaceInPlace(resultString, 
                         TskUtilities::toUTF8(TskModule::TASK_MACRO), 
                         TskUtilities::toUTF8(TSK_SYS_PROP_GET(TskModule::TASK_MACRO)));
    
    // Replace all occurences of NODE_MACRO with the computer name.
    if (resultString.find(TskUtilities::toUTF8(TskModule::NODE_MACRO)) != string::npos)
        Poco::replaceInPlace(resultString, 
                         TskUtilities::toUTF8(TskModule::NODE_MACRO), 
                         TskUtilities::toUTF8(TSK_SYS_PROP_GET(TskModule::NODE_MACRO)));

    // Replace all occurences of SEQUENCE_MACRO with the job sequence number.
    if (resultString.find(TskUtilities::toUTF8(TskModule::SEQUENCE_MACRO)) != string::npos)
        Poco::replaceInPlace(resultString, 
                         TskUtilities::toUTF8(TskModule::SEQUENCE_MACRO),
                         TskUtilities::toUTF8(TSK_SYS_PROP_GET(TskModule::SEQUENCE_MACRO)));

    // Replace all occurences of PID_MACRO with the process id.
    if (resultString.find(TskUtilities::toUTF8(TskModule::PID_MACRO)) != string::npos)
        Poco::replaceInPlace(resultString, 
                         TskUtilities::toUTF8(TskModule::PID_MACRO),
                         TskUtilities::toUTF8(TSK_SYS_PROP_GET(TskModule::PID_MACRO)));

    // Replace all occurences of STARTTIME_MACRO with the process start time
    if (resultString.find(TskUtilities::toUTF8(TskModule::STARTTIME_MACRO)) != string::npos)
        Poco::replaceInPlace(resultString, 
                         TskUtilities::toUTF8(TskModule::STARTTIME_MACRO),
                         TskUtilities::toUTF8(TSK_SYS_PROP_GET(TskModule::STARTTIME_MACRO)));

    if (resultString.find(TskUtilities::toUTF8(TskModule::UNIQUE_ID_MACRO)) != string::npos)
        Poco::replaceInPlace(resultString, 
                         TskUtilities::toUTF8(TskModule::UNIQUE_ID_MACRO),
                         TskUtilities::toUTF8(TSK_SYS_PROP_GET(TskModule::UNIQUE_ID_MACRO)));


    if (resultString.find(TskUtilities::toUTF8(TskModule::CURTIME_MACRO)) != string::npos) {
        Poco::LocalDateTime localDateTime;
        std::string curTimeStr = Poco::DateTimeFormatter::format(localDateTime, "%Y_%m_%d_%H_%M_%S");
        Poco::replaceInPlace(resultString, TskUtilities::toUTF8(TskModule::CURTIME_MACRO), curTimeStr);
    }

    return resultString;
}
