/*
 *
 *  The Sleuth Kit
 *
 *  Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 *  Copyright (c) 2010-2011 Basis Technology Corporation. All Rights
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
#include "Services/TskSystemPropertiesImpl.h"

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

const std::wstring TskModule::FILE_MACRO = L"@FILE";
const std::wstring TskModule::OUT_MACRO = L"@OUT";
const std::wstring TskModule::SESSION_MACRO = L"@SESSION";
const std::wstring TskModule::PROGDIR_MACRO = L"@PROGDIR";
const std::wstring TskModule::TASK_MACRO = L"@TASK";
const std::wstring TskModule::NODE_MACRO = L"@NODE";
const std::wstring TskModule::SEQUENCE_MACRO = L"@SEQUENCE";
const std::wstring TskModule::PID_MACRO = L"@PID";
const std::wstring TskModule::STARTTIME_MACRO = L"@STARTTIME";
const std::wstring TskModule::CURTIME_MACRO = L"@CURTIME";
const std::wstring TskModule::UNIQUE_ID_MACRO = L"@UNIQUE_ID";

TskModule::TskModule() : m_modulePath(""), m_arguments(""), m_name(""), m_moduleId(0)
{
}

TskModule::~TskModule()
{
}

/**
 * Determines the fully qualified path to a module given either an
 * absolute or relative location string. For relative paths we look for the
 * module first in our program directory, then the "Modules" folder and 
 * finally the system path. Will throw an exception if the module cannot 
 * be found.
 * @param location Absolute or relative path string.
 */
void TskModule::setPath(const std::string& location)
{
    if (location.empty()) 
    {
        throw TskException("location is empty or missing.");
    }

    Poco::Path tempPath = location;

    if (!tempPath.isAbsolute())
    {
        // If this is not an absolute path see if we can find the
        // executable either relative to our program directory, in
        // our "Modules" folder or on our system path.

        std::string progDir = TskUtilities::toUTF8(TSK_SYS_PROP_GET(TskSystemPropertiesImpl::PROG_DIR));
        
        std::string moduleDir = TskUtilities::toUTF8(TSK_SYS_PROP_GET(TskSystemPropertiesImpl::MODULE_DIR));

        std::string pathsToSearch = progDir + Poco::Path::pathSeparator() + moduleDir;

        if (!Poco::Path::find(pathsToSearch, location, tempPath))
        {
            std::string systemPath;

            if (Poco::Environment::has("Path"))
            {
                systemPath = Poco::Environment::get("Path");
            }

            if (!systemPath.empty())
            {
                Poco::Path::find(systemPath, location, tempPath);
            }
        }
    }

    // Confirm existence of file at location.
    Poco::File moduleFile(tempPath);

    if (!moduleFile.exists())
    {
        std::wstringstream msg;
        msg << L"TskModule::setPath - File does not exist: "
            << tempPath.toString().c_str() << std::endl;
        LOGERROR(msg.str());
        throw TskException("Module not found.");
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
    Poco::replaceInPlace(resultString, 
                         TskUtilities::toUTF8(TskModule::OUT_MACRO), 
                         TskUtilities::toUTF8(TSK_SYS_PROP_GET(TskSystemPropertiesImpl::OUTDIR)));

    // Replace all occurences of PROGDIR_MACRO with the program directory.
    Poco::replaceInPlace(resultString, 
                         TskUtilities::toUTF8(TskModule::PROGDIR_MACRO), 
                         TskUtilities::toUTF8(TSK_SYS_PROP_GET(TskSystemPropertiesImpl::PROG_DIR)));

    // Replace all occurences of SESSION_MACRO with the session id.
    Poco::replaceInPlace(resultString, 
                         TskUtilities::toUTF8(TskModule::SESSION_MACRO), 
                         TskUtilities::toUTF8(TSK_SYS_PROP_GET(TskSystemPropertiesImpl::SESSION_ID)));

    // Replace all occurences of TASK_MACRO with the task name.
    Poco::replaceInPlace(resultString, 
                         TskUtilities::toUTF8(TskModule::TASK_MACRO), 
                         TskUtilities::toUTF8(TSK_SYS_PROP_GET(TskModule::TASK_MACRO)));
    
    // Replace all occurences of NODE_MACRO with the computer name.
    Poco::replaceInPlace(resultString, 
                         TskUtilities::toUTF8(TskModule::NODE_MACRO), 
                         TskUtilities::toUTF8(TSK_SYS_PROP_GET(TskModule::NODE_MACRO)));

    // Replace all occurences of SEQUENCE_MACRO with the job sequence number.
    Poco::replaceInPlace(resultString, 
                         TskUtilities::toUTF8(TskModule::SEQUENCE_MACRO),
                         TskUtilities::toUTF8(TSK_SYS_PROP_GET(TskModule::SEQUENCE_MACRO)));

    // Replace all occurences of PID_MACRO with the process id.
    Poco::replaceInPlace(resultString, 
                         TskUtilities::toUTF8(TskModule::PID_MACRO),
                         TskUtilities::toUTF8(TSK_SYS_PROP_GET(TskModule::PID_MACRO)));

    // Replace all occurences of STARTTIME_MACRO with the process start time
    Poco::replaceInPlace(resultString, 
                         TskUtilities::toUTF8(TskModule::STARTTIME_MACRO),
                         TskUtilities::toUTF8(TSK_SYS_PROP_GET(TskModule::STARTTIME_MACRO)));

    Poco::replaceInPlace(resultString, 
                         TskUtilities::toUTF8(TskModule::UNIQUE_ID_MACRO),
                         TskUtilities::toUTF8(TSK_SYS_PROP_GET(TskModule::UNIQUE_ID_MACRO)));

    Poco::LocalDateTime localDateTime;
    std::string curTimeStr = Poco::DateTimeFormatter::format(localDateTime, "%Y_%m_%d_%H_%M_%S");
    Poco::replaceInPlace(resultString, TskUtilities::toUTF8(TskModule::CURTIME_MACRO), curTimeStr);

    return resultString;
}
