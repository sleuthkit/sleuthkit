/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2013 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

/**
 * \file RegRipperModule.cpp
 * Contains the implementation for the reg ripper reporting module.
 * This module runs the RegRipper executable against the common set of
 * Windows registry files (i.e., NTUSER, SYSTEM, SAM and SOFTWARE).
 */

// TSK Framework includes
#include "tsk/framework/utilities/TskModuleDev.h"

// Poco includes
#include "Poco/String.h"
#include "Poco/StringTokenizer.h"
#include "Poco/File.h"
#include "Poco/Process.h"
#include "Poco/PipeStream.h"
#include "Poco/FileStream.h"
#include "Poco/StreamCopier.h"
#include "Poco/Path.h"
#include "Poco/RegularExpression.h"
#include "Poco/Environment.h"

// C/C++ standard library includes
#include <string>
#include <sstream>
#include <cassert>

namespace
{
    const char *MODULE_NAME = "RegRipper";
    const char *MODULE_DESCRIPTION = "Runs the RegRipper executable against the common set of Windows registry files (i.e., NTUSER, SYSTEM, SAM and SOFTWARE)";
    const char *MODULE_VERSION = "1.0.2";
    const uint64_t VOLUME_SHADOW_SNAPSHOT_FILE_PARENT_ID = 9223372036854775807;

    std::string ripExePath;
    std::string outputFolderPath;
    std::vector<std::string> interpreterArgs;
    std::string pluginPath;
    
    enum RegistryHiveType
    {
        NTUSER,
        SYSTEM,
        SAM,
        SOFTWARE
    };

    /**
     * Looks for an executable file in the PATH environment variable.
     * If exeFilename is found, it is also tested to see if it's executable.
     * @param  exeFilename The filename of an executable file.
     * @return Path found to the executable if it exists, otherwise an empty string
     */
    static const std::string checkExeEnvPath(const std::string & exeFilename)
    {
        static const short unsigned int MAX_ENV_LEN = 4096;

        std::string envPaths = Poco::Environment::get("PATH");

        // Don't waste time checking if env var is unreasonably large
        if (envPaths.length() < MAX_ENV_LEN)
        {
            Poco::Path p;
            if (Poco::Path::find(envPaths, exeFilename, p))
            {
                std::string newExePath = p.toString();

                // Check if executable mode is set
                Poco::File exeFile(newExePath);
                if (exeFile.canExecute())
                {
                    return newExePath;
                }
            }
        }
        return std::string();
    }

    /**
     * Parse RegRipper output from a specific output file for matches on the valueName. The 
     * function will return all lines in the file that match the valueName followed by one 
     * of the potential RegRipper separators. This may not always find all lines if a plugin
     * writer uses a new separator.
     * @param regRipperFileName The full path to a regRipper output file.
     * @param valueName The name of the value to search for. Will support regex matches that
     * come before a separator.
     * @return A vector of matching lines from the file.
     */
    std::vector<std::string> getRegRipperValues(const std::string& regRipperFileName, const std::string& valueName)
    {
        Poco::FileInputStream inStream(regRipperFileName);
        std::vector<std::string> results;

        std::string line;

        std::stringstream pattern;
        pattern << valueName << "[\\s\\->=:]+";

        Poco::RegularExpression regex(pattern.str(), 0, true);
        Poco::RegularExpression::Match match;

        while (std::getline(inStream, line))
        {
            int nummatches = regex.match(line, match, 0);
            if (nummatches > 0)
            {
                results.push_back(line.substr(match.offset + match.length, line.size()));
            }
        }

        inStream.close();
        return results;
    }

    /**
     * Processes the RegRipper output from a SOFTWARE hive and creates blackboard
     * entries for operating system details.
     * @param pFile A pointer to the SOFTWARE file object.
     * @param fileName The name of the RegRipper output file for the SOFTWARE hive.
     */
    void getSoftwareInfo(TskFile * pFile, const std::string& fileName)
    {
        std::vector<std::string> names = getRegRipperValues(fileName, "ProductName");

        TskBlackboardArtifact osart = pFile->createArtifact(TSK_OS_INFO);
        for (size_t i = 0; i < names.size(); i++)
        {
            TskBlackboardAttribute attr(TSK_NAME, MODULE_NAME, "", names[i]);
            osart.addAttribute(attr);
        }

        vector<std::string> versions = getRegRipperValues(fileName, "CSDVersion");
        for (size_t i = 0; i < versions.size(); i++)
        {
            TskBlackboardAttribute attr(TSK_VERSION, MODULE_NAME, "", versions[i]);
            osart.addAttribute(attr);
        }
    }

    /**
     * Processes the RegRipper output from a SYSTEM hive and creates blackboard
     * entries for operating system details.
     * @param pFile A pointer to the SYSTEM file object.
     * @param fileName The name of the RegRipper output file for the SYSTEM hive.
     */
    void getSystemInfo(TskFile * pFile, const std::string& fileName)
    {
        std::vector<std::string> names = getRegRipperValues(fileName, "ProcessorArchitecture");
        TskBlackboardArtifact osart = pFile->createArtifact(TSK_OS_INFO);
        for (size_t i = 0; i < names.size(); i++)
        {
            if (names[i].compare("AMD64") == 0)
            {
                TskBlackboardAttribute attr(TSK_PROCESSOR_ARCHITECTURE, MODULE_NAME, "", "x86-64");
                osart.addAttribute(attr);
            }
            else
            {
                TskBlackboardAttribute attr(TSK_PROCESSOR_ARCHITECTURE, MODULE_NAME, "", names[i]);
                osart.addAttribute(attr);
            }
        }
    }

    void getFileNamesForHiveType(RegistryHiveType type, std::string &hiveFileName, std::string &pluginSetFileName)
    {
        std::string funcName(MODULE_NAME + std::string("RegRipperModule::getFileNamesForHiveType"));

        std::string pluginsPath;
        pluginsPath = Poco::Path(ripExePath).parent().toString();
        pluginsPath.append("plugins");

        Poco::Path pluginSetFilePath;
        switch (type)
        {
        case NTUSER:
            hiveFileName = "NTUSER.DAT";
            if (!Poco::Path::find(pluginsPath, "ntuser-all", pluginSetFilePath) && 
                !Poco::Path::find(pluginsPath, "ntuser", pluginSetFilePath))
            {
                throw TskException("failed to find either ntuser-all or ntuser plugin wrapper file");
            }
            break;

        case SYSTEM:
            hiveFileName = "SYSTEM";
            if (!Poco::Path::find(pluginsPath, "system-all", pluginSetFilePath) && 
                !Poco::Path::find(pluginsPath, "system", pluginSetFilePath))
            {
                throw TskException("failed to find either system-all or system plugin wrapper file");
            }
            break;

        case SOFTWARE:
            hiveFileName = "SOFTWARE";
            if (!Poco::Path::find(pluginsPath, "software-all", pluginSetFilePath) &&
                !Poco::Path::find(pluginsPath, "software", pluginSetFilePath))
            {
                throw TskException("failed to find either software-all or software plugin wrapper file");
            }
            break;

        case SAM:
            hiveFileName = "SAM";
            if (!Poco::Path::find(pluginsPath, "sam-all", pluginSetFilePath) &&
                !Poco::Path::find(pluginsPath, "sam", pluginSetFilePath))
            {
                throw TskException("failed to find either sam-all or sam plugin wrapper file");
            }
            break;

        default:
            std::ostringstream msg;
            msg << "unexpected RegistryHiveType value " << type << " in " << funcName;
            assert(false && msg.str().c_str());
            throw TskException(msg.str());
        }

        pluginSetFileName = pluginSetFilePath.getFileName();
    }

    void runRegRipper(RegistryHiveType type)
    {
        std::string funcName(MODULE_NAME + std::string("RegRipperModule::runRegRipper"));

        // Get the hive name and plugin set file names.
        std::string hiveFileName; 
        std::string pluginSetFileName;
        getFileNamesForHiveType(type, hiveFileName, pluginSetFileName);

        TskFileManager& fileManager = TskServices::Instance().getFileManager();

        // Get a list corresponding to the files
        TskFileManager::AutoFilePtrList files(fileManager.findFilesByName(hiveFileName, TSK_FS_META_TYPE_REG));

        // Iterate over the files running RegRipper on each one.
        for (TskFileManager::FilePtrList::iterator file = files.begin(); file != files.end(); ++file)
        {
            // Skip empty files
            if ((*file)->getSize() == 0)
            {
                continue;
            }

            // Save the file content so that we can run RegRipper against it
            fileManager.saveFile(*file);

            // Create a file stream for the RegRipper output. 
            Poco::Path outputFilePath = Poco::Path::forDirectory(outputFolderPath);
            std::ostringstream fileName;
            if ((*file)->getParentFileId() == VOLUME_SHADOW_SNAPSHOT_FILE_PARENT_ID)
            {
                Poco::Path filePath((*file)->getFullPath());
                fileName << filePath.directory(0) << "_"; 
            }
            fileName << (*file)->getName() << "_" << (*file)->getHash(TskImgDB::MD5) << "_" << (*file)->getId() << ".txt";
            outputFilePath.setFileName(fileName.str());

            // Log what's happening.
            std::ostringstream msg;
            msg << funcName << " : ripping " << (*file)->getName() << " to " << outputFilePath.toString();
            LOGINFO(msg.str());

            // Run RegRipper.
            Poco::Process::Args cmdArgs;

            // Insert interpreter arguments, if any
            for (std::vector<std::string>::iterator it = interpreterArgs.begin(); it != interpreterArgs.end(); ++it) {
                cmdArgs.push_back(*it);
            }

            cmdArgs.push_back("-f");
            cmdArgs.push_back(pluginSetFileName);
            cmdArgs.push_back("-r");
            cmdArgs.push_back((*file)->getPath());
            Poco::Pipe outPipe;
            Poco::ProcessHandle handle = Poco::Process::launch(ripExePath, cmdArgs, NULL, &outPipe, &outPipe);

            // Capture the RegRipper output.
            Poco::PipeInputStream istr(outPipe);
            Poco::FileOutputStream ostr(outputFilePath.toString());
            while (istr)
            {
                Poco::StreamCopier::copyStream(istr, ostr);
            }
            ostr.close();

            if (Poco::Process::wait(handle) == 0)
            {
                // If Regripper runs without error, parse selected artifacts from the raw output and post them to the blackboard.
                if (type == SOFTWARE)
                {
                    getSoftwareInfo(*file, outputFilePath.toString());
                }
                else if (type == SYSTEM)
                {
                    getSystemInfo(*file, outputFilePath.toString());
                }
            }
            else
            {
                // If RegRipper fails on a particular file, log a warning and move on to the next file.
                std::stringstream msg;
                msg << funcName << " : RegRipper returned error code for " << (*file)->getName() << " (file id = " << (*file)->getId() << ")";
                LOGWARN(msg.str());            
            }
        }
    }

    void parseOption(const std::string &option, std::string &arg)
    {
        if (!arg.empty())
        {
            std::ostringstream msg;
            msg << "module command line has multiple " << option << " options";
            throw TskException(msg.str());                
        }

        arg = option.substr(3);
        if (arg.empty())
        {
            std::ostringstream msg;
            msg << "module command line missing argument for " << option << " option";
            throw TskException(msg.str());                
        }

        TskUtilities::stripQuotes(arg);
    }

    void parseModuleCommandLine(const char *arguments)
    {
        ripExePath.clear();
        outputFolderPath.clear();

        Poco::StringTokenizer tokenizer(std::string(arguments), ";");
        for (Poco::StringTokenizer::Iterator token = tokenizer.begin(); token != tokenizer.end(); ++token)
        {
            if ((*token).find("-e") == 0)
            {
                parseOption(*token, ripExePath); 
            }
            else if ((*token).find("-o") == 0)
            {
                parseOption(*token, outputFolderPath); 
            }
            else
            {
                std::ostringstream msg;
                msg << "module command line " << *token << " option not recognized";
                throw TskException(msg.str());                
            }
        }

        if (ripExePath.empty())
        {
            Poco::Path defaultPath = Poco::Path::forDirectory(GetSystemProperty(TskSystemProperties::PROG_DIR));
            defaultPath.pushDirectory("RegRipper");
            defaultPath.setFileName("rip.exe");
            ripExePath = defaultPath.toString();
        }
        else
        {
            // Check to see if we have been asked to run RegRipper through 
            // the perl interpreter. 
            std::string perl = "perl";

            if (ripExePath.substr(0, perl.size()) == perl)
            {
                /* We have been asked to run the perl interpreter format (e.g. "perl /foobar/rip.pl").
                   Assumptions:
                   - The last token is the script path
                   - Any other script arguments are space delimited
                   - There are no nested quotes
                */
                Poco::StringTokenizer tokenizer(ripExePath, " ");
                if (tokenizer.count() > 1)
                {
                    ripExePath = *tokenizer.begin();             // The interpreter exe path
                    std::string ripdotplPath = tokenizer[tokenizer.count()-1]; // RegRipper script path

                    // Our plugin path will be relative to where rip.pl lives
                    pluginPath = Poco::Path(ripdotplPath).parent().toString();

                    // Get interpreter arguments, if any
                    Poco::StringTokenizer::Iterator it = tokenizer.begin();
                    interpreterArgs = std::vector<std::string>(++it, tokenizer.end());
                }

            }
            else
            {
                // Not perl so the plugin path is relative to the RegRipper executable
                pluginPath = Poco::Path(ripExePath).parent().toString();
            }
        }

        if (outputFolderPath.empty())
        {
            std::string moduleOutDir = GetSystemProperty(TskSystemProperties::MODULE_OUT_DIR);
            if (moduleOutDir.empty())
            {
                throw TskException("output folder not specified in module command line and MODULE_OUT_DIR is system property not set");
            }

            Poco::Path defaultPath(Poco::Path::forDirectory(moduleOutDir));
            defaultPath.pushDirectory(MODULE_NAME);
            outputFolderPath = defaultPath.toString();
        }
    }
}

extern "C" 
{
    /**
     * Module identification function. 
     *
     * @return The name of the module.
     */
    TSK_MODULE_EXPORT const char *name()
    {
        return MODULE_NAME;
    }

    /**
     * Module identification function. 
     *
     * @return A description of the module.
     */
    TSK_MODULE_EXPORT const char *description()
    {
        return MODULE_DESCRIPTION;
    }

    /**
     * Module identification function. 
     *
     * @return The version of the module.
     */
    TSK_MODULE_EXPORT const char *version()
    {
        return MODULE_VERSION;
    }

    /**
     * Module initialization function. Receives a string of intialization arguments, 
     * typically read by the caller from a pipeline configuration file. 
     * Returns TskModule::OK or TskModule::FAIL. Returning TskModule::FAIL indicates 
     * the module is not in an operational state.  
     *
     * @param args An optional semicolon separated list of arguments:
     *      -e Path to the RegRipper executable
     *      -o Directory in which to place RegRipper output
     * @return TskModule::OK if initialization succeeded, otherwise TskModule::FAIL.
     */
    TskModule::Status TSK_MODULE_EXPORT initialize(const char* arguments)
    {
		const std::string funcName(MODULE_NAME + std::string("::initialize"));
        try
        {
            parseModuleCommandLine(arguments);

            // Log the configuration of the module.
            std::ostringstream msg;
            msg << funcName << " : using RegRipper executable '" << ripExePath << "'";
            LOGINFO(msg.str());

            msg.str("");
            msg.clear();
            msg << funcName << " : writing output to '" + outputFolderPath << "'";
            LOGINFO(msg.str());

            // Verify the RegRipper executable path.
            Poco::File ripExe(ripExePath);
            if (!ripExe.exists() || !ripExe.canExecute())
            {
                // Try to find it in a dir in the path environment variable
                std::string newpath = checkExeEnvPath(ripExePath);

                if (!newpath.empty())
                {
                    ripExePath = newpath;
                }
                else
                {
                    std::ostringstream msg;
                    msg << "'" << ripExePath << "' does not exist or is not executable";
                    throw TskException(msg.str());
                }
            }

            // Create the output folder.
            Poco::File(outputFolderPath).createDirectories();

            return TskModule::OK;
        }
        catch (TskException &ex)
        {
            std::ostringstream msg;
            msg << funcName << ": TskException : " << ex.message();
            LOGERROR(msg.str());
            return TskModule::FAIL;
        }
        catch (Poco::Exception &ex)
        {
            std::ostringstream msg;
            msg << funcName << ": Poco::Exception : " << ex.displayText();
            LOGERROR(msg.str());
            return TskModule::FAIL;
        }
        catch (std::exception &ex)
        {
            std::ostringstream msg;
            msg << funcName << ": std::exception : " << ex.what();
            LOGERROR(msg.str());
            return TskModule::FAIL;
        }
        catch (...)
        {
            LOGERROR(funcName + ": unrecognized exception");
            return TskModule::FAIL;
        }
    }

    /**
     * Module execution function. Returns TskModule::OK, TskModule::FAIL, or TskModule::STOP. 
     * Returning TskModule::FAIL indicates error performing its job. Returning TskModule::STOP
     * is a request to terminate execution of the reporting pipeline.
     *
     * @returns TskModule::OK on success, TskModule::FAIL on error, or TskModule::STOP.
     */
    TskModule::Status TSK_MODULE_EXPORT report()
    {
        std::string funcName(MODULE_NAME + std::string("report"));
        try
        {
            runRegRipper(NTUSER);
            runRegRipper(SYSTEM);
            runRegRipper(SAM);
            runRegRipper(SOFTWARE);

            return TskModule::OK;
        }
        catch (TskException &ex)
        {
            std::ostringstream msg;
            msg << funcName << ": TskException : " << ex.message();
            LOGERROR(msg.str());
            return TskModule::FAIL;
        }
        catch (Poco::Exception &ex)
        {
            std::ostringstream msg;
            msg << funcName << ": Poco::Exception : " << ex.displayText();
            LOGERROR(msg.str());
            return TskModule::FAIL;
        }
        catch (std::exception &ex)
        {
            std::ostringstream msg;
            msg << funcName << ": std::exception : " << ex.what();
            LOGERROR(msg.str());
            return TskModule::FAIL;
        }
        catch (...)
        {
            LOGERROR(funcName + ": unrecognized exception");
            return TskModule::FAIL;
        }
    }

    /**
     * Module cleanup function. Deletes output directory if it is empty.
     *
     * @returns TskModule::OK on success and TskModule::FAIL on error.
     */
    TskModule::Status TSK_MODULE_EXPORT finalize()
    {
        std::string funcName(MODULE_NAME + std::string("report"));
        try
        {
#if !defined(_DEBUG) 

            Poco::File folder(outputFolderPath);
            std::vector<std::string> files;
            folder.list(files);

            if (files.empty())
            {
                folder.remove(false);
            }

#endif

            return TskModule::OK;
        }
        catch (TskException &ex)
        {
            std::ostringstream msg;
            msg << funcName << ": TskException : " << ex.message();
            LOGERROR(msg.str());
            return TskModule::FAIL;
        }
        catch (Poco::Exception &ex)
        {
            std::ostringstream msg;
            msg << funcName << ": Poco::Exception : " << ex.displayText();
            LOGERROR(msg.str());
            return TskModule::FAIL;
        }
        catch (std::exception &ex)
        {
            std::ostringstream msg;
            msg << funcName << ": std::exception : " << ex.what();
            LOGERROR(msg.str());
            return TskModule::FAIL;
        }
        catch (...)
        {
            LOGERROR(funcName + ": unrecognized exception");
            return TskModule::FAIL;
        }
    }
 }
