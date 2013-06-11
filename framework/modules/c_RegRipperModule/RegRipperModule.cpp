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
 * \file RegRipperModule.cpp
 * Contains the implementation for the reg ripper reporting module.
 * This module runs the RegRipper executable against the common set of
 * Windows registry files (i.e., NTUSER, SYSTEM, SAM and SOFTWARE).
 */

// System includes
#include <string>
#include <sstream>
#include <memory>

// Framework includes
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

namespace
{
    const char *MODULE_NAME = "tskRegRipperModule";
    const char *MODULE_DESCRIPTION = "Runs the RegRipper executable against the common set of Windows registry files (i.e., NTUSER, SYSTEM, SAM and SOFTWARE)";
    const char *MODULE_VERSION = "1.0.2";

    static Poco::Path outPath;
    static std::string ripExePath;
    static std::string pluginPath;
    static std::vector<std::string> interpArgs;
    enum RegType
    {
        NTUSER,
        SYSTEM,
        SAM,
        SOFTWARE,
        ALL
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
    static std::vector<std::string> getRegRipperValues(const std::string& regRipperFileName, const std::string& valueName)
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
    static void getSoftwareInfo(TskFile * pFile, const std::string& fileName)
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
    static void getSystemInfo(TskFile * pFile, const std::string& fileName)
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
    
    static TskModule::Status runRegRipper(RegType type)
    {
        std::string funcName(MODULE_NAME + std::string("::runRegRipper"));
        std::string condition("WHERE files.dir_type = 5 AND UPPER(files.name) = '");
        std::string fileName;
        Poco::Path pluginFile;

        switch (type)
        {
        case NTUSER:
            fileName = "NTUSER.DAT";

            // Search for the "ntuser-all" or "ntuser" plugin wrappers
            if (!Poco::Path::find(pluginPath, "ntuser-all", pluginFile) &&
                !Poco::Path::find(pluginPath, "ntuser", pluginFile))
            {
                LOGERROR(funcName + "Failed to find either ntuser-all or ntuser");
                return TskModule::FAIL;
            }

            break;
        case SYSTEM:
            fileName = "SYSTEM";

            // Search for the "system-all" or "system" plugin wrappers
            if (!Poco::Path::find(pluginPath, "system-all", pluginFile) &&
                !Poco::Path::find(pluginPath, "system", pluginFile))
            {
                LOGERROR(funcName + "Failed to find either system-all or system");
                return TskModule::FAIL;
            }

            break;
        case SOFTWARE:
            fileName = "SOFTWARE";

            // Search for the "software-all" or "software" plugin wrappers
            if (!Poco::Path::find(pluginPath, "software-all", pluginFile) &&
                !Poco::Path::find(pluginPath, "software", pluginFile))
            {
                LOGERROR(funcName + "Failed to find either software-all or software");
                return TskModule::FAIL;
            }

            break;
        case SAM:
            fileName = "SAM";

            // Search for the "sam-all" or "sam" plugin wrappers
            if (!Poco::Path::find(pluginPath, "sam-all", pluginFile) &&
                !Poco::Path::find(pluginPath, "sam", pluginFile))
            {
                LOGERROR(funcName + "Failed to find either sam-all or sam");
                return TskModule::FAIL;
            }

            break;
        default:
            std::stringstream msg;
            msg << funcName << " - Unknown type: " << type;
            LOGERROR(msg.str());
            return TskModule::FAIL;
        }

        condition.append(fileName);
        condition.append("'");

        try 
        {
            // Get the file ids matching our condition
            TskImgDB& imgDB = TskServices::Instance().getImgDB();
            std::vector<uint64_t> fileIds = imgDB.getFileIds(condition);

            TskFileManager& fileManager = TskServices::Instance().getFileManager();

            // Iterate over the files running RegRipper on each one.
            for (std::vector<uint64_t>::iterator it = fileIds.begin(); it != fileIds.end(); it++)
            {
                // Create a file object for the id
                std::auto_ptr<TskFile> pFile(fileManager.getFile(*it));

                // Skip empty files
                if (pFile->getSize() == 0)
                    continue;

                // Save the file content so that we can run RegRipper against it
                fileManager.saveFile(pFile.get());

                Poco::Process::Args cmdArgs;

                // Insert interpreter arguments, if any
                for (std::vector<std::string>::iterator it = interpArgs.begin(); it != interpArgs.end(); ++it) {
                    cmdArgs.push_back(*it);
                }

                cmdArgs.push_back("-f");
                cmdArgs.push_back(pluginFile.getFileName());

                cmdArgs.push_back("-r");
                cmdArgs.push_back(pFile->getPath());

                // Create the output file if it does not exist.
                Poco::Path outFilePath = outPath;
                std::stringstream fileName;
                fileName << pFile->getName() << "_" << pFile->getHash(TskImgDB::MD5) << "_" << pFile->getId() << ".txt";
                outFilePath.setFileName(fileName.str());

                Poco::File outFile(outFilePath);

                if (!outFile.exists())
                {
                    outFile.createFile();
                }

                std::stringstream msg;
                msg << funcName << " - Analyzing hive " << pFile->getPath() << " to " << outFile.path();
                LOGINFO(msg.str());

                Poco::Pipe outPipe;

                // Launch RegRipper
                Poco::ProcessHandle handle = Poco::Process::launch(ripExePath, cmdArgs, NULL, &outPipe, &outPipe);

                // Copy output from Pipe to the output file.
                Poco::PipeInputStream istr(outPipe);
                Poco::FileOutputStream ostr(outFile.path());

                while (istr)
                {
                    Poco::StreamCopier::copyStream(istr, ostr);
                }

                ostr.close();

                // The process should be finished. Check its exit code.
                int exitCode = Poco::Process::wait(handle);

                // If RegRipper fails on a particular file, we log a warning and continue.
                if (exitCode != 0)
                {
                    std::stringstream msg;
                    msg << funcName << " - RegRipper failed on file: " << pFile->getName();
                    LOGWARN(msg.str());            
                }
                else
                {
                    if (type == SOFTWARE)
                    {
                        getSoftwareInfo(pFile.get(), outFilePath.toString());
                    }
                    else if (type == SYSTEM)
                    {
                        getSystemInfo(pFile.get(), outFilePath.toString());
                    }
                }
            }
        }
        catch (std::exception& ex)
        {
            std::stringstream msg;
            msg << funcName << " - Error: " << ex.what();
            LOGERROR(msg.str());
            return TskModule::FAIL;
        }

        return TskModule::OK;
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
        std::string funcName(MODULE_NAME + std::string("::initialize"));
        std::string args(arguments);
        std::string outPathArg;

        // Split the incoming arguments
        Poco::StringTokenizer tokenizer(args, ";");

        std::vector<std::string> vectorArgs(tokenizer.begin(), tokenizer.end());
        std::vector<std::string>::const_iterator it;

        for (it = vectorArgs.begin(); it < vectorArgs.end(); it++)
        {
            if ((*it).find("-e") == 0)
            {
                ripExePath = (*it).substr(3);
                if (ripExePath.empty())
                {
                    LOGERROR(funcName + " - missing argument to -e option.");
                    return TskModule::FAIL;
                }
                
            }
            else if ((*it).find("-o") == 0)
            {
                outPathArg = (*it).substr(3);
                if (outPathArg.empty())
                {
                    LOGERROR(funcName + " - missing argument to -o option.");
                    return TskModule::FAIL;
                }
            }
        }
        
        if (ripExePath.empty())
        {
            ripExePath = GetSystemProperty(TskSystemProperties::PROG_DIR);
            ripExePath.append(".\\RegRipper\\rip.exe");
        }

        std::string regRipPath;

        // Strip off quotes if they were passed in via XML
        std::string strippedRipExePath = TskUtilities::stripQuotes(ripExePath);
        if (strippedRipExePath != ripExePath)
        {
            ripExePath = strippedRipExePath;
        }
        else
        {
            /* If ripExePath itself is not in quotation marks, it might be in 
               interpreter format (e.g. "perl /foobar/rip.pl").
               Assumptions:
                - The last token is the script path
                - Any other script arguments are space delimited
                - There are no nested quotes
            */
            Poco::StringTokenizer tokenizer(ripExePath, " ");
            if (tokenizer.count() > 1)
            {
                ripExePath = *tokenizer.begin();             // The interpreter exe path
                regRipPath = tokenizer[tokenizer.count()-1]; // RegRipper script path

                // Get interpreter arguments, if any
                Poco::StringTokenizer::Iterator it = tokenizer.begin();
                interpArgs = std::vector<std::string>(++it, tokenizer.end());
            }
        }

        std::stringstream msg;
        msg << funcName << " - Using exec: " << ripExePath.c_str();
        LOGINFO(msg.str());

        if (outPathArg.empty())
        {
            outPathArg = GetSystemProperty(TskSystemProperties::MODULE_OUT_DIR);

            if (outPathArg.empty())
            {
                LOGERROR(funcName + " - Empty output path.");
                return TskModule::FAIL;
            }
        }

        try
        {
            // Confirm that the RegRipper executable exists in the given path
            Poco::File exeFile(ripExePath);
            if (!(exeFile.exists() && exeFile.canExecute()))
            {
                // Try to find it in a dir in the path environment variable
                std::string newpath = checkExeEnvPath(ripExePath);

                if (!newpath.empty())
                {
                    ripExePath = newpath;
                }
                else
                {
                    std::stringstream msg;
                    msg << funcName << " - " << ripExePath.c_str()
                        << " does not exist or is not executable.";
                    LOGERROR(msg.str());
                    return TskModule::FAIL;
                }
            }
        }
        catch(std::exception& ex)
        {
            std::stringstream msg;
            msg << funcName << " - RegRipper executable location - Unexpected error: "
                << ex.what();
            LOGERROR(msg.str());
            return TskModule::FAIL;
        }

        // Set the RegRipper plugins path
        if (regRipPath.empty())
        {
            regRipPath = ripExePath;
        }
        pluginPath = Poco::Path(regRipPath).parent().toString();
        pluginPath.append("plugins");

        // Create an output folder to store results
        outPath = Poco::Path::forDirectory(outPathArg);
        outPath.pushDirectory("RegRipper");
        outPath.pushDirectory("RegRipperOutput");

        LOGINFO(funcName + " - Using output: " + outPath.toString());

        try
        {
            Poco::File outDir(outPath);
            outDir.createDirectories();
        }
        catch(std::exception& ex)
        {
            std::stringstream msg;
            msg << funcName << " - output location - Unexpected error: " << ex.what();
            LOGERROR(msg.str());
            return TskModule::FAIL;
        }
        
        return TskModule::OK;
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
            if (runRegRipper(NTUSER) != TskModule::OK)
                return TskModule::FAIL;
            if (runRegRipper(SYSTEM) != TskModule::OK)
                return TskModule::FAIL;
            if (runRegRipper(SAM) != TskModule::OK)
                return TskModule::FAIL;
            if (runRegRipper(SOFTWARE) != TskModule::OK)
                return TskModule::FAIL;
        }
        catch (TskException& tskEx)
        {
            std::stringstream msg;
            msg << funcName << " - Caught framework exception: " << tskEx.what();
            LOGERROR(msg.str());
            return TskModule::FAIL;
        }
        catch (std::exception& ex)
        {
            std::stringstream msg;
            msg << funcName << " - Caught exception: " << ex.what();
            LOGERROR(msg.str());
            return TskModule::FAIL;
        }

        return TskModule::OK;
    }

    /**
     * Module cleanup function. Deletes output directory if it is empty.
     *
     * @returns TskModule::OK on success and TskModule::FAIL on error.
     */
    TskModule::Status TSK_MODULE_EXPORT finalize()
    {
        // Delete output directory if it contains no files.
        std::vector<std::string> fileList;
        Poco::File outDir(outPath);
        outDir.list(fileList);

        if (fileList.empty())
        {
            Poco::File(outPath.parent()).remove(true);
        }

        return TskModule::OK;
    }
}
