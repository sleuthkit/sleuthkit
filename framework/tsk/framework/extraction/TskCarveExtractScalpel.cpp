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
 * \file TskCarveExtractScalpel.cpp
 * Contains the implementation of the TskCarveExtractScalpel class.
 */

// Include the class definition first to ensure it does not depend on subsequent includes in this file.
#include "TskCarveExtractScalpel.h"

// TSK Framework includes
#include "tsk/framework/services/TskServices.h"
#include "tsk/framework/services/TskImgDB.h"
#include "tsk/framework/utilities/TskUtilities.h"
#include "tsk/framework/utilities/UnallocRun.h"
#include "tsk/framework/utilities/TskException.h"

// Poco includes
#include "Poco/Path.h"
#include "Poco/File.h"
#include "Poco/Process.h"
#include "Poco/Pipe.h"
#include "Poco/PipeStream.h"
#include "Poco/FileStream.h"
#include "Poco/StreamCopier.h"
#include "Poco/StringTokenizer.h"
#include "Poco/Exception.h"

// C/C++ library includes
#include <sstream>
#include <fstream>
#include <cstdlib>
#include <vector>
#include <algorithm>
#include <memory>

namespace
{
#ifdef TSK_WIN32
    const std::string SCALPEL_EXE_FILE_NAME = "scalpel.exe";
#else
    const std::string SCALPEL_EXE_FILE_NAME = "scalpel";
#endif
    const std::string CARVED_FILES_FOLDER = "CarvedFiles";
    const std::string SCALPEL_RESULTS_FILE_NAME = "audit.txt";
    const std::string STD_OUT_DUMP_FILE_NAME = "stdout.txt";
    const std::string STD_ERR_DUMP_FILE_NAME = "stderr.txt";
}

int TskCarveExtractScalpel::processFile(int unallocImgId)
{
    TskImgDB *imgDB = NULL; 
    try
    {
        imgDB = &TskServices::Instance().getImgDB();

        // Get the input folder path. The file to carve resides in a subdirectory of the carve prep output folder. The name of the subdirectory is the unallocated image file id.
        std::string carvePrepOutputPath = GetSystemProperty("CARVE_DIR");
        if (!Poco::File(carvePrepOutputPath).exists())
        {
            std::stringstream msg;
            msg << "TskCarveExtractScalpel::processFile : specified carve prep output folder '" << carvePrepOutputPath << "' does not exist";
            throw TskException(msg.str());
        }
        std::stringstream inputFolderPathBuilder; 
        inputFolderPathBuilder << carvePrepOutputPath << Poco::Path::separator() << unallocImgId;
    
        // Get the input file name and construct the input file path. All of the files to carve have the same name.
        std::string carvePrepOutputFileName = GetSystemProperty("UNALLOC_SECTORS_IMG_FILE_NAME");
        std::stringstream unallocImgFilePathBuilder;
        unallocImgFilePathBuilder << inputFolderPathBuilder.str() <<  Poco::Path::separator() << carvePrepOutputFileName;
        Poco::File unallocImgFile(unallocImgFilePathBuilder.str());

        if (!unallocImgFile.exists())
        {
            std::stringstream msg;
            msg << "TskCarveExtractScalpel::processFile : did not find unalloc img file number " << unallocImgId << " at '" << unallocImgFilePathBuilder.str() << "'";
            throw TskException(msg.str());
        }

        if (unallocImgFile.getSize() > static_cast<Poco::File::FileSize>(0))
        {
            // Attempt to carve the file, storing the carved files in a subdirectory of the input folder and the Scalpel console output in the input folder.
            // The console output is placed in the input folder rather than the output folder because Scalpel will only write to an empty directory.
            std::stringstream outputFolderPath;
            outputFolderPath << inputFolderPathBuilder.str() << Poco::Path::separator() << CARVED_FILES_FOLDER;
            std::stringstream stdOutFilePath;
            stdOutFilePath << inputFolderPathBuilder.str() << Poco::Path::separator() << STD_OUT_DUMP_FILE_NAME;
            std::stringstream stdErrFilePath;
            stdErrFilePath << inputFolderPathBuilder.str() << Poco::Path::separator() << STD_ERR_DUMP_FILE_NAME;
            carveFile(unallocImgFilePathBuilder.str(), outputFolderPath.str(), stdOutFilePath.str(), stdErrFilePath.str());

            // Scalpel lists any files it carves out in a results file. Use the file list to add the files to the image DB and copy them to file storage.
            std::stringstream resultsFilePath;
            resultsFilePath << outputFolderPath.str() << Poco::Path::separator() << SCALPEL_RESULTS_FILE_NAME;
            processCarvedFiles(outputFolderPath.str(), parseCarvingResultsFile(unallocImgId, resultsFilePath.str()));

            // Update the unused sector info in the image database so it is known which of the unallocated sectors just carved did not go into a carved file.
            if (m_createUnusedSectorFiles)
            {
                std::vector<TskUnusedSectorsRecord> unusedSectorsList;
                imgDB->addUnusedSectors(unallocImgId, unusedSectorsList);
            }
        }
        else
        {
            // There is nothing to do if the file to be carved is of length zero.
            imgDB->setUnallocImgStatus(unallocImgId, TskImgDB::IMGDB_UNALLOC_IMG_STATUS_CARVED_NOT_NEEDED);
        }

        return 0;
    }
    catch (TskException &ex)
    {
        LOGERROR(TskUtilities::toUTF16(ex.message()));

        if (imgDB)
        {
            imgDB->setUnallocImgStatus(unallocImgId, TskImgDB::IMGDB_UNALLOC_IMG_STATUS_CARVED_ERR);
        }

        return 1;
    }
}

void TskCarveExtractScalpel::carveFile(const std::string &unallocImgPath, const std::string &outputFolderPath, const std::string &stdOutFilePath, const std::string &stdErrFilePath) const
{
    try
    {
        // Find out where Scalpel is installed.
        std::string scalpelDirPath = GetSystemProperty("SCALPEL_DIR");
        if (scalpelDirPath.empty())
        {
            throw TskException("TskCarveExtractScalpel::configure : Scalpel directory not set");
        }

        if (!Poco::File(scalpelDirPath).exists())
        {
            std::stringstream msg;
            msg << "TskCarveExtractScalpel::configure : specified Scalpel directory '" << scalpelDirPath << "' does not exist";
            throw TskException(msg.str());
        }

        // Get the path to the Scalpel executable.
        std::stringstream pathBuilder;
        pathBuilder << scalpelDirPath << Poco::Path::separator() << SCALPEL_EXE_FILE_NAME;
        std::string scalpelExePath = pathBuilder.str();
        if (!Poco::File(scalpelExePath).exists())
        {
            std::stringstream msg;
            msg << "TskCarveExtractScalpel::configure : Scalpel executable '" << scalpelExePath << "' does not exist";
            throw TskException(msg.str());
        }

        // Get the path to the Scalpel config file.
        std::string scalpelConfigFilePath = GetSystemProperty("SCALPEL_CONFIG_FILE");
        if (!Poco::File(scalpelConfigFilePath).exists())
        {
            std::stringstream msg;
            msg << "TskCarveExtractScalpel::TskCarveExtractScalpel : Scalpel config file '" << scalpelConfigFilePath << "' does not exist";
            throw TskException(msg.str());
        }

        // Set the Scalpel command line: specify the Scalpel config file.
        Poco::Process::Args args;
        args.push_back("-c");
        args.push_back(scalpelConfigFilePath);

        // Set the Scalpel command line: allow for nested headers and footers.
        args.push_back("-e");
        
        // Set the Scalpel command line: put any carved files directly into the output folder.
        args.push_back("-o");
        args.push_back(outputFolderPath);
        args.push_back("-O");

        // Set the Scalpel command line: specify the file to carve.
        args.push_back(unallocImgPath);

        // Launch Scalpel with console output redirects.
        Poco::Pipe outPipe;
        Poco::Pipe errPipe;
        Poco::ProcessHandle handle = Poco::Process::launch(scalpelExePath, args, NULL, &outPipe, &errPipe);

        // Capture the console output. Note that Scalpel may block at times as it waits for this loop to empty the stream buffers.
        Poco::PipeInputStream stdOutInputStream(outPipe);
        Poco::FileOutputStream stdOutOutputStream(stdOutFilePath);
        Poco::PipeInputStream stdErrInputStream(errPipe);
        Poco::FileOutputStream stdErrOutputStream(stdErrFilePath);
        while (stdOutInputStream || stdErrInputStream)
        {
            if (stdOutInputStream)
            {
                Poco::StreamCopier::copyStream(stdOutInputStream, stdOutOutputStream);
            }

            if (stdErrInputStream)
            {
                Poco::StreamCopier::copyStream(stdErrInputStream, stdErrOutputStream);
            }
        }
    
        // Scalpel should be finished since the console output streams are closed.
        int exitCode = Poco::Process::wait(handle);

        stdOutOutputStream.flush();
        stdErrOutputStream.flush();

        // On the first invocation of Scalpel, record its use in the image database.
        static bool toolInfoRecorded = false;
        if (!toolInfoRecorded)
        {
            std::ifstream stdOutStream(stdOutFilePath.c_str());
            if (stdOutStream)
            {
                std::string versionString;
                std::getline(stdOutStream, versionString);
                Poco::StringTokenizer tokenizer(versionString, "\t ", Poco::StringTokenizer::TOK_IGNORE_EMPTY | Poco::StringTokenizer::TOK_TRIM); 
                if (tokenizer[0] == "Scalpel" && tokenizer[1] == "version")
                {
                    TskServices::Instance().getImgDB().addToolInfo("Scalpel", tokenizer[2].c_str());
                    toolInfoRecorded = true;
                }
                else
                {
                    LOGWARN("TskCarveExtractScalpel::carveFile : Scalpel stdout output format changed, cannot record tool info");
                }
            }
            else
            {
                LOGWARN("TskCarveExtractScalpel::carveFile : failed to open stdout stream, cannot record tool info");
            }
        }

        // Delete input files by default.
        std::string option = GetSystemProperty("CARVE_EXTRACT_KEEP_INPUT_FILES");
        std::transform(option.begin(), option.end(), option.begin(), ::toupper);
        bool deleteInputFiles = (option != "TRUE");

        if (deleteInputFiles)
        {
            Poco::File file(unallocImgPath);
            file.remove();
        }

        if (exitCode != 0)
        {
            std::stringstream msg;
            msg << "TskCarveExtractScalpel::carveFile : Scalpel exited with error exit code " << exitCode << " when carving '" << unallocImgPath.c_str() << "'";
            throw TskException(msg.str());
        }
    }
    catch (Poco::Exception &ex)
    {
        std::stringstream msg;
        msg << "TskCarveExtractScalpel::carveFile : Poco exception: " << ex.displayText();
        throw TskException(msg.str());
    }
}

std::vector<TskCarveExtractScalpel::CarvedFile> TskCarveExtractScalpel::parseCarvingResultsFile(int unallocImgId, const std::string &resultsFilePath) const
{
    try
    {
        std::vector<CarvedFile> carvedFiles;

        Poco::File resultsFile(resultsFilePath);
        if (!resultsFile.exists())
        {
            std::stringstream msg;
            msg << "TskCarveExtractScalpel::parseCarvingResultsFile : could not find Scalpel carving results file for unalloc img id " << unallocImgId;
            throw TskException(msg.str());
        }
        
        std::ifstream resultsStream(resultsFilePath.c_str());
        if (!resultsStream)
        {
            std::stringstream msg;
            msg << "TskCarveExtractScalpel::parseCarvingResultsFile : unable to open Scalpel carving results file for unalloc img id " << unallocImgId;
            throw TskException(msg.str());
        }

        // Discard all of the file up to and including the header for the carved files list.
        std::string line;
        while (std::getline(resultsStream, line) && line.find("Extracted From") == std::string::npos);

        // Parse the files list.
        const std::size_t numberOfFileFields = 5;
        while (std::getline(resultsStream, line))
        {
            // Tokenize the next line of the results file and see if it is part of the files list by checking the number of tokens.
            Poco::StringTokenizer tokenizer(line, "\t ", Poco::StringTokenizer::TOK_IGNORE_EMPTY | Poco::StringTokenizer::TOK_TRIM); 
            if (tokenizer.count() != numberOfFileFields)
            {
                // No more files in the files list.
                break;
            }

            carvedFiles.push_back(CarvedFile(unallocImgId, tokenizer[0], tokenizer[1], tokenizer[3]));
        }

        resultsStream.close();

        return carvedFiles;
    }
    catch (Poco::Exception &ex)
    {
        std::stringstream msg;
        msg << "TskCarveExtractScalpel::parseCarvingResultsFile : Poco exception: " <<  ex.displayText();
        throw TskException(msg.str());
    }
}

void TskCarveExtractScalpel::processCarvedFiles(const std::string &outputFolderPath, const std::vector<TskCarveExtractScalpel::CarvedFile> &carvedFiles) const
{
    try
    {
        TskImgDB& imgDB = TskServices::Instance().getImgDB();
        const uint64_t sectorSize = 512;

        for (std::vector<CarvedFile>::const_iterator file = carvedFiles.begin(); file != carvedFiles.end(); ++file)
        {
            std::stringstream filePath;
            filePath << outputFolderPath << Poco::Path::separator() << (*file).name;

            // Convert the starting offset (in bytes) of the carved file in the unallocated image file the and length of the carved file (in bytes)
            // into a range of "sectors."
            int fileStartSectorOffset = static_cast<int>((*file).offset / sectorSize); 
            int fileEndSectorOffset = static_cast<int>(((*file).offset + (*file).length) / sectorSize); 
            
            // Get the unallocated sectors run corresponding to the unallocated image file and map the file sector offsets to image sector offset and length. 
            std::auto_ptr<UnallocRun> run(imgDB.getUnallocRun((*file).id, fileStartSectorOffset));
            int numberOfRuns = 1;
            uint64_t sectorRunStart[] = { run->getAllocStart() + fileStartSectorOffset - run->getUnallocStart() };
            uint64_t sectorRunLength[] = { run->getAllocStart() + fileEndSectorOffset - run->getUnallocStart() - sectorRunStart[0] };

            // Add the mapping to the image database.
            uint64_t fileId;
            if (imgDB.addCarvedFileInfo(run->getVolId(), (*file).name.c_str(), (*file).length, &sectorRunStart[0], &sectorRunLength[0], numberOfRuns, fileId) == -1)
            {
                std::stringstream msg;
                msg << "TskCarveExtractScalpel::processCarvedFiles : unable to save carved file info for '" << filePath.str() << "'";
                throw TskException(msg.str());
            }

            std::wstring f(TskUtilities::toUTF16(filePath.str()));
            TskServices::Instance().getFileManager().addFile(fileId, f);

            // Delete output (carved) files by default.
            std::string option = GetSystemProperty("CARVE_EXTRACT_KEEP_OUTPUT_FILES");
            std::transform(option.begin(), option.end(), option.begin(), ::toupper);
            bool deleteOutputFiles = (option != "TRUE");

            if (deleteOutputFiles)
            {
                Poco::File file(filePath.str());
                file.remove();
            }

            if (imgDB.updateFileStatus(fileId, TskImgDB::IMGDB_FILES_STATUS_READY_FOR_ANALYSIS) == 1)
            {
                std::stringstream msg;
                msg << "TskCarveExtractScalpel::processCarvedFiles : unable to update file status for '" << filePath.str() << "'";
                throw TskException(msg.str());
            }
        }
    }
    catch (Poco::Exception &ex)
    {
        std::stringstream msg;
        msg << "TskCarveExtractScalpel::processCarvedFiles : Poco exception: " <<  ex.displayText();
        throw TskException(msg.str());
    }
}

// @@@ TODO: Replace strtoul() call with a strtoull() call when a newer version of C++ is available.
TskCarveExtractScalpel::CarvedFile::CarvedFile(int unallocImgId, const std::string &fileName, const std::string &offsetInBytes, const std::string &lengthInBytes) : 
    id(unallocImgId), name(fileName), offset(strtoul(offsetInBytes.c_str(), 0, 10)), length(strtoul(lengthInBytes.c_str(), 0, 10))
{
}
