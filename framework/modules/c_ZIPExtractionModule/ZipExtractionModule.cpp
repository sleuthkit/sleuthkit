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
 * \file ZipExtractionModule.cpp
 * Contains the implementation for the Zip extraction file analysis module.
 * This module extracts zip file content and creates entries in the database 
 * for the extracted files. 
 */

// System includes
#include <sstream>
#include <iostream>
#include <fstream>

// Poco includes
#include "Poco/Path.h"
#include "Poco/Zip/ZipStream.h"
#include "Poco/Zip/Decompress.h"

// Framework includes
#include "tsk/framework/utilities/TskModuleDev.h"

namespace
{
    const char *MODULE_NAME = "tskZipExtractionModule";
    const char *MODULE_DESCRIPTION = "Extracts the files stored inside of ZIP files";
    const char *MODULE_VERSION = "1.0.0";
}

namespace
{
    std::set<uint64_t> fileIdsToSchedule;

    /**
     * Schedule files for analysis. Iterates over the fileIdsToSchedule
     * set calling Scheduler::schedule() for each consecutive range of
     * file ids.
     */
    void scheduleFiles()
    {
        if (fileIdsToSchedule.empty())
            return;

        Scheduler& scheduler = TskServices::Instance().getScheduler();

        std::set<uint64_t>::const_iterator it = fileIdsToSchedule.begin();
        uint64_t startId = *it, endId = *it;

        while (++it != fileIdsToSchedule.end())
        {
            if (*it > endId + 1)
            {
                scheduler.schedule(Scheduler::FileAnalysis, startId, endId);
                startId = endId = *it;
            }
            else
            {
                endId++;
            }
        }

        scheduler.schedule(Scheduler::FileAnalysis, startId, endId);
        fileIdsToSchedule.clear();
    }
}

/**
 * Get the file id corresponding to the last directory on the given path.
 * If elements along the path have not been seen before, create new entries
 * for those elements both in the database and in the directory map (3rd parameter). 
 * Note that the parent id for top level directories will be the file id of the zip file.
 */
static uint64_t getParentIdForPath(Poco::Path& path, const uint64_t fileId, std::string parentPath, std::map<std::string, uint64_t>& directoryMap)
{
    // If the path references a file, make it refer to to its parent instead
    if (path.isFile())
        path = path.makeParent();

    // Initialize parent id to be the file id of the zip file.
    uint64_t parentId = fileId;

    // Iterate over every element of the path checking to see if we 
    // already have an entry in the database and in the directory map.
    Poco::Path tempPath;
    TskImgDB& imgDB = TskServices::Instance().getImgDB();
    std::map<std::string, uint64_t>::const_iterator pos;
    for (int i = 0; i < path.depth(); i++)
    {
        // Build up a temporary path that only contains the path
        // elements seen so far. This temporary path will be used
        // below to add the full path to the map.
        tempPath.pushDirectory(path[i]);

        // Have we already seen this path?
        pos = directoryMap.find(tempPath.toString());

        if (pos == directoryMap.end())
        {
			std::string fullpath = "";
            fullpath.append(parentPath);
            fullpath.append("\\");
            fullpath.append(path.toString());

            // No entry exists for this directory so we create one.
            if (imgDB.addDerivedFileInfo(path[i], parentId,
                                         true, // isDirectory
                                         0, // uncompressed size
                                         "", // no details
                                         0, // ctime
                                         0, // crtime
                                         0, // atime
                                         0, // mtime
                                         parentId,
                                         fullpath) == -1)
            {
                throw TskException("ZipExtraction::getParentIdForPath : Failed to add derived file for " + path[i]);
            }

            // Add the full path (to this point) and new id to the map.
            directoryMap[tempPath.toString()] = parentId;

            // Update file status to indicate that it is ready for analysis.
            imgDB.updateFileStatus(parentId, TskImgDB::IMGDB_FILES_STATUS_READY_FOR_ANALYSIS);
            fileIdsToSchedule.insert(parentId);
        }
        else
        {
            parentId = pos->second;
        }
    }

    return parentId;
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
     * @param args Initialization arguments.
     * @return TskModule::OK if initialization succeeded, otherwise TskModule::FAIL.
     */
    TskModule::Status TSK_MODULE_EXPORT initialize(const char* args)
    {
        return TskModule::OK;
    }
    
    /**
     * Module execution function. Receives a pointer to a file the module is to
     * process. The file is represented by a TskFile interface from which both
     * file content and file metadata can be retrieved. Returns TskModule::OK, 
     * TskModule::FAIL, or TskModule::STOP. Returning TskModule::FAIL indicates 
     * the module experienced an error processing the file. Returning TskModule::STOP
     * is a request to terminate processing of the file.
     *
     * @param pFile A pointer to a file to be processed.
     * @returns TskModule::OK on success, TskModule::FAIL on error, or TskModule::STOP.
     */
    TskModule::Status TSK_MODULE_EXPORT run(TskFile * pFile)
    {
        if (pFile == NULL)
        {
            LOGERROR(L"Zip extraction module passed NULL file pointer.");
            return TskModule::FAIL;
        }

        try
        {
            TskImgDB& imgDB = TskServices::Instance().getImgDB();

			// Create a map of directory names to file ids to use to 
			// associate files/directories with the correct parent.
			std::map<std::string, uint64_t> directoryMap;
            uint64_t parentId = 0;

            // Save the file to disk and attempt to open it as an archive file.
            pFile->save();
            std::ifstream input(pFile->getPath().c_str(), std::ios_base::binary);
            Poco::Zip::ZipArchive archive(input);
            Poco::Zip::ZipArchive::FileHeaders::const_iterator fh;

            // Attempt to extract the files contained in the archive file.
            for (fh = archive.headerBegin(); fh != archive.headerEnd(); ++fh)
            {
                Poco::Path path(fh->first);
                Poco::Path parent = path.parent();
                std::string name;

                if (path.isDirectory())
                    name = path[path.depth() - 1];
                else
                    name = path[path.depth()];

                // Determine the parent id of the file.
                if (path.depth() == 0 || (path.isDirectory() && path.depth() == 1))
                    // This file or directory lives at the root so our parent id
                    // is the containing file id.
                    parentId = pFile->getId();
                else
                {
                    // We are not at the root so we need to lookup the id of our
                    // parent directory.
                    std::map<std::string, uint64_t>::const_iterator pos;
                    pos = directoryMap.find(parent.toString());

                    if (pos == directoryMap.end())
                    {
                        // In certain circumstances (Windows Send to zip and .docx files)
                        // there may not be entries in the zip file for directories.
                        // For these cases we create database entries for the directories
                        // so that we can accurately track parent relationships. The
                        // getParentIdForPath() method creates the database entries for the
                        // given path and returns the parentId of the last directory on the path.
                        parentId = getParentIdForPath(parent, pFile->getId(), pFile->getFullPath(), directoryMap);
                    }
                    else
                    {
                        parentId = pos->second;
                    }
                }

                // Store some extra details about the derived (i.e, extracted) file.
                std::stringstream details;
                details << "<ZIPFILE name=\"" << fh->second.getFileName()
                    << "\" compressed_size=\"" << fh->second.getCompressedSize()
                    << "\" uncompressed_size=\"" << fh->second.getUncompressedSize()
                    << "\" crc=\"" << fh->second.getCRC()
                    << "\" start_pos=\"" << fh->second.getStartPos()
                    << "\" end_pos=\"" << fh->second.getEndPos()
                    << "\" major_version=\"" << fh->second.getMajorVersionNumber()
                    << "\" minor_version=\"" << fh->second.getMinorVersionNumber() << "\""
                    << "</ZIPFILE>";

                uint64_t fileId;

                std::string fullpath = "";
                fullpath.append(pFile->getFullPath());
                fullpath.append("\\");
                fullpath.append(path.toString());

                if (imgDB.addDerivedFileInfo(name,
                    parentId,
                    path.isDirectory(),
                    fh->second.getUncompressedSize(),
                    details.str(), 
                    0, // ctime
                    0, // crtime
                    0, // atime
                    static_cast<int>(fh->second.lastModifiedAt().utcTime()),
                    fileId, fullpath) == -1) 
                {
                        std::wstringstream msg;
                        msg << L"ZipExtractionModule - addDerivedFileInfo failed for name="
                            << name.c_str();
                        LOGERROR(msg.str());

                        return TskModule::FAIL;
                }

                TskImgDB::FILE_STATUS fileStatus = TskImgDB::IMGDB_FILES_STATUS_READY_FOR_ANALYSIS;

                if (path.isDirectory())
                {
                    directoryMap[path.toString()] = fileId;
                }
                else
                {
                    // Only DEFLATE and STORE compression methods are supported. The STORE method
                    // simply stores a file without compression.
                    if (fh->second.getCompressionMethod() == Poco::Zip::ZipCommon::CM_DEFLATE ||
                        fh->second.getCompressionMethod() == Poco::Zip::ZipCommon::CM_STORE)
                    {
                        // Save the file for subsequent processing.
                        Poco::Zip::ZipInputStream zipin(input, fh->second);
                        TskServices::Instance().getFileManager().addFile(fileId, zipin);
                    }
                    else
                    {
                        std::wstringstream msg;
                        msg << L"ZipExtractionModule - Unsupported compression method for file: "
                            << name.c_str();
                        LOGWARN(msg.str());
                        
                        fileStatus = TskImgDB::IMGDB_FILES_STATUS_ANALYSIS_FAILED;
                    }
                }

                // Update file status to indicate that it is ready for analysis.
                imgDB.updateFileStatus(fileId, fileStatus);
                fileIdsToSchedule.insert(fileId);
            }

            // Schedule files for analysis
            scheduleFiles();
        }
        catch (Poco::IllegalStateException&)
        {
            // Poco::IllegalStateException is thrown if the file is not a valid zip file
            // so we simply skip the file.
            return TskModule::OK;
        }
        catch (Poco::AssertionViolationException&)
        {
            // Corrupt zip files are not uncommon, especially for carved files.
            std::wstringstream msg;
            msg << L"ZipExtractionModule - Encountered corrupt zip file ( " << pFile->getName().c_str()
                << L")";
            LOGWARN(msg.str());

            return TskModule::FAIL;
        }
        catch (std::exception& ex)
        {
            std::wstringstream msg;
            msg << L"ZipExtractionModule - Error processing zip file ( " << pFile->getName().c_str()
                << L") : " << ex.what();
            LOGERROR(msg.str());

            return TskModule::FAIL;
        }

        return TskModule::OK;
    }

    /**
     * Module cleanup function. This is where the module should free any resources 
     * allocated during initialization or execution.
     *
     * @returns TskModule::OK on success and TskModule::FAIL on error.
     */
    TskModule::Status TSK_MODULE_EXPORT finalize()
    {
        return TskModule::OK;
    }
}
