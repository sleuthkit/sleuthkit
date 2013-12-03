/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2012 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

/** \file InterestingFiles.cpp
 * This file contains the implementation of a module that saves interesting 
 * files recorded on the blackboard to a user-specified output directory.
 */

// Framework includes
#include "tsk/framework/utilities/TskModuleDev.h"

// Poco includes
#include "Poco/Path.h"
#include "Poco/File.h"
#include "Poco/FileStream.h"
#include "Poco/Exception.h"
#include "Poco/XML/XMLWriter.h"
#include "Poco/DOM/AutoPtr.h"
#include "Poco/DOM/Document.h"
#include "Poco/DOM/Element.h"
#include "Poco/DOM/Attr.h"
#include "Poco/DOM/DOMWriter.h"
#include "Poco/DOM/Text.h"
#include "Poco/DOM/Text.h"
#include "Poco/DOM/DOMException.h"

// System includes
#include <string>
#include <sstream>
#include <vector>
#include <set>
#include <map>
#include <iostream>
#include <memory>
#include <string.h>

namespace
{
    const char *MODULE_NAME = "tskSaveInterestingFilesModule";
    const char *MODULE_DESCRIPTION = "Saves files and directories that were flagged as being interesting to a location for further analysis";
    const char *MODULE_VERSION = "1.0.0";

    typedef std::map<std::string, std::string> FileSets; 
    typedef std::multimap<std::string, TskBlackboardArtifact> FileSetHits;
    typedef std::pair<FileSetHits::iterator, FileSetHits::iterator> FileSetHitsRange; 

    std::string outputFolderPath;

    void addFileToReport(const TskFile &file, const std::string &filePath, Poco::XML::Document *report)
    {
        Poco::XML::Element *reportRoot = static_cast<Poco::XML::Element*>(report->firstChild());

        Poco::AutoPtr<Poco::XML::Element> fileElement; 
        if (file.getMetaType() == TSK_FS_META_TYPE_DIR)
        {
            fileElement = report->createElement("SavedDirectory");
        }
        else
        {
            fileElement = report->createElement("SavedFile");
        }
        reportRoot->appendChild(fileElement);

        Poco::AutoPtr<Poco::XML::Element> savedPathElement = report->createElement("Path");
        fileElement->appendChild(savedPathElement);        
        Poco::AutoPtr<Poco::XML::Text> savedPathText = report->createTextNode(filePath);
        savedPathElement->appendChild(savedPathText);

        Poco::AutoPtr<Poco::XML::Element> originalPathElement = report->createElement("OriginalPath");        
        fileElement->appendChild(originalPathElement);
        Poco::AutoPtr<Poco::XML::Text> originalPathText = report->createTextNode(file.getFullPath());
        originalPathElement->appendChild(originalPathText);

        Poco::AutoPtr<Poco::XML::Element> uniquePathElement = report->createElement("UniquePath");        
        fileElement->appendChild(uniquePathElement);
        Poco::AutoPtr<Poco::XML::Text> uniquePathText = report->createTextNode(file.getUniquePath());
        uniquePathElement->appendChild(uniquePathText);

        if (file.getMetaType() != TSK_FS_META_TYPE_DIR)
        {
            // This element will be empty unless a hash calculation module has operated on the file.
            Poco::AutoPtr<Poco::XML::Element> md5HashElement = report->createElement("MD5");        
            fileElement->appendChild(md5HashElement);                
            Poco::AutoPtr<Poco::XML::Text> md5HashText = report->createTextNode(file.getHash(TskImgDB::MD5));
            md5HashElement->appendChild(md5HashText);
        }
    }

    void saveDirectoryContents(const std::string &dirPath, const TskFile &dir, Poco::XML::Document *report)
    {
        // Get a list corresponding to the files in the directory.
        TskFileManager::AutoFilePtrList files(TskServices::Instance().getFileManager().findFilesByParent(dir.getId()));

        // Save each file and subdirectory in the directory.
        for (TskFileManager::FilePtrList::iterator file = files.begin(); file != files.end(); ++file)
        {
            if ((*file)->getMetaType() == TSK_FS_META_TYPE_DIR)
            {
                // Create a subdirectory to hold the contents of this subdirectory.
                Poco::Path subDirPath(Poco::Path::forDirectory(dirPath));
                subDirPath.pushDirectory((*file)->getName());
                Poco::File(subDirPath).createDirectory();
                
                // Recurse into the subdirectory.
                saveDirectoryContents(subDirPath.toString(), **file, report);
            }
            else
            {
                // Save the file.
                std::stringstream filePath;
                filePath << dirPath << Poco::Path::separator() << (*file)->getName();
                TskServices::Instance().getFileManager().copyFile(*file, TskUtilities::toUTF16(filePath.str()));
                addFileToReport(**file, (*file)->getName(), report);
            }
        }
    }

    void saveInterestingDirectory(const TskFile &dir, const std::string &fileSetFolderPath, Poco::XML::Document *report)
    {
        // Make a subdirectory of the output folder named for the interesting file search set and create a further subdirectory
        // corresponding to the directory to be saved. The resulting directory structure will look like this:
        // <output folder>/
        //      <interesting file set name>/
        //          <directory name>_<file id>/ /*Suffix the directory with its its file id to ensure uniqueness*/
        //              <directory name>/
        //                  <contents of directory including subdirectories>
        //
        Poco::Path path(Poco::Path::forDirectory(fileSetFolderPath));
        std::stringstream subDir;
        subDir << dir.getName() << '_' << dir.getId();
        path.pushDirectory(subDir.str());
        path.pushDirectory(dir.getName());
        Poco::File(path).createDirectories();

        addFileToReport(dir, path.toString(), report);

        saveDirectoryContents(path.toString(), dir, report);
    }

    void saveInterestingFile(const TskFile &file, const std::string &fileSetFolderPath, Poco::XML::Document *report)
    {
        // Construct a path to write the contents of the file to a subdirectory of the output folder named for the interesting file search
        // set. The resulting directory structure will look like this:
        // <output folder>/
        //      <interesting file set name>/
        //          <file name>_<fileId>.<ext> /*Suffix the file with its its file id to ensure uniqueness*/
        std::string fileName = file.getName();
        std::stringstream id;
        id << '_' << file.getId();
        std::string::size_type pos = 0;
        if ((pos = fileName.rfind(".")) != std::string::npos && pos != 0)
        {
            // The file name has a conventional extension. Insert the file id before the '.' of the extension.
            fileName.insert(pos, id.str());
        }
        else
        {
            // The file has no extension or the only '.' in the file is an initial '.', as in a hidden file.
            // Add the file id to the end of the file name.
            fileName.append(id.str());
        }
        std::stringstream filePath;
        filePath << fileSetFolderPath.c_str() << Poco::Path::separator() << fileName.c_str();
    
        // Save the file.
        TskServices::Instance().getFileManager().copyFile(file.getId(), TskUtilities::toUTF16(filePath.str()));

        addFileToReport(file, fileName.c_str(), report);
    }

    void saveFiles(const std::string &setName, const std::string &setDescription, FileSetHitsRange fileSetHitsRange)
    {
        // Start an XML report of the files in the set.
        Poco::AutoPtr<Poco::XML::Document> report = new Poco::XML::Document();
        Poco::AutoPtr<Poco::XML::Element> reportRoot = report->createElement("InterestingFileSet");
        reportRoot->setAttribute("name", setName);
        reportRoot->setAttribute("description", setDescription);
        report->appendChild(reportRoot);

        // Make a subdirectory of the output folder named for the interesting file set.
        Poco::Path fileSetFolderPath(Poco::Path::forDirectory(outputFolderPath));
        fileSetFolderPath.pushDirectory(setName);
        Poco::File(fileSetFolderPath).createDirectory();
        
        // Save all of the files in the set.
        for (FileSetHits::iterator fileHit = fileSetHitsRange.first; fileHit != fileSetHitsRange.second; ++fileHit)
        {
            std::auto_ptr<TskFile> file(TskServices::Instance().getFileManager().getFile((*fileHit).second.getObjectID()));
            if (file->getMetaType() == TSK_FS_META_TYPE_DIR)
            {
                 saveInterestingDirectory(*file, fileSetFolderPath.toString(), report); 
            }
            else
            {
                saveInterestingFile(*file, fileSetFolderPath.toString(), report);
            }
        }

        // Write out the completed XML report.
        fileSetFolderPath.setFileName(setName + ".xml");
        Poco::FileStream reportFile(fileSetFolderPath.toString());
        Poco::XML::DOMWriter writer;
        writer.setNewLine("\n");
        writer.setOptions(Poco::XML::XMLWriter::PRETTY_PRINT);
        writer.writeNode(reportFile, report);
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
     * Module initialization function. Optionally receives an output folder
     * path as the location for saving the files corresponding to interesting
     * file set hits. The default output folder path is a folder named for the
     * module in #MODULE_OUT_DIR#.
     *
     * @param args Optional output folder path.
     * @return TskModule::OK if an output folder is created, TskModule::FAIL
     * otherwise. 
     */
    TSK_MODULE_EXPORT TskModule::Status initialize(const char* arguments)
    {
        TskModule::Status status = TskModule::OK;

        const std::string MSG_PREFIX = "SaveInterestingFilesModule::initialize : ";
        try
        {
            Poco::Path outputDirPath;
            if (strlen(arguments) != 0)
            {
                outputDirPath = Poco::Path::forDirectory(arguments);
            }
            else
            {
                outputDirPath = Poco::Path::forDirectory(GetSystemProperty(TskSystemProperties::MODULE_OUT_DIR));
                outputDirPath.pushDirectory(MODULE_NAME);
            }
            outputFolderPath = outputDirPath.toString();

            Poco::File(outputDirPath).createDirectories();
        }
        catch (TskException &ex)
        {
            status = TskModule::FAIL;
            outputFolderPath.clear();
            std::stringstream msg;
            msg << MSG_PREFIX << "TskException: " << ex.message();
            LOGERROR(msg.str());
        }
        catch (Poco::Exception &ex)
        {
            status = TskModule::FAIL;
            outputFolderPath.clear();
            std::stringstream msg;
            msg << MSG_PREFIX << "Poco::Exception: " << ex.displayText();
            LOGERROR(msg.str());
        }
        catch (std::exception &ex)
        {
            status = TskModule::FAIL;
            outputFolderPath.clear();
            std::stringstream msg;
            msg << MSG_PREFIX << "std::exception: " << ex.what();
            LOGERROR(msg.str());
        }
        catch (...)
        {
            status = TskModule::FAIL;
            outputFolderPath.clear();
            LOGERROR(MSG_PREFIX + "unrecognized exception");
        }

        return status;
    }

    /**
     * Module execution function. Saves interesting files recorded on the 
     * blackboard to a user-specified output directory.
     *
     * @returns TskModule::OK on success if all files saved, TskModule::FAIL if one or more files were not saved
     */
    TSK_MODULE_EXPORT TskModule::Status report()
    {
        TskModule::Status status = TskModule::OK;
        
        const std::string MSG_PREFIX = "SaveInterestingFilesModule::report : ";
        try
        {
            if (outputFolderPath.empty())
            {
                // Initialization failed. The reason why was already logged in initialize().
                return TskModule::FAIL;
            }

            // Get the interesting file set hits from the blackboard and sort them by set name.
            FileSets fileSets;
            FileSetHits fileSetHits;
            std::vector<TskBlackboardArtifact> fileSetHitArtifacts = TskServices::Instance().getBlackboard().getArtifacts(TSK_INTERESTING_FILE_HIT);
            for (std::vector<TskBlackboardArtifact>::iterator fileHit = fileSetHitArtifacts.begin(); fileHit != fileSetHitArtifacts.end(); ++fileHit)
            {
                // Find the set name attrbute of the artifact.
                bool setNameFound = false;
                std::vector<TskBlackboardAttribute> attrs = (*fileHit).getAttributes();
                for (std::vector<TskBlackboardAttribute>::iterator attr = attrs.begin(); attr != attrs.end(); ++attr)
                {
                    if ((*attr).getAttributeTypeID() == TSK_SET_NAME)
                    {
                        setNameFound = true;
                        
                        // Save the set name and description, using a map to ensure that these values are saved once per file set.
                        fileSets.insert(make_pair((*attr).getValueString(), (*attr).getContext()));
                        
                        // Drop the artifact into a multimap to allow for retrieval of all of the file hits for a file set as an 
                        // iterator range.
                        fileSetHits.insert(make_pair((*attr).getValueString(), (*fileHit)));
                    }
                }

                if (!setNameFound)
                {
                    // Log the error and try the next artifact.
                    std::stringstream msg;
                    msg << MSG_PREFIX << "failed to find TSK_SET_NAME attribute for TSK_INTERESTING_FILE_HIT artifact with id '" << (*fileHit).getArtifactID() << "', skipping artifact";
                    LOGERROR(msg.str());
                }
            }

            // Save the interesting files to the output directory, file set by file set.
            for (map<std::string, std::string>::const_iterator fileSet = fileSets.begin(); fileSet != fileSets.end(); ++fileSet)
            {
                // Get the file hits for the file set as an iterator range.
                FileSetHitsRange fileSetHitsRange = fileSetHits.equal_range((*fileSet).first); 

                // Save the files corresponding to the file hit artifacts.
                saveFiles((*fileSet).first, (*fileSet).second, fileSetHitsRange);
            }
        }
        catch (TskException &ex)
        {
            status = TskModule::FAIL;
            std::stringstream msg;
            msg << MSG_PREFIX << "TskException: " << ex.message();
            LOGERROR(msg.str());
        }
        catch (Poco::Exception &ex)
        {
            status = TskModule::FAIL;
            std::stringstream msg;
            msg << MSG_PREFIX << "Poco::Exception: " << ex.displayText();
            LOGERROR(msg.str());
        }
        catch (std::exception &ex)
        {
            status = TskModule::FAIL;
            std::stringstream msg;
            msg << MSG_PREFIX << "std::exception: " << ex.what();
            LOGERROR(msg.str());
        }
        catch (...)
        {
            status = TskModule::FAIL;
            LOGERROR(MSG_PREFIX + "unrecognized exception");
        }
        
        return status;
    }

    /**
     * Module cleanup function. Deletes output folder if empty.
     *
     * @returns TskModule::OK on success and TskModule::FAIL on error.
     */
    TSK_MODULE_EXPORT TskModule::Status finalize()
    {
        TskModule::Status status = TskModule::OK;        

        const std::string MSG_PREFIX = "SaveInterestingFilesModule::finalize : ";
        try
        {
            #if !defined(_DEBUG) 

            Poco::File outputFolder(outputFolderPath);
            std::vector<Poco::File> filesList;
            outputFolder.list(filesList);
            if (filesList.empty())
            {
                outputFolder.remove(true);
            }

            #endif
        }
        catch (TskException &ex)
        {
            status = TskModule::FAIL;
            std::stringstream msg;
            msg << MSG_PREFIX << "TskException: " << ex.message();
            LOGERROR(msg.str());
        }
        catch (Poco::Exception &ex)
        {
            status = TskModule::FAIL;
            std::stringstream msg;
            msg << MSG_PREFIX << "Poco::Exception: " << ex.displayText();
            LOGERROR(msg.str());
        }
        catch (std::exception &ex)
        {
            status = TskModule::FAIL;
            std::stringstream msg;
            msg << MSG_PREFIX << "std::exception: " << ex.what();
            LOGERROR(msg.str());
        }
        catch (...)
        {
            status = TskModule::FAIL;
            LOGERROR(MSG_PREFIX + "unrecognized exception");
        }

        return status;
    }
}
