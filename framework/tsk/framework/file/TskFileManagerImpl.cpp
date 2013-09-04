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
 * \file TskFileManagerImpl.cpp
 * Default implementation of the TskFileManager class.
 */

#include <sstream>
#include <cstring>

// Framework includes
#include "TskFileManagerImpl.h"
#include "TskFileTsk.h"
#include "tsk/framework/services/TskSystemProperties.h"
#include "tsk/framework/services/TskServices.h"
#include "tsk/framework/utilities/TskException.h"
#include "tsk/framework/utilities/TskUtilities.h"

// Poco includes
#include "Poco/Exception.h"
#include "Poco/Path.h"
#include "Poco/FileStream.h"
#include "Poco/StreamCopier.h"
#include "Poco/NumberFormatter.h"

// C/C++ standard library includes
#include <cassert>
#include <sstream>
#include <memory>

TskFileManagerImpl * TskFileManagerImpl::m_pInstance = NULL;

const int TskFileManagerImpl::FILES_PER_DIR = 1000;
const int TskFileManagerImpl::FILE_BUFFER_SIZE = 8192;
const std::string TskFileManagerImpl::FILES_DIRECTORY = "Files";

TskFileManagerImpl& TskFileManagerImpl::instance()
{
    if (!m_pInstance)
    {
        m_pInstance = new TskFileManagerImpl();
        m_pInstance->initialize();
    }

    return *m_pInstance;
}

void TskFileManagerImpl::initialize()
{
    try
    {
        std::string storagePath = GetSystemProperty(TskSystemProperties::SYSTEM_OUT_DIR);
        m_storageDir = new Poco::File(storagePath + Poco::Path::separator() + FILES_DIRECTORY);

        // Create the directory if it does not exist.
        try {
            m_storageDir->createDirectory();
        } catch (Poco::FileExistsException &) {
            ; // Ignore. This can happen when another process is creating the same directory.
        }
    }
    catch (Poco::Exception& ex)
    {
        // Log a message
        std::wstringstream errorMsg;
        errorMsg << L"TskFileManagerImpl::initialize - File manager initialization failed with the following message: " 
            << ex.message().c_str() << std::endl;
        LOGERROR(errorMsg.str());
        
        // Throw a framework specific exception
        throw TskFileException(ex.message());
    }
}

TskFile * TskFileManagerImpl::getFile(const uint64_t fileId)
{
    /* If we were to ever have different subclasses of TskFile
     * that differentiate file types, this is where the logic
     * should go to create the correct version. 
     */
    return new TskFileTsk(fileId);
}

TskFileManager::FilePtrList TskFileManagerImpl::getFiles(const std::vector<uint64_t>& fileIds)
{
	TskFileManager::FilePtrList ret;
    for (std::vector<uint64_t>::const_iterator it = fileIds.begin(); it != fileIds.end(); ++it)
    {
        ret.push_back(TskFileManager::FilePtr(getFile(*it)));
    }

	return ret;
}

TskFileManager::FilePtrList TskFileManagerImpl::findFilesByName(const std::string& name, const TSK_FS_META_TYPE_ENUM fsFileType /*= TSK_FS_META_TYPE_UNDEF*/)
{
    // Construct SQL condition
    std::stringstream condition;
    condition << "WHERE UPPER(files.name) = '" << name << "'";
    if (fsFileType != TSK_FS_META_TYPE_UNDEF)
    {
        condition << " AND files.meta_type = " << static_cast<int>(fsFileType);
    }

    // Get the file ids matching our condition
    TskImgDB& imgDB = TskServices::Instance().getImgDB();
    std::vector<uint64_t> fileIds = imgDB.getFileIds(condition.str());

    return getFiles(fileIds);
}

TskFileManager::FilePtrList TskFileManagerImpl::findFilesByExtension(const std::vector<std::string>& extensions)
{
    // Construct SQL condition
    TskImgDB& imgDB = TskServices::Instance().getImgDB();
    std::stringstream condition;
    ///@todo check if extension already has a period
    //period = ".";
    condition << "WHERE (UPPER(name) LIKE ";
    for (std::vector<std::string>::const_iterator it = extensions.begin(); it != extensions.end(); ++it)
    {
        condition << imgDB.quote("%." + *it);
        if (it != --extensions.end())
        {
            condition << " OR UPPER(name) LIKE ";
        }
    }
    condition << ") AND size > 0";

    // Get the file ids matching our condition
    std::vector<uint64_t> fileIds = imgDB.getFileIds(condition.str());

	return getFiles(fileIds);
}

TskFileManager::FilePtrList TskFileManagerImpl::findFilesByParent(const uint64_t parentFileId)
{
    // Construct SQL condition
    std::stringstream condition;
    condition << "WHERE par_file_id = " << parentFileId;

    // Get the file ids matching our condition
    TskImgDB& imgDB = TskServices::Instance().getImgDB();
    std::vector<uint64_t> fileIds = imgDB.getFileIds(condition.str());

	return getFiles(fileIds);
}

TskFileManager::FilePtrList TskFileManagerImpl::findFilesByFsFileType(TSK_FS_META_TYPE_ENUM fsFileType)
{
    // Construct SQL condition
    std::stringstream condition;
    condition << "WHERE files.meta_type = " << static_cast<int>(fsFileType);

    // Get the file ids matching our condition
    TskImgDB& imgDB = TskServices::Instance().getImgDB();
    std::vector<uint64_t> fileIds = imgDB.getFileIds(condition.str());

    return getFiles(fileIds);
}

TskFileManager::FilePtrList TskFileManagerImpl::findFilesByPattern(const std::string& namePattern, const std::string& pathPattern)
{
    // Construct SQL condition
    TskImgDB& imgDB = TskServices::Instance().getImgDB();
    std::stringstream condition;
    condition << "WHERE files.meta_type = " << static_cast<int>(TSK_FS_META_TYPE_REG)
              << " AND UPPER(files.name) LIKE " << imgDB.quote(namePattern) 
              << " AND UPPER(files.full_path) LIKE " << imgDB.quote(pathPattern);

    // Get the file ids matching our condition
    std::vector<uint64_t> fileIds = imgDB.getFileIds(condition.str());

    return getFiles(fileIds);
}

std::wstring TskFileManagerImpl::getPath(const uint64_t fileId)
{
    // Determine which directory the file should live in.
    std::stringstream dirPath;
    dirPath << m_storageDir->path() << Poco::Path::separator()
        << fileId / FILES_PER_DIR;

    // Create the directory if it does not exist.
    Poco::File fileDir(dirPath.str());
    try {
        fileDir.createDirectory();
    } catch (Poco::FileExistsException &) {
        ; // Ignore. This can happen when another process is creating the same directory.
    }

    // Add the fileId onto the path
    dirPath << Poco::Path::separator() << fileId;

    // Convert from Poco's UTF8 representation to std::wstring
    std::wstring path = TskUtilities::toUTF16(dirPath.str());

    return path;
}

void TskFileManagerImpl::saveFile(TskFile* fileToSave)
{
    TskImgDB::FILE_TYPES fileType = fileToSave->getTypeId(); 
    if ((fileType != TskImgDB::IMGDB_FILES_TYPE_CARVED) && (fileType != TskImgDB::IMGDB_FILES_TYPE_DERIVED)) 
    {
        copyFile(fileToSave, getPath(fileToSave->getId()));
    }
    else
    {
        // Carved and derived files should already have been saved to storage by a call to addFile().
        Poco::File file(Poco::Path(TskUtilities::toUTF8(getPath(fileToSave->getId()))));
        assert(file.exists());
        if(!file.exists())
        {
            std::ostringstream msg;
            msg << "TskFileManagerImpl::saveFile : " << (fileType == TskImgDB::IMGDB_FILES_TYPE_CARVED ? "carved file" : "derived file") << " with file id = " << fileToSave->getId() << " does not exist in storage"; 
            throw TskException(msg.str());
        }
    }
}

void TskFileManagerImpl::copyFile(TskFile* fileToSave, const std::wstring& filePath)
{
    try 
    {
        if (fileToSave == NULL)
        {
			throw TskException("TskFile pointer is NULL.");
        }

		if (fileToSave->isDirectory())
		{
			throw TskException("Attempt to copy directory where file is expected.");
		}

        Poco::Path destPath(TskUtilities::toUTF8(filePath));

        // Create directories that may be missing along the path.
        Poco::File destDir(destPath.parent());

        try
        {
            destDir.createDirectories();
        }
        catch (Poco::FileExistsException& )
        {
            // It's ok if the directory already exists.
        }

        Poco::File destFile(destPath);

        // If the destination file exists it is replaced
        if (destFile.exists())
        {
            destFile.remove();
        }

        // If the source file exists we simply copy it to the target
        if (fileToSave->exists())
        {
            Poco::File sourceFile(fileToSave->getPath());
            sourceFile.copyTo(destPath.toString());
        }
        else
        {
            // We read the content from the file and write it to the target

            // Open the file whose content we are saving
            fileToSave->open();

            // Create a new empty file.
            destFile.createFile();

            // Call File.read() to get the file content and write to new file.
            Poco::FileOutputStream fos(destFile.path());
            char buffer[FILE_BUFFER_SIZE];
            int bytesRead = 0;

            // Remember the offset the file was at when we were called.
            TSK_OFF_T savedOffset = fileToSave->tell();

            // Reset to start of file to ensure all content is saved.
            fileToSave->seek(0, std::ios_base::beg);

            do
            {
                memset(buffer, 0, FILE_BUFFER_SIZE);
                bytesRead = fileToSave->read(buffer, FILE_BUFFER_SIZE);
                if (bytesRead > 0)
                    fos.write(buffer, bytesRead);
            } while (bytesRead > 0);

            // Flush and close the output stream.
            fos.flush();
            fos.close();

            // Restore the saved offset.
            fileToSave->seek(savedOffset, std::ios_base::beg);

            // Close the file
            fileToSave->close();
        }
    }
    catch (TskFileException& tskEx)
    {
        // Rethrow the exception up to our caller
        throw tskEx;
    }
    catch (Poco::PathNotFoundException&)
    {
        throw TskException("Path not found : " + fileToSave->getPath());
    }
    catch (std::exception & ex)
    {
        throw ex;
    }
}

void TskFileManagerImpl::copyDirectory(TskFile* directoryToCopy, const std::wstring& destinationPath, const bool bRecurse)
{
	if (directoryToCopy == NULL)
	{
		throw TskException("Directory pointer is NULL.");
	}

	if (!directoryToCopy->isDirectory())
	{
		throw TskException("File object to copy is not a directory.");
	}

	try
	{
		Poco::File destDir(TskUtilities::toUTF8(destinationPath));

        // If the destination directory exists it is replaced.
        if (destDir.exists())
        {
            destDir.remove(true);
        }

        // Create directories that may be missing along the path.
		destDir.createDirectories();

        // If the source directory exists we simply copy it to the destination.
        if (directoryToCopy->exists())
        {
            Poco::File sourceFile(directoryToCopy->getPath());
            sourceFile.copyTo(destDir.path());
        }
        else
        {
			// Find all files contained in this directory.
			std::stringstream condition;
			condition << "WHERE par_file_id = " << directoryToCopy->getId();

			std::vector<uint64_t> fileIds = TskServices::Instance().getImgDB().getFileIds(condition.str());

			for (std::vector<uint64_t>::const_iterator it = fileIds.begin(); it != fileIds.end(); ++it)
			{
				TskFile * pFile = getFile(*it);

				if (pFile == NULL)
				{
				  std::stringstream msg;
				  msg << "Failed to create file object for file id " << *it;
				  throw TskException(msg.str());
				}

				if (pFile->isDirectory() && bRecurse)
				{
					Poco::Path subDirPath = Poco::Path::forDirectory(destDir.path());
					subDirPath.pushDirectory(pFile->getName());
					copyDirectory(pFile, TskUtilities::toUTF16(subDirPath.toString()), bRecurse);
				}

				if (!pFile->isDirectory())
				{
					Poco::Path filePath(destDir.path());
					filePath.append(pFile->getName());
					copyFile(pFile, TskUtilities::toUTF16(filePath.toString()));
				}
                delete pFile;
			}
		}
	}
    catch (TskException& tskEx)
    {
        // Rethrow the exception up to our caller
        throw tskEx;
    }
    catch (std::exception & ex)
    {
        throw ex;
    }
}

void TskFileManagerImpl::addFile(const uint64_t fileId, std::istream& istr)
{
    // If a file with this id already exists we raise an error
    TskFile * pFile = getFile(fileId);

    if (pFile != NULL && pFile->exists())
    {
        delete pFile;
        std::stringstream msg;
        msg << "File id " << fileId << " already exists.";
        throw TskFileException(msg.str());
    }
    delete pFile;

    try
    {
        Poco::Path destPath(TskUtilities::toUTF8(getPath(fileId)));
        Poco::File destFile(destPath);

        // Create the destination
        destFile.createFile();

        // Save the file
        Poco::FileOutputStream fos(destFile.path(), std::ios::binary);
        Poco::StreamCopier::copyStream(istr, fos);
    }
    catch (Poco::Exception& ex)
    {
        std::wstringstream msg;
        msg << L"TskFileManagerImpl::addFile - Error saving file from stream : " << ex.displayText().c_str();
        LOGERROR(msg.str());
        throw TskFileException("Error saving file from stream.");
    }
}

void TskFileManagerImpl::addFile(const uint64_t fileId, std::wstring& filePath)
{
    try
    {
        Poco::File sourceFile(TskUtilities::toUTF8(filePath));
        sourceFile.copyTo(TskUtilities::toUTF8(getPath(fileId)));
    }
    catch (Poco::Exception& ex)
    {
        std::wstringstream msg;
        msg << L"TskFileManagerImpl::addFile - Error opening file " << TskUtilities::toUTF8(filePath).c_str()  
            << L" : " << ex.displayText().c_str();
        LOGERROR(msg.str());
        throw TskFileException("Error opening input file.");
    }
}

void TskFileManagerImpl::deleteFile(TskFile* fileToDelete)
{
    try
    {
        if (fileToDelete == NULL)
        {
            LOGERROR(L"TskFileManagerImpl::deleteFile - Passed NULL file pointer.");
            throw TskNullPointerException();
        }

        if (fileToDelete->exists())
        {
            Poco::File targetFile(fileToDelete->getPath());
            targetFile.remove();
        }
    }
    catch (Poco::Exception& ex)
    {
        std::wstringstream errorMsg;
        errorMsg << L"TskFileManagerImpl::delete - Failed to delete file " 
            << fileToDelete->getPath().c_str() << L". Error: " << ex.displayText().c_str() << std::endl;
        LOGERROR(errorMsg.str());

        throw TskFileException("Failed to delete file.");
    }
}