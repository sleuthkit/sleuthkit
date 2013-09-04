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
 * \file TskFileManagerImpl.h
 * Default implementation of the TskFileManager class.
 */

#ifndef _TSK_FILEMANAGERIMPL_H
#define _TSK_FILEMANAGERIMPL_H

// Framework Includes
#include "TskFileManager.h"

// Poco Includes
#include "Poco/File.h"

/**
 * An implementation of the TskFileManager
 * interface that stores files in a directory named 'files' 
 * based on their file ids.
 */
class TSK_FRAMEWORK_API TskFileManagerImpl : public TskFileManager
{
public:
    static const int FILES_PER_DIR;
    static const int FILE_BUFFER_SIZE;
    static const std::string FILES_DIRECTORY;

    // The TskFileManagerImpl is implemented as a singleton
    static TskFileManagerImpl& instance();

    // Return a File object for the given file id.
    virtual TskFile* getFile(const uint64_t fileId);

    // Return a list of File objects mapped to the given list of file ids.
    virtual TskFileManager::FilePtrList getFiles(const std::vector<uint64_t>& fileIds);

    // Return a list of File objects matching the given filename
    virtual TskFileManager::FilePtrList findFilesByName(const std::string& name, const TSK_FS_META_TYPE_ENUM fsFileType = TSK_FS_META_TYPE_UNDEF);
    
    // Return a list of File objects matching the given filename extension
    virtual TskFileManager::FilePtrList findFilesByExtension(const std::vector<std::string>& extensions);
    
    // Return a list of File objects that are children of the given file id
    virtual TskFileManager::FilePtrList findFilesByParent(const uint64_t parentFileId);
    
    // Return a list of File objects that match the given file meta type
    virtual TskFileManager::FilePtrList findFilesByFsFileType(TSK_FS_META_TYPE_ENUM fsFileType);
    
    // Return a list of File objects that match the given filename and path patterns.
    virtual TskFileManager::FilePtrList findFilesByPattern(const std::string& namePattern, const std::string& pathPattern);

    // Return the path including the file name for the given file id.
    virtual std::wstring getPath(const uint64_t fileId);

    // Save the given file to disk.
    virtual void saveFile(TskFile* fileToSave);

    // Copy the given file to the specified fully qualified file name
    virtual void copyFile(TskFile* fileToSave, const std::wstring& filePath);

	// Copy the contents of a directory to the specified path.
	virtual void copyDirectory(TskFile* directoryToCopy, const std::wstring& destinationPath, const bool bRecurse = false);

	// Save the contents of the input stream to a file with the given fileId
    virtual void addFile(const uint64_t fileId, std::istream& istr);

    virtual void addFile(const uint64_t fileId, std::wstring& filePath);

    // Delete the file from disk.
    virtual void deleteFile(TskFile* fileToDelete);

private:
    // Private constructors and assignment operator to prevent direct
    // instantiation.
    TskFileManagerImpl() {};
    TskFileManagerImpl(TskFileManagerImpl const&) {};
    TskFileManagerImpl& operator=(TskFileManagerImpl const&) { return * m_pInstance; };
    ~TskFileManagerImpl() {};

    // Our one and only instance
    static TskFileManagerImpl * m_pInstance;

    // Our storage location
    Poco::File * m_storageDir;

    // Ensure that the storage location is set up
    void initialize();
};
#endif
