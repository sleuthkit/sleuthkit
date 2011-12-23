/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2011 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

/**
 * \file TskFileManager.h
 * Contains the interface for the TskFileManager class.
 */

#ifndef _TSK_FILEMANAGER_H
#define _TSK_FILEMANAGER_H

#include "framework_i.h"
#include "TskFile.h"

/**
 * Responsible for managing TskFile objects in the system.
 */
class TSK_FRAMEWORK_API TskFileManager
{
public:
    /**
     * Return a TskFile object for a given file ID.
     * @param fileId ID of file to return object of.
     * @returns Pointer to file object. Caller must free it.
     */
    virtual TskFile * getFile(const uint64_t fileId) = 0;

    /**
     * Return a TskFile object for a file stored locally at a given path.
     * @param fileId ID of file to assign to file at the path
     * @param path Location to find the file at. 
     * @returns Pointer to file object. Caller must free it.
     */
    virtual TskFile * getFile(const uint64_t fileId, const std::wstring& path) = 0;

    /// Return the path including the file name for the given file id.
    virtual std::wstring getPath(const uint64_t fileId) = 0;

    //// Save the given file to disk.
    virtual void saveFile(TskFile* fileToSave) = 0;

    virtual void saveFile(const uint64_t fileId)
    {
        saveFile(getFile(fileId));
    }

    /// Save the given file to the specified path
    virtual void saveFile(TskFile* fileToSave, const std::wstring& filePath) = 0;

    virtual void saveFile(const uint64_t fileId, const std::wstring& filePath)
    {
        saveFile(getFile(fileId), filePath);
    }

    /// Save the content represented by the input stream using the given file id
    virtual void saveFile(const uint64_t fileId, std::istream& istr) = 0;

    /// Delete the file from disk.
    virtual void deleteFile(TskFile* fileToDelete) = 0;
    virtual void deleteFile(const uint64_t fileId)
    {
        deleteFile(getFile(fileId));
    }

protected:
    /// Default Constructor
    TskFileManager() {};

    /// Copy Constructor
    TskFileManager(TskFileManager const&) {};

    /// Destructor
    virtual ~TskFileManager() {};
};

#endif
