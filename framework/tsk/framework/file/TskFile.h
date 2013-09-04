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
 * \file TskFile.h
 * Contains the interface for the TskFile class.
 */

#ifndef _TSK_FILE_H
#define _TSK_FILE_H

// System includes
#include <string>
#include <ios>

// Framework includes
#include "tsk/framework/services/TskImgDB.h"
#include "tsk/framework/services/TskBlackboardArtifact.h"

/**
 * An interface that is used to represent a file. This interface
 * is used during the analysis of a file and is typically created
 * based on data in TskImgDB, which was created by CarveExtract
 * or TskImageFile.  Different implementations of this class 
 * may retrieve file content and metadata in different ways.
 * TskFile objects are obtained from TskFileManager.
 */
class TSK_FRAMEWORK_API TskFile
{
public:
	virtual ~TskFile();

    /** Returns the file id.
     */
    uint64_t getId() const;

    /**
     * Get the high-level type (file system, local, carved, etc.)
     */
    TskImgDB::FILE_TYPES getTypeId() const;

    /** Get the name
     */
    std::string getName() const;

    /** Get the extension
    */
    std::string getExtension() const;

    /** Get the parent file id
    */
    uint64_t getParentFileId() const;

    /** Get the directory type
    */
    TSK_FS_NAME_TYPE_ENUM getDirType() const;

    /** Get the metadata flags
    */
    TSK_FS_META_TYPE_ENUM getMetaType() const;

    /** Get the directory flags
    */
    TSK_FS_NAME_FLAG_ENUM getDirFlags() const;

    /** Get the metadata flags
    */
    TSK_FS_META_FLAG_ENUM getMetaFlags() const;

    /** Get the file size
    */
    TSK_OFF_T getSize() const;

    /** Get the change time
     */
    time_t getCtime() const;

    /** Get the creation time
    */
    time_t getCrtime() const;

    /** Get the last access time
    */
    time_t getAtime() const;

    /** Get the modify time
    */
    time_t getMtime() const;

    /** Get the mode
    */
    TSK_FS_META_MODE_ENUM  getMode() const;

    /** Get the user id
    */
    TSK_UID_T getUid() const;

    /** Get the group id
    */
    TSK_GID_T getGid() const;

    /**
     * Get the path of the file in the disk image.  This
     * will not include the file name and will not include 
     * any information about the file system or volume that
     * it was found in (if there were multiple file systems
     * in the image. 
     * @returns Original path of the file.
     */
    std::string getFullPath() const;
    
    /**
     * Get the path of the file in the disk image.  This
     * will not include the file name but will include 
     * either information about the file system or volume that
     * it was found in or an indicator that the file was produced
     * by carving. 
     * @returns Original path of the file.
     */
    std::string getUniquePath() const;

    /**
     * Get the fully qualified path of where this file should
     * be locally stored.  It does not check if the file is 
     * locally stored.   Use exists() for that.
     */
    virtual std::string getPath() const = 0;

    /** 
     * Get the pre-calculated hash value of the specified type.
     * @param hashType Type of hash to lookup
     * @returns String of hash value or empty string if the value
     * has not been calculated. 
     */
    std::string getHash(TskImgDB::HASH_TYPE hashType) const;

    /**
     * Sets the file's hash value in the database.  note that hash values
     * are not stored in the blackboard. 
     * @param hashType Type of hash value
     * @param hash String value of hash.
     */
    void setHash(TskImgDB::HASH_TYPE hashType, const std::string hash);
    
    /**
     * Return the known status of the file
     * @returns KNOWN_STATUS or -1 on error
     */
    TskImgDB::KNOWN_STATUS getKnownStatus() const;

    /**
     * Tests if a local copy of the file exists at the default location. 
     * @return True if a file exists, false otherwise
     */ 
    virtual bool exists() const = 0;

    /**
     * @return True if this is a directory, false otherwise
     */ 
    virtual bool isDirectory() const = 0;

    /**
     * @return True if this is a "virtual" file, false otherwise
     */ 
    virtual bool isVirtual() const = 0;

    /** 
     * Open the file. Must be called before reading. Implementations must
     * support concept of open() being called multiple times even if file 
     * is already open. 
     * @throws TskFileException on error
     */
    virtual void open() = 0;

    /**
     * Closes the open file.
     */
    virtual void close() = 0;

    /**
     * Save the file to the default location. This is a simple wrapper
     * around TskFileManager::saveFile.
     * @throws TskException if file id is zero along with exceptions 
     * thrown by TskFileManager::saveFile.
     */
    virtual void save();

    /**
     * Get the current byte offset within the file.
     * @returns Current byte offset.
     * @throws TskFileException if file is not open.
     */
    virtual TSK_OFF_T tell() const = 0;

    /**
     * Set the byte offset within the file. If the second parameter is not
     * supplied the offset will be set relative to the beginning of the file.
     * @param off Number off bytes to offset from origin.
     * @param origin The point from which the given offset is relative to. Defaults
     * to beginning of file. If origin is std::ios::end the offset must be a 
     * negative number.
     * @returns The absolute file offset resulting from the repositioning.
     * @throws TskFileException if file is not open or if you attempt to seek
     * to an invalid offset.
     */
    virtual TSK_OFF_T seek(const TSK_OFF_T off, std::ios::seekdir origin = std::ios::beg) = 0;

    /**
     * Read file content into a buffer.  Reads from end of last read.
     * @param buf Buffer into which file content will be placed.
     * Must be at least "count" bytes in size.
     * @param count The number of bytes to read from the file.
     * @return The number of bytes read or -1 on error.
     */
    virtual ssize_t read(char * buf, const size_t count) = 0;

    /**
     * Set the file status (where it is in its analysis life cycle)
     */
    void setStatus(TskImgDB::FILE_STATUS status);

    /** Get the analysis status of the file (where it is in the analysis life cycle)
     */
    TskImgDB::FILE_STATUS getStatus() const;

    //Blackboard methods
    virtual TskBlackboardArtifact createArtifact(int artifactTypeID);
    virtual TskBlackboardArtifact createArtifact(TSK_ARTIFACT_TYPE type);
    virtual TskBlackboardArtifact createArtifact(string artifactTypeName);
    virtual vector<TskBlackboardArtifact> getArtifacts(string artifactTypeName);
    virtual vector<TskBlackboardArtifact> getArtifacts(int artifactTypeID);
    virtual vector<TskBlackboardArtifact> getArtifacts(TSK_ARTIFACT_TYPE type);
    virtual vector<TskBlackboardArtifact> getAllArtifacts();
    virtual TskBlackboardArtifact getGenInfo();
    virtual void addGenInfoAttribute(TskBlackboardAttribute attr);


protected:
    // File id.
    uint64_t m_id;

    // Our current offset into the file
    TSK_OFF_T m_offset;

    // Is the file open (used for both on disk and image files)
    bool m_isOpen;

    // The database file record.
    TskFileRecord m_fileRecord;

    /**
     * Loads the raw file data from the database.
     * @throws TskException on error
     */
    void initialize();
};

#endif
