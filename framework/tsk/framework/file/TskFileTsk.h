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

#ifndef _TSK_FILE_TSK_H
#define _TSK_FILE_TSK_H

// System includes
#include <string>

// Framework includes
#include "TskFile.h"
#include "tsk/framework/services/TskImgDB.h"
#include "tsk/base/tsk_os.h"

// Poco includes
#include "Poco/File.h"
#include "Poco/FileStream.h"

/**
 * TskFileTsk is a Sleuthkit and Poco based implementation
 * of the TskFile interface.
 */
class TSK_FRAMEWORK_API TskFileTsk : public TskFile
{
public:
    

	virtual ~TskFileTsk();

    /// Fully qualified path to on-disk representation of file.
    virtual std::string getPath() const;

    /// Does a file exist on disk for this TskFile object.
    /**
     * @return True if a file exists, false otherwise
     */ 
    virtual bool exists() const;

    /// Does this file represent a directory.
    /**
     * @return True if this is a directory, false otherwise
     */ 
    virtual bool isDirectory() const;

    /// Is this a Sleuthkit "virtual" file (created by TSK for
    /// file system areas).
    /**
     * @return True if this is a "virtual" file, false otherwise
     */ 
    virtual bool isVirtual() const;

    /// Open the file. Must be called before reading.
    virtual void open();

    /// Close the file.
    virtual void close();

    virtual TSK_OFF_T tell() const;

    virtual TSK_OFF_T seek(const TSK_OFF_T off, std::ios::seekdir origin = std::ios::beg);

    virtual ssize_t read(char * buf, const size_t count);

protected:
    friend class TskFileManagerImpl;

    // Construct a file for the given id.
	TskFileTsk(const uint64_t id);

    TskFileTsk() {};

    // A handle to the file on disk
    Poco::File m_file;

    // An input stream for the file on disk
    Poco::FileInputStream * m_fileInStream;

    // A Sleuthkit handle to the file in an image
    int m_handle;

    // For IMGDB_FILES_TYPE_UNUSED unused_sectors only
    TskUnusedSectorsRecord m_unusedSectorsRecord;
};
#endif
