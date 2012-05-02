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
 * \file TskFileTsk.cpp
 * Contains a Sleuthkit and Poco implementation of the TskFileTsk class.
 */

// System includes
#include <sstream>

// Framework includes
#include "TskFileTsk.h"
#include "Services/TskServices.h"
#include "Utilities/TskException.h"

/**
 * Create a TskFileTsk object given a file id.
 */
TskFileTsk::TskFileTsk(uint64_t id) 
    : m_file(), m_fileInStream(NULL), m_handle(-1)
{
    m_id = id;
    m_offset = 0;
    m_filePath = "";
    m_isOpen = false;

    initialize();
}

/**
 * Create a TskFileTsk object given a file id and a path
 * to an on disk representation of that file.
 */
TskFileTsk::TskFileTsk(const uint64_t id, const std::string& path) 
    : m_file(path), m_fileInStream(), m_handle(-1)
{
    m_id = id;
    m_offset = 0;
    m_filePath = path;
    m_isOpen = false;

    initialize();
}

/**
 * Delete the TskFileTsk object.
 */
TskFileTsk::~TskFileTsk(void)
{
    close();
}

/**
 * Does the file have on disk storage
 */
bool TskFileTsk::exists() const
{
    if (m_file.path().empty())
        return false;
    else
        return m_file.exists();
}

/**
 * Does this file object represent a directory?
 */
bool TskFileTsk::isDirectory() const
{
    return m_fileRecord.dirType == TSK_FS_NAME_TYPE_DIR;
}

/**
 * Is this a Sleuthkit virtual file?
 */
bool TskFileTsk::isVirtual() const
{
    return m_fileRecord.dirType == TSK_FS_NAME_TYPE_VIRT;
}

/**
 * Get the fully qualified path to the on-disk
 * representation of the file.
 */
std::string TskFileTsk::getPath() const
{
    return m_filePath;
}

/**
 * Set the fully qualified path to the on-disk
 * representation of the file.
 */
void TskFileTsk::setPath(const std::string& path)
{
    m_filePath = path;
    m_file = Poco::File(path);
}

/**
 * Either initialize an input stream for files that exist on disk
 * or open a handle through the Sleuthkit for file system files that
 * have not been written to disk.
 */
void TskFileTsk::open()
{
    // If the file exists on disk we initialize the input stream.
    if (exists())
    {
        // Open our input stream if not already open
        if (m_fileInStream == NULL)
        {
            m_fileInStream = new Poco::FileInputStream(m_filePath);
        }
    }
    // We currently only support accessing file system files 
    else if (typeId() == TskImgDB::IMGDB_FILES_TYPE_FS)
    {
        // Otherwise, we open a handle to the file in ImageFile
        m_handle = TskServices::Instance().getImageFile().openFile(m_id);

        if (m_handle == -1)
        {
            LOGERROR(L"TskFileTsk::open - Error opening file.");
            throw TskFileException("Error opening file");
        }
    }
    else if (typeId() == TskImgDB::IMGDB_FILES_TYPE_UNUSED)
    {
        if (TskServices::Instance().getImgDB().getUnusedSector(id(), m_unusedSectorsRecord) == -1) {
            LOGERROR(L"TskFileTsk::open - Error opening file.");
            throw TskFileException("Error opening file");
        }
    }
    else
    {
        std::wstringstream msg;
        msg << L"TskFileTsk::open - Open failed because file id (" << m_id
            << ") does not exist on disk and is not a file system file.";

        LOGERROR(msg.str());

        throw TskFileException("Error opening file");
    }

    m_isOpen = true;
}

/**
 * Close the input stream or the Sleuthkit handle for this file.
 */
void TskFileTsk::close()
{
    // Close and delete our input stream if it's open.
    if (m_fileInStream != NULL)
    {
        m_fileInStream->close();
        delete m_fileInStream;
        m_fileInStream = NULL;
    }

    // Close our handle in the image file if it's open.
    if (m_handle != -1)
    {
        TskServices::Instance().getImageFile().closeFile(m_handle);
        m_handle = -1;
        m_offset = 0;
    }

    if (typeId() == TskImgDB::IMGDB_FILES_TYPE_UNUSED) {
        m_handle = -1;
        m_offset = 0;
    }

    m_isOpen = false;
}

/**
 * Read count bytes from the file into buf. The source of
 * the file content can be either a file on disk or an
 * image file.
 */
ssize_t TskFileTsk::read(char *buf, const size_t count)
{
    // File must be opened before you can read.
    if (!m_isOpen)
    {
        LOGERROR(L"TskFileTsk::read - File not open.");
        throw TskFileException("File not open.");
    }
    
    //if the file size is 0 don't bother trying to read
    if (!size())
        return 0;

    try
    {
        // If an on disk file exists we read the content from it
        if (m_fileInStream != NULL)
        {
            m_fileInStream->read(buf, count);

            return m_fileInStream->gcount();
        }
        else if (typeId() == TskImgDB::IMGDB_FILES_TYPE_FS)
        {
            // The file doesn't exist on disk so we need to read the content
            // from the ImageFile.
            int bytesRead = TskServices::Instance().getImageFile().readFile(m_handle, m_offset, count, buf);

            if (bytesRead > 0)
                m_offset += bytesRead;

            return bytesRead;
        }
        else if (typeId() == TskImgDB::IMGDB_FILES_TYPE_UNUSED)
        {
            int bytesRead = 0;
            uint64_t bytesToRead = 0;
            uint64_t fileSize = m_unusedSectorsRecord.sectLen * 512;
            if (m_offset + count > fileSize) {
                if (fileSize - m_offset > 0)
                    bytesToRead = fileSize - m_offset;
                else
                    return bytesRead;
            } else {
                bytesToRead = count;
            }
            bytesRead = TskServices::Instance().getImageFile().getByteData(m_unusedSectorsRecord.sectStart * 512 + m_offset, bytesToRead, buf);
            if (bytesRead > 0)
                m_offset += bytesRead;
            return bytesRead;
        }
    }
    catch (std::exception& ex)
    {
        // Log a message and throw a framework exception.
        std::wstringstream errorMsg;
        errorMsg << "TskFileTsk::read : " << ex.what() << std::endl;
        LOGERROR(errorMsg.str());

        throw TskFileException("Failed to read from file: " + m_filePath);
    }
    return 0;
}

/**
 * Starting at specified offset in file, read count bytes into buf.
 */
ssize_t TskFileTsk::read(const int64_t offset, char *buf, const size_t count)
{
    return 0;
}
