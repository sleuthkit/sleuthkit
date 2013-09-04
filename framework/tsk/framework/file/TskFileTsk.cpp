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
 * \file TskFileTsk.cpp
 * Contains a Sleuthkit and Poco implementation of the TskFileTsk class.
 */

// System includes
#include <sstream>

// Framework includes
#include "TskFileTsk.h"
#include "tsk/framework/services/TskServices.h"
#include "tsk/framework/utilities/TskException.h"
#include "tsk/framework/utilities/TskUtilities.h"
#include "TskFileManagerImpl.h"

/**
 * Create a TskFileTsk object given a file id.
 */
TskFileTsk::TskFileTsk(uint64_t id) 
    : m_file(TskUtilities::toUTF8(TskFileManagerImpl::instance().getPath(id))), 
    m_fileInStream(NULL), m_handle(-1)
{
    m_id = id;
    m_offset = 0;
    m_isOpen = false;

    initialize();
}


TskFileTsk::~TskFileTsk(void)
{
    close();
}


bool TskFileTsk::exists() const
{
    if (m_file.path().empty())
        return false;
    else
        return m_file.exists();
}


bool TskFileTsk::isDirectory() const
{
    return m_fileRecord.dirType == TSK_FS_NAME_TYPE_DIR;
}


bool TskFileTsk::isVirtual() const
{
    return m_fileRecord.dirType == TSK_FS_NAME_TYPE_VIRT;
}


std::string TskFileTsk::getPath() const
{
    return m_file.path();
}



/*
 * Either initialize an input stream for files that exist on disk
 * or open a handle through the Sleuthkit for file system files that
 * have not been written to disk.
 */
void TskFileTsk::open()
{
    if (m_isOpen)
        return;
    
    // Files inside of the file system
    if (getTypeId() == TskImgDB::IMGDB_FILES_TYPE_FS)
    {
        // Otherwise, we open a handle to the file in ImageFile
        m_handle = TskServices::Instance().getImageFile().openFile(m_id);

        if (m_handle == -1)
        {
            LOGERROR(L"TskFileTsk::open - Error opening file.");
            throw TskFileException("Error opening file");
        }
    }
    else if (getTypeId() == TskImgDB::IMGDB_FILES_TYPE_UNUSED)
    {
        if (TskServices::Instance().getImgDB().getUnusedSector(getId(), m_unusedSectorsRecord) == -1) {
            LOGERROR(L"TskFileTsk::open - Error opening file.");
            throw TskFileException("Error opening file");
        }
    }
    // CARVED and DERIVED
    else if ((getTypeId() == TskImgDB::IMGDB_FILES_TYPE_CARVED) || (getTypeId() == TskImgDB::IMGDB_FILES_TYPE_DERIVED)) {
        if (exists()) {
            // Open our input stream if not already open
            if (m_fileInStream == NULL)
            {
                m_fileInStream = new Poco::FileInputStream(m_file.path());
            }
        }
        else {
            std::wstringstream msg;
            msg << L"TskFileTsk::open - Open failed because file id (" << m_id
                << ") does not exist on disk and is carved or derived.";
            LOGERROR(msg.str());
            throw TskFileException("Error opening file");
        }
    }
    else
    {
        std::wstringstream msg;
        msg << L"TskFileTsk::open - Open failed because file id (" << m_id
            << ") has unknown type (" << getTypeId() << ").";
        LOGERROR(msg.str());
        throw TskFileException("Error opening file");
    }

    m_offset = 0;
    m_isOpen = true;
}

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
    }

    if (getTypeId() == TskImgDB::IMGDB_FILES_TYPE_UNUSED) {
        m_handle = -1;
    }

    m_offset = 0;
    m_isOpen = false;
}


ssize_t TskFileTsk::read(char *buf, const size_t count)
{
    // File must be opened before you can read.
    if (!m_isOpen)
    {
        LOGERROR(L"TskFileTsk::read - File not open.");
        return -1;
    }
    
    //if the file size is 0 don't bother trying to read
    if (!getSize())
        return 0;

    try
    {
        // If an on disk file exists we read the content from it
        if (m_fileInStream != NULL)
        {
            m_fileInStream->read(buf, count);
            /* @@@ BC: I am not entirely sure that POCO will
             * not be throwing this as an exception -- the C++ streams can be 
             * configured either way.  If it is, we'll catch that below */
            // check for errors -- fail is set if EOF is reached
            if ((m_fileInStream->fail()) && (m_fileInStream->eof() == false)) {
                std::wstringstream message;
                message << L"TskFileTsk::read - error reading stream -  offset: " 
                    << m_fileInStream->tellg() << " -- len: " << count << std::endl;
                LOGERROR(message.str());
                return -1;
            }
            return m_fileInStream->gcount();
        }
        else if (getTypeId() == TskImgDB::IMGDB_FILES_TYPE_FS)
        {
            // readFile will log any errors
            int bytesRead = TskServices::Instance().getImageFile().readFile(m_handle, m_offset, count, buf);
            if (bytesRead > 0)
                m_offset += bytesRead;

            return bytesRead;
        }
        else if (getTypeId() == TskImgDB::IMGDB_FILES_TYPE_UNUSED)
        {
            int bytesRead = 0;
            uint64_t bytesToRead = 0;
            uint64_t fileSize = m_unusedSectorsRecord.sectLen * 512;
            if ((uint64_t)m_offset + count > fileSize) {
                if (fileSize - m_offset > 0)
                    bytesToRead = fileSize - m_offset;
                else
                    return bytesRead;
            } else {
                bytesToRead = count;
            }
            // getByteData will log any errors
            bytesRead = TskServices::Instance().getImageFile().getByteData(m_unusedSectorsRecord.sectStart * 512 + m_offset, bytesToRead, buf);
            if (bytesRead > 0)
                m_offset += bytesRead;
            return bytesRead;
        }
        else {
            std::wstringstream errorMsg;
            errorMsg << "TskFileTsk::read ID: " << m_id << " -- unknown type" << std::endl;
            LOGERROR(errorMsg.str());
            return -1;
        }
    }
    catch (std::exception& ex)
    {
        std::wstringstream errorMsg;
        errorMsg << "TskFileTsk::read ID: " << m_id << " -- " << ex.what() << std::endl;
        LOGERROR(errorMsg.str());
        return -1;
    }
}

TSK_OFF_T TskFileTsk::tell() const
{
    if (!m_isOpen)
    {
        LOGERROR(L"TskFileTsk::tell : File not open.");
        throw TskFileException("File not open.");
    }

    if (m_fileInStream != NULL)
        return m_fileInStream->tellg();
    else
        return m_offset;
}

TSK_OFF_T TskFileTsk::seek(const TSK_OFF_T off, std::ios::seekdir origin)
{
    if (!m_isOpen)
    {
        LOGERROR(L"TskFileTsk::seek : File not open.");
        throw TskFileException("File not open.");
    }

    if (m_fileInStream != NULL)
    {
        // Clear all error flags before seeking since an earlier
        // read may have set the eof flag.
        m_fileInStream->clear();
        m_fileInStream->seekg(off, origin);
        return m_fileInStream->tellg();
    }
    else
    {
        if (origin == std::ios::beg)
        {
            if (off > getSize())
            {
                LOGERROR(L"TskFileTsk::seek - Attempt to seek beyond end of file.");
                throw TskFileException("Attempt to seek beyond end of file.");
            }

            m_offset = off;
        }
        else if (origin == std::ios::end)
        {
            if (off > 0)
            {
                LOGERROR(L"TskFileTsk::seek - Offset must be a negative number when seeking from end of file.");
                throw TskFileException("Seek from end requires negative offset.");
            }
            if (getSize() + off < 0)
            {
                LOGERROR(L"TskFileTsk::seek - Attempt to seek prior to start of file.");
                throw TskFileException("Attempt to seek prior to start of file");
            }
            m_offset = getSize() + off;
        }
        else
        {
            if (m_offset + off > getSize())
            {
                LOGERROR(L"TskFileTsk::seek - Attempt to seek beyond end of file.");
                throw TskFileException("Attempt to seek beyond end of file.");
            }
            if (m_offset + off < 0)
            {
                LOGERROR(L"TskFileTsk::seek - Attempt to seek prior to start of file.");
                throw TskFileException("Attempt to seek prior to start of file.");
            }
            m_offset += off;
        }
        return m_offset;
    }
}
