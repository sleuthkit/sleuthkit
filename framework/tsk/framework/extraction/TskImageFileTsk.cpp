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
 * \file TskImageFileTsk.cpp
 * Contains The Sleuth Kit implementation of the TskImageFile interface.
 */

#include <iostream>
#include <sstream>
#include <algorithm>

#include "TskImageFileTsk.h"
#include "TskAutoImpl.h"
#include "tsk/framework/utilities/TskUtilities.h"
#include "tsk/framework/services/TskServices.h"
#include "tsk/base/tsk_base_i.h"


/**
 * Utility function to close file system handles.
 * @param pair An element from the file system map.
 */
void TskImageFileTsk::closeFs(std::pair<uint64_t, TSK_FS_INFO*> pair)
{
    tsk_fs_close(pair.second);
}

TskImageFileTsk::TskImageFileTsk() : m_db(TskServices::Instance().getImgDB())
{
    m_img_info = NULL;
    m_images_ptrs = NULL;
}

TskImageFileTsk::~TskImageFileTsk()
{
    close();
}

/*
 * Opens the image files listed in ImgDB for later analysis and extraction.  
 * @returns -1 on error and 0 on success
 */
int TskImageFileTsk::open()
{
    if (!m_images.empty()) {
        close();        
    }
    std::vector<std::string> images = m_db.getImageNames();
    if (images.empty()) {
        LOGERROR(L"TskImageFileTsk::open: Error getting image names from ImgDB");
        return -1;
    }
    for (size_t i = 0; i < images.size(); i++) {
        m_images.push_back(images[i]);
    }
    return openImages();
}

/**
 * Open the image using the names that were already populated in
 * m_images.  Used internally by both open() methods.
 * @returns -1 on error.
 */
int TskImageFileTsk::openImages(const TSK_IMG_TYPE_ENUM imageType,
                                const unsigned int sectorSize) 
{
    m_images_ptrs = (const char **)malloc(m_images.size() * sizeof(char *));
    if (m_images_ptrs == NULL)
        return -1;

    int i = 0;
    for(std::vector<std::string>::iterator list_iter = m_images.begin(); 
        list_iter != m_images.end(); list_iter++) {
            m_images_ptrs[i++] = (*list_iter).c_str();
    }

    m_img_info = tsk_img_open_utf8(i, m_images_ptrs, imageType, sectorSize);
    if (m_img_info == NULL) 
    {
        std::wstringstream logMessage;
        logMessage << L"TskImageFileTsk::openImages - Error with tsk_img_open: " << tsk_error_get() << std::endl;
        LOGERROR(logMessage.str());

        return -1;
    }

    return 0;
}


void TskImageFileTsk::close()
{
    if (m_img_info) {
        tsk_img_close(m_img_info);
        m_img_info = NULL;
    }

    if (m_images_ptrs) {
        free(m_images_ptrs);
        m_images_ptrs = NULL;
    }

    m_images.clear();

    // Close the handles in m_openFiles and m_openFs
    for (uint32_t i = 0; i < m_openFiles.size(); i++)
        closeFile(i);

    std::for_each(m_openFs.begin(), m_openFs.end(), (&TskImageFileTsk::closeFs));
}

/*
 * @param start Sector offset to start reading from in current sector run
 * @param len Number of sectors to read
 * @param a_buffer Buffer to read into (must be of size a_len * 512 or larger)
 * @returns -1 on error or number of sectors read
 */
int TskImageFileTsk::getSectorData(const uint64_t sect_start, 
                                const uint64_t sect_len, 
                                char *buffer)
{
    int retval = getByteData(sect_start*512, sect_len*512, buffer);
    if (retval != -1)
        return retval / 512;
    else
        return retval;
}

/*
 * @param byte_start Byte offset to start reading from start of file
 * @param byte_len Number of bytes to read
 * @param buffer Buffer to read into (must be of size byte_len or larger)
 * @returns -1 on error or number of bytes read
 */
int TskImageFileTsk::getByteData(const uint64_t byte_start, 
                                const uint64_t byte_len, 
                                char *buffer)
{
    if (m_img_info == NULL) {
        if (open() != 0)
            return -1;
    }

    int retval = tsk_img_read(m_img_info, byte_start, buffer, (size_t)(byte_len));
    if (retval == -1) {
        std::wstringstream message;
        message << L"TskImageFileTsk::getByteData - tsk_img_read -- start: " 
            << byte_start << " -- len: " << byte_len
            << "(" << tsk_error_get() << ")" << std::endl;
        LOGERROR(message.str());
        return -1;
    }

    return retval;
}

int TskImageFileTsk::extractFiles()
{
    // @@@ Add Sanity check that DB is empty 
    if (m_img_info == NULL) {
        LOGERROR(L"TskImageFileTsk::extractFiles: Images not open yet\n");
        return 1;
    }

    m_db.addImageInfo((int)m_img_info->itype, m_img_info->sector_size);

    for (uint32_t i = 0; i < m_images.size(); i++) {
        const char *img_ptr = NULL;
        img_ptr = m_images[i].c_str();
        m_db.addImageName(img_ptr);
     }

    TSKAutoImpl tskAutoImpl;
    if (tskAutoImpl.openImage(m_img_info)) 
    {
        std::wstringstream msg;
        msg << L"TSKExtract::processImage - Error opening image: " << tsk_error_get() << std::endl;
        LOGERROR(msg.str());
        return 1;
    }

    // TskAutoImpl will log errors as they occur
    tskAutoImpl.extractFiles();

    // It's possible that this is an image with no volumes or file systems.
    // Scan the image for file systems starting at sector 0.
    // By default it will scan 1024 sectors.
    if (m_db.getNumVolumes() == 0)
    {
        tskAutoImpl.scanImgForFs(0);
    }

    return 0;
}

int TskImageFileTsk::openFile(const uint64_t fileId)
{
    if (m_img_info == NULL) {
        if (open() != 0)
            return -1;
    }

    // Use ImgDb::getFileUniqueIdentifiers to get the four needed values.
    uint64_t fsByteOffset = 0;
    uint64_t fsFileId = 0;
    int attrType = TSK_FS_ATTR_TYPE_NOT_FOUND;
    int attrId = 0;

    if (m_db.getFileUniqueIdentifiers(fileId, fsByteOffset, fsFileId, attrType, attrId) != 0)
    {
        LOGERROR(L"TskImageFileTsk::openFile - Error getting file identifiers.\n");
        return -1;
    }

    // Check if the file system at the offset is already open (using m_openFs).  If not, open it (tsk_fs_open) and add it to the map.
    TSK_FS_INFO * fsInfo = m_openFs[fsByteOffset];

    if (fsInfo == NULL)
    {
        // Open the file system and add it to the map.
        fsInfo = tsk_fs_open_img(m_img_info, fsByteOffset, TSK_FS_TYPE_DETECT);

        if (fsInfo == NULL)
        {
            std::wstringstream errorMsg;
            errorMsg << L"TskImageFileTsk::openFile - Error opening file system : " << tsk_error_get();
            LOGERROR(errorMsg.str());
            return -1;
        }

        m_openFs[fsByteOffset] = fsInfo;
    }

    // Find a new entry in m_openFiles and use tsk_fs_file_open to open the file and save the handle in m_openFiles. 
    TSK_FS_FILE * fsFile = tsk_fs_file_open_meta(fsInfo, NULL, fsFileId);

    if (fsFile == NULL)
    {
        std::wstringstream errorMsg;
        errorMsg << L"TskImageFileTsk::openFile - Error opening file : " << tsk_error_get();
        LOGERROR(errorMsg.str());
        return -1;
    }

    const TSK_FS_ATTR * fsAttr = tsk_fs_file_attr_get_id(fsFile, attrId);

    // @@@ TSK_ATTR_TYPE_ENUM should have a value added to it to represent an
    // empty (or null) attribute type and we should then compare attrType against
    // this enum value instead of 0.

    // It is possible to have a file with no attributes. We only report an
    // error if we are expecting a valid attribute.
    if (attrType != TSK_FS_ATTR_TYPE_NOT_FOUND && fsAttr == NULL)
    {
        std::wstringstream msg;
        msg << L"TskImageFileTsk::openFile - Error getting attribute : " << tsk_error_get();
        LOGERROR(msg.str());
        return -1;
    }

    TskImageFileTsk::OPEN_FILE * openFile = new TskImageFileTsk::OPEN_FILE();
    openFile->fsFile = fsFile;
    openFile->fsAttr = fsAttr;

    m_openFiles.push_back(openFile);

    // Return the index into m_openFiles
    return m_openFiles.size() - 1;
}

int TskImageFileTsk::readFile(const int handle, 
                              const TSK_OFF_T byte_offset, 
                              const size_t byte_len, 
                              char * buffer)
{
    TskImageFileTsk::OPEN_FILE * openFile = m_openFiles[handle];

    if (openFile == NULL || openFile->fsFile == NULL)
    {
        std::wstringstream errorMsg;
        errorMsg << L"TskImageFileTsk::readFile - Either OPEN_FILE or TSK_FS_FILE is null." << std::endl;
        LOGERROR(errorMsg.str());
        return -1;
    }

    // fsAttr can be NULL if the file has no attributes.
    if (openFile->fsAttr == NULL || (TSK_OFF_T)byte_offset >= openFile->fsAttr->size)
    {
        // If the offset is larger than the attribute size then there is nothing left to read.
        return 0;
    }

    int bytesRead = tsk_fs_attr_read(openFile->fsAttr, byte_offset, buffer, 
                                          byte_len, TSK_FS_FILE_READ_FLAG_NONE);
    if (bytesRead == -1)
    {
        std::wstringstream errorMsg;
        errorMsg << L"TskImageFileTsk::readFile - Error reading file (FS_OFFSET: " 
            << openFile->fsFile->fs_info->offset << " - ID: "
            << openFile->fsFile->meta->addr << " - " 
            << ((openFile->fsFile->meta->flags & TSK_FS_META_FLAG_ALLOC) ? "Allocated" : "Deleted")
            << ") (" 
            << tsk_error_get() << ")" << std::endl;
        LOGERROR(errorMsg.str());
    }

    return bytesRead;
}

int TskImageFileTsk::closeFile(const int handle)
{
    // get the handle from m_openFiles
    TskImageFileTsk::OPEN_FILE * openFile = m_openFiles[handle];

    if (openFile == NULL || openFile->fsFile == NULL)
    {
        std::wstringstream errorMsg;
        errorMsg << L"TskImageFileTsk::closeFile - Either OPEN_FILE ot TSK_FS_FILE is null." << std::endl;
        LOGERROR(errorMsg.str());
        return -1;
    }

    // close the file
    tsk_fs_file_close(openFile->fsFile);

    // remove the entry from m_openFiles
    m_openFiles.erase(m_openFiles.begin() + handle);

    // delete the struct
    delete openFile;

    return 0;
}

std::vector<std::wstring> TskImageFileTsk::getFileNamesW() const
{
    std::vector<std::wstring>imagesWide;
    for (size_t i = 0; i < imagesWide.size(); i++) {
        imagesWide.push_back(TskUtilities::toUTF16(m_images[i]));
    }
    return imagesWide;
}

int TskImageFileTsk::open(const TSK_TCHAR *imageFile, 
                          const TSK_IMG_TYPE_ENUM imageType,
                          const unsigned int sectorSize)
{
    if (!m_images.empty()) {
        close();        
    }
#ifdef TSK_WIN32
    m_images.push_back(TskUtilities::toUTF8(imageFile));
#else
    m_images.push_back(std::string(imageFile));
#endif
    return openImages(imageType, sectorSize);
}

int TskImageFileTsk::open(const int numberOfImages, 
                          const TSK_TCHAR * const imageFile[], 
                          const TSK_IMG_TYPE_ENUM imageType,
                          const unsigned int sectorSize)
{
    if (!m_images.empty()) {
        close();        
    }
    for (int i = 0; i < numberOfImages; i++) {
#ifdef WIN32
        m_images.push_back(TskUtilities::toUTF8(imageFile[i]));
#else
        m_images.push_back(std::string(imageFile[i]));
#endif
    }
    return openImages(imageType, sectorSize);
}

int TskImageFileTsk::open(const std::string &imageFile, 
                          const TSK_IMG_TYPE_ENUM imageType,
                          const unsigned int sectorSize)
{
    if (!m_images.empty()) {
        close();        
    }
    m_images.push_back(imageFile);
    return openImages(imageType, sectorSize);
}

int TskImageFileTsk::open(const std::wstring &imageFile, 
                          const TSK_IMG_TYPE_ENUM imageType,
                          const unsigned int sectorSize)
{
    return open(TskUtilities::toUTF8(imageFile), imageType, sectorSize);
}

int TskImageFileTsk::open(const std::vector<std::string> &imageFile, 
                          const TSK_IMG_TYPE_ENUM imageType,
                          const unsigned int sectorSize)
{
    if (!m_images.empty()) {
        close();        
    }
    for (size_t i = 0; i < imageFile.size(); i++) {
        m_images.push_back(imageFile[i]);
    }
    return openImages(imageType, sectorSize);
}

int TskImageFileTsk::open(const std::vector<std::wstring> &imageFile, 
                          const TSK_IMG_TYPE_ENUM imageType,
                          const unsigned int sectorSize)
{
    if (!m_images.empty()) {
        close();        
    }
    for (size_t i = 0; i < imageFile.size(); i++) {
        m_images.push_back(TskUtilities::toUTF8(imageFile[i]));
    }
    return openImages(imageType, sectorSize);
}


