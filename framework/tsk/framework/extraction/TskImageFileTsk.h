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
 * \file TskImageFile.h
 * An implementation of the TskImageFile class that uses The Sleuth Kit.
 */
#ifndef _TSK_IMAGEFILETSK_H
#define _TSK_IMAGEFILETSK_H

#include "TskImageFile.h"
#include "tsk/framework/services/TskImgDB.h"
#include "tsk/framework/services/Log.h"
#include "tsk/libtsk.h"

#include <vector>
#include <map>

/// A Sleuth Kit implementation of the TskImageFile interface. 
/**
 * TskImageFile defines an interface for interacting with disk images.
 * TskImageFileTsk is an implementation of that interface that uses The Sleuth Kit 
 */
class TSK_FRAMEWORK_API TskImageFileTsk : public TskImageFile
{
public:
    TskImageFileTsk();

    virtual ~TskImageFileTsk();

    virtual int open();
    virtual void close();

    virtual std::vector<std::string> getFileNames() const { return m_images; }
    virtual std::vector<std::wstring> getFileNamesW() const;

    virtual int getSectorData(const uint64_t sect_start, 
                              const uint64_t sect_len, 
                              char *buffer);

    virtual int getByteData(const uint64_t byte_start, 
                            const uint64_t byte_len, 
                            char *buffer);

    virtual int extractFiles();

    virtual int openFile(const uint64_t fileId);

    virtual int readFile(const int handle, 
                         const TSK_OFF_T byte_offset, 
                         const size_t byte_len, 
                         char * buffer);

    virtual int closeFile(const int handle);

    virtual int open(const TSK_TCHAR *imageFile, 
                     const TSK_IMG_TYPE_ENUM imageType = TSK_IMG_TYPE_DETECT, 
                     const unsigned int sectorSize = 0);

    virtual int open(const int numberOfImages, 
                     const TSK_TCHAR * const imageFile[], 
                     const TSK_IMG_TYPE_ENUM imageType = TSK_IMG_TYPE_DETECT, 
                     const unsigned int sectorSize = 0);

    virtual int open(const std::string &imageFile, 
                     const TSK_IMG_TYPE_ENUM imageType = TSK_IMG_TYPE_DETECT, 
                     const unsigned int sectorSize = 0);

    virtual int open(const std::wstring &imageFile, 
                     const TSK_IMG_TYPE_ENUM imageType = TSK_IMG_TYPE_DETECT, 
                     const unsigned int sectorSize = 0);

    virtual int open(const std::vector<std::string> &imageFile, 
                     const TSK_IMG_TYPE_ENUM imageType = TSK_IMG_TYPE_DETECT, 
                     const unsigned int sectorSize = 0);

    virtual int open(const std::vector<std::wstring> &imageFile,
                     const TSK_IMG_TYPE_ENUM imageType = TSK_IMG_TYPE_DETECT,
                     const unsigned int sectorSize = 0);

private:
    TskImgDB &m_db;
    TSK_IMG_INFO *m_img_info;
    std::vector<std::string> m_images;
    const char **m_images_ptrs;

    struct TSK_FRAMEWORK_API OPEN_FILE
    {
        TSK_FS_FILE * fsFile;
        const TSK_FS_ATTR * fsAttr;
    };

    std::vector<OPEN_FILE *> m_openFiles; // maps handle returned from openFile() to the open TSK_FS_FILE object
    std::map<uint64_t, TSK_FS_INFO *> m_openFs; // maps the byte offset of a file system to its open object.

    int openImages(const TSK_IMG_TYPE_ENUM imageType = TSK_IMG_TYPE_DETECT,
                   const unsigned int sectorSize = 0);

    static void closeFs(std::pair<uint64_t, TSK_FS_INFO *> pair);
};

#endif
