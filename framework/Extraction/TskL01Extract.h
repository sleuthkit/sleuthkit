/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2013 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

/**
 * \file
 * 
 */
#ifndef _TSK_L01EXTRACT_H
#define _TSK_L01EXTRACT_H

#include "TskImageFile.h"
#include "Services/TskImgDB.h"
#include "Services/Log.h"
#include "tsk3/libtsk.h"

#include <vector>
#include <map>

#ifndef HAVE_LIBEWF
#define HAVE_LIBEWF 1
#endif

namespace ewf
{
    #include "ewf.h"
}



/**
 * @todo This might be used by class TskImageFileTsk
 * @todo derive from a new base class (or none at all)?
 * 
 */
class TSK_FRAMEWORK_API TskL01Extract : public TskImageFile
{
public:
    TskL01Extract();

    virtual ~TskL01Extract();

    virtual int open(const std::vector<std::wstring> &images);
    virtual int open(const TSK_TCHAR *imageFile);
    virtual int open();
    virtual void close();

    virtual std::vector<std::wstring> filenames() const { return m_images; }

    virtual int getSectorData(const uint64_t sect_start, 
                              const uint64_t sect_len, 
                              char *buffer);

    virtual int getByteData(const uint64_t byte_start, 
                            const uint64_t byte_len, 
                            char *buffer);

    virtual int extractFiles();

    virtual int openFile(const uint64_t fileId);

    virtual int readFile(const int handle, 
                         const uint64_t byte_offset, 
                         const size_t byte_len, 
                         char * buffer);

    virtual int closeFile(const int handle);

private:
    struct TSK_FRAMEWORK_API OPEN_FILE
    {
        TSK_FS_FILE * fsFile;
        const TSK_FS_ATTR * fsAttr;
    };

    int openContainers();
    void traverse(ewf::libewf_file_entry_t *parent, int index);
    void printName(ewf::libewf_file_entry_t *node);

    TskImgDB &m_db;
    TSK_IMG_INFO *m_img_info;
    
    // Not actually images; these refer to L01 files
    std::vector<std::wstring> m_images; 
    const wchar_t **m_images_ptrs;

    //std::vector<OPEN_FILE *> m_openFiles; // maps handle returned from openFile() to the open TSK_FS_FILE object
    //std::map<uint64_t, TSK_FS_INFO *> m_openFs; // maps the byte offset of a file system to its open object.
};

#endif
