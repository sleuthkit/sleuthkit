/*
 *
 *  The Sleuth Kit
 *
 *  Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 *  Copyright (c) 2010-2013 Basis Technology Corporation. All Rights
 *  reserved.
 *
 *  This software is distributed under the Common Public License 1.0
 */

/**
 * \file
 * 
 */

#include <iostream>
#include <sstream>
#include <algorithm>

#include "TskL01Extract.h"
//#include "TskAutoImpl.h"
#include "Services/TskServices.h"
#include "tsk3/base/tsk_base_i.h"

#ifndef HAVE_LIBEWF
#define HAVE_LIBEWF 1
#endif

namespace ewf
{
#include "ewf.h"
}

TskL01Extract::TskL01Extract() :
    m_db(TskServices::Instance().getImgDB())
{
    m_img_info = NULL;
    m_images_ptrs = NULL;
}

TskL01Extract::~TskL01Extract()
{
    close();
}

/**

*/
int TskL01Extract::open(const TSK_TCHAR *imageFile)
{
    if (!m_images.empty()) {
        close();        
    }
    m_images.push_back(imageFile);
    return openContainers();
}

int TskL01Extract::open(const std::vector<std::wstring> &images)
{
    return -1;
}

/*
 * Opens the image files listed in ImgDB for later analysis and extraction.  
 * @returns -1 on error and 0 on success
 */
int TskL01Extract::open()
{
    return -1;
}


int TskL01Extract::openContainers()
{
    m_images_ptrs = (const wchar_t **)malloc(m_images.size() * sizeof(wchar_t *));
    if (m_images_ptrs == NULL)
        return -1;

    int i = 0;
    for(std::vector<std::wstring>::iterator list_iter = m_images.begin(); 
        list_iter != m_images.end(); list_iter++)
    {
            m_images_ptrs[i++] = (*list_iter).c_str();
    }

    m_img_info = tsk_img_open(i, m_images_ptrs, TSK_IMG_TYPE_EWF_EWF, 512);
    if (m_img_info == NULL) 
    {
        std::wstringstream logMessage;
        logMessage << L"TskL01Extract::openContainers - Error with tsk_img_open: " << tsk_error_get() << std::endl;
        LOGERROR(logMessage.str());
        return -1;
    }

    ewf::IMG_EWF_INFO* ewfInfo = (ewf::IMG_EWF_INFO*)m_img_info;

    return 0;
}


void TskL01Extract::close()
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
}

/*
 * @param start Sector offset to start reading from in current sector run
 * @param len Number of sectors to read
 * @param a_buffer Buffer to read into (must be of size a_len * 512 or larger)
 * @returns -1 on error or number of sectors read
 */
int TskL01Extract::getSectorData(const uint64_t sect_start, 
                                const uint64_t sect_len, 
                                char *buffer)
{
    return -1;
}

/*
 * @param byte_start Byte offset to start reading from start of file
 * @param byte_len Number of bytes to read
 * @param buffer Buffer to read into (must be of size byte_len or larger)
 * @returns -1 on error or number of bytes read
 */
int TskL01Extract::getByteData(const uint64_t byte_start, 
                                const uint64_t byte_len, 
                                char *buffer)
{
    return -1;
}

int TskL01Extract::extractFiles()
{

    return 0;
}

int TskL01Extract::openFile(const uint64_t fileId)
{
    return -1;

}

int TskL01Extract::readFile(const int handle, 
                              const uint64_t byte_offset, 
                              const size_t byte_len, 
                              char * buffer)
{
    return -1;
}

int TskL01Extract::closeFile(const int handle)
{
    return -1;
}
