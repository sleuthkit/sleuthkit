/*
 ** The Sleuth Kit
 **
 ** Brian Carrier [carrier <at> sleuthkit [dot] org]
 ** Copyright (c) 2010-2013 Brian Carrier.  All Rights reserved
 **
 ** This software is distributed under the Common Public License 1.0
 **
 */

/**
 * \file tsk_is_image_supported.cpp
 * Class to test whether a given image can be processed by tsk
 * 
 * Usage:
 *  Create a TskIsImageSupported object
 *  Call openImage
 *  Call findFilesInImg
 *  Call isImageSupported - if this returns true then the image is supported. If false or
 *                            if there was an error along the way, the image is not supported
 */

#include "tsk_is_image_supported.h"

TskIsImageSupported::TskIsImageSupported()
{
    m_wasDataFound = false;
}

bool TskIsImageSupported::isImageSupported()
{
    return m_wasDataFound ;
}


uint8_t TskIsImageSupported::handleError() 
{
    // we don't care about errors for this use case
    //fprintf(stderr, "%s", tsk_error_get());
    return 0;
}


TSK_RETVAL_ENUM TskIsImageSupported::processFile(TSK_FS_FILE * fs_file, const char *path)
{
    return TSK_OK;
}


TSK_FILTER_ENUM
TskIsImageSupported::filterFs(TSK_FS_INFO * fs_info)
{
    m_wasDataFound = true;
    return TSK_FILTER_SKIP;
}


TSK_FILTER_ENUM
TskIsImageSupported::filterVol(const TSK_VS_PART_INFO * vs_part)
{
    m_wasDataFound = true;
    return TSK_FILTER_SKIP;
}