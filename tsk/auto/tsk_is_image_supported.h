/*
 ** The Sleuth Kit
 ** 
 ** Brian Carrier [carrier <at> sleuthkit [dot] org]
 ** Copyright (c) 2010-2021 Brian Carrier.  All Rights reserved
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


#include "tsk/tsk_tools_i.h"
#include "tsk/util/detect_encryption.h"

class TskIsImageSupported:public TskAuto {


public:
    TskIsImageSupported();
    virtual TSK_RETVAL_ENUM processFile(TSK_FS_FILE * fs_file, const char *path);
    virtual TSK_FILTER_ENUM filterVol(const TSK_VS_PART_INFO * vs_part);
    virtual TSK_FILTER_ENUM filterPool(const TSK_POOL_INFO * pool_info);
    virtual TSK_FILTER_ENUM filterPoolVol(const TSK_POOL_VOLUME_INFO * pool_vol);
    virtual TSK_FILTER_ENUM filterFs(TSK_FS_INFO * fs_info);
    virtual uint8_t handleError();
    bool isImageSupported();
    bool isImageEncrypted();
    void printResults();
    
private:
    bool m_wasDataFound;
    bool m_wasEncryptionFound;
    bool m_wasPossibleEncryptionFound;
    bool m_wasFileSystemFound;
    bool m_wasUnsupported;
    char m_encryptionDesc[1024];
    char m_possibleEncryptionDesc[1024];
    char m_unsupportedDesc[1024];
};