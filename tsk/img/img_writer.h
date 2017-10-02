/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2005-2011 Brian Carrier.  All rights reserved 
 *
 * This software is distributed under the Common Public License 1.0
 */

/* 
 * Contains the single raw data file-specific functions and structures.
 */

#ifndef _IMG_WRITER_H
#define _IMG_WRITER_H

#include "tsk/base/tsk_base.h"

#ifdef __cplusplus
extern "C" {
#endif
    TSK_RETVAL_ENUM tsk_img_writer_create(TSK_IMG_INFO* img_info, const TSK_TCHAR * outputFileName);

    enum IMG_WRITER_BLOCK_STATUS_ENUM {
        IMG_WRITER_BLOCK_STATUS_UNALLOC = 0,
        IMG_WRITER_BLOCK_STATUS_ALLOC = 1,
        IMG_WRITER_BLOCK_STATUS_FINISHED = 2
    };
    typedef enum IMG_WRITER_BLOCK_STATUS_ENUM IMG_WRITER_BLOCK_STATUS_ENUM;

    typedef struct TSK_IMG_WRITER TSK_IMG_WRITER;
    struct TSK_IMG_WRITER {
        TSK_IMG_INFO * img_info;
        int is_finished;
        int finishProgress;
        int cancelFinish;

        TSK_TCHAR* fileName;
#ifdef TSK_WIN32
        HANDLE outputFileHandle;
#else
        int outputFileHandle;
#endif

        unsigned char* footer;

        uint32_t blockSize;
        TSK_OFF_T imageSize;
        uint32_t totalBlocks;
        uint32_t sectorBitmapLength;
        uint32_t sectorBitmapArrayLength;
        uint32_t sectorsPerBlock;
        TSK_OFF_T batOffset;
        TSK_OFF_T nextDataOffset;

        IMG_WRITER_BLOCK_STATUS_ENUM* blockStatus;
        uint32_t* blockToSectorNumber;
        unsigned char ** blockToSectorBitmap;

        TSK_RETVAL_ENUM(*add)(TSK_IMG_WRITER* img_writer, TSK_OFF_T addr, char *buffer, size_t len);
        TSK_RETVAL_ENUM(*close)(TSK_IMG_WRITER* img_writer);
        TSK_RETVAL_ENUM(*finish_image)(TSK_IMG_WRITER* img_writer);
    };

#ifdef __cplusplus
}
#endif
#endif
