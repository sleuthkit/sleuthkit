/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2012 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

#include "framework_i.h"

#ifndef _TSK_AUTO_IMPL_H
#define _TSK_AUTO_IMPL_H

#ifdef __cplusplus

// Include the other TSK header files
#include "tsk3/libtsk.h"
#include "Services/TskImgDB.h"
#include <map>
#include <string>

/** 
 * Implements TskAuto and is used to analyze the data in a disk image
 * and populate TskImgDB with the results.
 */
class TSK_FRAMEWORK_API TSKAutoImpl:public TskAuto {
public:
    TSKAutoImpl();
    virtual ~ TSKAutoImpl();

    virtual uint8_t openImage(TSK_IMG_INFO *);
    virtual void closeImage();

    virtual TSK_FILTER_ENUM filterVol(const TSK_VS_PART_INFO * vs_part);
    virtual TSK_FILTER_ENUM filterFs(TSK_FS_INFO * fs_info);
    virtual TSK_RETVAL_ENUM processFile(TSK_FS_FILE * fs_file, const char *path);
    virtual uint8_t handleError();

    uint8_t scanImgForFs(const uint64_t sect_start, const uint64_t sect_count = 1024);

private:
    TskImgDB &m_db;
    int m_curFsId;
    int m_curVsId;
    bool m_vsSeen;
    uint64_t m_numFilesSeen;
    time_t m_lastUpdateMsg;

    TSK_RETVAL_ENUM insertFileData(TSK_FS_FILE * fs_file,
        const TSK_FS_ATTR *, const char *path, uint64_t & fileId);
    TSK_RETVAL_ENUM insertBlockData(const TSK_FS_ATTR * fs_attr);
    virtual TSK_RETVAL_ENUM processAttribute(TSK_FS_FILE *,
        const TSK_FS_ATTR * fs_attr, const char *path);
    void createDummyVolume(const TSK_DADDR_T sect_start, const TSK_DADDR_T sect_len, 
                           char * desc, TSK_VS_PART_FLAG_ENUM flags);
};

#endif

#endif
