/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2011 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

#ifndef _OSS_CARVEEXTRACT_H
#define _OSS_CARVEEXTRACT_H

#include "Services/TskImgDB.h"

/**
 * Interface for class that will carve a chunk of data. 
 * The design assumption is that the unallocated space has
 * already been broken up into multiple chunks and the 
 * corresponding information for each chunk is stored in the 
 * ImgDB. The sequence in this class corresponds to the chunk ID
 */
class TSK_FRAMEWORK_API CarveExtract
{
public:
    virtual ~CarveExtract() = 0;
    /**
     * @param sequence Id of chunk to carve
     * @returns 1 on error 
     */
    virtual int processFile(TskImgDB * imgDB, int sequence) = 0;
};
#endif
