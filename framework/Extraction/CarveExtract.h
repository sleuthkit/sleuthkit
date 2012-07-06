/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2012 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

#ifndef _OSS_CARVEEXTRACT_H
#define _OSS_CARVEEXTRACT_H

#include "Services/TskImgDB.h"

/**
 * Interface for class that will carve an unallocated sectors image file. The 
 * design assumes that the unallocated sectors image file was created by a 
 * CarvePrep implementation. 
 */
class TSK_FRAMEWORK_API CarveExtract
{
public:
    virtual ~CarveExtract() {}
    /**
     * Carve a specified unallocated sectors image file. 
     *
     * @param unallocImgId Id of the file to carve.
     * @returns 1 on error. 
     */
    virtual int processFile(int unallocImgId) = 0;
};
#endif
