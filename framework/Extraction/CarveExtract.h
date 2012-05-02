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
 * Interface for class that will carve an unallocated image file. 
 * The design assumption is that the unallocated image file was
 * created by a CarvePrep implementation.  The framework does not
 * place any requirements on where the unallocated image files are
 * stored -- it is up to CarvePrep to decide. 
 */
class TSK_FRAMEWORK_API CarveExtract
{
public:
    virtual ~CarveExtract() = 0;
    /**
     * Carve a specified unallocated image. 
     * @param unallocImgId Id of the unallocated image to carve
     * @returns 1 on error 
     */
    virtual int processFile(int unallocImgId) = 0;
};
#endif
