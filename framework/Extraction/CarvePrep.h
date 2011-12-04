/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2011 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

#ifndef _OSS_CARVEPREP_H
#define _OSS_CARVEPREP_H

#include "Services/TskImgDB.h"

/**
 * Interface for class that prepares for later carving. 
 * Prep and carving is separate so that the unallocated data to 
 * be carved can be broken up into smaller chunks and different 
 * nodes in a cluster could process each chunk.  The prep step
 * would make the chunks.
 */
class TSK_FRAMEWORK_API CarvePrep
{
public:
    virtual ~CarvePrep(void) = 0;
    /**
     * a_img
     * a_toSchedule True if the scheduler should be called to queue
     * up the data or false if it shoudl be processed now.
     * @returns 1 on error 
     */
    virtual int processSectors(TskImgDB * a_img,  bool a_toSchedule) = 0;
};

#endif
