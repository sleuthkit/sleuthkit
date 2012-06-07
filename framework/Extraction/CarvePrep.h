/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2012 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

#ifndef _OSS_CARVEPREP_H
#define _OSS_CARVEPREP_H

#include "Services/TskImgDB.h"

/**
 * Interface for class that prepares for later carving. 
 * CarvePrep is responsible for making unallocated image files
 * (image files that contain only unallocated data) for later
 * carving.  The implementation can choose to create 1 or dozens
 * of such files.  Refer to \ref fw_extract_carve for details,
 * but this class should get unallocated image IDs from TskImgDB,
 * populate the unalloc_alloc map in the database, and schedule
 * each unallocated image for later carving. 
 */
class TSK_FRAMEWORK_API CarvePrep
{
public:
    virtual ~CarvePrep(void) = 0;
    /**
     * Make one or more files to carve. 
     * @param a_toSchedule True if the scheduler should be called to queue
     * up the data or false if it should be processed now.
     * @returns 1 on error 
     */
    virtual int processSectors(bool a_toSchedule) = 0;
};

#endif
