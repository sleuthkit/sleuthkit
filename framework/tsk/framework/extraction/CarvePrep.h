/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2012 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

/**
 * \file CarvePrep.h
 * Contains the interface of the abstract CarvePrep class.
 */
#ifndef _TSK_CARVE_PREP_H
#define _TSK_CARVE_PREP_H

#include "tsk/framework/services/TskImgDB.h"

/**
 * Interface for class that prepares for later carving. 
 * CarvePrep is responsible for making unallocated sectors image files for 
 * later carving.  The implementation can choose to create 1 or dozens
 * of such files.  Refer to \ref fw_extract_carve for details,
 * but this class should get unallocated image IDs from TskImgDB,
 * populate the unalloc_alloc map in the database, and schedule
 * each unallocated image for later carving. 
 */
class TSK_FRAMEWORK_API CarvePrep
{
public:
    /**
     * Virtual destructor to ensure derived class constructors are called
     * polymorphically.
     */
    virtual ~CarvePrep(void) {}
    
    /**
     * Make one or more unallocated sectors image files to carve. 
     *
     * @returns 0 on success, 1 on error. 
     */
    virtual int processSectors() = 0;
};

#endif
