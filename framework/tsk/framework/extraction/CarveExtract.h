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
 * \file CarveExtract.h
 * Contains the interface of the abstract CarveExtract class.
 */
#ifndef _TSK_CARVEEXTRACT_H
#define _TSK_CARVEEXTRACT_H

#include "tsk/framework/services/TskImgDB.h"

/**
 * Interface for class that will carve an unallocated sectors image file. The 
 * design assumes that the unallocated sectors image file was created by a 
 * CarvePrep implementation. 
 */
class TSK_FRAMEWORK_API CarveExtract
{
public:
    /**
     * Virtual destructor to ensure derived class constructors are called
     * polymorphically.
     */
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
