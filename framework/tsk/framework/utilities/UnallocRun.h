/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2012 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

#ifndef _OSS_UNALLOCRUN_H
#define _OSS_UNALLOCRUN_H

#include "tsk/framework/framework_i.h"

/**
 * Stores information that can map a region in the original disk image
 * to a region in one of the chunks of unallocated space (as created by
 * the CarvePrep implementation. 
 */
class TSK_FRAMEWORK_API UnallocRun
{
public:
    UnallocRun(int a_volId, int a_unallocImgId, uint64_t a_unallocStart,
        uint64_t a_length, uint64_t a_allocStart);
    ~UnallocRun();

    int getVolId() const;
    int getUnallocImgId() const;
    uint64_t getUnallocStart() const;
    uint64_t getLength() const;
    uint64_t getAllocStart() const;

private:
    int m_volId;
    int m_unallocImgId;
    uint64_t m_unallocStart;
    uint64_t m_length;
    uint64_t m_origStart;
};

#endif
