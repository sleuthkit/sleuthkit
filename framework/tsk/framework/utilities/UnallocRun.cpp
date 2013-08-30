/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2012 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

#include "UnallocRun.h"

/**
 * Stores mapping between the unallocated images that are used for carving and
 * the original images.
 * @param a_volId Volume ID in original image that sector run is located in.
 * @param a_unallocImgId ID of the unallocated image
 * @param a_unallocStart Starting sector in unallocated image
 * @param a_length Number of sectors in run
 * @param a_allocStart Starting sector in original image
 */
UnallocRun::UnallocRun(int a_volId, int a_unallocImgId, uint64_t a_unallocStart,
                       uint64_t a_length, uint64_t a_allocStart) :
        m_volId(a_volId),
        m_unallocImgId(a_unallocImgId),
        m_unallocStart(a_unallocStart),
        m_length(a_length),
        m_origStart(a_allocStart)
{
}

UnallocRun::~UnallocRun()
{
}

int UnallocRun::getVolId() const
{
    return m_volId;
}

int UnallocRun::getUnallocImgId() const
{
    return m_unallocImgId;
}

uint64_t UnallocRun::getUnallocStart() const
{
    return m_unallocStart;
}

uint64_t UnallocRun::getLength() const
{
    return m_length;
}

uint64_t UnallocRun::getAllocStart() const
{
    return m_origStart;
}
