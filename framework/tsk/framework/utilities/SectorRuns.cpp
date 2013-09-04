/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2012 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

#include "SectorRuns.h"
#include "tsk/framework/services/TskServices.h"

/* This class is used to store a list of sector runs.  It is 
 * used to identify which runs contain unallocated data.
 */
SectorRuns::SectorRuns() :
    m_runs(NULL),
    m_numRunsUsed(0),
    m_numRunsAlloc(0),
    m_curRun(0)
{
    // @@@
    // Constructor should query the DB
    // and build a list of IDs to empty sectors.
    // The list is what will be iterated over.
}

SectorRuns::~SectorRuns()
{
    if (m_runs)
        free(m_runs);
    m_runs = NULL;
}


/**
 * Add a run to the list. 
 *
 * @param a_start Starting sector address relative to start of image file
 * @param a_len Length of run in sectors. 
 * @param a_vol_id Volume ID that run is located in
 * @returns -1 on error
 */
int SectorRuns::addRun(uint64_t a_start, uint64_t a_len, int a_vol_id)
{
    if (m_numRunsUsed == m_numRunsAlloc)
    {
        m_numRunsAlloc += 64;
        if ((m_runs = (SectorRun *)realloc(m_runs, m_numRunsAlloc * sizeof(SectorRun))) == NULL)
        {
            TskServices::Instance().getLog().logError(L"SectorRuns::addRun - Error allocating sector runs\n");
            return -1;
        }
    }
    m_runs[m_numRunsUsed].start = a_start;
    m_runs[m_numRunsUsed].len = a_len;
    m_runs[m_numRunsUsed].vol_id = a_vol_id;
    m_numRunsUsed++;
    return 0;
}

/** 
 * reset so that the next get() returns data on the first entry.
 */
void SectorRuns::reset()
{
    m_curRun = 0;
}

/**
 * Advances internal pointer to next run.
 *
 * @returns -1 when at end of list
 */
int SectorRuns::next()
{
    if (m_curRun + 1 == m_numRunsUsed)
        return -1;

    m_curRun++;
    return 0;
}

/**
 * Get the length of the current entry.
 * @returns length of run in sectors
 */
uint64_t SectorRuns::getDataLen() const
{
    if (m_curRun >= m_numRunsUsed)
        return 0;
    return m_runs[m_curRun].len;
}

/**
 * Get starting address of current entry. 
 * @returns start of run in sectors
 */
uint64_t SectorRuns::getDataStart() const
{
    if (m_curRun >= m_numRunsUsed)
        return 0;
    return m_runs[m_curRun].start;
}

/**
 * Get volume id of current entry.
 * @returns volume ID of run in sectors
 */
int SectorRuns::getVolID() const
{
    if (m_curRun >= m_numRunsUsed)
        return 0;
    return m_runs[m_curRun].vol_id;
}

/**
 * Read data in the current entry into the buffer.
 *
 * @param a_offsetSect Sector offset to start reading from (relative to start of current sector run)
 * @param a_lenSect Number of sectors to read
 * @param a_buffer Buffer to read into (must be of size a_len * 512 or larger)
 * @returns -1 on error or number of sectors read
 */
int SectorRuns::getData(uint64_t a_offsetSect, int a_lenSect, char * a_buffer) const
{
    if (m_curRun >= m_numRunsUsed)
        return -1;

    if (a_offsetSect > m_runs[m_curRun].len) 
        return -1;

    uint64_t len_toread = a_lenSect;
    if (a_offsetSect + a_lenSect > m_runs[m_curRun].len)
        len_toread = m_runs[m_curRun].len - a_offsetSect;

    return TskServices::Instance().getImageFile().getSectorData(m_runs[m_curRun].start + a_offsetSect, len_toread, a_buffer);
}
