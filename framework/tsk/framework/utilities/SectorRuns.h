/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2012 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

#ifndef _OSS_SECTORRUNS_H
#define _OSS_SECTORRUNS_H

#include "tsk/framework/framework_i.h"

/**
 * Stores a list of runs (which have a starting sector and length).
 * Can be used to store information about a file, unused areas of an
 * image, or ...
 */
class TSK_FRAMEWORK_API SectorRuns
{
public:
    SectorRuns();
    virtual ~SectorRuns();

    int addRun(uint64_t start, uint64_t len, int vol_id);

    int next();     // updates the current run; return -1 if none available
    void reset();
    int getData(uint64_t offset, int len, char * buffer) const;   // fills buffer with data from current run
                                                  // returns the number of bytes written
                                                  // returns -1 if no further data in the run
    uint64_t getDataLen() const;
    uint64_t getDataStart() const;
    int getVolID() const;

private:
    typedef struct {
        uint64_t start;
        uint64_t len;
        int vol_id;
    } SectorRun;

    SectorRun *m_runs;
    unsigned int m_numRunsUsed;
    unsigned int m_numRunsAlloc;
    unsigned int m_curRun; 
};

#endif
