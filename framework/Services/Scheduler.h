/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2011 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

#ifndef _OSS_SCHEDULER_H
#define _OSS_SCHEDULER_H

#include "framework_i.h"


/**
 * Interface for class that will handle scheduling of tasks.  
 * Different implementations will deal with how to get the tasks out 
 * because some will immediately schedule and others may keep a sorted
 * list locally. 
 * The current scheduler can be registered with and retrieved from TskServices.
 */
class TSK_FRAMEWORK_API Scheduler
{
public:
    virtual ~Scheduler();
    /* Returns 1 on error */
    virtual int scheduleTask(int task, const void * args) = 0;

    enum TaskType {
        Extract, ///< Analyze image and add files to database.
        Carve,  ///< Carve a file that contains unallocated data.
        FileAnalysis,    ///< Analye a file using a file analysis pipeline
        Reporting   ///< Run the reporting / post-processing pipeline
    };
    virtual int schedule(Scheduler::TaskType task, uint64_t startId, uint64_t endId) {
        return 0;
    };
};
#endif
