/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2012 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

#ifndef _OSS_SCHEDULER_H
#define _OSS_SCHEDULER_H

#include "tsk/framework/framework_i.h"


/**
 * Interface for class that will handle scheduling of tasks.  
 * Different implementations will deal with how to get the tasks out (nextTask())
 * because some will immediately schedule and others may keep a sorted
 * list locally.  
 * The current scheduler can be registered with and retrieved from TskServices.
 */
class TSK_FRAMEWORK_API Scheduler
{
public:
    /// Types of tasks that can be scheduled or performed. 
    enum TaskType {
        Extract, ///< Analyze image and add files to database.
        Carve,  ///< Carve a file that contains unallocated data.
        FileAnalysis,    ///< Analye a file using a file analysis pipeline
        Reporting   ///< Run the reporting / post-processing pipeline
    };

    
    /// Describes a single task to be scheduled or perform. 
    typedef struct {
        Scheduler::TaskType task;   ///< type of task to perform
        uint64_t id;    ///< ID of object to run task on
    } task_struct;

    virtual ~Scheduler();
    
    /**
     * Schedule a new task for the range of IDs.
     * @param task Task to schedule
     * @param startId Starting ID of object to process
     * @param endId Ending ID of object to process.
     * @returns 1 on error 
     */
    virtual int schedule(Scheduler::TaskType task, uint64_t startId, uint64_t endId) {
        return 0;
    };

    /**
     * Schedule a new task for a specific ID.
     * @param task Task to schedule
     * @returns 1 on error 
     */
    int schedule(Scheduler::task_struct &task) {
        return schedule(task.task, task.id, task.id);
    };

    /**
     * Get the next task to process from the scheduler.  Note that different
     * scheduling systems have a pull versus push architecture. This method is for 
     * pulling designs and may return NULL in push designs (i.e. if the scheduler is
     * a wrapper around another distributed system scheduler, then it may constantly 
     * push tasks to the system scheduler and this will always return NULL because everything
     * has already been submitted).
     * @returns Next task to run or NULL if there are none to process.  Caller must 
     * free the object.
     */
    virtual task_struct *nextTask() = 0;
};
#endif
