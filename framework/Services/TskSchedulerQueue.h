/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2012 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

#ifndef TSK_SCHEDULER_QUEUE
#define TSK_SCHEDULER_QUEUE

#include "Scheduler.h"
#include <queue>

/**
 * Implementation of the Scheduler interface that keeps a 
 * local queue of tasks to run. Can be used in a non-distributed
 * environment.
 */
class TSK_FRAMEWORK_API TskSchedulerQueue : public Scheduler {
public:
    typedef struct {
        Scheduler::TaskType task;   ///< type of task to perform
        uint64_t id;    ///< ID of object to run task on
    } task_struct;

    /* Returns 1 on error */
    int scheduleTask(int task, const void * args);
    int schedule(Scheduler::TaskType task, uint64_t startId, uint64_t endId);
    TskSchedulerQueue::task_struct *next();
private:
    std::queue <task_struct *> m_queue;  
};


#endif