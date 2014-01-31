/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2012 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */
#include "TskSchedulerQueue.h"

int TskSchedulerQueue::schedule(Scheduler::TaskType task, uint64_t startId, uint64_t endId)
{
    if (endId < startId) {
        // @@@ Log a message
        return -1;
    }

    for (uint64_t i = startId; i <= endId; i++) {
        TskSchedulerQueue::task_struct *t = new(task_struct);
        t->task = task;
        t->id = i;
        m_queue.push(t);
    }
    return 0;
};

Scheduler::task_struct *TskSchedulerQueue::nextTask() 
{
    if (m_queue.empty())
        return NULL;
    
    task_struct *t = m_queue.front();
    m_queue.pop();
    return t;
};