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

class TSK_FRAMEWORK_API Scheduler
{
public:
    virtual ~Scheduler();
    /* Returns 1 on error */
    virtual int scheduleTask(int task, const void * args) = 0;
};
#endif
