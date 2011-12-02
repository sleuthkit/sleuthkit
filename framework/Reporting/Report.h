/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2011 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

#ifndef _OSS_REPORT_H
#define _OSS_REPORT_H

#include "Services/TskImgDB.h"

class TSK_FRAMEWORK_API Report
{
public:
    virtual ~Report() = 0;
    /* @returns 1 on error */
    virtual int runReport(TskImgDB * a_img) = 0;
};
#endif
