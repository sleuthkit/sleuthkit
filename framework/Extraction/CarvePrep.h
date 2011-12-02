/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2011 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

#ifndef _OSS_CARVEPREP_H
#define _OSS_CARVEPREP_H

#include "Services/TskImgDB.h"

class TSK_FRAMEWORK_API CarvePrep
{
public:
    virtual ~CarvePrep(void) = 0;
    /* @returns 1 on error */
    virtual int processSectors(TskImgDB * a_img,  bool a_toSchedule) = 0;
};

#endif
