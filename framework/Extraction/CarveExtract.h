/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2011 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

#ifndef _OSS_CARVEEXTRACT_H
#define _OSS_CARVEEXTRACT_H

#include "Services/TskImgDB.h"

class TSK_FRAMEWORK_API CarveExtract
{
public:
    virtual ~CarveExtract() = 0;
    /* @returns 1 on error */
    virtual int processFile(TskImgDB * imgDB, int sequence) = 0;
};
#endif
