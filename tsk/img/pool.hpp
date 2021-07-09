/*
* The Sleuth Kit
*
* Brian Carrier [carrier <at> sleuthkit [dot] org]
* Copyright (c) 2019 Brian Carrier.  All rights reserved
*
* This software is distributed under the Common Public License 1.0
*/

/*
* Contains the pool image structure.
*/

#ifndef _POOL_H
#define _POOL_H

#include "../pool/tsk_pool.h"
#include "../fs/tsk_apfs.hpp"

#ifdef __cplusplus
extern "C" {
#endif

    typedef struct {
        TSK_IMG_INFO img_info;

        const TSK_POOL_INFO *pool_info;
        TSK_DADDR_T pvol_block;

    } IMG_POOL_INFO;

#ifdef __cplusplus
}
#endif
#endif
