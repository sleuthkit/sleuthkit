/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2018-2019 BlackBag Technologies.  All Rights reserved
 *
 * This software is distributed under the Common Public License 1.0
 */
#pragma once

#include "tsk_pool.h"

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#define APFS_POOL_NX_BLOCK_LAST_KNOWN_GOOD 0ULL
#define APFS_POOL_NX_BLOCK_LATEST 0xFFFFFFFFFFFFFFFFULL

typedef uint64_t apfs_block_num;

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus
