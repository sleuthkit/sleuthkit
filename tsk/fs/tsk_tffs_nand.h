/*
** The Sleuth Kit
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2006-2011 Brian Carrier, Basis Technology.  All Rights reserved
** Copyright (c) 2003-2005 Brian Carrier.  All rights reserved
**
** TASK
** Copyright (c) 2002-2003 Brian Carrier, @stake Inc.  All rights reserved
**
** Copyright (c) 1997,1998,1999, International Business Machines
** Corporation and others. All Rights Reserved.
*/

/**
*\file tsk_tffs_nand.cpp
* Contains the internal TSK TFFS NAND file system functions.
*/

/* TCT
* LICENSE
*	This software is distributed under the Common Public License version 1.0
* AUTHOR(S)
*	David Langsam
*	Hochschule Albstadt-Sigmaringen
*	Poststraße 6
*   72458 Albstadt
*   Deutschland
--*/

#ifndef _TSK_TFFS_H
#define _TSK_TFFS_H

#include "tsk_fs.h"

#ifdef __cplusplus
extern "C" {
#endif

/* TFFS image signature */
#define TFFS_MAGIC "AVM_TFFS"
#define TFFS_MAGIC_LEN (sizeof(TFFS_MAGIC) - 1)

/*
** Format constants
** Add TFFS-specific size limits, identifiers, and state flags here.
*/

#define TFFS_PAGE_SIZE 2112
#define TFFS_PAGES_PER_BLOCK 64
#define TFFS_ERASE_BLOCK_SIZE (TFFS_PAGE_SIZE * TFFS_PAGES_PER_BLOCK)
#define TFFS_BLOCK_COUNT 32
#define TFFS_FS_SIZE (TFFS_ERASE_BLOCK_SIZE * TFFS_BLOCK_COUNT)

#define TFFS_NAME_DIRECTORY_ID 511

/*
** On-disk structures
** Define TFFS records here. Decode image bytes explicitly rather than relying
** on native structure packing or host byte order.
*/

/*
** Parsed/cache structures
** Add helper types used to index TFFS objects, directories, or data extents.
*/

    /*
    ** TFFS file system handle
    ** Keep TSK_FS_INFO as the first member; add parsed geometry, inode/object
    ** bounds, and any TFFS-specific cache/state fields here.
    */
    typedef struct _TFFSFS_INFO {
        TSK_FS_INFO fs_info;
    } TFFSFS_INFO;

    /*
     * Structure of an yaffsfs file system handle.
     */
    typedef struct {
        uint32_t file_id;
        uint32_t size;
        uint32_t timestamp;
        uint32_t version;
        uint32_t part;
        uint32_t nextpart;
    } TFFS_HEADER;

#define TFFS_FILE_CONTENT_LEN 0

#ifdef __cplusplus
}
#endif
#endif

