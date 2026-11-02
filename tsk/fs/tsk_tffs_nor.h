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
*\file tffs_nor.cpp
* Contains the internal TSK TFFS NOR file system functions.
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

#ifndef _TSK_TFFS_NOR_H
#define _TSK_TFFS_NOR_H

#include "tsk_fs.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TFFS_NOR_ENTRY_HEADER_SIZE 4
#define TFFS_NOR_ENTRY_ALIGNMENT 4
#define TFFS_NOR_DELETED_ID 0
#define TFFS_NOR_ERASED_VALUE 0xffff
#define TFFS_NOR_NAME_TABLE_ID 511

TSK_FS_INFO *tffs_nor_open(TSK_IMG_INFO *a_img_info, TSK_OFF_T a_offset,
    TSK_FS_TYPE_ENUM a_ftype, const char *a_pass, uint8_t a_test);

/* NOR entry fields are stored as two big-endian 16-bit values: ID, then size. */
typedef struct {
    uint16_t file_id;
    uint16_t data_size;
} TFFS_NOR_ENTRY_HEADER;

#ifdef __cplusplus
}
#endif

#endif 