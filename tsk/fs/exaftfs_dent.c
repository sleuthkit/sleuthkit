/*
** The Sleuth Kit
**
** Copyright (c) 2013 Basis Technology Corp.  All rights reserved
** Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
**
** This software is distributed under the Common Public License 1.0
**
*/

/*
 * This code makes use of research presented in the following paper:
 * "Reverse Engineering the exFAT File System" by Robert Shullich
 * Retrieved May 2013 from: 
 * http://www.sans.org/reading_room/whitepapers/forensics/reverse-engineering-microsoft-exfat-file-system_33274
 *
 * Some additional details concerning TexFAT were obtained in May 2013
 * from:
 * http://msdn.microsoft.com/en-us/library/ee490643(v=winembedded.60).aspx
*/

/**
 * \file exfatfs_dent.c
 * Contains the internal TSK exFAT file system code to handle name 
 * category processing. 
 */

#include "tsk_exfatfs.h" /* Include first to make sure it stands alone. */
#include "tsk_fs_i.h"
#include "tsk_fatfs.h"

// RJCTODO