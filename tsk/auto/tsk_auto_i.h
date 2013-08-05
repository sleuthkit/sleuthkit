/*
 ** The Sleuth Kit 
 **
 ** Brian Carrier [carrier <at> sleuthkit [dot] org]
 ** Copyright (c) 2010-2011 Brian Carrier.  All Rights reserved
 **
 ** This software is distributed under the Common Public License 1.0
 **
 */

/*
 * Contains the internal-only methods/etc that TSK code may need, but that
 * does not get exported.  This includes the external files too.
 */


#ifndef _TSK_AUTO_I_H
#define _TSK_AUTO_I_H

#ifdef __cplusplus

// Include the other internal TSK header files
#include "tsk/base/tsk_base_i.h"
#include "tsk/img/tsk_img_i.h"
#include "tsk/vs/tsk_vs_i.h"
#include "tsk/fs/tsk_fs_i.h"

// Include the external file 
#include "tsk_auto.h"

#endif

#endif
