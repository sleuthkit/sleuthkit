#ifndef _TSK_TOOLS_I_H
#define _TSK_TOOLS_I_H

/* same as tsklib.h except that it includes the base_i.h file
 * instead of base.h so that we can get the _config defines.
 * This is to be used by the tools included with TSK (such as fls).
 */
#include "tsk/base/tsk_base_i.h"
#include "tsk/img/tsk_img.h"
#include "tsk/vs/tsk_vs.h"
#include "tsk/fs/tsk_fs.h"
#include "tsk/hashdb/tsk_hashdb.h"
#include "tsk/auto/tsk_auto.h"

#endif
