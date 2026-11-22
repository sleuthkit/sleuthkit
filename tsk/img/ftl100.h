#ifndef TSK_FTL100_H
#define TSK_FTL100_H
#include "tsk_img_i.h"
/* matched is set when an FTL100 signature is present. NULL forces explicit open. */
TSK_IMG_INFO *ftl100_open(int,const TSK_TCHAR * const[],unsigned int,int *matched);
#endif
