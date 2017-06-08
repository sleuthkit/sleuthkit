/*
 * The Sleuth Kit
 *
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2006-2011 Brian Carrier, Basis Technology.  All rights reserved.
 */

/** \file mymalloc.c
 * These functions allocate and reallocate memory and set the error handling functions
 * when an error occurs.
 */

/*	The IBM Public Licence must be distributed with this software.
* AUTHOR(S)
*	Wietse Venema
*	IBM T.J. Watson Research
*	P.O. Box 704
*	Yorktown Heights, NY 10598, USA
*--*/

#include "tsk_base_i.h"
#include <errno.h>

/* tsk_malloc - allocate and zero memory and set error values on error
 */
void *
tsk_malloc(size_t len)
{
    void *ptr;

    if ((ptr = malloc(len)) == 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUX_MALLOC);
        tsk_error_set_errstr("tsk_malloc: %s (%" PRIuSIZE" requested)", strerror(errno), len);
    }
    else {
        memset(ptr, 0, len);
    }
    return (ptr);
}

/* tsk_realloc - reallocate memory and set error values if needed */
void *
tsk_realloc(void *ptr, size_t len)
{
    if ((ptr = realloc(ptr, len)) == 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUX_MALLOC);
        tsk_error_set_errstr("tsk_realloc: %s (%" PRIuSIZE" requested)", strerror(errno), len);
    }
    return (ptr);
}
