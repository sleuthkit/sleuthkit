/*
 * The Sleuth Kit
 *
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2006-2011 Brian Carrier, Basis Technology.  All rights reserved.
 */

/** \file mymalloc.c
 * These functions allocate and realocate memory and set the error handling functions
 * when an error occurs.
 */

/*++
* NAME
*	tsk_malloc 3
* SUMMARY
*	memory management wrappers
* SYNOPSIS
*	#include <tsk_malloc.h>
*
*	char	*tsk_malloc(len)
*	int	len;
*
*	char	*tsk_realloc(ptr, len)
*	char	*ptr;
*	int	len;
*
*	char	*mystrdup(str)
*const char *str;
*DESCRIPTION
*	This module performs low-level memory management with error
*	handling. A call of these functions either succeeds or it does
*	not return at all.
*
*	tsk_malloc() allocates the requested amount of memory. The memory
*	is not set to zero.
*
*	tsk_realloc() resizes memory obtained from tsk_malloc() or tsk_realloc()
*	to the requested size. The result pointer value may differ from
*	that given via the \fBptr\fR argument.
*
*	mystrdup() returns a dynamic-memory copy of its null-terminated
*	argument. This routine uses tsk_malloc().
* SEE ALSO
*	error(3) error reporting module.
* DIAGNOSTICS
*	Fatal errors: the requested amount of memory is not available.
* LICENSE
* .ad
* .fi
*	The IBM Public Licence must be distributed with this software.
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
        tsk_error_set_errstr("tsk_malloc: %s (%zu requested)", strerror(errno), len);
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
        tsk_error_set_errstr("tsk_realloc: %s (%zu requested)", strerror(errno), len);
    }
    return (ptr);
}
