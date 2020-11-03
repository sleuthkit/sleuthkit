/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2007-2020 Brian Carrier.  All Rights reserved
 *
 * This software is distributed under the Common Public License 1.0
 */


/** \file tsk_base_i.h
 * Contains the general internal TSK type and function definitions.
 * This is needed by the library as it is built.
 */
#ifndef _TSK_BASE_I_H
#define _TSK_BASE_I_H

// include the autoconf header file
#if HAVE_CONFIG_H
#include "tsk/tsk_config.h"
#endif

/* Some Linux systems need LARGEFILE64_SOURCE and autoconf does
 * not define it, so we hack it here */
#ifdef _LARGEFILE_SOURCE
#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE 1
#endif
#endif

#include "tsk_base.h"
#include "tsk_unicode.h"

// most of the local files need this, so we include it here
#include <string.h>


#ifdef __cplusplus
extern "C" {
#endif


    extern void tsk_init_lock(tsk_lock_t *);
    extern void tsk_deinit_lock(tsk_lock_t *);
    extern void tsk_take_lock(tsk_lock_t *);
    extern void tsk_release_lock(tsk_lock_t *);

#ifndef rounddown
#define rounddown(x, y)	\
    ((((x) % (y)) == 0) ? (x) : \
    (roundup((x),(y)) - (y)))
#endif

    extern void *tsk_malloc(size_t);
    extern void *tsk_realloc(void *, size_t);

// getopt for windows
#ifdef TSK_WIN32
    extern int tsk_optind;
    extern TSK_TCHAR *tsk_optarg;
    extern int tsk_getopt(int argc, TSK_TCHAR * const argv[],
        const TSK_TCHAR * optstring);
#endif




/* Endian Ordering */
/* macros to read in multi-byte fields
* file system is an array of 8-bit values, not 32-bit values
*/
    extern uint8_t tsk_guess_end_u16(TSK_ENDIAN_ENUM *, uint8_t *,
        uint16_t);
    extern uint8_t tsk_guess_end_u32(TSK_ENDIAN_ENUM *, uint8_t *,
        uint32_t);
    extern uint8_t tsk_guess_end_u64(TSK_ENDIAN_ENUM *, uint8_t *,
        uint64_t);


/** \internal
* Read a 16-bit unsigned value.
* @param endian Flag that identifies local ordering.
* @param x Byte array to read from
* @returns 16-bit unsigned value
*/
#define tsk_getu16(endian, x)   \
(uint16_t)(((endian) == TSK_LIT_ENDIAN) ? \
           (((uint8_t *)(x))[0] + (((uint8_t *)(x))[1] << 8)) :    \
           (((uint8_t *)(x))[1] + (((uint8_t *)(x))[0] << 8)) )

/** \internal
* Read a 16-bit signed value.
* @param endian Flag that identifies local ordering.
* @param x Byte array to read from
* @returns 16-bit signed value
*/
#define tsk_gets16(endian, x)	\
((int16_t)tsk_getu16(endian, x))

/** \internal
 * Read a 24-bit unsigned value into a uint32_t variable.
 * @param endian Flag that identifies local ordering.
 * @param x Byte array to read from
 * @returns 16-bit unsigned value
 */
#define tsk_getu24(endian, x)   \
		(uint32_t)(((endian) == TSK_LIT_ENDIAN) ? \
				(((uint8_t *)(x))[0] + (((uint8_t *)(x))[1] << 8) + (((uint8_t *)(x))[2] << 16)) :    \
				(((uint8_t *)(x))[2] + (((uint8_t *)(x))[1] << 8) + (((uint8_t *)(x))[0] << 16)) )



/** \internal
* Read a 32-bit unsigned value.
* @param endian Flag that identifies local ordering.
* @param x Byte array to read from
* @returns 32-bit unsigned value
*/
#define tsk_getu32(endian, x)	\
(uint32_t)( ((endian) == TSK_LIT_ENDIAN)  ?	\
            ((((uint8_t *)(x))[0] <<  0) + \
             (((uint8_t *)(x))[1] <<  8) + \
             (((uint8_t *)(x))[2] << 16) + \
             ((uint32_t)((uint8_t *)(x))[3] << 24) ) \
                                          :	\
            ((((uint8_t *)(x))[3] <<  0) + \
             (((uint8_t *)(x))[2] <<  8) + \
             (((uint8_t *)(x))[1] << 16) + \
             ((uint32_t)((uint8_t *)(x))[0] << 24) ) )

/** \internal
* Read a 32-bit signed value.
* @param endian Flag that identifies local ordering.
* @param x Byte array to read from
* @returns 32-bit signed value
*/
#define tsk_gets32(endian, x)	\
((int32_t)tsk_getu32(endian, x))

/** \internal
* Read a 48-bit unsigned value.
* @param endian Flag that identifies local ordering.
* @param x Byte array to read from
* @returns 48-bit unsigned value
*/
#define tsk_getu48(endian, x)   \
(uint64_t)( ((endian) == TSK_LIT_ENDIAN)  ?	\
            ((uint64_t) \
             ((uint64_t)((uint8_t *)(x))[0] <<  0)+ \
             ((uint64_t)((uint8_t *)(x))[1] <<  8) + \
             ((uint64_t)((uint8_t *)(x))[2] << 16) + \
             ((uint64_t)((uint8_t *)(x))[3] << 24) + \
             ((uint64_t)((uint8_t *)(x))[4] << 32) + \
             ((uint64_t)((uint8_t *)(x))[5] << 40)) \
                                          : \
            ((uint64_t) \
             ((uint64_t)((uint8_t *)(x))[5] <<  0)+ \
             ((uint64_t)((uint8_t *)(x))[4] <<  8) + \
             ((uint64_t)((uint8_t *)(x))[3] << 16) + \
             ((uint64_t)((uint8_t *)(x))[2] << 24) + \
             ((uint64_t)((uint8_t *)(x))[1] << 32) + \
             ((uint64_t)((uint8_t *)(x))[0] << 40)) )


/** \internal
* Read a 64-bit unsigned value.
* @param endian Flag that identifies local ordering.
* @param x Byte array to read from
* @returns 64-bit unsigned value
*/
#define tsk_getu64(endian, x)   \
(uint64_t)( ((endian) == TSK_LIT_ENDIAN)  ?	\
            ((uint64_t) \
             ((uint64_t)((uint8_t *)(x))[0] << 0)  + \
             ((uint64_t)((uint8_t *)(x))[1] << 8) + \
             ((uint64_t)((uint8_t *)(x))[2] << 16) + \
             ((uint64_t)((uint8_t *)(x))[3] << 24) + \
             ((uint64_t)((uint8_t *)(x))[4] << 32) + \
             ((uint64_t)((uint8_t *)(x))[5] << 40) + \
             ((uint64_t)((uint8_t *)(x))[6] << 48) + \
             ((uint64_t)((uint8_t *)(x))[7] << 56)) \
                                          : \
            ((uint64_t) \
             ((uint64_t)((uint8_t *)(x))[7] <<  0) + \
             ((uint64_t)((uint8_t *)(x))[6] <<  8) + \
             ((uint64_t)((uint8_t *)(x))[5] << 16) + \
             ((uint64_t)((uint8_t *)(x))[4] << 24) + \
             ((uint64_t)((uint8_t *)(x))[3] << 32) + \
             ((uint64_t)((uint8_t *)(x))[2] << 40) + \
             ((uint64_t)((uint8_t *)(x))[1] << 48) + \
             ((uint64_t)((uint8_t *)(x))[0] << 56)) )

/** \internal
* Read a 64-bit signed value.
* @param endian Flag that identifies local ordering.
* @param x Byte array to read from
* @returns 64-bit signed value
*/
#define tsk_gets64(endian, x)	\
((int64_t)tsk_getu64(endian, x))


#define TSK_IS_CNTRL(x) \
(((x) < 0x20) && ((x) >= 0x00))


#ifdef __cplusplus
}
#endif
#endif
