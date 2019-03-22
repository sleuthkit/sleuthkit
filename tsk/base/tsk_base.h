/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2007-2011 Brian Carrier.  All Rights reserved
 *
 * This software is distributed under the Common Public License 1.0
 */

/** \file tsk_base.h
 * Contains the type and function definitions that are needed
 * by external programs to use the TSK library.
 * Note that this file is not meant to be directly included.
 * It is included by both libtsk.h and tsk_base_i.h.
 */


/**
 * \defgroup baselib C Base TSK Library Functions
 * \defgroup baselib_cpp C++ Base TSK Library Classes
 */

#ifndef _TSK_BASE_H
#define _TSK_BASE_H

// standard C header files
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

/** Version of code in number form.
 * Upper byte is A, next is B, and next byte is C in version A.B.C.
 * Lowest byte is 0xff, except in beta releases, in which case it
 * increments from 1.  Nightly snapshots will have upper byte as
 * 0xff and next bytes with year, month, and date, respectively.
 * Note that you will not be able to differentiate between snapshots
 * from the trunk or branches with this method...
 * For example, 3.1.2 would be stored as 0x030102FF.
 * 3.1.2b1 would be 0x03010201.  Snapshot from Jan 2, 2003 would be
 * 0xFF030102.
 * See TSK_VERSION_STR for string form. */
#define TSK_VERSION_NUM 0x040606ff

/** Version of code in string form. See TSK_VERSION_NUM for
 * integer form. */
#define TSK_VERSION_STR "4.6.6"


/* include the TSK-specific header file that we created in autoconf
 * On Win32 (Visual Studio) though, we will not have this file...
 */
#if !defined(_MSC_VER)
#include "tsk/tsk_incs.h"
#endif

// get some other TSK / OS settings
#include "tsk_os.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TSK_ERROR_STRING_MAX_LENGTH 1024

    typedef struct {
        uint32_t t_errno;
        char errstr[TSK_ERROR_STRING_MAX_LENGTH + 1];
        char errstr2[TSK_ERROR_STRING_MAX_LENGTH + 1];
        char errstr_print[TSK_ERROR_STRING_MAX_LENGTH + 1];
    } TSK_ERROR_INFO;

    /* The core function here is to retrieve the per-thread error structure. Other functions to follow
     * are for convenience of performing common operations. */
    extern TSK_ERROR_INFO *tsk_error_get_info();

    extern uint32_t tsk_error_get_errno();
    extern void tsk_error_set_errno(uint32_t t_errno);

#ifdef __GNUC__
#define TSK_ERROR_FORMAT_ATTRIBUTE(n,m) __attribute__((format (printf, n, m)))
#else
#define TSK_ERROR_FORMAT_ATTRIBUTE(n,m)
#endif

    extern char *tsk_error_get_errstr();
    extern void tsk_error_set_errstr(const char *format,
        ...) TSK_ERROR_FORMAT_ATTRIBUTE(1, 2);
    extern void tsk_error_vset_errstr(const char *format, va_list args);
    extern char *tsk_error_get_errstr2();
    extern void tsk_error_set_errstr2(const char *format,
        ...) TSK_ERROR_FORMAT_ATTRIBUTE(1, 2);
    extern void tsk_error_vset_errstr2(const char *format, va_list args);
    extern void tsk_error_errstr2_concat(const char *format,
        ...) TSK_ERROR_FORMAT_ATTRIBUTE(1, 2);

    /** Return a human-readable form of tsk_error_get_errno **/
    extern const char *tsk_error_get();

    extern void tsk_error_print(FILE *);
    extern void tsk_error_reset();


#ifdef TSK_MULTITHREAD_LIB
#ifdef TSK_WIN32
    void *tsk_error_win32_get_per_thread_(unsigned struct_size);
    typedef struct {
        CRITICAL_SECTION critical_section;
    } tsk_lock_t;

    // non-windows
#else
/* Note that there is an assumption that TSK_MULTITHREADED_LIB was
 * set only if we have pthreads. If we add a check for HAVE_PTHREAD
 * here, it causes problems when you try to include the library in
 * a tool because they do not have tsk_config.h included.
 */
#include <pthread.h>
    typedef struct {
        pthread_mutex_t mutex;
    } tsk_lock_t;

#endif

    // single threaded lib
#else
    typedef struct {
        void *dummy;
    } tsk_lock_t;
#endif

/**
 * Return values for some TSK functions that need to differentiate between errors and corrupt data.
 */
    typedef enum {
        TSK_OK,                 ///< Ok -- success
        TSK_ERR,                ///< System error -- should abort
        TSK_COR,                ///< Data is corrupt, can still process another set of data
        TSK_STOP                ///< Stop further processing, not an error though.
    } TSK_RETVAL_ENUM;


    typedef struct TSK_LIST TSK_LIST;
    /**
    * Linked list structure that holds a 'key' and optional 'length'.
    * Note that the data is stored in reverse sort order so that inserts
    * are faster.  Also note that the length is a negative number. A key of
    * '6' and a len of '2' means that the run contains 6 and 5.
    */
    struct TSK_LIST {
        TSK_LIST *next;         ///< Pointer to next entry in list
        uint64_t key;           ///< Largest value in this run
        uint64_t len;           ///< Length of run (negative number, stored as positive)
    };
    extern uint8_t tsk_list_find(TSK_LIST * list, uint64_t key);
    extern uint8_t tsk_list_add(TSK_LIST ** list, uint64_t key);
    extern void tsk_list_free(TSK_LIST * list);


    // note that the stack code is in this file and not internal for convenience to users
    /**
     * Basic stack structure to push and pop (used for finding loops in recursion).
     */
    typedef struct {
        uint64_t *vals;         ///< Array that contains the values in the stack
        size_t top;             ///< Index to the top stack entry
        size_t len;             ///< Number of entries in the stack
    } TSK_STACK;

    extern uint8_t tsk_stack_push(TSK_STACK * stack, uint64_t key);
    extern void tsk_stack_pop(TSK_STACK * stack);
    extern uint8_t tsk_stack_find(TSK_STACK * stack, uint64_t key);
    extern void tsk_stack_free(TSK_STACK * stack);
    extern TSK_STACK *tsk_stack_create();


    // print internal UTF-8 strings to local platform Unicode format
    extern void tsk_fprintf(FILE * fd, const char *msg, ...);
    extern void tsk_printf(const char *msg, ...);

    // print path removing special characters
    extern int tsk_print_sanitized(FILE * fd, const char *str);


/** \name printf macros if system does not define them */
//@{
#ifndef PRIx64
#define PRIx64 "llx"
#endif

#ifndef PRIX64
#define PRIX64 "llX"
#endif

#ifndef PRIu64
#define PRIu64 "llu"
#endif

#ifndef PRId64
#define PRId64 "lld"
#endif

#ifndef PRIo64
#define PRIo64 "llo"
#endif

#ifndef PRIx32
#define PRIx32 "x"
#endif

#ifndef PRIX32
#define PRIX32 "X"
#endif

#ifndef PRIu32
#define PRIu32 "u"
#endif

#ifndef PRId32
#define PRId32 "d"
#endif

#ifndef PRIx16
#define PRIx16 "hx"
#endif

#ifndef PRIX16
#define PRIX16 "hX"
#endif

#ifndef PRIu16
#define PRIu16 "hu"
#endif

#ifndef PRIu8
#define PRIu8 "hhu"
#endif

#ifndef PRIx8
#define PRIx8 "hhx"
#endif
//@}



/** @name  Internal integer types and printf macros*/
//@{
    typedef uint64_t TSK_INUM_T;        ///< Data type used to internally store metadata / inode addresses
#define PRIuINUM	PRIu64
#define PRIxINUM	PRIx64
#define PRIdINUM	PRId64

    typedef uint32_t TSK_UID_T; ///< Data type used to internally store User IDs
#define PRIuUID	    PRIu32
#define PRIxUID	    PRIx32
#define PRIdUID	    PRId32

    typedef uint32_t TSK_GID_T; ///< Data type used to internally store Group IDs
#define PRIuGID	    PRIu32
#define PRIxGID	    PRIx32
#define PRIdGID	    PRId32

    typedef uint64_t TSK_DADDR_T;       ///< Data type used to internally store sector and block addresses
#define PRIuDADDR   PRIu64
#define PRIxDADDR   PRIx64
#define PRIdDADDR   PRId64

    typedef int64_t TSK_OFF_T;  ///< Data type used to internally store volume, file, etc. sizes and offsets
#define PRIuOFF		PRIu64
#define PRIxOFF		PRIx64
#define PRIdOFF		PRId64

    typedef uint32_t TSK_PNUM_T;        ///< Data type used to internally store partition addresses
#define PRIuPNUM	PRIu32
#define PRIxPNUM	PRIx32
#define PRIdPNUM	PRId32
//@}


    extern void tsk_version_print(FILE *);
    extern const char *tsk_version_get_str();


/*********** RETURN VALUES ************/

/**
 * Values that callback functions can return to calling walk function.
 */
    typedef enum {
        TSK_WALK_CONT = 0x0,    ///< Walk function should continue to next object
        TSK_WALK_STOP = 0x1,    ///< Walk function should stop processing units and return OK
        TSK_WALK_ERROR = 0x2   ///< Walk function should stop processing units and return error
    } TSK_WALK_RET_ENUM;


/************ ERROR HANDLING *************/
    //TODO: make this per-thread?
    extern int tsk_verbose;     ///< Set to 1 to have verbose debug messages printed to stderr


#define TSK_ERR_AUX	0x01000000
#define TSK_ERR_IMG	0x02000000
#define TSK_ERR_VS	0x04000000
#define TSK_ERR_FS	0x08000000
#define TSK_ERR_HDB	0x10000000
#define TSK_ERR_AUTO 0x20000000
#define TSK_ERR_MASK	0x00ffffff

#define TSK_ERR_AUX_MALLOC	(TSK_ERR_AUX | 0)
#define TSK_ERR_AUX_GENERIC (TSK_ERR_AUX | 2)
#define TSK_ERR_AUX_MAX		2

#define TSK_ERR_IMG_NOFILE	(TSK_ERR_IMG | 0)
#define TSK_ERR_IMG_OFFSET	(TSK_ERR_IMG | 1)
#define TSK_ERR_IMG_UNKTYPE	(TSK_ERR_IMG | 2)
#define TSK_ERR_IMG_UNSUPTYPE 	(TSK_ERR_IMG | 3)
#define TSK_ERR_IMG_OPEN 	(TSK_ERR_IMG | 4)
#define TSK_ERR_IMG_STAT	(TSK_ERR_IMG | 5)
#define TSK_ERR_IMG_SEEK	(TSK_ERR_IMG | 6)
#define TSK_ERR_IMG_READ	(TSK_ERR_IMG | 7)
#define TSK_ERR_IMG_READ_OFF	(TSK_ERR_IMG | 8)
#define TSK_ERR_IMG_ARG	    (TSK_ERR_IMG | 9)
#define TSK_ERR_IMG_MAGIC	(TSK_ERR_IMG | 10)
#define TSK_ERR_IMG_WRITE	(TSK_ERR_IMG | 11)
#define TSK_ERR_IMG_CONVERT	(TSK_ERR_IMG | 12)
#define TSK_ERR_IMG_PASSWD	(TSK_ERR_IMG | 13)
#define TSK_ERR_IMG_MAX		14

#define TSK_ERR_VS_UNKTYPE	(TSK_ERR_VS | 0)
#define TSK_ERR_VS_UNSUPTYPE	(TSK_ERR_VS | 1)
#define TSK_ERR_VS_READ		(TSK_ERR_VS | 2)
#define TSK_ERR_VS_MAGIC	(TSK_ERR_VS | 3)
#define TSK_ERR_VS_WALK_RNG	(TSK_ERR_VS | 4)
#define TSK_ERR_VS_BUF		(TSK_ERR_VS | 5)
#define TSK_ERR_VS_BLK_NUM	(TSK_ERR_VS | 6)
#define TSK_ERR_VS_ARG	    (TSK_ERR_VS | 7)
#define TSK_ERR_VS_MAX		8

#define TSK_ERR_FS_UNKTYPE	(TSK_ERR_FS | 0)
#define TSK_ERR_FS_UNSUPTYPE	(TSK_ERR_FS | 1)
#define TSK_ERR_FS_UNSUPFUNC		(TSK_ERR_FS | 2)
#define TSK_ERR_FS_WALK_RNG	(TSK_ERR_FS | 3)
#define TSK_ERR_FS_READ		(TSK_ERR_FS | 4)
#define TSK_ERR_FS_READ_OFF	(TSK_ERR_FS | 5)
#define TSK_ERR_FS_ARG		(TSK_ERR_FS | 6)
#define TSK_ERR_FS_BLK_NUM	(TSK_ERR_FS | 7)
#define TSK_ERR_FS_INODE_NUM	(TSK_ERR_FS | 8)
#define TSK_ERR_FS_INODE_COR	(TSK_ERR_FS | 9)
#define TSK_ERR_FS_MAGIC	(TSK_ERR_FS | 10)
#define TSK_ERR_FS_FWALK	(TSK_ERR_FS | 11)
#define TSK_ERR_FS_WRITE	(TSK_ERR_FS | 12)
#define TSK_ERR_FS_UNICODE	(TSK_ERR_FS | 13)
#define TSK_ERR_FS_RECOVER	(TSK_ERR_FS | 14)
#define TSK_ERR_FS_GENFS	(TSK_ERR_FS | 15)
#define TSK_ERR_FS_CORRUPT	(TSK_ERR_FS | 16)
#define TSK_ERR_FS_ATTR_NOTFOUND (TSK_ERR_FS | 17)
#define TSK_ERR_FS_MAX		18


#define TSK_ERR_HDB_UNKTYPE     (TSK_ERR_HDB | 0)
#define TSK_ERR_HDB_UNSUPTYPE   (TSK_ERR_HDB | 1)
#define TSK_ERR_HDB_READDB	(TSK_ERR_HDB | 2)
#define TSK_ERR_HDB_READIDX	(TSK_ERR_HDB | 3)
#define TSK_ERR_HDB_ARG		(TSK_ERR_HDB | 4)
#define TSK_ERR_HDB_WRITE	(TSK_ERR_HDB | 5)
#define TSK_ERR_HDB_CREATE	(TSK_ERR_HDB | 6)
#define TSK_ERR_HDB_DELETE      (TSK_ERR_HDB | 7)
#define TSK_ERR_HDB_MISSING     (TSK_ERR_HDB | 8)
#define TSK_ERR_HDB_PROC        (TSK_ERR_HDB | 9)
#define TSK_ERR_HDB_OPEN        (TSK_ERR_HDB | 10)
#define TSK_ERR_HDB_CORRUPT     (TSK_ERR_HDB | 11)
#define TSK_ERR_HDB_UNSUPFUNC     (TSK_ERR_HDB | 11)
#define TSK_ERR_HDB_MAX		13

#define TSK_ERR_AUTO_DB (TSK_ERR_AUTO | 0)
#define TSK_ERR_AUTO_CORRUPT (TSK_ERR_AUTO | 1)
#define TSK_ERR_AUTO_UNICODE (TSK_ERR_AUTO | 2)
#define TSK_ERR_AUTO_NOTOPEN (TSK_ERR_AUTO | 3)
#define TSK_ERR_AUTO_MAX 4
//@}


/** \name Endian Ordering Functions */
//@{
    /**
     * Flag that identifies the endian ordering of the data being read.
     */
    typedef enum {
        TSK_UNKNOWN_ENDIAN = 0x00, ///< Endianness is unknown
        TSK_LIT_ENDIAN = 0x01,  ///< Data is in little endian
        TSK_BIG_ENDIAN = 0x02   ///< Data is in big endian
    } TSK_ENDIAN_ENUM;

//@}



    extern TSK_OFF_T tsk_parse_offset(const TSK_TCHAR *);
    extern int tsk_parse_pnum(const TSK_TCHAR * a_pnum_str,
        TSK_PNUM_T * a_pnum);



/** \name MD5 and SHA-1 hashing */
//@{

/* Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
rights reserved.

License to copy and use this software is granted provided that it
is identified as the "RSA Data Security, Inc. MD5 Message-Digest
Algorithm" in all material mentioning or referencing this software
or this function.

License is also granted to make and use derivative works provided
that such works are identified as "derived from the RSA Data
Security, Inc. MD5 Message-Digest Algorithm" in all material
mentioning or referencing the derived work.

RSA Data Security, Inc. makes no representations concerning either
the merchantability of this software or the suitability of this
software for any particular purpose. It is provided "as is"
without express or implied warranty of any kind.

These notices must be retained in any copies of any part of this
documentation and/or software.
 */


/* POINTER defines a generic pointer type */
    typedef unsigned char *POINTER;

/* UINT2 defines a two byte word */
//typedef unsigned short int UINT2;
    typedef uint16_t UINT2;

/* UINT4 defines a four byte word */
    typedef uint32_t UINT4;

/* Added for sha1 */
/* BYTE defines a unsigned character */
    typedef uint8_t BYTE;

#ifndef TRUE
#define FALSE 0
#define TRUE  ( !FALSE )
#endif                          /* TRUE */



/* MD5 context. */
#define TSK_MD5_DIGEST_LENGTH 16
    typedef struct {
        UINT4 state[4];         /* state (ABCD) */
        UINT4 count[2];         /* number of bits, modulo 2^64 (lsb first) */
        unsigned char buffer[64];       /* input buffer */
    } TSK_MD5_CTX;

    void TSK_MD5_Init(TSK_MD5_CTX *);
    void TSK_MD5_Update(TSK_MD5_CTX *, unsigned char *, unsigned int);
    void TSK_MD5_Final(unsigned char[16], TSK_MD5_CTX *);



/* sha.h */

/* The structure for storing SHS info */
#define TSK_SHA_DIGEST_LENGTH 32
    typedef struct {
        UINT4 digest[5];        /* Message digest */
        UINT4 countLo, countHi; /* 64-bit bit count */
        UINT4 data[16];         /* SHS data buffer */
        int Endianness;
    } TSK_SHA_CTX;

/* Message digest functions */

    void TSK_SHA_Init(TSK_SHA_CTX *);
    void TSK_SHA_Update(TSK_SHA_CTX *, BYTE * buffer, int count);
    void TSK_SHA_Final(BYTE * output, TSK_SHA_CTX *);

/* Flags for which type of hash(es) to run */
	typedef enum{
		TSK_BASE_HASH_INVALID_ID = 0,
		TSK_BASE_HASH_MD5 = 0x01,
		TSK_BASE_HASH_SHA1 = 0x02
		//TSK_BASE_HASH_SHA256 = 0x04,
	} TSK_BASE_HASH_ENUM;


//@}

#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
#if 0
class TskStack {
  private:
    TSK_STACK * m_stack;

  public:
    /**
    * Create a TSK_STACK structure. See tsk_stack_create() for details.
    * @returns Pointer to structure or NULL on error
    */
    TskStack() {
        m_stack = tsk_stack_create();
    };
   /**
   * Free an allocated TSK_STACK structure. See tsk_stack_free() for details.
   */
    ~TskStack() {
        tsk_stack_free(m_stack);
    };
    /**
    * Pop a value from the top of the stack. See tsk_stack_pop() for details.
    */
    void pop() {
        tsk_stack_pop(m_stack);
    };
    /**
    * Push a value to the top of TSK_STACK. See tsk_stack_push() for details.
    * @param a_val Value to push on
    * @returns 1 on error
    */
    uint8_t push(uint64_t a_val) {
        return tsk_stack_push(m_stack, a_val);
    };
    /**
    * Search a TSK_STACK for a given value. See tsk_stack_find() for details.
    * @param a_val Value to search for
    * @returns 1 if found and 0 if not
    */
    uint8_t find(uint64_t a_val) {
        return tsk_stack_find(m_stack, a_val);
    };
     /**
    * Return Number of entries in the stack
    * @returns number of entries in the stack
    */
    size_t length() {
        if (m_stack != NULL)
            return m_stack->len;
        else
            return 0;
    };
};
#endif

/**
 * \ingroup baselib_cpp
 * Allows access to most recent error message and code in the thread.
 */
class TskError {
  public:
    /**
    * Return the string with the current error message.  The string does not end with a
    * newline. See tsk_error_get() for details.
    *
    * @returns String with error message or NULL if there is no error
    */
    static const char *get() {
        return tsk_error_get();
    };

   /**
   * Print the current error message to a file. See tsk_error_print() for details.
   *
   * @param a_hFile File to print message to
   */
    static void print(FILE * a_hFile) {
        tsk_error_print(a_hFile);
    };

    /**
    * Clear the error number and error message. See tsk_error_reset() for details.
    */
    static void reset() {
        tsk_error_reset();
    };
};

#endif
#endif
