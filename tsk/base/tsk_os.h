/*
** The Sleuth Kit 
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2004-2011 Brian Carrier.  All rights reserved
*/

/** \file tsk_os.h
 * Contains some OS-specific type settings.
 */

#ifndef _TSK_OS_H
#define _TSK_OS_H

    /*
     * Solaris 2.x. Build for large files when dealing with filesystems > 2GB.
     * With the 32-bit file model, needs pread() to access filesystems > 2GB.
     */
#if defined(sun)
#include <sys/sysmacros.h>
#endif

#if defined(__CYGWIN__)
#ifndef roundup
#define roundup(x, y)	\
	( ( ((x)+((y) - 1)) / (y)) * (y) )
#endif
#endif

#if defined(__INTERNIX)
#define roundup(x, y)	\
	( ( ((x)+((y) - 1)) / (y)) * (y) )
#endif


// mingw Windows cross compile
#ifdef __MINGW32__

#ifndef UNICODE
#define UNICODE
#endif

#ifndef _UNICODE
#define _UNICODE
#endif

#include <windows.h>
#include <wchar.h>

#define TSK_WIN32
#define roundup(x, y)   \
    ( ( ((x)+((y) - 1)) / (y)) * (y) )

#define fseeko fseek
#define daddr_t int
#endif



// Visual Studio / Windows
#ifdef _MSC_VER
#define TSK_WIN32
#define TSK_MULTITHREAD_LIB

#ifndef UNICODE
#define UNICODE
#endif

#ifndef _UNICODE
#define _UNICODE
#endif

#define WIN32_LEAN_AND_MEAN     /* somewhat limit Win32 pollution */
#define _CRT_SECURE_NO_DEPRECATE	1

#include <windows.h>
#include <shellapi.h>
#include <tchar.h>
#include <io.h>
#include "intrin.h"

// define the sized int types
#if _MSC_VER >= 1600
#include <stdint.h>
#else
typedef unsigned __int8 uint8_t;
typedef __int8 int8_t;
typedef unsigned __int16 uint16_t;
typedef __int16 int16_t;
typedef unsigned __int32 uint32_t;
typedef __int32 int32_t;
typedef unsigned __int64 uint64_t;
typedef __int64 int64_t;
#endif
// define the typical unix types
typedef int mode_t;
// ifdef added from Joachim because it can cause conflicts
// if python.h is included
#if !defined( HAVE_SSIZE_T )
#define HAVE_SSIZE_T
#if _WIN64
typedef int64_t ssize_t;
#else
typedef int32_t ssize_t;
#endif
#endif

// remap some of the POSIX functions
#define snprintf   _snprintf
#define strcasecmp(string1, string2)	_stricmp(string1, string2)
#define putenv _putenv

#define roundup(x, y)	\
	( ( ((x)+((y) - 1)) / (y)) * (y) )

#define fseeko _fseeki64

#endif


/* When TSK deals with the outside world (printing / input), the data will 
 * be in either UTF-16 or UTF-8 (Windows or Unix).  TSK_TCHAR is defined 
 * as the data type needed and the following function map to the required 
 * function. 
 */

#ifdef TSK_WIN32

/* TSK_TCHAR is a wide 2-byte character */
typedef WCHAR TSK_TCHAR;        ///< Character data type that is UTF-16 (wchar_t) in Windows and UTF-8 (char) in Unix
#define _TSK_T(x)      L ## x
#define TSTRTOK	wcstok
#define TSTRLEN	wcslen
#define TSTRCMP	wcscmp
#define TSTRNCMP	wcsncmp
#define TSTRICMP _wcsicmp
#define TSTRNCPY wcsncpy
#define TSTRNCAT wcsncat
#define TSTRCHR	wcschr
#define TSTRRCHR wcsrchr
#define TSTRTOUL wcstoul

#define TATOI	_wtoi
#define TFPRINTF fwprintf
#define TSNPRINTF _snwprintf
#define TPUTENV	_wputenv
#define TZSET	_tzset
#define TZNAME _tzname
#if defined(_MSC_VER)
#define TSTRTOULL _wcstoui64
#define STAT_STR    __stat64
#define TSTAT _wstat64
#define atoll(S) _atoi64(S)
#elif defined(__MINGW32__)
#define TSTRTOULL wcstoull
#define STAT_STR    _stat
#define TSTAT _wstat
#endif


#define PRIcTSK _TSK_T("S")     ///< sprintf macro to print a UTF-8 char string to TSK_TCHAR buffer
#define PRIwTSK _TSK_T("s")     ///< sprintf macro to print a UTF-16 wchar_t string to TSK_TCHAR buffer
#define PRIttocTSK  "S"         ///< printf macro to print a TSK_TCHAR string to stderr or other char device
#define PRIuSIZE "Iu"           ///< printf macro to print a size_t value in Windows printf codes

#define unlink _unlink

#define GETOPT tsk_getopt       // points to local wchar version
#define OPTIND tsk_optind
#define OPTARG tsk_optarg


#define strtok_r(a,b,c) strtok(a,b)

// Non-Win32
#else

/* TSK_TCHAR is a 1-byte character */
typedef char TSK_TCHAR;         ///< Character data type that is UTF-16 (wchar_t) in Windows and UTF-8 (char) in Unix
#define _TSK_T(x)	x

#define TSTAT	stat
#define STAT_STR    stat
#define TSTRTOK	strtok
#define TSTRLEN	strlen
#define TSTRCMP	strcmp
#define TSTRNCMP strncmp
#define TSTRICMP strcasecmp
#define TSTRNCPY strncpy
#define TSTRNCAT strncat
#define TSTRCHR	strchr
#define TSTRRCHR strrchr
#define TSTRTOUL strtoul
#define TSTRTOULL strtoull
#define TATOI	atoi
#define TFPRINTF fprintf
#define TSNPRINTF snprintf
#define TPUTENV	putenv
#define TZSET	tzset
#define TZNAME	tzname

#define PRIcTSK _TSK_T("s")     ///< sprintf macro to print a UTF-8 char string to TSK_TCHAR buffer
#define PRIwTSK _TSK_T("S")     ///< sprintf macro to print a UTF-16 wchar_t string to TSK_TCHAR buffer
#define PRIttocTSK  "s"         ///< printf macro to print a TSK_TCHAR string to stderr or other char device
#define PRIuSIZE "zu"           ///< printf macro to print a size_t value in non-Windows printf codes

#define GETOPT getopt           // points to system char * version
#define OPTIND optind           // points to system char * variable
#define OPTARG optarg           // points to system char * variable

#endif

#endif
