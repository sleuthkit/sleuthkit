/* This config.h is created specifically for the visual studio build. */

#include <windows.h>
#include <shellapi.h>
#include <tchar.h>
#include <io.h>
#include "intrin.h"

/* Define to 1 if translation of program messages to the user's native
   language is requested. */
//#define ENABLE_NLS 1

/* Define if the GNU dcgettext() function is already present or preinstalled.
   */
//#define HAVE_DCGETTEXT 1

/* Define to 1 if you have the <dlfcn.h> header file. */
/* #undef HAVE_DLFCN_H */

/* Define if the GNU gettext() function is already present or preinstalled. */
//#define HAVE_GETTEXT 1

/* Define if you have the iconv() function. */
//#define HAVE_ICONV 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if you have the `localtime_r' function. */
/* #undef HAVE_LOCALTIME_R */

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define to 1 if you have the <stdint.h> header file. */
#ifdef _MSC_VER 
#if _MSC_VER >= 1600
#define HAVE_STDINT_H 1
#else
typedef unsigned __int16 uint16_t;
typedef __int16 int16_t;
typedef unsigned __int32 uint32_t;
typedef __int32 int32_t;
#endif
#endif
/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define as const if the declaration of iconv() needs const. */
#define ICONV_CONST 

/* Define to the sub-directory in which libtool stores uninstalled libraries.
   */
#define LT_OBJDIR ".libs/"

/* Name of package */
#define PACKAGE "libexif"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "libexif-devel@lists.sourceforge.net"

/* Define to the full name of this package. */
#define PACKAGE_NAME "EXIF library"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "EXIF library 0.6.20"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "libexif"

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
#define PACKAGE_VERSION "0.6.20"

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Version number of package */
#define VERSION "0.6.20"

typedef int ssize_t;
#define  inline __inline
#define snprintf   _snprintf
#undef ENABLE_NLS
#undef HAVE_DCGETTEXT
#undef HAVE_GETTEXT
#undef HAVE_ICONV
