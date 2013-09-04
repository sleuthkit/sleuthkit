/**
 * A collection of utility functions that are useful.
 */

// Just for this module
#define _FILE_OFFSET_BITS 64


/* required per C++ standard */
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#include "tsk/tsk_config.h"
#include "utils.h"

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <assert.h>

#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>

#ifndef HAVE_ERR
#include <stdarg.h>
void err(int eval,const char *fmt,...)
{
  va_list ap;
  va_start(ap,fmt);
  vfprintf(stderr,fmt,ap);
  va_end(ap);
  fprintf(stderr,": %s\n",strerror(errno));
  exit(eval);
}
#endif

#ifndef HAVE_ERRX
#include <stdarg.h>
void errx(int eval,const char *fmt,...)
{
  va_list ap;
  va_start(ap,fmt);
  vfprintf(stderr,fmt,ap);
  fprintf(stderr,"%s\n",strerror(errno));
  va_end(ap);
  exit(eval);
}
#endif

#ifndef HAVE_WARN
#include <stdarg.h>
void	warn(const char *fmt, ...)
{
    va_list args;
    va_start(args,fmt);
    vfprintf(stderr,fmt, args);
    fprintf(stderr,": %s\n",strerror(errno));
}
#endif

#ifndef HAVE_WARNX
#include <stdarg.h>
void warnx(const char *fmt,...)
{
  va_list ap;
  va_start(ap,fmt);
  vfprintf(stderr,fmt,ap);
  va_end(ap);
}
#endif

#ifdef _MSC_VER
#define inline
#include <io.h>
#include <stdio.h>
//pread implementation from https://gist.github.com/1258986
int pread(unsigned int fd, char *buf, size_t count, int offset)
{
if (_lseek(fd, offset, SEEK_SET) != offset) {
return -1;
}
return read(fd, buf, count);
}

#endif

#ifndef HAVE_ISHEXNUMBER
int ishexnumber(int c);
inline int ishexnumber(int c)
{
    switch(c){
    case '0':         case '1':         case '2':         case '3':         case '4':
    case '5':         case '6':         case '7':         case '8':         case '9':
    case 'A':         case 'B':         case 'C':         case 'D':         case 'E':
    case 'F':         case 'a':         case 'b':         case 'c':         case 'd':
    case 'e':         case 'f':
	return 1;
    }
    return 0;
}
#endif


