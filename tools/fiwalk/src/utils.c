/**
 * A collection of utility functions that are useful.
 */

// Just for this module
#define _FILE_OFFSET_BITS 64


/* required per C++ standard */
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#include "tsk3/tsk_tools_i.h"
//#include "config.h"
#include "utils.h"

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <assert.h>
#include <inttypes.h>
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

/** Extract a buffer...
 * @param buf - the buffer to extract;
 * @param buflen - the size of the page to extract
 * @param pos0 - the byte position of buf[0]
 */

int ends_with(const char *buf,const char *with)
{
    if(buf && with){
	size_t buflen = strlen(buf);
	size_t withlen = strlen(with);
	if(buflen>withlen && strcmp(buf+buflen-withlen,with)==0) return 1;
    }
    return 0;
}

/**
 * It's hard to figure out the filesize in an opearting system independent method that works with both
 * files and devices. This seems to work. It only requires a functioning pread64 or pread.
 */



#if !defined(HAVE_PREAD64) && !defined(HAVE_PREAD) && defined(HAVE__LSEEKI64)
static size_t pread64(int d,void *buf,size_t nbyte,int64_t offset)
{
    if(_lseeki64(d,offset,0)!=offset) return -1;
    return read(d,buf,nbyte);
}
#endif

int64_t get_filesize(int fd)
{
    struct stat st;
    char buf[64];
    int64_t raw_filesize = 0;		/* needs to be signed for lseek */
    int bits = 0;
    int i =0;

#if defined(HAVE_PREAD64)
    /* If we have pread64, make sure it is defined */
    extern size_t pread64(int fd,char *buf,size_t nbyte,off_t offset);
#endif

#if !defined(HAVE_PREAD64) && defined(HAVE_PREAD)
    /* if we are not using pread64, make sure that off_t is 8 bytes in size */
#define pread64(d,buf,nbyte,offset) pread(d,buf,nbyte,offset)
    if(sizeof(off_t)!=8){
	err(1,"Compiled with off_t==%d and no pread64 support.",(int)sizeof(off_t));
    }
#endif


    /* We can use fstat if sizeof(st_size)==8 and st_size>0 */
    if(sizeof(st.st_size)==8 && fstat(fd,&st)==0){
	if(st.st_size>0) return st.st_size;
    }

    /* Phase 1; figure out how far we can seek... */
    for(bits=0;bits<60;bits++){
	raw_filesize = ((int64_t)1<<bits);
	if(pread64(fd,buf,1,raw_filesize)!=1){
	    break;
	}
    }
    if(bits==60) errx(1,"Partition detection not functional.\n");

    /* Phase 2; blank bits as necessary */
    for(i=bits;i>=0;i--){
	int64_t test = (int64_t)1<<i;
	int64_t test_filesize = raw_filesize | ((int64_t)1<<i);
	if(pread64(fd,buf,1,test_filesize)==1){
	    raw_filesize |= test;
	} else{
	    raw_filesize &= ~test;
	}
    }
    if(raw_filesize>0) raw_filesize+=1;	/* seems to be needed */
    return raw_filesize;
}


#ifdef USE_PRIVATE_REGEX
#include <regex.c>
#endif
