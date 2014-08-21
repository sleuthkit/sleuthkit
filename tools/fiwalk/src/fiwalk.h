/**
 * fiwalk.h
 *
 * The software provided here is released by the Naval Postgraduate
 * School, an agency of the U.S. Department of Navy.  The software
 * bears no warranty, either expressed or implied. NPS does not assume
 * legal liability nor responsibility for a User's use of the software
 * or the results of such use.
 *
 * Please note that within the United States, copyright protection,
 * under Section 105 of the United States Code, Title 17, is not
 * available for any work of the United States Government and/or for
 * any works created by United States Government employees. User
 * acknowledges that this software contains work which was created by
 * NPS government employees and is therefore in the public domain and
 * not subject to copyright.
 */

#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <fcntl.h>
#ifndef WIN32
#include <pwd.h>
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#ifdef HAVE_INTTYPES_H
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif
#include <inttypes.h>
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif


#include <sys/types.h>

#ifdef _MSC_VER
#include <winsock.h>
#include <time.h>
#define _CRT_SECURE_NO_WARNINGS
#else
#include <sys/time.h>
#endif

#include <sys/stat.h>

#ifdef HAVE_SIGNAL_H
#include <sys/signal.h>
#endif

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

#ifdef HAVE_SYS_UTSNAME_H
#include <sys/utsname.h>
#endif

#include <algorithm>
#include <cstdlib>
#include <vector>
#include <string>

#ifdef AFFLIB_OBSOLETE
#undef HAVE_LIBAFFLIB
#endif

#ifdef HAVE_LIBAFFLIB
#define HAVE_STL
#include <afflib/afflib.h>
#include <afflib/afflib_i.h>
#include <afflib/utils.h>		// aff::seglist
#endif

#ifdef HAVE_LIBEWF

#if defined(_MSC_VER)
#include <config_msc.h>
#endif

#include <libewf.h>
#endif

#include "hash_t.h"
#include "utils.h"
#include "dfxml.h"
#include "base64.h"
#include "content.h"

using namespace std;

typedef vector<string> namelist_t;
extern namelist_t namelist;

extern int	opt_maxgig;
extern bool	opt_save;			// should we save content?
extern bool	opt_magic;			// should we run libmagic?
extern bool	opt_md5;			// do we need md5s?
extern bool	opt_sha1;			// do we need sha1s?
extern string	save_outdir;
extern bool	opt_get_fragments;
extern int	opt_debug;
extern bool	opt_no_data;
extern bool	opt_allocated_only;
extern bool	opt_body_file;
extern bool	opt_ignore_ntfs_system_files;
extern bool     opt_sector_hash;
extern int	current_partition_num;
extern int64_t	current_partition_start;
extern const char *config_file;
extern int  file_count_max;
extern int  file_count;
extern int  next_id;
extern int opt_M;
extern int opt_k;
extern bool opt_parent_tracking;


void comment(const char *format,...);
void file_info(const string &name,const string &value);
void file_info(const md5_t &t);
void file_info(const sha1_t &t);
void file_info(const sha256_t &t);
void file_info_xml(const string &name,const string &value);
void file_info(const string name, int64_t value);
void file_infot(const string name,time_t t0);
void file_infot(const string name,time_t t0, TSK_FS_TYPE_ENUM ftype);

extern u_int sectorhash_size;		// for the computation of sector hashes
extern namelist_t namelist;		// names of files that we want to find


/* fiwalk.cpp */

extern class arff *a;
extern class xml *x;
extern FILE  *t;				// text output or body file enabled

void partition_info(const string &name,const string &value,const string &attribute);
void partition_info(const string &name,const string &value);
void partition_info(const string &name,long i);
void partition_info(const string &name, const struct timeval &ts);



/* fiwalk_tsk.cpp */
int process_image_file(int argc,char *const *argv,const char *audit_file,u_int sector_size);

#ifdef _MSC_VER
#define F_OK 00
#define W_OK 02
#define R_OK 04
#endif
