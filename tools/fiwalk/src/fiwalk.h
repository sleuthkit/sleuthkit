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

#ifndef FIWALK_H
#define FIWALK_H

#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#include "tsk/tsk_tools_i.h"

#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#ifndef TSK_WIN32
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

using namespace std;
typedef vector<string> namelist_t;

struct fiwalk {
    bool opt_allocated_only;
    bool opt_body_file;
    bool opt_get_fragments;
    bool opt_ignore_ntfs_system_files;
    bool opt_magic;			// should we run libmagic?
    bool opt_md5;			// do we need md5s?
    bool opt_no_data;
    bool opt_parent_tracking;
    bool opt_save;			// should we save content?
    bool opt_sector_hash;
    bool opt_sha1;			// do we need sha1s?
    bool opt_x;
    bool opt_variable;
    bool opt_zap;
    const char *arff_fn;
    char * const *argv;
    const char *audit_file;
    const char *config_file;
    const char *filename;
    const char *text_fn;
    int argc;
    int	current_partition_num;
    int	opt_debug;
    int file_count;
    int file_count_max;
    int next_id;
    int opt_M;
    int opt_k;
    int opt_maxgig;
    int vs_count;
    int64_t current_partition_start;
    namelist_t namelist;             // in content.h
    string command_line;
    string save_outdir;
    string xml_fn;
    struct timeval tv0;
    struct timeval tv1;
    uint32_t sector_size;
    uint32_t sectorhash_size;		// for the computation of sector hashes
    int run();                          // run fiwalk
    int proc_fs(TSK_IMG_INFO * img_info, TSK_OFF_T start);
    int proc_vs(TSK_IMG_INFO * img_info);
    uint8_t process_tsk_file(TSK_FS_FILE * fs_file, const char *path);
    int process_image_file(int argc,char *const *argv,const char *audit_file, uint32_t sector_size);
    void process_scalpel_audit_file(TSK_IMG_INFO *img_info,const char *audit_file);
    class xml *x;
    FILE  *t;				// text output or body file enabled
    class arff *a;

    void comment(const char *format,...);
    void file_info(const string &name,const string &value);
    void file_info(const md5_t &t);
    void file_info(const sha1_t &t);
    void file_info(const sha256_t &t);
    void file_info_xml(const string &name,const string &value);
    void file_info_xml2(const string &name,const string &attrib,const string &value);
    void file_info(const string name, int64_t value);
    void file_infot(const string name,time_t t0);
    void file_infot(const string name,time_t t0, TSK_FS_TYPE_ENUM ftype);
    void partition_info(const string &name,const string &value,const string &attribute);
    void partition_info(const string &name,const string &value);
    void partition_info(const string &name,long i);
    void partition_info(const string &name, const struct timeval &ts);
    void plugin_process(const std::string &fname);
    void config_read(const char *fname);



    fiwalk():opt_allocated_only(false),
             opt_body_file(false),
             opt_get_fragments(false),
             opt_ignore_ntfs_system_files(false),
             opt_magic(false),
             opt_md5(true),
             opt_no_data(false),
             opt_parent_tracking(false),
             opt_save(false),
             opt_sector_hash(false),
             opt_sha1(true),
             opt_x(false),
             opt_variable(true),
             opt_zap(false),
             arff_fn(0),
             argv((char * const *)0),
             audit_file(0),
             config_file(0),
             filename(0),
             text_fn(0),
             argc(0),
             current_partition_num(0),
             opt_debug(0),
             file_count(0),
             file_count_max(0),
             next_id(1),
             opt_M(0),
             opt_k(0),
             opt_maxgig(0),
             vs_count(0),
             sector_size(512),
             sectorhash_size(512),
             x(0),
             t(0),
             a(0)
    {};
};



//extern namelist_t namelist;		// names of files that we want to find


/* fiwalk.cpp */


int fiwalk_main(int argc, const char * const *argv1);

/* fiwalk_tsk.cpp */



#ifdef _MSC_VER
#define F_OK 00
#define W_OK 02
#define R_OK 04
#endif

#endif
