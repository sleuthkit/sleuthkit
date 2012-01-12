/*
 * Simson's XML output class.
 * Ideally include this AFTER your config file with the HAVE statements.
 */

#ifndef _XML_H_
#define _XML_H_

#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#endif

#include <fstream>
#include <string.h>
#include <sys/types.h>

#ifdef _MSC_VER
#include <winsock.h>
#include <time.h>
#include <windows.h>
#else
#include <sys/time.h>
#endif


/* c++ */
#include <string>
#include <stack>
#include <set>
#include <map>

#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#endif

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

#ifdef HAVE_PWD_H
#include <pwd.h>
#endif

#ifdef HAVE_LIBAFFLIB
#include <afflib/afflib.h>
#endif

#ifdef HAVE_LIBEWF
#if defined(_MSC_VER)
#include <config_msc.h>
#endif

#include <libewf.h>
#endif

#ifdef HAVE_SYS_UTSNAME_H
#include <sys/utsname.h>
#endif

#ifdef HAVE_LIBAFFLIB
#include <afflib/afflib.h>
#endif

#ifndef __BEGIN_DECLS
#if defined(__cplusplus)
#define __BEGIN_DECLS   extern "C" {
#define __END_DECLS     }
#else
#define __BEGIN_DECLS
#define __END_DECLS
#endif
#endif

#ifdef HAVE_LIBTSK3
//#include <tsk3/libtsk.h>
#include "tsk3/lib_tsk.h"
#endif

#ifdef __cplusplus
class xml {
private:
#ifdef HAVE_PTHREAD_H
    pthread_mutex_t M;			// mutext protecting out
#endif
    std::fstream out;				// where it is being written
    std::set<std::string> tags;			// XML tags
    std::string  tempfilename;
    std::stack<std::string>tag_stack;
    std::string tempfile_template;
    void  write_doctype(std::fstream &out);
    void  write_dtd();
    bool  make_dtd;
    void  verify_tag(std::string tag);
    void  spaces();			// print spaces corresponding to tag stack
    struct timeval t0;
    
public:
    std::string outfilename;
    static std::string make_command_line(int argc,char * const *argv){
	std::string command_line;
	for(int i=0;i<argc;i++){
	    if(i>0) command_line.push_back(' ');
	    command_line.append(argv[i]);
	}
	return command_line;
    }

    xml();			
    void set_makeDTD(bool flag);		 // should we write the DTD?
    void set_outfilename(const std::string &outfname);     // writes to this outfile with a DTD (needs a temp file)
    void set_tempfile_template(const std::string &temp);

    static std::string xmlescape(const std::string &xml);
    static std::string xmlstrip(const std::string &xml);
    
    void open();			// opens the output file

    /**
     * opens an existing XML file and jumps to the end.
     * @param tagmap  - any keys that are tags capture the values.
     * @param tagid   - if a tagid is provided, fill tagid_set with all of the tags seen.
     */
    void open_existing(std::map<std::string,std::string> *tagmap,std::string *tagid,std::set<std::string> *tagid_set);
    void close();			// writes the output to the file

    void tagout( const std::string &tag,const std::string &attribute);
    void push(const std::string &tag,const std::string &attribute);
    void push(const std::string &tag) {push(tag,"");}

    // writes a std::string as parsed data
    void puts(const std::string &pdata);

    // writes a std::string as parsed data
#ifdef __GNUC__
    void printf(const char *fmt,...) __attribute__((format(printf, 2, 3))); // "2" because this is "1"
#else
	void printf(const char *fmt,...);
#endif

    void pop();	// close the tag

/* These support Digital Forensics XML and require certain variables to be defined */
    void add_DFXML_build_environment(){
	/* __DATE__ formats as: Apr 30 2011 */
	struct tm tm;
	memset(&tm,0,sizeof(tm));
	push("build_environment");
#ifdef __GNUC__
	xmlprintf("compiler","","GCC %d.%d",__GNUC__, __GNUC_MINOR__);
#endif
#if defined(__DATE__) && defined(__TIME__) && defined(HAVE_STRPTIME)
	if(strptime(__DATE__,"%b %d %Y",&tm)){
	    char buf[64];
	    snprintf(buf,sizeof(buf),"%4d-%02d-%02dT%s",tm.tm_year+1900,tm.tm_mon+1,tm.tm_mday,__TIME__);
	    xmlout("compilation_date",buf);
	}
#endif
#ifdef HAVE_LIBTSK3
	xmlout("library", "", std::string("name=\"tsk\" version=\"") + tsk_version_get_str() + "\"",false);
#endif
#ifdef HAVE_LIBAFFLIB
	xmlout("library", "", std::string("name=\"afflib\" version=\"") + af_version() +"\"",false);
#endif
#ifdef HAVE_LIBEWF
	xmlout("library", "", std::string("name=\"libewf\" version=\"") + libewf_get_version() + "\"",false);
#endif
	pop();
    }
    void add_DFXML_execution_environment(const std::string &command_line);
    void add_DFXML_creator(const std::string &program,const std::string &version,const std::string &command_line){
	push("creator","version='1.0'");
	xmlout("program",program);
	xmlout("version",version);
	add_DFXML_build_environment();
	add_DFXML_execution_environment(command_line);
	pop();			// creator
    }
    void add_rusage();

    /**********************************************
     *** THESE ARE THE ONLY THREADSAFE ROUTINES ***
     **********************************************/
    void xmlcomment(const std::string &comment);

#ifdef __GNUC__
    void xmlprintf(const std::string &tag,const std::string &attribute,const char *fmt,...) 
	__attribute__((format(printf, 4, 5))); // "4" because this is "1";
#else
	void xmlprintf(const std::string &tag,const std::string &attribute,const char *fmt,...);
#endif

    void xmlout( const std::string &tag,const std::string &value, const std::string &attribute,
		 const bool escape_value);

    /* These all call xmlout or xmlprintf which already has locking */
    void xmlout( const std::string &tag,const std::string &value){ xmlout(tag,value,"",true); }
    void xmlout( const std::string &tag,const int value){ xmlprintf(tag,"","%d",value); }
    void xmloutl(const std::string &tag,const long value){ xmlprintf(tag,"","%ld",value); }
    void xmlout( const std::string &tag,const int64_t value){ xmlprintf(tag,"","%"PRId64,value); }
    void xmlout( const std::string &tag,const double value){ xmlprintf(tag,"","%f",value); }
    void xmlout( const std::string &tag,const struct timeval &ts) {
	xmlprintf(tag,"","%d.%06d",(int)ts.tv_sec, (int)ts.tv_usec);
    }
};
#endif

#endif
