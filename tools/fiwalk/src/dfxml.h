/*
 * Simson's XML output class.
 * Ideally include this AFTER your config file with the HAVE statements.
 */

#ifndef _XML_H_
#define _XML_H_

#ifndef __STDC_FORMAT_MACROS
  #define __STDC_FORMAT_MACROS
#endif

#ifdef HAVE_PTHREAD
  #include <pthread.h>
#endif
#include <stdio.h>
#include <fstream>
#include <string.h>
#include <sys/types.h>

#ifdef _MSC_VER
  #include <winsock.h>
  #include <time.h>
  #include <windows.h>
#else
  #include <sys/time.h>
  #include <inttypes.h>
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

#include "tsk/libtsk.h"

#ifdef __cplusplus
class xml {
private:
    /*** neither copying nor assignment is implemented ***
     *** We do this by making them private constructors that throw exceptions. ***/
    class not_impl: public std::exception {
	virtual const char *what() const throw() {
	    return "copying feature_recorder objects is not implemented.";
	}
    };
    xml(const xml &fr):
#ifdef HAVE_PTHREAD
	M(),
#endif
	outf(),out(),tags(),tag_stack(),tempfilename(),tempfile_template(),t0(),
	make_dtd(),outfilename(){
	throw new not_impl();
    }
    const xml &operator=(const xml &x){ throw new not_impl(); }
    /****************************************************************/
#ifdef HAVE_PTHREAD
    pthread_mutex_t M;			// mutext protecting out
#endif
    std::fstream outf;
    std::ostream *out;				// where it is being written; defaults to stdout
    std::set<std::string> tags;			// XML tags
    std::stack<std::string>tag_stack;
    std::string  tempfilename;
    std::string  tempfile_template;
    struct timeval t0;
    bool  make_dtd;
    std::string outfilename;
    void  write_doctype(std::fstream &out);
    void  write_dtd();
    void  verify_tag(std::string tag);
    void  spaces();			// print spaces corresponding to tag stack
public:
    std::stack<TSK_INUM_T> parent_stack;


    static std::string make_command_line(int argc,char * const *argv){
	std::string command_line;
	for(int i=0;i<argc;i++){
	    if(i>0) command_line.push_back(' ');
	    command_line.append(argv[i]);
	}
	return command_line;
    }

    xml();					 // defaults to stdout
    xml(const std::string &outfilename,bool makeDTD); // write to a file, optionally making a DTD
    virtual ~xml(){};
    void set_tempfile_template(const std::string &temp);

    static std::string xmlescape(const std::string &xml);
    static std::string xmlstrip(const std::string &xml);

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

    void add_DFXML_build_environment();
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

