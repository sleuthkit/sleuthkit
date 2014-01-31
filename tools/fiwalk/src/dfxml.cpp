/**
 * implementation for C++ XML generation class
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


#include "tsk/tsk_tools_i.h"

#include "dfxml.h"
#include <errno.h>

using namespace std;

#include <iostream>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#ifndef _MSC_VER
  #include <sys/param.h>
#endif
#include <assert.h>
#include <fcntl.h>
#include <stack>

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

static const char *xml_header = "<?xml version='1.0' encoding='UTF-8'?>\n";

// Implementation of mkstemp for windows found on pan-devel mailing
// list archive
// @http://www.mail-archive.com/pan-devel@nongnu.org/msg00294.html
#ifndef _S_IREAD
  #define _S_IREAD 256
#endif

#ifndef _S_IWRITE
  #define _S_IWRITE 128
#endif

#ifndef O_BINARY
  #define O_BINARY 0
#endif

#ifndef _O_SHORT_LIVED
  #define _O_SHORT_LIVED 0
#endif

#ifdef _MSC_VER
  #include <fcntl.h>
int mkstemp(char *tmpl)
{
   int ret=-1;
   mktemp(tmpl);
   ret=open(tmpl,O_RDWR|O_BINARY|O_CREAT|O_EXCL|_O_SHORT_LIVED, _S_IREAD|_S_IWRITE);
   return ret;
}
#endif


#ifndef O_BINARY
#define O_BINARY 0
#endif

#ifndef _O_SHORT_LIVED
#define _O_SHORT_LIVED 0
#endif

static string xml_lt("&lt;");
static string xml_gt("&gt;");
static string xml_am("&amp;");
static string xml_ap("&apos;");
static string xml_qu("&quot;");

#if _MSC_VER
//Internal gettimeofday for windows builds
static int gettimeofday(struct timeval *tp, void* tzp){
    tp->tv_sec = time(0);
    return 0;
}
#endif

string xml::xmlescape(const string &xml)
{
    string ret;
    for(string::const_iterator i = xml.begin(); i!=xml.end(); i++){
	switch(*i){
	case '>':  ret += xml_gt; break;
	case '<':  ret += xml_lt; break;
	case '&':  ret += xml_am; break;
	case '\'': ret += xml_ap; break;
	case '"':  ret += xml_qu; break;
	case '\000': break;		// remove nulls
	default:
	    ret += *i;
	}
    }
    return ret;
}

/**
 * Strip an XML string as necessary for a tag name.
 */

string xml::xmlstrip(const string &xml)
{
    string ret;
    for(string::const_iterator i = xml.begin(); i!=xml.end(); i++){
	if(isprint(*i) && !strchr("<>\r\n&'\"",*i)){
	    ret += isspace(*i) ? '_' : tolower(*i);
	}
    }
    return ret;
}

#include <iostream>
#include <streambuf>

#ifdef _MSC_VER
# include <io.h>
#else
# include <unistd.h>
#endif

/****************************************************************/

xml::xml():outf(),out(&cout),tags(),tag_stack(),tempfilename(),tempfile_template("/tmp/xml_XXXXXXXX"),
	   t0(),make_dtd(false),outfilename()
{
    gettimeofday(&t0,0);
    *out << xml_header;
}

/* This should be rewritten so that the temp file is done on close, not on open */
xml::xml(const std::string &outfilename_,bool makeDTD):
    outf(outfilename_.c_str(),ios_base::out),
    out(),tags(),tag_stack(),tempfilename(),tempfile_template(outfilename_+"_tmp_XXXXXXXX"),
    t0(),make_dtd(false),outfilename(outfilename_)
{
    gettimeofday(&t0,0);
    if(!outf.is_open()){
	perror(outfilename_.c_str());
	exit(1);
    }
    out = &outf;						// use this one instead
    *out << xml_header;
}





void xml::set_tempfile_template(const std::string &temp)
{
    tempfile_template = temp;
}





void xml::close()
{
    outf.close();
}

void xml::write_dtd()
{
    *out << "<!DOCTYPE fiwalk\n";
    *out << "[\n";
    for(set<string>::const_iterator it = tags.begin(); it != tags.end(); it++){
	*out << "<!ELEMENT " << *it << "ANY >\n";
    }
    *out << "<!ATTLIST volume startsector CDATA #IMPLIED>\n";
    *out << "<!ATTLIST run start CDATA #IMPLIED>\n";
    *out << "<!ATTLIST run len CDATA #IMPLIED>\n";
    *out << "]>\n";
}

/**
 * make sure that a tag is valid and, if so, add it to the list of tags we use
 */
void xml::verify_tag(string tag)
{
    if(tag[0]=='/') tag = tag.substr(1);
    if(tag.find(" ") != string::npos){
	cerr << "tag '" << tag << "' contains space. Cannot continue.\n";
	exit(1);
    }
    tags.insert(tag);
}

void xml::puts(const string &v)
{
    *out << v;
}

void xml::spaces()
{
    for(u_int i=0;i<tag_stack.size();i++){
	*out << "  ";
    }
}

void xml::tagout(const string &tag,const string &attribute)
{
    verify_tag(tag);
    *out << "<" << tag;
    if(attribute.size()>0) *out << " " << attribute;
    *out << ">";
}

#if (!defined(HAVE_VASPRINTF)) || defined(_WIN32)
#ifndef _WIN32
#define ms_printf __print
#define __MINGW_ATTRIB_NONNULL(x) 
#endif

extern "C" {
    /**
     * We do not have vasprintf.
     * We have determined that vsnprintf() does not perform properly on windows.
     * So we just allocate a huge buffer and then strdup() and hope!
     */
#ifdef _GNUC_
    int vasprintf(char **ret,const char *fmt,va_list ap)
	__attribute__((__format__(ms_printf, 2, 0))) 
	__MINGW_ATTRIB_NONNULL(2) ;
#endif
    int vasprintf(char **ret,const char *fmt,va_list ap) 
    {
	/* Figure out how long the result will be */
	char buf[65536];
	int size = vsnprintf(buf,sizeof(buf),fmt,ap);
	if(size<0) return size;
	/* Now allocate the memory */
	*ret = (char *)strdup(buf);
	return size;
    }
}
#endif


void xml::printf(const char *fmt,...)
{
    va_list ap;
    va_start(ap, fmt);

    /** printf to stream **/
    char *ret = 0;
    if(vasprintf(&ret,fmt,ap) < 0){
	*out << "xml::xmlprintf: " << strerror(errno);
	exit(EXIT_FAILURE);
    }
    *out << ret;
    free(ret);
    /** end printf to stream **/

    va_end(ap);
}

void xml::push(const string &tag,const string &attribute)
{
    spaces();
    tag_stack.push(tag);
    tagout(tag,attribute);
    *out << '\n';
}

void xml::pop()
{
    assert(tag_stack.size()>0);
    string tag = tag_stack.top();
    tag_stack.pop();
    spaces();
    tagout("/"+tag,"");
    *out << '\n';
}




void xml::add_DFXML_execution_environment(const std::string &command_line)
{
    char buf[256];

    push("execution_environment");
#ifdef HAVE_ASM_CPUID
#ifndef __WORDSIZE
#define __WORDSIZE 32
#endif
#define cpuid(id) __asm__( "cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(id), "b"(0), "c"(0), "d"(0))
#define b(val, base, end) ((val << (__WORDSIZE-end-1)) >> (__WORDSIZE-end+base-1))
    unsigned long eax, ebx, ecx, edx;
    cpuid(0);
    
    snprintf(buf,sizeof(buf),"%.4s%.4s%.4s", (char *)&ebx, (char *)&edx, (char *)&ecx);
    push("cpuid");
    xmlout("identification",buf);

    cpuid(1);
    xmlout("family", (int64_t) b(eax, 8, 11));
    xmlout("model", (int64_t) b(eax, 4, 7));
    xmlout("stepping", (int64_t) b(eax, 0, 3));
    xmlout("efamily", (int64_t) b(eax, 20, 27));
    xmlout("emodel", (int64_t) b(eax, 16, 19));
    xmlout("brand", (int64_t) b(ebx, 0, 7));
    xmlout("clflush_size", (int64_t) b(ebx, 8, 15) * 8);
    xmlout("nproc", (int64_t) b(ebx, 16, 23));
    xmlout("apicid", (int64_t) b(ebx, 24, 31));
    
    cpuid(0x80000006);
    xmlout("L1_cache_size", (int64_t) b(ecx, 16, 31) * 1024);
    pop();
#endif


#ifdef HAVE_SYS_UTSNAME_H
    struct utsname name;
    if(uname(&name)==0){
	xmlout("os_sysname",name.sysname);
	xmlout("os_release",name.release);
	xmlout("os_version",name.version);
	xmlout("host",name.nodename);
	xmlout("arch",name.machine);
    }
#else
#ifdef UNAMES
    xmlout("os_sysname",UNAMES,"",false);
#endif
#ifdef HAVE_GETHOSTNAME
    {
	char hostname[1024];
	if(gethostname(hostname,sizeof(hostname))==0){
	    xmlout("host",hostname);
	}
    }
#endif
#endif	

#ifdef _MSC_VER
#define TM_FORMAT "%Y-%m-%dT%H:%M:%SZ"
#else
#define TM_FORMAT "%FT%TZ"
#endif

    xmlout("command_line", command_line); // quote it!
#ifdef HAVE_GETUID
    xmlprintf("uid","","%d",getuid());
#ifdef HAVE_GETPWUID
    xmlout("username",getpwuid(getuid())->pw_name);
#endif
#endif
    
    time_t t = time(0);
    strftime(buf,sizeof(buf),TM_FORMAT,gmtime(&t));
    xmlout("start_time",buf);
    pop();			// <execution_environment>
}


void xml::add_rusage()
{
#ifdef HAVE_SYS_RESOURCE_H
#ifdef HAVE_GETRUSAGE
    struct rusage ru;
    memset(&ru,0,sizeof(ru));
    if(getrusage(RUSAGE_SELF,&ru)==0){
	push("rusage");
	xmlout("utime",ru.ru_utime);
	xmlout("stime",ru.ru_stime);
	xmloutl("maxrss",(long)ru.ru_maxrss);
	xmloutl("minflt",(long)ru.ru_minflt);
	xmloutl("majflt",(long)ru.ru_majflt);
	xmloutl("nswap",(long)ru.ru_nswap);
	xmloutl("inblock",(long)ru.ru_inblock);
	xmloutl("oublock",(long)ru.ru_oublock);

	struct timeval t1;
	gettimeofday(&t1,0);
	struct timeval t;
	
	t.tv_sec = t1.tv_sec - t0.tv_sec;
	if(t1.tv_usec > t0.tv_usec){
	    t.tv_usec = t1.tv_usec - t0.tv_usec;
	} else {
	    t.tv_sec--;
	    t.tv_usec = (t1.tv_usec+1000000) - t0.tv_usec;
	}
	xmlout("clocktime",t);
	pop();
    }
#endif
#endif
}


/****************************************************************
 *** THESE ARE THE ONLY THREADSAFE ROUTINES
 ****************************************************************/
void xml::xmlcomment(const string &comment_)
{
    *out << "<!-- " << comment_ << " -->\n";
    out->flush();
}


void xml::xmlprintf(const std::string &tag,const std::string &attribute, const char *fmt,...)
{
    spaces();
    tagout(tag,attribute);
    va_list ap;
    va_start(ap, fmt);

    /** printf to stream **/
    char *ret = 0;
    if(vasprintf(&ret,fmt,ap) < 0){
	cerr << "xml::xmlprintf: " << strerror(errno) << "\n";
	exit(EXIT_FAILURE);
    }
    *out << ret;
    free(ret);
    /** end printf to stream **/

    va_end(ap);
    tagout("/"+tag,"");
    *out << '\n';
    out->flush();
}

void xml::xmlout(const string &tag,const string &value,const string &attribute,bool escape_value)
{
    spaces();
    if(value.size()==0){
	tagout(tag,attribute+"/");
    } else {
	tagout(tag,attribute);
	if(escape_value) *out << xmlescape(value);
	else *out << value;
	tagout("/"+tag,"");
    }
    *out << "\n";
    out->flush();
}

#ifdef HAVE_LIBEWF
#include <libewf.h>
#endif

#ifdef HAVE_EXIV2
#ifdef GNUC_HAS_DIAGNOSTIC_PRAGMA
#pragma GCC diagnostic ignored "-Wshadow"
#pragma GCC diagnostic ignored "-Weffc++"
#endif
#include <exiv2/exiv2.hpp>
#include <exiv2/version.hpp>
#endif

#ifdef HAVE_LIBAFFLIB
#include <afflib/afflib.h>
#endif


/* These support Digital Forensics XML and require certain variables to be defined */
void xml::add_DFXML_build_environment()
{
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
#ifdef HAVE_LIBTSK
    xmlout("library", "", std::string("name=\"tsk\" version=\"") + tsk_version_get_str() + "\"",false);
#endif
#ifdef HAVE_LIBAFFLIB
    xmlout("library", "", std::string("name=\"afflib\" version=\"") + af_version() +"\"",false);
#endif
#ifdef HAVE_LIBEWF
    xmlout("library", "", std::string("name=\"libewf\" version=\"") + libewf_get_version() + "\"",false);
#endif
#ifdef HAVE_EXIV2
    xmlout("library", "", std::string("name=\"exiv2\" version=\"") + EXV_PACKAGE_VERSION + "\"",false);
#endif
    pop();
}

