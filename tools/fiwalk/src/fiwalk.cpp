/**
 * fiwalk.cpp:
 * File and Inode Walk.
 *
 * This application uses SleuthKit to generate a report of all of the files
 * and orphaned inodes found in a disk image. It can optionally compute the
 * MD5 of any objects, save those objects into a directory, or both.
 *
 * Algorithm:
 * 1 - Find all of the partitions on the disk.
 * 2 - For each partition, walk the files.
 * 3 - For each file, print the requested information.
 * 4 - For each partition, walk the indoes
 * 5 - For each inode, print the requested information.
 *
 * @author Simson Garfinkel
 *
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


/* config.h must be first */
#include "tsk/tsk_tools_i.h"


#include <stdio.h>
#include "fiwalk.h"
#include "content.h"

/* Bring in our headers */
#include "arff.h"
#include "plugin.h"

#include "utils.h"

#ifdef _MSC_VER
#include <direct.h>
#include <crtdefs.h>
#include <windows.h>
#define _CRT_SECURE_NO_WARNINGS
//#define mkdir _mkdir
#endif


#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

/* Individual 'state' variables */
string  plugin_filename;


/****************************************************************
 ** Support routines
 ****************************************************************/
static const char *cstr(const string &str){
    return str.c_str();
}

static string fw_empty("");


/****************************************************************
 ** XML output
 ****************************************************************/

/****************************************************************
 ** Metadata Output
 ****************************************************************/

/**
 * output a comment in the current file format
 */
void fiwalk::comment(const char *format,...)
{
    if(opt_body_file) return;           // no comments in body file

    char buf[1024];
    va_list ap;
    va_start(ap, format);
    vsnprintf(buf,sizeof(buf),format,ap);
    va_end(ap);

    if(t) fprintf(t,"# %s\n",buf);
    if(x) x->xmlcomment(buf);
    if(a) a->add_comment(buf);
}

/**
 * output a name/format/value for the current partition.
 * This information is simply printed as comments for ARFF files.
 *
 * @param name - the name of the thing being output
 * @param format - the format for the thing
 * @param ... - the value
 * This will output as a comment in the ARFF file
 */
void fiwalk::partition_info(const string &name,const string &value,const string &attribute)
{

    if(name.find(" ")!=string::npos) err(1,"partition_info(%s) has a space in it",cstr(name));
    if(a) a->add_comment(name + ": " + value);
    if(t && !opt_body_file) fputs(cstr(name + ": " + value + "\n"),t);
    if(x) x->xmlout(name,value,attribute,true);
}

void fiwalk::partition_info(const string &name,const string &value)
{
    partition_info(name,value,fw_empty);
}

void fiwalk::partition_info(const string &name,long i)
{
    char buf[1024];
    snprintf(buf,sizeof(buf),"%ld",i);
    partition_info(name,buf,fw_empty);
}

void fiwalk::partition_info(const string &name, const struct timeval &ts)
{
    char buf[64];
    snprintf(buf, sizeof(buf), "%d.%06d",(int)ts.tv_sec, (int)ts.tv_usec);
    partition_info(name,buf,fw_empty);
}

/****************************************************************
 * These file_info(name,value) are called for each extracted attribute
 * for each file.  Some of the class are made by metadata extraction
 * in this module; others are called from the plugin system.
 */
void fiwalk::file_info_xml(const string &name,const string &value)
{
    if(x){
	x->push(name);
	x->puts(value);
	x->pop();
    }
}

void fiwalk::file_info_xml2(const string &name,const string &attrib,const string &value)
{
    if(x){
	x->push(name,attrib);
	x->puts(value);
	x->pop();
    }
}


/* Process a string value */
void fiwalk::file_info(const string &name,const string &value)
{
    if(a) a->add_value(name,value);
    if(t && !opt_body_file) fputs(cstr(name + ": " + value + "\n"),t);
    if(x) x->xmlout(name,value,std::string(),true); // escape the XML
}

/* this file_info is for sending through a hash. */
void fiwalk::file_info(const md5_t &h)
{
    if(a) a->add_value("md5",h.hexdigest());
    if(t && !opt_body_file) fputs(cstr("md5: " + h.hexdigest() + "\n"),t);
    if(x) x->xmlout("hashdigest",h.hexdigest(),"type='md5'",false);
}

void fiwalk::file_info(const sha1_t &h)
{
    if(a) a->add_value("sha1",h.hexdigest());
    if(t && !opt_body_file) fputs(cstr("sha1: " + h.hexdigest() + "\n"),t);
    if(x) x->xmlout("hashdigest",h.hexdigest(),"type='sha1'",false);
}

void fiwalk::file_info(const sha256_t &h)
{
    if(a) a->add_value("sha256",h.hexdigest());
    if(t && !opt_body_file) fputs(cstr("sha256: " + h.hexdigest() + "\n"),t);
    if(x) x->xmlout("hashdigest",h.hexdigest(),"type='sha256'",false);
}


/* Process a numeric value */
void fiwalk::file_info(const string name, int64_t value)
{
    if(a) a->add_value(name,value);
    if(t || x){
	if(t) fprintf(t,"%s: %" PRId64 "\n",cstr(name),value);
	if(x) x->xmlprintf(name,"","%" PRId64,value);
    }
}

/* Process a temporal value */
void fiwalk::file_infot(const string name,time_t t0, TSK_FS_TYPE_ENUM ftype)
{
    const char * tm_format = NULL;

    if(TSK_FS_TYPE_ISFAT(ftype))
    {
#if defined(_MSC_VER) || (defined(__MINGW32__) && !defined(_UCRT))
        tm_format="%Y-%m-%dT%H:%M:%S";
#else
        tm_format="%FT%T";
#endif
    }
    else
    {
#if defined(_MSC_VER) || (defined(__MINGW32__) && !defined(_UCRT))
        tm_format="%Y-%m-%dT%H:%M:%SZ";
#else
        tm_format="%FT%TZ";
#endif
    }

    if(a) a->add_valuet(name,t0);
//	struct tm *temp_time = gmtime(&t0);
    if(x){
	char buf[32];
	strftime(buf,sizeof(buf),tm_format,gmtime(&t0));
	if (TSK_FS_TYPE_ISFAT(ftype)) {
            if (!name.compare("atime"))
                x->xmlout(name,buf,"prec=\"86400\"", false);
            if (!name.compare("mtime"))
                x->xmlout(name,buf,"prec=\"2\"", false);
            if (!name.compare("crtime"))
                x->xmlout(name,buf,"prec=\"2\"", false);
	}
	else
            x->xmlout(name,buf);
    }
    if(t) {
	char buf[64];
	fprintf(t,"%s: %ld\n",name.c_str(),(long)t0);
	strftime(buf,sizeof(buf),tm_format,gmtime(&t0));
	fprintf(t,"%s_txt: %s\n",name.c_str(),buf);
    }
}

void fiwalk::file_infot(const string name,time_t t0)
{
#if defined(_MSC_VER) || (defined(__MINGW32__) && !defined(_UCRT))
#define TM_FORMAT "%Y-%m-%dT%H:%M:%SZ"
#else
#define TM_FORMAT "%FT%TZ"
#endif

    if(a) a->add_valuet(name,t0);
//	struct tm *temp_time = gmtime(&t0);
    if(x){
	char buf[32];
	strftime(buf,sizeof(buf),TM_FORMAT,gmtime(&t0));
	x->xmlout(name,buf);
    }
    if(t) {
	char buf[64];
	fprintf(t,"%s: %ld\n",name.c_str(),(long)t0);
	strftime(buf,sizeof(buf),TM_FORMAT,gmtime(&t0));
	fprintf(t,"%s_txt: %s\n",name.c_str(),buf);
    }
}

/****************************************************************/
string mytime()
{
    time_t t = time(0);
    char *buf = ctime(&t);
    buf[24] = 0;
    return string(buf);
}

bool has_unprintable(const u_char *buf,int buflen)
{
    while(buflen>0){
	if(!isprint(*buf)) return true;
	buf++;
	buflen--;
    }
    return false;
}


#if defined(HAVE_LIBAFFLIB) && defined(HAVE_AF_DISPLAY_AS_QUAD)
static const char *quads[] = {
    AF_IMAGESIZE,
    AF_BADSECTORS,
    AF_BLANKSECTORS,
    AF_DEVICE_SECTORS,
    0
};


int af_display_as_quad(const char *segname)
{
    for(int i=0;quads[i];i++){
	if(strcmp(segname,quads[i])==0) return true;
    }
    return false;
}


int af_display_as_hex(const char *segname)
{
    if(strcmp(segname,AF_MD5)==0) return 1;
    if(strcmp(segname,AF_SHA1)==0) return 1;
    if(strcmp(segname,AF_SHA256)==0) return 1;
    if(strcmp(segname,AF_IMAGE_GID)==0) return 1;
    return 0;
}
#endif

int fiwalk::run()
{
    gettimeofday(&tv0,0);
    std::ofstream xout;
    if (opt_no_data && (opt_md5 || opt_sha1 || opt_save || opt_magic)) {
        errx(1, "-g conflicts with options requiring data access (-z may be needed)");
    }

    if (opt_save){
	if (access(save_outdir.c_str(),F_OK)){
	    if (mkdir(save_outdir.c_str()
#ifdef WIN32
#else
                     ,0777
#endif
                   )){
                err(1,"Cannot make directory: %s",save_outdir.c_str());
            }
        }
        if (access(save_outdir.c_str(),R_OK)){
            err(1,"Cannot access directory: %s",save_outdir.c_str());
        }
    }

    if (text_fn){
        if (access(text_fn,F_OK)==0) errx(1,"%s: file exists",text_fn);
        t = fopen(text_fn,"w");
        if (!t) err(1,"%s",text_fn);
    }

    if (arff_fn){
        if (access(arff_fn,F_OK)==0) errx(1,"%s: file exists",arff_fn);
        a = new arff("fiwalk");		// the ARFF output object
        a->set_outfile(arff_fn);
    }

    /* XML initialization */
    x = nullptr;

    if (opt_x){
        x = new xml(std::cout, false);			// default to stdout
    }

    if (xml_fn.size()>0){
        if (x) errx(1,"Cannot write XML to stdout and file at same time\n");
        if (xml_fn == "0"){              // special case of -X0
            string newfn = filename;
            xml_fn = newfn.substr(0,newfn.rfind(".")) + ".xml";
        }
        if (access(xml_fn.c_str(),F_OK)==0){
            if (opt_zap){
                if (unlink(xml_fn.c_str())){
                    err(1,"%s: file exists and cannot unlink",xml_fn.c_str());
                }
            }
            else{
                errx(1,"%s: file exists",xml_fn.c_str());
            }
        }
        xout = std::ofstream(xml_fn.c_str());
        if (!xout.is_open()){
            errx(1,"Cannot open %s: %s",xml_fn.c_str(),strerror(errno));
        }
        delete x;
        x = new xml(xout,true);	// we will make DTD going to a file
    }

    /* If no output file has been specified, output text to stdout */
    if (a==0 && x==0 && t==0){
        t = stdout;
    }

    if (strstr(filename,".aff") || strstr(filename,".afd") || strstr(filename,".afm")){
#ifndef HAVE_LIBAFFLIB
        fprintf(stderr,"ERROR: fiwalk was compiled without AFF support.\n");
        exit(0);
#else
#endif
    }

    /* If we are outputing ARFF, create the ARFF object and set the file types for the file system metadata */
    if (a){
        a->add_attribute("id",arff::NUMERIC);
        a->add_attribute("partition",arff::NUMERIC);
        a->add_attribute("filesize",arff::NUMERIC);
        a->add_attribute("mtime",arff::DATE);
        a->add_attribute("ctime",arff::DATE);
        a->add_attribute("atime",arff::DATE);
        a->add_attribute("fragments",arff::NUMERIC);
        a->add_attribute("frag1startsector",arff::NUMERIC);
        a->add_attribute("frag2startsector",arff::NUMERIC);
        a->add_attribute("filename",arff::STRING);
        if (opt_md5) a->add_attribute("md5",arff::STRING);
        if (opt_sha1) a->add_attribute("sha1",arff::STRING);
    }

    /* output per-run metadata for XML output */
    if (x){
        /* Output Dublin Core information */
        x->push("dfxml",
                "\n  xmlns='http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML'"
                "\n  xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'"
                "\n  xmlns:dc='http://purl.org/dc/elements/1.1/'"
                "\n  version='1.1.0+'" );
        x->push("metadata", "");
        x->xmlout("dc:type","Disk Image",fw_empty,false);
        x->pop();

        if (opt_variable) {
            x->add_DFXML_creator("fiwalk",tsk_version_get_str(),command_line);
        }
    }

    /* Can't use comment until after here... */
    if (config_file){
        comment("Reading configuration file %s",config_file);
        config_read(config_file);    /* Read the configuration file */
    }

    /* Check that we have a valid file format */
    if (x) x->push("source");
    partition_info("image_filename",filename);

    if (!x){
        partition_info("fiwalk_version",tsk_version_get_str());
        partition_info("start_time",mytime());
        partition_info("tsk_version",tsk_version_get_str());
    }
    if (x) x->pop();                     // source

    if (opt_debug) printf("calling tsk_img_open(%s)\n",filename);

    int count = process_image_file(argc, argv, audit_file, sector_size);
    if (count<=0 || sector_size!=512){
        comment("Retrying with 512 byte sector size.");
        count = process_image_file(argc, argv, audit_file, 512);
    }

    /* Calculate time elapsed (reported as a comment and with rusage) */
    struct timeval tv;
    char tvbuf[64];
    gettimeofday(&tv1,0);
    tv.tv_sec = tv1.tv_sec - tv0.tv_sec;
    if (tv1.tv_usec > tv0.tv_usec){
        tv.tv_usec = tv1.tv_usec - tv0.tv_usec;
    } else {
        tv.tv_sec--;
        tv.tv_usec = (tv1.tv_usec+1000000) - tv0.tv_usec;
    }
    snprintf(tvbuf, sizeof(tvbuf), "%d.%06d",(int)tv.tv_sec, (int)tv.tv_usec);

    if (opt_variable) {
        comment("clock: %s",tvbuf);
    }

#ifdef HAVE_SYS_RESOURCE_H
#ifdef HAVE_GETRUSAGE
    /* Print usage information */
    struct rusage ru;
    memset(&ru,0,sizeof(ru));
    if (getrusage(RUSAGE_SELF,&ru)==0 && opt_variable){
        if (x) x->push("rusage");
        partition_info("utime",ru.ru_utime);
        partition_info("stime",ru.ru_stime);
        partition_info("maxrss",ru.ru_maxrss);
        partition_info("minflt",ru.ru_minflt);
        partition_info("majflt",ru.ru_majflt);
        partition_info("nswap",ru.ru_nswap);
        partition_info("inblock",ru.ru_inblock);
        partition_info("oublock",ru.ru_oublock);
        partition_info("clocktime",tv);
        comment("stop_time: %s",cstr(mytime()));
        if (x) x->pop();
    }
#endif
#endif


    // *** Added <finished time="(time_t)" duration="<seconds>" />

    if (a){
        a->write();
        delete a;
    }


    if (t) comment("=EOF=");
    if (x) {
        x->pop();			// <dfxml>
    }
    delete(x);
    return 0;
}
