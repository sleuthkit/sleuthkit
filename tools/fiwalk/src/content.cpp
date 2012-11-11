#include "tsk3/tsk_tools_i.h"


#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

#include <sys/types.h>

#ifdef _MSC_VER
  #ifndef _CRT_SECURE_NO_WARNINGS
  #define _CRT_SECURE_NO_WARNINGS
  #endif

  #ifndef _CRT_NONSTDC_NO_WARNINGS
  #define _CRT_NONSTDC_NO_WARNINGS
  #endif

#include <winsock.h>
#include <time.h>
#else
#include <sys/time.h>
#endif


#include <ctype.h>
#include <fcntl.h>

#ifndef O_BINARY
#define O_BINARY 0
#endif

#include <iostream>

#include "fiwalk.h"
#include "content.h"
#include "plugin.h"
#include "unicode_escape.h"

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif 

#ifdef HAVE_MAGIC_H
#include <magic.h>
#endif

#ifdef HAVE_ERR_H
#include <err.h>
#endif

/****************************************************************
 ** Content Output
 ****************************************************************/

/* strcasestrm from http://www.koders.com/ */
#ifndef HAVE_STRCASESTR
static char * strcasestr (char *haystack, char *needle)
{
    char *p, *startn = 0, *np = 0;

    for (p = haystack; *p; p++) {
	if (np) {
	    if (toupper(*p) == toupper(*np)) {
		if (!*++np)
		    return startn;
	    } else
		np = 0;
	} else if (toupper(*p) == toupper(*needle)) {
	    np = needle + 1;
	    startn = p;
	}
    }

    return 0;
}
#endif

/** set the filename and see if we need to do the plugin
 */
void content::set_filename(const string &filename)
{
    this->evidence_filename = filename;
    this->do_plugin = plugin_match(this->evidence_filename);
    if(do_plugin || opt_magic) open_tempfile();
    if(opt_save)               open_savefile();
}


bool content::name_filtered()
{
    if(namelist.size()>0 && evidence_filename.size()>0){
	for(vector<string>::const_iterator i = namelist.begin(); i!=namelist.end(); i++){
	    if(strcasestr((char*)evidence_filename.c_str(), (char*)i->c_str())){
		return false;		// no, name is not filtered
	    }
	}
	return true;			// name is filtered because it was not wanted
    }
    return false;			// name is not filtered because there is no filter list
}



/** given a filename, open the file and return the file descriptor.
 * If the file already exists, change the file name until it doesn't exist and open.
 */

#if _MSC_VER
#define MAXPATHLEN _MAX_PATH //found in stdlib.h of VC++
#endif 
static int open_filename_with_suffix(string &filename)
{
    for(int i=0;i<10000;i++){
	/* Make a format string that is filename.%d.ext if i>0 */
	char fname[MAXPATHLEN];
	if(i==0){
	    strcpy(fname,filename.c_str()); // just use the filename as is the first time
	} else {			      // otherwise, try a numeric suffix
	    string fmtstring = filename;
	    int ext = fmtstring.rfind('.');
	    if(ext==-1){
		fmtstring += ".%03d";
	    }
	    else {
		fmtstring.insert(ext,".%03d");
	    }
	    snprintf(fname,sizeof(fname),fmtstring.c_str(),i);
	}
	int fd = open(fname,O_WRONLY|O_TRUNC|O_CREAT|O_EXCL|O_BINARY,0777); // try to open
	if (fd>0){			// open is successful; return the fd
	    filename = fname;		// update the filename
	    return fd;
	}
    }
    return -1;			// something is very wrong; can't find a valid filename?
}

/** Open a temporary file to put the file for the plugin and/or the file command
 */
void content::open_tempfile()
{
    if(fd_temp>0) return;		//  already opened

    int added = 0;
    tempfile_path = tempdir + "/";
    for(string::const_iterator cc = evidence_filename.begin();
	cc != evidence_filename.end();
	cc++){
	if(isalnum(*cc) || *cc=='.'){
	    tempfile_path.push_back(*cc);
	    added++;
	}
    }
    if(added==0) tempfile_path += "tempfile";
    fd_temp = open_filename_with_suffix(tempfile_path);
    if(fd_temp<0) errx(1,"cannot open temp file %s:",tempfile_path.c_str());
}


/** Open a file where a bytestream will be saved.
 *
 * @param filename - specifies the name of the file. If the file
 * exists, then start a counter between the end of the file and the
 * extension and keep incrementing...
 *
 */
void content::open_savefile()
{
  /* Figure out the pathname to save */
  save_path = save_outdir + "/" + evidence_filename;
  fd_save = open_filename_with_suffix(save_path);
  if(fd_save<0){
      warn("cannot open save file '%s'",save_path.c_str());
      fd_save = 0;
  }
}


/**
 * run the file command.
 * -b = do not put the filename in the output.
 * -z = attempt to decompress compressed files.
 */
 
string content::filemagic()
{
#ifdef HAVE_LIBMAGIC
    static bool magic_init=false;
    static bool magic_bad = false;
    static magic_t mt;

    if(magic_bad) return string("");

    if(magic_init==false){
	magic_init=true;
	mt = magic_open(MAGIC_NONE);
	if(magic_load(mt,NULL)==-1){
	    magic_bad = true;
	    return string("");
	}
    }
    const char *ret_ = magic_file(mt,tempfile_path.c_str());
    string ret(ret_ ? ret_ : "");
#elif _MSC_VER
	char cmd[1024];
    char buf[1024];
    string ret;
    snprintf(cmd,sizeof(cmd),"file -b -z '%s'",tempfile_path.c_str());
    FILE *f = _popen(cmd,"r");
    while(!feof(f)){
	if(fgets(buf,sizeof(buf),f)) ret += buf;
    }
    _pclose(f);
    /* Remove the newlines */
#else
    char cmd[1024];
    char buf[1024];
    string ret;
    snprintf(cmd,sizeof(cmd),"file -b -z '%s'",tempfile_path.c_str());
    FILE *f = popen(cmd,"r");
    while(!feof(f)){
	if(fgets(buf,sizeof(buf),f)) ret += buf;
    }
    pclose(f);
    /* Remove the newlines */
#endif
    /* Remove newlines and invalid characters */
    for(string::iterator cc = ret.begin(); cc!=ret.end(); cc++){
	if(!isprint(*cc)){
	    *cc = ' ';
	}
    }
    while(ret.size()>0 && ret[ret.size()-1]=='\n'){
	ret.erase(ret.size()-1);
    }
    return ret;
}


void content::write_record()
{
    if(opt_magic) {
	file_info("libmagic",validateOrEscapeUTF8(this->filemagic()));
    }
    if(this->segs.size()>0){
	string runs = "";
	for(seglist::const_iterator i = this->segs.begin();i!=this->segs.end();i++){
	    char buf[1024];
	    if(i->flags & TSK_FS_BLOCK_FLAG_SPARSE){
		sprintf(buf,"       <byte_run file_offset='%"PRIu64"' fill='0' len='%"PRIu64"'/>\n",
			i->file_offset,i->len);
	    } else if (i->flags & TSK_FS_BLOCK_FLAG_RAW){
		sprintf(buf,
			"       <byte_run file_offset='%"PRIu64"' fs_offset='%"PRIu64"' " "img_offset='%"PRIu64"' len='%"PRIu64"'/>\n",
			i->file_offset,i->fs_offset,i->img_offset,i->len);
	    } else if (i->flags & TSK_FS_BLOCK_FLAG_COMP){
		if(i->fs_offset){
		    sprintf(buf,
			    "       <byte_run file_offset='%"PRIu64"' fs_offset='%"PRIu64"' "
			    "img_offset='%"PRIu64"' uncompressed_len='%"PRIu64"'/>\n",
			    i->file_offset,i->fs_offset,i->img_offset,i->len);
		} else {
		    sprintf(buf,
			    "       <byte_run file_offset='%"PRIu64"' uncompressed_len='%"PRIu64"'/>\n",
			    i->file_offset,i->len);
		}
	    } else if (i->flags & TSK_FS_BLOCK_FLAG_RES){
		sprintf(buf,
			"       <byte_run file_offset='%"PRIu64"' fs_offset='%"PRIu64"' "
                "img_offset='%"PRIu64"' len='%"PRIu64"' type='resident'/>\n",
			i->file_offset,i->fs_offset,i->img_offset,i->len);
	    } else{
		sprintf(buf,"       <byte_run file_offset='%"PRIu64"' unknown_flags='%d'/>\n",i->file_offset,i->flags);
	    }
	    runs += buf;
	}
	file_info_xml("byte_runs",runs);
	if(!invalid){
	    if(opt_md5  && h_md5.hashed_bytes>0)   file_info(h_md5.final());
	    if(opt_sha1 && h_sha1.hashed_bytes>0)  file_info(h_sha1.final());
	}
    }

    /* This stuff is only if we are creating ARFF output */
    if(a){
	file_info("fragments",this->segs.size());
	if(img_info->sector_size>0){
	    if(this->segs.size()>=1){
		int64_t frag1start = this->segs[0].img_offset / img_info->sector_size;
		file_info("frag1startsector",frag1start);
	    }
	    if(this->segs.size()>=2){
		int64_t frag2start = this->segs[1].img_offset / img_info->sector_size;
		file_info("frag2startsector",frag2start);
	    }
	}
    }
}

/* Do we need full content? */
bool content::need_file_walk()
{
  return opt_md5 || opt_sha1 || opt_save || do_plugin || opt_magic
      || opt_get_fragments;
//      || opt_compute_sector_hashes;
}

/** Called to create a new segment. */
void content::add_seg(int64_t img_offset,int64_t fs_offset,
		      int64_t file_offset,int64_t len,
		      TSK_FS_BLOCK_FLAG_ENUM flags)
{
    struct seg newseg;
    newseg.img_offset = img_offset;
    newseg.fs_offset = fs_offset;
    newseg.file_offset = file_offset;
    newseg.len   = len;
    newseg.flags = flags;
    this->segs.push_back(newseg);
}


/** Called when new bytes are encountered.
 * An important bug: currently we assume that the bytes added are contigious.
 */
void content::add_bytes(const u_char *buf,uint64_t file_offset,ssize_t size)
{
//    if(opt_compute_sector_hashes){
//	/* process the sector hashes as necessary */
//	const u_char *b = buf;
//	ssize_t s = size;
//
//	while(s>0){
//	    /* See how many bytes to copy */
//	    ssize_t count = s;
//	    ssize_t needed = sectorhash_size-h_sectorhash.hashed_bytes;
//	    if (count > needed) count = needed;
//	    h_sectorhash.update(b,needed);
//	    if(h_sectorhash.hashed_bytes == sectorhash_size){
//		/* Time to write the sector hash and reset the hash counter */
//		sectorhashes.push_back(h_sectorhash.final().hexdigest());
//		h_sectorhash.release();	
//	    }
//	    b += count;
//	    s -= count;
//	}
//    }
    if(invalid==false){
	if(opt_md5)   h_md5.update((unsigned char *)buf,size);
	if(opt_sha1)  h_sha1.update((unsigned char *)buf,size);
    }
    if(fd_save){
	if(lseek(fd_save,file_offset,SEEK_SET)<0){
	    warn("lseek(fd_save) failed:");
	    close(fd_save);
	    fd_save=0;
	}
	if(fd_save){
	    ssize_t res = write(fd_save,buf,size);
	    if(res!=size){
		warn("write(%d,%p,%"PRId64")=%"PRId64,
		     fd_save,buf,(int64_t)size,(int64_t)res);
		close(fd_save);
		fd_save=0;
	    }
	}
    }
    if(fd_temp){
	if(lseek(fd_temp,file_offset,SEEK_SET)<0){
	    warn("lseek(fd_temp) failed:");
	    close(fd_temp);
	    fd_temp = 0;
	}
	if(fd_temp){
	    ssize_t res = write(fd_temp,buf,size);
	    if(res!=size){
		warn("write(%d,%p,%"PRId64")=%"PRId64,
		     fd_temp,buf,(int64_t)size,(int64_t)res);
		close(fd_temp);
		fd_temp=0;
	    }
	}
    }
    total_bytes += size;
}


content::~content()
{
    if(fd_save){			// close the save file if it exists
	close(fd_save);
	if(total_bytes==0){		// unlink the save file if it has no bytes
	    ::unlink(save_path.c_str());
	}
	fd_save = 0;
    }
    if(fd_temp){			// close temp file if it is open
	close(fd_temp);
	fd_temp = 0;
    }
    if(tempfile_path.size()>0){		// unlink temp file if one was created
	::unlink(tempfile_path.c_str());
    }
}
