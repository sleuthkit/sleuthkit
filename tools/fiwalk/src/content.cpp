#include "tsk/tsk_tools_i.h"


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

#define MAX_SPARSE_SIZE 1024*1024*64


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
		sprintf(buf,"       <byte_run file_offset='%" PRIu64 "' fill='0' len='%" PRIu64 "'", i->file_offset,i->len);
	    } else if (i->flags & TSK_FS_BLOCK_FLAG_RAW){
		sprintf(buf,
			"       <byte_run file_offset='%" PRIu64 "' fs_offset='%" PRIu64 "' " "img_offset='%" PRIu64 "' len='%" PRIu64 "'",
			i->file_offset,i->fs_offset,i->img_offset,i->len);
	    } else if (i->flags & TSK_FS_BLOCK_FLAG_COMP){
		if(i->fs_offset){
		    sprintf(buf,
			    "       <byte_run file_offset='%" PRIu64 "' fs_offset='%" PRIu64 "' "
			    "img_offset='%" PRIu64 "' uncompressed_len='%" PRIu64 "'",
			    i->file_offset,i->fs_offset,i->img_offset,i->len);
		} else {
		    sprintf(buf,
			    "       <byte_run file_offset='%" PRIu64 "' uncompressed_len='%" PRIu64 "'", i->file_offset,i->len);
		}
	    } else if (i->flags & TSK_FS_BLOCK_FLAG_RES){
		sprintf(buf,
			"       <byte_run file_offset='%" PRIu64 "' fs_offset='%" PRIu64 "' "
                        "img_offset='%" PRIu64 "' len='%" PRIu64 "' type='resident'",
			i->file_offset,i->fs_offset,i->img_offset,i->len);
	    } else{
		sprintf(buf,"       <byte_run file_offset='%" PRIu64 "' unknown_flags='%d'",i->file_offset,i->flags);
	    }
	    runs += buf;

            if(i->md5.size()){
                runs += "><hashdigest type='MD5'>" + i->md5 + "</hashdigest></byte_run>\n";
            } else {
                runs += "/>\n";
            }
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
      || opt_get_fragments || opt_body_file
      || opt_sector_hash;
}

/** Called to create a new segment. */
void content::add_seg(int64_t img_offset,int64_t fs_offset,
		      int64_t file_offset,int64_t len,
		      TSK_FS_BLOCK_FLAG_ENUM flags,
                      const std::string &md5)
{
    seg newseg;
    newseg.img_offset = img_offset;
    newseg.fs_offset = fs_offset;
    newseg.file_offset = file_offset;
    newseg.len   = len;
    newseg.flags = flags;
    newseg.md5   = md5;
    this->segs.push_back(newseg);
}


/** Called when new bytes are encountered.
 * An important bug: currently we assume that the bytes added are contiguous.
 */
void content::add_bytes(const u_char *buf,uint64_t file_offset,ssize_t size)
{
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
		warn("write(%d,%p,%" PRId64 ")=%" PRId64,
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
		warn("write(%d,%p,%" PRId64 ")=%" PRId64,
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

TSK_WALK_RET_ENUM
content::file_act(TSK_FS_FILE * fs_file, TSK_OFF_T a_off, TSK_DADDR_T addr, char *buf,
	 size_t size, TSK_FS_BLOCK_FLAG_ENUM flags)
{
    if(opt_debug>1){
	printf("file_act(fs_file=%p,addr=%" PRIuDADDR " buf=%p size=%d)\n",
	       fs_file,addr,buf,(int)size);
	if(opt_debug>1 && segs.size()==0){
	    if(fwrite(buf,size,1,stdout)!=1) err(1,"fwrite");
	    printf("\n");
	}
    }

    if(size==0)  return TSK_WALK_CONT;	// can't do much with this...

    if(opt_no_data==false){
	if (flags & TSK_FS_BLOCK_FLAG_SPARSE){
            if (size < MAX_SPARSE_SIZE && !invalid) {
                /* Manufacture NULLs that correspond with a sparse file */
                char nulls[65536];
                memset(nulls,0,sizeof(nulls));
                for(size_t i=0; i<size; i += sizeof(nulls)){
                    size_t bytes_to_hash = sizeof(nulls);
                    if ( i + bytes_to_hash > size) bytes_to_hash = size - i;
                    add_bytes(nulls, a_off + i,bytes_to_hash);
                }
            } else {
                set_invalid(true);		// make this data set invalid
            }
	}
	else {
	    add_bytes(buf,a_off,size);	// add these bytes to the file
	}
    }

    /* "Address 0 is reserved in ExtX and FFS to denote a "sparse"
       block (one which is all zeros).  TSK knows this and returns
       zeros when a file refers to block 0.  You can check the 'flags'
       argument to the callback to determine if the data is from
       sparse or compressed data. RAW means that the data in the
       buffer was read from the disk.

       TSK_FS_BLOCK_FLAG_RAW - data on the disk
       TSK_FS_BLOCK_FLAG_SPARSE - a whole
       TSK_FS_BLOCK_FLAG_COMP - the file is compressed
    */

    uint64_t  fs_offset = addr * fs_file->fs_info->block_size;
    uint64_t img_offset = current_partition_start + fs_offset;

    if(opt_sector_hash){
        if(h_sectorhash==0){
            h_sectorhash = new md5_generator();
            sectorhash_byte_counter   = 0;
            sectorhash_initial_offset = (int64_t)a_off;
        }
        h_sectorhash->update((const uint8_t *)buf,size);
        sectorhash_byte_counter += size;
        if (sectorhash_byte_counter==sectorhash_size){
            add_seg(0,0,sectorhash_initial_offset,sectorhash_byte_counter,flags,h_sectorhash->final().hexdigest());
        }
        if (sectorhash_byte_counter>=sectorhash_size){
            delete h_sectorhash;
            h_sectorhash=0;
        }
        return TSK_WALK_CONT;
    }

    /* We are not sector hashing; try to determine disk runs */
    if(segs.size()>0){
	/* Does this next segment fit after the prevous segment logically? */
	if(segs.back().next_file_offset()==(uint64_t)a_off){

	    /* if both the last and the current are sparse, this can be extended. */
	    if((segs.back().flags & TSK_FS_BLOCK_FLAG_SPARSE) &&
	       (flags & TSK_FS_BLOCK_FLAG_SPARSE)){

		segs.back().len += size;
		return TSK_WALK_CONT;
	    }

	    /* If both are compressed, then this can be extended? */
	    if((segs.back().flags & TSK_FS_BLOCK_FLAG_COMP) &&
	       (flags & TSK_FS_BLOCK_FLAG_COMP) &&
	       (segs.back().img_offset + segs.back().len == img_offset)){
		segs.back().len += size;
		return TSK_WALK_CONT;
	    }

	    /* See if we can extend the last segment in the segment list,
	     * or if this is the start of a new fragment.
	     */
	    if((segs.back().flags & TSK_FS_BLOCK_FLAG_RAW) &&
	       (flags & TSK_FS_BLOCK_FLAG_RAW) &&
	       (segs.back().img_offset + segs.back().len == img_offset)){
		segs.back().len += size;
		return TSK_WALK_CONT;
	    }
	}
    }
    /* Need to add a new element to the list */
    add_seg(img_offset,fs_offset,(int64_t)a_off,size,flags,"");
    return TSK_WALK_CONT;
}
