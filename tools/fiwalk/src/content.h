/**
 * The content class is a class that deals with content when it is encountered.
 */

#ifndef CONTENT_H
#define CONTENT_H
#include "hash_t.h"
#include <vector>
#include <string>


//#ifndef HAVE_ERR_H
//extern void err(int eval, const char *fmt, ...);
//extern void errx(int eval, const char *fmt, ...);
//#endif

/* Structure for keeping track of file segments */
class seg {
public:;
    uint64_t fs_offset;		    // byte offset from start of file system
    uint64_t img_offset;	    // offset from beginning of image
    uint64_t file_offset;           // logical number of bytes from beginning of file
    uint64_t len;		    // number of bytes
    TSK_FS_BLOCK_FLAG_ENUM flags;   // 
    uint64_t next_file_offset() {return file_offset + len;}
    uint64_t next_img_offset()  {return img_offset + len;}
};

typedef std::vector<class seg> seglist;	// vector of blocks
class content {
private:
    std::string   evidence_filename;         // filename of what's currently being saved (from evidence file system)
    void     open_tempfile();
    void     open_savefile();
public:
    /* Class Initialization Stuff */
    TSK_IMG_INFO *img_info;
    bool     invalid;
    bool     need_file_walk();	        // true if we need the full content or disk sectors
					// depends on options and plugins

    bool     do_plugin;
    void     set_filename(const std::string &filename);
    bool     name_filtered();
    std::string   evidence_dirname;		// where it is being put

    int      fd_save;		        // where the file gets saved (fd_save>0)
    std::string   save_path;	                // full path of where it is being saved

    int      fd_temp;			// temp copy for plugin and "file" command
    std::string   tempdir;			// directory where temporary files are put
    std::string   tempfile_path;		// where the tempfile was put

    md5_generator	h_md5;
    sha1_generator	h_sha1;
    md5_generator	h_sectorhash;
    uint64_t sectorhash_counter;
    seglist segs;			// the segments that make up the file
    uint64_t total_bytes;
    std::vector<std::string> sectorhashes;	// a vector of sector hashes, if any have been computed

    content(TSK_IMG_INFO *img_info_):
	img_info(img_info_),
	invalid(false),
	fd_save(0),
	fd_temp(0),
	tempdir("/tmp"),
	sectorhash_counter(0),
	total_bytes(0) {
    }
    ~content();
    void   set_invalid(bool f) { invalid = f;}
    bool   has_filename() { return evidence_filename.size()>0;}
    std::string filename()     { return evidence_dirname + evidence_filename; }
    std::string filemagic();			// returns output of the 'file' command or libmagic
    void   add_seg(int64_t img_offset,int64_t fs_offset,int64_t file_offset,
		   int64_t len, TSK_FS_BLOCK_FLAG_ENUM flags);

    void   add_bytes(const u_char *buf,uint64_t file_offset,ssize_t size);
    void   add_bytes(const char *buf,uint64_t file_offset,ssize_t size){ // handle annoying sign problems
	add_bytes((const u_char *)buf,file_offset,size); 
    }
    void write_record();		// writes the ARFF record for this content
};

#endif
