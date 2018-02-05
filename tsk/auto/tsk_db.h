/*
 ** The Sleuth Kit 
 **
 ** Brian Carrier [carrier <at> sleuthkit [dot] org]
 ** Copyright (c) 2011-2012 Brian Carrier.  All Rights reserved
 **
 ** This software is distributed under the Common Public License 1.0
 **
 */

/**
 * \file tsk_db.h
 * Contains TSK interface to abstract database handling class. The intent of this class
 * is so that different databases can be seamlessly used by TSK. 
 */

#ifndef _TSK_DB_H
#define _TSK_DB_H

#include <vector>
#include <string>
#include <ostream>

#include "tsk_auto_i.h"
#include "db_connection_info.h"

using std::ostream;
using std::vector;
using std::string;

#define TSK_SCHEMA_VER 8
#define TSK_SCHEMA_MINOR_VER 0

/**
 * Values for the type column in the tsk_objects table. 
 */
typedef enum {
    TSK_DB_OBJECT_TYPE_IMG = 0, ///< Object is a disk image
    TSK_DB_OBJECT_TYPE_VS,      ///< Object is a volume system. 
    TSK_DB_OBJECT_TYPE_VOL,     ///< Object is a volume 
    TSK_DB_OBJECT_TYPE_FS,      ///< Object is a file system
    TSK_DB_OBJECT_TYPE_FILE,    ///< Object is a file (exact type can be determined in the tsk_files table via TSK_DB_FILES_TYPE_ENUM)
} TSK_DB_OBJECT_TYPE_ENUM;

/**
 * Values for the files type column in the tsk_files table.
 */
typedef enum {
    TSK_DB_FILES_TYPE_FS = 0,   ///< File that can be found in file system tree. 
    TSK_DB_FILES_TYPE_CARVED,   ///< Set of blocks for a file found from carving.  Could be on top of a TSK_DB_FILES_TYPE_UNALLOC_BLOCKS range. 
    TSK_DB_FILES_TYPE_DERIVED,  ///< File derived from a parent file (i.e. from ZIP)
    TSK_DB_FILES_TYPE_LOCAL,    ///< Local file that was added (not from a disk image)
    TSK_DB_FILES_TYPE_UNALLOC_BLOCKS,   ///< Set of blocks not allocated by file system.  Parent should be image, volume, or file system.  Many columns in tsk_files will be NULL. Set layout in tsk_file_layout. 
    TSK_DB_FILES_TYPE_UNUSED_BLOCKS, ///< Set of blocks that are unallocated AND not used by a carved or other file type.  Parent should be UNALLOC_BLOCKS, many columns in tsk_files will be NULL, set layout in tsk_file_layout. 
    TSK_DB_FILES_TYPE_VIRTUAL_DIR, ///< Virtual directory (not on fs) with no meta-data entry that can be used to group files of types other than TSK_DB_FILES_TYPE_FS. Its parent is either another TSK_DB_FILES_TYPE_FS or a root directory or type TSK_DB_FILES_TYPE_FS.
    TSK_DB_FILES_TYPE_SLACK   ///< Slack space for a single file
} TSK_DB_FILES_TYPE_ENUM;



/**
* Values for the "known" column of the tsk_files table
*/
typedef enum  {
    TSK_DB_FILES_KNOWN_UNKNOWN = 0,  ///< Not matched against an index
    TSK_DB_FILES_KNOWN_KNOWN = 1,    ///< Match found in a "known" file index (such as NIST NSRL)and could be good or bad.  
    TSK_DB_FILES_KNOWN_KNOWN_BAD = 2,      ///< Match found in a "known bad" index
    TSK_DB_FILES_KNOWN_KNOWN_GOOD = 3,      ///< Match found in a "known good" index
} TSK_DB_FILES_KNOWN_ENUM;


/**
* Structure wrapping a single tsk objects db entry
*/
typedef struct _TSK_DB_OBJECT {
    int64_t objId; ///< set to 0 if unknown (before it becomes a db object)
    int64_t parObjId;
    TSK_DB_OBJECT_TYPE_ENUM type;    
} TSK_DB_OBJECT;

ostream& operator <<(ostream &os,const TSK_DB_OBJECT &dbObject);

/**
* Structure wrapping a single file_layout db entry
*/
typedef struct _TSK_DB_FILE_LAYOUT_RANGE {
    //default constructor
    _TSK_DB_FILE_LAYOUT_RANGE()
        : fileObjId(0),byteStart(0),byteLen(0),sequence(0) {}
    //constructor for non-db object (before it becomes one)
    _TSK_DB_FILE_LAYOUT_RANGE(uint64_t byteStart, uint64_t byteLen, int sequence)
        : fileObjId(0),byteStart(byteStart),byteLen(byteLen),sequence(sequence) {}
 
    int64_t fileObjId; ///< set to 0 if unknown (before it becomes a db object)
    uint64_t byteStart;
    uint64_t byteLen;
    uint32_t sequence;

    //default comparator by sequence
    bool operator< (const struct _TSK_DB_FILE_LAYOUT_RANGE & rhs) const
    { return sequence < rhs.sequence; }

} TSK_DB_FILE_LAYOUT_RANGE;

ostream& operator <<(ostream &os,const TSK_DB_FILE_LAYOUT_RANGE &layoutRange);

/**
* Structure wrapping a single fs info db entry
*/
typedef struct _TSK_DB_FS_INFO {
    int64_t objId; ///< set to 0 if unknown (before it becomes a db object)
    TSK_OFF_T imgOffset;
    TSK_FS_TYPE_ENUM fType;
    unsigned int block_size;
    TSK_DADDR_T block_count;
    TSK_INUM_T root_inum;
    TSK_INUM_T first_inum;
    TSK_INUM_T last_inum;     
} TSK_DB_FS_INFO;

ostream& operator <<(ostream &os,const TSK_DB_FS_INFO &fsInfo);


/**
* Structure wrapping a single vs info db entry
*/
typedef struct _TSK_DB_VS_INFO {
    int64_t objId; ///< set to 0 if unknown (before it becomes a db object)
    TSK_VS_TYPE_ENUM vstype;
    TSK_DADDR_T offset;
    unsigned int block_size;  
} TSK_DB_VS_INFO;

ostream& operator <<(ostream &os,const TSK_DB_VS_INFO &vsInfo);

/**
* Structure wrapping a single vs part db entry
*/
#define TSK_MAX_DB_VS_PART_INFO_DESC_LEN 512
typedef struct _TSK_DB_VS_PART_INFO {
    int64_t objId; ///< set to 0 if unknown (before it becomes a db object)
    TSK_PNUM_T addr;
    TSK_DADDR_T start;
    TSK_DADDR_T len;
    char desc[TSK_MAX_DB_VS_PART_INFO_DESC_LEN];
    TSK_VS_PART_FLAG_ENUM flags;  
} TSK_DB_VS_PART_INFO;

ostream& operator <<(ostream &os,const TSK_DB_VS_PART_INFO &vsPartInfos);

/** \internal
 * C++ class that serves as interface to direct database handling classes. 
 */
class TskDb {

    // these buffers are used to manipulate strings in getParentPathAndName()
    #define MAX_PATH_LENGTH 2048
    char parent_name[MAX_PATH_LENGTH];
    char parent_path[MAX_PATH_LENGTH + 2]; // +2 is for leading slash and trailing slash

  public:
#ifdef TSK_WIN32
//@@@@
    TskDb(const TSK_TCHAR * a_dbFilePath, bool a_blkMapFlag);
#endif
    TskDb(const char *a_dbFilePathUtf8, bool a_blkMapFlag);
    virtual ~TskDb() {};
    virtual int open(bool) = 0;
    virtual int close() = 0;
    virtual TSK_RETVAL_ENUM setConnectionInfo(CaseDbConnectionInfo * info);
    virtual int addImageInfo(int type, int size, int64_t & objId, const string & timezone) = 0;
    virtual int addImageInfo(int type, int size, int64_t & objId, const string & timezone, TSK_OFF_T, const string &md5) = 0;
    virtual int addImageInfo(int type, TSK_OFF_T size, int64_t & objId, const string & timezone, TSK_OFF_T, const string &md5, const string& deviceId) = 0;
    virtual int addImageName(int64_t objId, char const *imgName, int sequence) = 0;
    virtual int addVsInfo(const TSK_VS_INFO * vs_info, int64_t parObjId, int64_t & objId) = 0;
    virtual int addVolumeInfo(const TSK_VS_PART_INFO * vs_part, int64_t parObjId, int64_t & objId) = 0;
    virtual int addFsInfo(const TSK_FS_INFO * fs_info, int64_t parObjId, int64_t & objId) = 0;
    virtual int addFsFile(TSK_FS_FILE * fs_file, const TSK_FS_ATTR * fs_attr,
        const char *path, const unsigned char *const md5,
        const TSK_DB_FILES_KNOWN_ENUM known, int64_t fsObjId,
        int64_t & objId, int64_t dataSourceObjId) = 0;

    virtual TSK_RETVAL_ENUM addVirtualDir(const int64_t fsObjId, const int64_t parentDirId, const char * const name, int64_t & objId, int64_t dataSourceObjId) = 0;
    virtual TSK_RETVAL_ENUM addUnallocFsBlockFilesParent(const int64_t fsObjId, int64_t & objId, int64_t dataSourceObjId) = 0;
    virtual TSK_RETVAL_ENUM addUnallocBlockFile(const int64_t parentObjId, const int64_t fsObjId, const uint64_t size, 
        vector<TSK_DB_FILE_LAYOUT_RANGE> & ranges, int64_t & objId, int64_t dataSourceObjId) = 0;
    virtual TSK_RETVAL_ENUM addUnusedBlockFile(const int64_t parentObjId, const int64_t fsObjId, const uint64_t size, 
        vector<TSK_DB_FILE_LAYOUT_RANGE> & ranges, int64_t & objId, int64_t dataSourceObjId) = 0;
    virtual TSK_RETVAL_ENUM addCarvedFile(const int64_t parentObjId, const int64_t fsObjId, const uint64_t size, 
        vector<TSK_DB_FILE_LAYOUT_RANGE> & ranges, int64_t & objId, int64_t dataSourceObjId) = 0;
    
    virtual int addFileLayoutRange(const TSK_DB_FILE_LAYOUT_RANGE & fileLayoutRange) = 0;
    virtual int addFileLayoutRange(int64_t a_fileObjId, uint64_t a_byteStart, uint64_t a_byteLen, int a_sequence) = 0;
    
    virtual bool isDbOpen() = 0;
    virtual int createSavepoint(const char *name) = 0;
    virtual int revertSavepoint(const char *name) = 0;
    virtual int releaseSavepoint(const char *name) = 0;
    virtual bool inTransaction() = 0;
    virtual bool dbExists() = 0;

    virtual bool getParentPathAndName(const char *path, char **ret_parent_path, char **ret_name);

    //query methods / getters
    virtual TSK_RETVAL_ENUM getFileLayouts(vector<TSK_DB_FILE_LAYOUT_RANGE> & fileLayouts) = 0;
    virtual TSK_RETVAL_ENUM getFsInfos(int64_t imgId, vector<TSK_DB_FS_INFO> & fsInfos) = 0;
    virtual TSK_RETVAL_ENUM getVsInfos(int64_t imgId, vector<TSK_DB_VS_INFO> & vsInfos) = 0;
    virtual TSK_RETVAL_ENUM getVsInfo(int64_t objId, TSK_DB_VS_INFO & vsInfo) = 0;
    virtual TSK_RETVAL_ENUM getVsPartInfos(int64_t imgId, vector<TSK_DB_VS_PART_INFO> & vsPartInfos) = 0;
    virtual TSK_RETVAL_ENUM getObjectInfo(int64_t objId, TSK_DB_OBJECT & objectInfo) = 0;
    virtual TSK_RETVAL_ENUM getParentImageId (const int64_t objId, int64_t & imageId) = 0;
    virtual TSK_RETVAL_ENUM getFsRootDirObjectInfo(const int64_t fsObjId, TSK_DB_OBJECT & rootDirObjInfo) = 0;

  protected:
	
	  /**
	  Extract the extension from the given file name and store it in the supplied string.

	  @param name A file name
	  @param extension The file name extension will be extracted to extension.
	  */void extractExtension(char *name, char *extension ) {
		   char *ext = strrchr(name, '.');

		   //if ext is not null and is not the entire filename...
		   if (ext && (name != ext)) {
			   size_t extLen = strlen(ext);
			   //... and doesn't only contain the '.' and isn't too long to be a real extension.
			   if ((1 < extLen) && (extLen < 15) ) {
				   strncpy(extension, ext + 1, extLen -1);
					//normalize to lower case, only works for ascii
				   for (int i = 0; extension[i]; i++) {
					   extension[i] = tolower(extension[i]);
				   }
			   }
		   }
	  }
};

#endif
