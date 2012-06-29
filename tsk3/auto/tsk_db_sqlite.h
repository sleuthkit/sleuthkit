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
 * \file tsk_db_sqlite.h
 * Contains the SQLite code for maintaining the case-level database.
 * In the future, an interface will be developed for these so that 
 * different databases can exist. 
 */

#ifndef _TSK_DB_SQLITE_H
#define _TSK_DB_SQLITE_H

#include <map>
#include <vector>

#include <string>
#include <ostream>


#include "sqlite3.h"
#include "tsk_auto_i.h"

using std::map;
using std::vector;
using std::string;
using std::ostream;

typedef struct sqlite3 sqlite3;


/**
 * Values for the object type value.
 */
typedef enum {
    TSK_DB_OBJECT_TYPE_IMG = 0,
    TSK_DB_OBJECT_TYPE_VS,
    TSK_DB_OBJECT_TYPE_VOL,
    TSK_DB_OBJECT_TYPE_FS,
    TSK_DB_OBJECT_TYPE_FILE,
} TSK_DB_OBJECT_TYPE_ENUM;

/**
 * Values for the files type column in the files table.
 */
typedef enum {
    TSK_DB_FILES_TYPE_FS = 0,   ///< File that can be found in file system tree. 
    TSK_DB_FILES_TYPE_CARVED,   ///< Set of blocks for a file found from carving.  Could be on top of a TSK_DB_FILES_TYPE_UNALLOC_BLOCKS range. 
    TSK_DB_FILES_TYPE_DERIVED,  ///< File derived from a parent file (i.e. from ZIP)
    TSK_DB_FILES_TYPE_LOCAL,    ///< Local file that was added (not from a disk image)
    TSK_DB_FILES_TYPE_UNALLOC_BLOCKS,   ///< Set of blocks not allocated by file system.  Parent should be image, volume, or file system.  Many columns in tsk_files will be NULL. Set layout in tsk_file_layout. 
    TSK_DB_FILES_TYPE_UNUSED_BLOCKS ///< Set of blocks that are unallocated AND not used by a carved or other file type.  Parent should be UNALLOC_BLOCKS, many columns in tsk_files will be NULL, set layout in tsk_file_layout. 
} TSK_DB_FILES_TYPE_ENUM;



/**
* Values for the "known" column of the files table
*/
typedef enum  {
    TSK_DB_FILES_KNOWN_UNKNOWN = 0,  ///< Not matched against an index
    TSK_DB_FILES_KNOWN_KNOWN = 1,    ///< Match found in NSRL "known" file index
    TSK_DB_FILES_KNOWN_KNOWN_BAD = 2,      ///< Match found in "known bad" index
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
    int sequence;

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
 * C++ class that wraps the database internals. 
 */
class TskDbSqlite {
  public:
#ifdef TSK_WIN32
//@@@@
    TskDbSqlite(const TSK_TCHAR * a_dbFilePath, bool a_blkMapFlag);
#endif
     TskDbSqlite(const char *a_dbFilePathUtf8, bool a_blkMapFlag);
    ~TskDbSqlite();
    int open(bool);
    int close();
    int addImageInfo(int type, int size, int64_t & objId, const string & timezone);
    int addImageName(int64_t objId, char const *imgName, int sequence);
    int addVsInfo(const TSK_VS_INFO * vs_info, int64_t parObjId,
        int64_t & objId);
    int addVolumeInfo(const TSK_VS_PART_INFO * vs_part, int64_t parObjId,
        int64_t & objId);
    int addFsInfo(const TSK_FS_INFO * fs_info, int64_t parObjId,
        int64_t & objId);
    int addFsFile(TSK_FS_FILE * fs_file, const TSK_FS_ATTR * fs_attr,
        const char *path, const unsigned char *const md5,
        const TSK_DB_FILES_KNOWN_ENUM known, int64_t fsObjId,
        int64_t & objId);

    int addUnallocBlockFile(const int64_t parentObjId, const int64_t fsObjId, const uint64_t size, 
        vector<TSK_DB_FILE_LAYOUT_RANGE> & ranges, int64_t & objId);
    int addUnusedBlockFile(const int64_t parentObjId, const int64_t fsObjId, const uint64_t size, 
        vector<TSK_DB_FILE_LAYOUT_RANGE> & ranges, int64_t & objId);
    int addCarvedFile(const int64_t parentObjId, const int64_t fsObjId, const uint64_t size, 
        vector<TSK_DB_FILE_LAYOUT_RANGE> & ranges, int64_t & objId);
    
    int addFileLayoutRange(const TSK_DB_FILE_LAYOUT_RANGE & fileLayoutRange);
    int addFileLayoutRange(int64_t a_fileObjId, uint64_t a_byteStart, uint64_t a_byteLen, int a_sequence);
    
    bool dbExist() const;
    int createSavepoint(const char *name);
    int revertSavepoint(const char *name);
    int releaseSavepoint(const char *name);
    bool inTransaction();

    //query methods / getters
    uint8_t getFileLayouts(vector<TSK_DB_FILE_LAYOUT_RANGE> & fileLayouts);
    uint8_t getFsInfos(int64_t imgId, vector<TSK_DB_FS_INFO> & fsInfos);
    uint8_t getVsInfos(int64_t imgId, vector<TSK_DB_VS_INFO> & vsInfos);
    uint8_t getVsInfo(int64_t objId, TSK_DB_VS_INFO & vsInfo);
    uint8_t getVsPartInfos(int64_t imgId, vector<TSK_DB_VS_PART_INFO> & vsPartInfos);
    uint8_t getObjectInfo(int64_t objId, TSK_DB_OBJECT & objectInfo);
    int64_t getParentImageId (const int64_t objId);


  private:
    // prevent copying until we add proper logic to handle it
    TskDbSqlite(const TskDbSqlite&);
    TskDbSqlite & operator=(const TskDbSqlite&);

    int initialize();
    int setupFilePreparedStmt();
    void cleanupFilePreparedStmt();
    int createIndexes();
    int attempt(int resultCode, const char *errfmt);
    int attempt(int resultCode, int expectedResultCode,
        const char *errfmt);
    int attempt_exec(const char *sql, int (*callback) (void *, int,
            char **, char **), void *callback_arg, const char *errfmt);
    int attempt_exec(const char *sql, const char *errfmt);
    int prepare_stmt(const char *sql, sqlite3_stmt ** ppStmt);
    int addObject(TSK_DB_OBJECT_TYPE_ENUM type, int64_t parObjId, int64_t & objId);
    int addFile(TSK_FS_FILE * fs_file, const TSK_FS_ATTR * fs_attr,
        const char *path, const unsigned char *const md5,
        const TSK_DB_FILES_KNOWN_ENUM known, int64_t fsObjId,
        int64_t parObjId, int64_t & objId);
    int addFileWithLayoutRange(const TSK_DB_FILES_TYPE_ENUM dbFileType, const int64_t parentObjId, const int64_t fsObjId,
        const uint64_t size, vector<TSK_DB_FILE_LAYOUT_RANGE> & ranges, int64_t & objId);
    int addLayoutFileInfo(const int64_t parObjId, const int64_t fsObjId, const TSK_DB_FILES_TYPE_ENUM dbFileType, const char *fileName, const uint64_t size,
        int64_t & objId);
    void storeObjId(const int64_t & fsObjId, const TSK_INUM_T & meta_addr, const int64_t & objId);
    int64_t findParObjId(const TSK_FS_FILE * fs_file, const int64_t & fsObjId);
    sqlite3 *m_db;
    TSK_TCHAR m_dbFilePath[1024];
    char m_dbFilePathUtf8[1024];
    bool m_blkMapFlag;
    bool m_utf8;
    sqlite3_stmt *m_selectFilePreparedStmt;
    map<int64_t, map<TSK_INUM_T,int64_t> > m_parentDirIdCache; //maps a file system ID to a map, which maps a directory file system meta address to its object ID in the database
};

#endif
