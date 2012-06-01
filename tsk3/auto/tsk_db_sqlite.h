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

#include <string>
#include <vector>

#include "sqlite3.h"
#include "tsk_auto_i.h"

using std::map;
using std::string;
using std::vector;

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
* Data wrapping a single file_layout entry
*/
typedef struct {
    int64_t a_fileObjId;
    uint64_t a_byteStart;
    uint64_t a_byteLen;
    int a_sequence;
} TSK_DB_FILE_LAYOUT_RANGE;

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

    int addUnallocBlockFile(const int64_t parentObjId, const uint64_t size, 
        const vector<TSK_DB_FILE_LAYOUT_RANGE> & ranges, int64_t & objId);
    int addUnusedBlockFile(const int64_t parentObjId, const uint64_t size, 
        const vector<TSK_DB_FILE_LAYOUT_RANGE> & ranges, int64_t & objId);
    int addCarvedFile(const int64_t parentObjId, const uint64_t size, 
        const vector<TSK_DB_FILE_LAYOUT_RANGE> & ranges, int64_t & objId);
    
    int addFileLayoutRange(const TSK_DB_FILE_LAYOUT_RANGE & fileLayoutRange);
    int addFileLayoutRange(int64_t a_fileObjId, uint64_t a_byteStart, uint64_t a_byteLen, int a_sequence);
    
    bool dbExist() const;
    int createSavepoint(const char *name);
    int revertSavepoint(const char *name);
    int releaseSavepoint(const char *name);
    bool inTransaction();
    

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
    int addFileWithLayoutRange(const TSK_DB_FILES_TYPE_ENUM dbFileType, const int64_t parentObjId, 
        const uint64_t size, const vector<TSK_DB_FILE_LAYOUT_RANGE> & ranges, int64_t & objId);
    int addCarvedFileInfo(int fsObjId, const char *fileName, uint64_t size,
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
