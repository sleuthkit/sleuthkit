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
 * The class is an extension of TSK abstract database handling class. 
 */

#ifndef _TSK_DB_SQLITE_H
#define _TSK_DB_SQLITE_H

#include <map>

#include "tsk_db.h"
#include <unordered_set>

#ifdef HAVE_LIBSQLITE3
  #include <sqlite3.h>
#else
  #include "sqlite3.h"
#endif

using std::map;
using std::vector;

/** \internal
 * C++ class that wraps the database internals. 
 */
class TskDbSqlite : public TskDb {
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
    int addImageInfo(int type, int size, int64_t & objId, const string & timezone, TSK_OFF_T, const string &md5, const string &sha1, const string &sha256);
    int addImageInfo(int type, TSK_OFF_T ssize, int64_t & objId, const string & timezone, TSK_OFF_T size, const string &md5, const string &sha1, const string &sha256, const string& deviceId, const string& collectionDetails);
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
        int64_t & objId, int64_t dataSourceObjId);

    TSK_RETVAL_ENUM addVirtualDir(const int64_t fsObjId, const int64_t parentDirId, const char * const name, int64_t & objId, int64_t dataSourceObjId);
    TSK_RETVAL_ENUM addUnallocFsBlockFilesParent(const int64_t fsObjId, int64_t & objId, int64_t dataSourceObjId);
    TSK_RETVAL_ENUM addUnallocBlockFile(const int64_t parentObjId, const int64_t fsObjId, const uint64_t size, 
        vector<TSK_DB_FILE_LAYOUT_RANGE> & ranges, int64_t & objId, int64_t dataSourceObjId);
    TSK_RETVAL_ENUM addUnusedBlockFile(const int64_t parentObjId, const int64_t fsObjId, const uint64_t size, 
        vector<TSK_DB_FILE_LAYOUT_RANGE> & ranges, int64_t & objId, int64_t dataSourceObjId);
    TSK_RETVAL_ENUM addCarvedFile(const int64_t parentObjId, const int64_t fsObjId, const uint64_t size, 
        vector<TSK_DB_FILE_LAYOUT_RANGE> & ranges, int64_t & objId, int64_t dataSourceObjId);
    
    int addFileLayoutRange(const TSK_DB_FILE_LAYOUT_RANGE & fileLayoutRange);
    int addFileLayoutRange(int64_t a_fileObjId, uint64_t a_byteStart, uint64_t a_byteLen, int a_sequence);
    
    bool isDbOpen();
    int createSavepoint(const char *name);
    int revertSavepoint(const char *name);
    int releaseSavepoint(const char *name);
    bool inTransaction();
    bool dbExists();

    //query methods / getters
    TSK_RETVAL_ENUM getFileLayouts(vector<TSK_DB_FILE_LAYOUT_RANGE> & fileLayouts);
    TSK_RETVAL_ENUM getFsInfos(int64_t imgId, vector<TSK_DB_FS_INFO> & fsInfos);
    TSK_RETVAL_ENUM getVsInfos(int64_t imgId, vector<TSK_DB_VS_INFO> & vsInfos);
    TSK_RETVAL_ENUM getVsInfo(int64_t objId, TSK_DB_VS_INFO & vsInfo);
    TSK_RETVAL_ENUM getVsPartInfos(int64_t imgId, vector<TSK_DB_VS_PART_INFO> & vsPartInfos);
    TSK_RETVAL_ENUM getObjectInfo(int64_t objId, TSK_DB_OBJECT & objectInfo);
    TSK_RETVAL_ENUM getParentImageId (const int64_t objId, int64_t & imageId);
    TSK_RETVAL_ENUM getFsRootDirObjectInfo(const int64_t fsObjId, TSK_DB_OBJECT & rootDirObjInfo);


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
    uint8_t addObject(TSK_DB_OBJECT_TYPE_ENUM type, int64_t parObjId, int64_t & objId);
    int addFile(TSK_FS_FILE * fs_file, const TSK_FS_ATTR * fs_attr,
        const char *path, const unsigned char *const md5,
        const TSK_DB_FILES_KNOWN_ENUM known, int64_t fsObjId,
        int64_t parObjId, int64_t & objId, int64_t dataSourceObjId);
    TSK_RETVAL_ENUM addFileWithLayoutRange(const TSK_DB_FILES_TYPE_ENUM dbFileType, const int64_t parentObjId, const int64_t fsObjId,
        const uint64_t size, vector<TSK_DB_FILE_LAYOUT_RANGE> & ranges, int64_t & objId, int64_t dataSourceObjId);
    TSK_RETVAL_ENUM addLayoutFileInfo(const int64_t parObjId, const int64_t fsObjId, const TSK_DB_FILES_TYPE_ENUM dbFileType, const char *fileName, const uint64_t size, int64_t & objId, int64_t dataSourceObjId);
    
    void storeObjId(const int64_t & fsObjId, const TSK_FS_FILE *fs_file, const char *path, const int64_t & objId);
    int64_t findParObjId(const TSK_FS_FILE * fs_file, const char *path, const int64_t & fsObjId);
    int addMACTimeEvents(const int64_t data_source_obj_id, const int64_t file_obj_id, std::map<int64_t, time_t> timeMap,
                         const char* full_description);

	uint32_t hash(const unsigned char *str);
    sqlite3 *m_db;
    TSK_TCHAR m_dbFilePath[1024];
    char m_dbFilePathUtf8[1024];
    bool m_blkMapFlag;
    bool m_utf8; //encoding used for the database file name, not the actual database
    sqlite3_stmt *m_selectFilePreparedStmt;
    sqlite3_stmt *m_insertObjectPreparedStmt;
    map<int64_t, map<TSK_INUM_T, map<uint32_t, map<uint32_t, int64_t> > > > m_parentDirIdCache; //maps a file system ID to a map, which maps a directory file system meta address to a map, which maps a sequence ID to a map, which maps a hash of a path to its object ID in the database
};

#endif
