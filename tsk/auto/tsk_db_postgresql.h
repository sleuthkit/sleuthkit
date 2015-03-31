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
 * \file tsk_db_postgresql.h
 * Contains the PostgreSQL code for maintaining the case-level database.
 * The class is an extension of TSK abstract database handling class. 
 */

#ifdef HAVE_POSTGRESQL

#ifndef _TSK_DB_POSTGRESQL_H
#define _TSK_DB_POSTGRESQL_H

#include "tsk_db.h"

#ifdef TSK_WIN32

#include "libpq-fe.h"
#include <string.h>


#include <map>
using std::map;


/** \internal
 * C++ class that wraps PostgreSQL database internals. 
 */
class TskDbPostgreSQL : public TskDb {
  public:
    TskDbPostgreSQL(const TSK_TCHAR * a_dbFilePath, bool a_blkMapFlag);
    ~TskDbPostgreSQL();
    int open(bool);
    int close();

    TSK_RETVAL_ENUM setLogInInfo();

// not implemeneted:
    int addImageInfo(int type, int size, int64_t & objId, const string & timezone);
    int addImageInfo(int type, int size, int64_t & objId, const string & timezone, TSK_OFF_T, const string &md5);
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

    TSK_RETVAL_ENUM addVirtualDir(const int64_t fsObjId, const int64_t parentDirId, const char * const name, int64_t & objId);
    TSK_RETVAL_ENUM addUnallocFsBlockFilesParent(const int64_t fsObjId, int64_t & objId);
    TSK_RETVAL_ENUM addUnallocBlockFile(const int64_t parentObjId, const int64_t fsObjId, const uint64_t size, 
        vector<TSK_DB_FILE_LAYOUT_RANGE> & ranges, int64_t & objId);
    TSK_RETVAL_ENUM addUnusedBlockFile(const int64_t parentObjId, const int64_t fsObjId, const uint64_t size, 
        vector<TSK_DB_FILE_LAYOUT_RANGE> & ranges, int64_t & objId);
    TSK_RETVAL_ENUM addCarvedFile(const int64_t parentObjId, const int64_t fsObjId, const uint64_t size, 
        vector<TSK_DB_FILE_LAYOUT_RANGE> & ranges, int64_t & objId);
    
    int addFileLayoutRange(const TSK_DB_FILE_LAYOUT_RANGE & fileLayoutRange);
    int addFileLayoutRange(int64_t a_fileObjId, uint64_t a_byteStart, uint64_t a_byteLen, int a_sequence);
    
    bool isDbOpen() const;
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

    PGconn *conn;
    bool m_blkMapFlag;
    TSK_TCHAR m_dBName[256];
    char userName[128];
    char password[128];
    char hostIpAddr[64];
    char hostPort[16];

    PGconn* connectToDatabase(TSK_TCHAR *dbName);
    TSK_RETVAL_ENUM createDatabase();
    int initialize();
    int attempt_exec(const char *sql, const char *errfmt);
    int attempt(int resultCode, const char *errfmt);
    int attempt(int resultCode, int expectedResultCode, const char *errfmt);
    PGresult* get_query_result_set(const char *sql, const char *errfmt);
    int createIndexes();

    uint8_t addObject(TSK_DB_OBJECT_TYPE_ENUM type, int64_t parObjId, int64_t & objId);
    int addFile(TSK_FS_FILE * fs_file, const TSK_FS_ATTR * fs_attr, const char *path, const unsigned char *const md5, 
        const TSK_DB_FILES_KNOWN_ENUM known, int64_t fsObjId, int64_t parObjId, int64_t & objId);

    // ELTODO: delete this:
    void test();
};

#endif // TSK_WIN32
#endif // _TSK_DB_POSTGRESQL_H
#endif // HAVE_POSTGRESQL