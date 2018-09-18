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


#ifndef _TSK_DB_POSTGRESQL_H
#define _TSK_DB_POSTGRESQL_H

#include "tsk_db.h"
#ifdef HAVE_LIBPQ_
#if defined(TSK_WIN32) || defined(HAVE_LIBPQ_FE_H)
    #include "libpq-fe.h"
#else
    #include <postgresql/libpq-fe.h>
#endif
#include <string.h>


#include <map>
using std::map;

#define MAX_CONN_INFO_FIELD_LENGTH  256
#define MAX_CONN_PORT_FIELD_LENGTH  5   // max number of ports on windows is 65535
#define MAX_DB_STRING_LENGTH        512

/** \internal
 * C++ class that wraps PostgreSQL database internals.
 */
class TskDbPostgreSQL : public TskDb {
  public:

    TskDbPostgreSQL(const TSK_TCHAR * a_dbFilePath, bool a_blkMapFlag);
    ~TskDbPostgreSQL();
    int open(bool);
    int close();

    TSK_RETVAL_ENUM setConnectionInfo(CaseDbConnectionInfo * info);

    int addImageInfo(int type, int size, int64_t & objId, const string & timezone);
    int addImageInfo(int type, int size, int64_t & objId, const string & timezone, TSK_OFF_T, const string &md5);
    int addImageInfo(int type, TSK_OFF_T ssize, int64_t & objId, const string & timezone, TSK_OFF_T size, const string &md5, const string& deviceId);
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

    PGconn *conn;
    bool m_blkMapFlag;
    char m_dBName[MAX_CONN_INFO_FIELD_LENGTH];
    char userName[MAX_CONN_INFO_FIELD_LENGTH];
    char password[MAX_CONN_INFO_FIELD_LENGTH];
    char hostNameOrIpAddr[MAX_CONN_INFO_FIELD_LENGTH];
    char hostPort[16];
    TSK_RETVAL_ENUM verifyConnectionInfoStringLengths(size_t userNameStrLen, size_t pwdStrLen, size_t hostNameStrLen, size_t portStrLen);

    PGconn* connectToDatabase(char *dbName);
    TSK_RETVAL_ENUM createDatabase();
    int initialize();
    int attempt_exec(const char *sql, const char *errfmt);
    int verifyResultCode(int resultCode, int expectedResultCode, const char *errfmt);
    int verifyNonEmptyResultSetSize(const char *sql, PGresult *res, int expectedNumFileds, const char *errfmt);
    int verifyResultSetSize(const char *sql, PGresult *res, int expectedNumFileds, const char *errfmt);
    PGresult* get_query_result_set(const char *sql, const char *errfmt);
    PGresult* get_query_result_set_binary(const char *sql, const char *errfmt);
    bool isQueryResultValid(PGresult *res, const char *sql);
    int isEscapedStringValid(const char *sql_str, const char *orig_str, const char *errfmt);
    int createIndexes();

    void removeNonUtf8(char* newStr, int newStrMaxSize, const char* origStr);

    uint8_t addObject(TSK_DB_OBJECT_TYPE_ENUM type, int64_t parObjId, int64_t & objId);
    int addFile(TSK_FS_FILE * fs_file, const TSK_FS_ATTR * fs_attr, const char *path, const unsigned char *const md5,
        const TSK_DB_FILES_KNOWN_ENUM known, int64_t fsObjId, int64_t parObjId, int64_t & objId, int64_t dataSourceObjId);

    void storeObjId(const int64_t & fsObjId, const TSK_FS_FILE *fs_file, const char *path, const int64_t & objId);
    int64_t findParObjId(const TSK_FS_FILE * fs_file, const char *path, const int64_t & fsObjId);
    uint32_t hash(const unsigned char *str);
    map<int64_t, map<TSK_INUM_T, map<uint32_t, map<uint32_t, int64_t> > > > m_parentDirIdCache; //maps a file system ID to a map, which maps a directory file system meta address to a map, which maps a sequence ID to a map, which maps a hash of a path to its object ID in the database

    TSK_RETVAL_ENUM addFileWithLayoutRange(const TSK_DB_FILES_TYPE_ENUM dbFileType, const int64_t parentObjId, const int64_t fsObjId,
        const uint64_t size, vector<TSK_DB_FILE_LAYOUT_RANGE> & ranges, int64_t & objId, int64_t dataSourceObjId);
    TSK_RETVAL_ENUM addLayoutFileInfo(const int64_t parObjId, const int64_t fsObjId, const TSK_DB_FILES_TYPE_ENUM dbFileType, const char *fileName, const uint64_t size, int64_t & objId, int64_t dataSourceObjId);

	int addMACTimeEvent(char *& zSQL, const int64_t data_source_obj_id, const int64_t obj_id, time_t time, const int64_t sub_type, const char * full_desc, const char * med_desc, const char * short_desc);

};

#endif //HAVE_LIBPQ_
#endif // _TSK_DB_POSTGRESQL_H
