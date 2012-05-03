#ifndef _TSK_DB_SQLITE_H
#define _TSK_DB_SQLITE_H

#include <map>

#include "sqlite3.h"
#include "tsk_auto_i.h"

using std::map;

typedef struct sqlite3 sqlite3;


typedef enum {
    DB_FILES_TYPE_FS = 0,
    DB_FILES_TYPE_CARVED,
    DB_FILES_TYPE_DERIVED,
    DB_FILES_TYPE_LOCAL
} DB_FILES_TYPES;


typedef enum {
    DB_OBJECT_TYPE_IMG = 0,
    DB_OBJECT_TYPE_VS,
    DB_OBJECT_TYPE_VOL,
    DB_OBJECT_TYPE_FS,
    DB_OBJECT_TYPE_FILE,
} DB_OBJECT_TYPES;


/**
* Values for the "known" column of the files table
*/
typedef enum  {
    TSK_AUTO_CASE_FILE_KNOWN_UNKNOWN = 0,  ///< Not matched against an index
    TSK_AUTO_CASE_FILE_KNOWN_KNOWN = 1,    ///< Match found in NSRL "known" file index
    TSK_AUTO_CASE_FILE_KNOWN_BAD = 2,      ///< Match found in "known bad" index
} TSK_AUTO_CASE_KNOWN_FILE_ENUM;



/** \internal
 * C++ class that wraps the specifics of interacting with a SQLite database for TskAutoDb 
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
    int addImageInfo(int type, int size, int64_t & objId);
    int addImageName(int64_t objId, char const *imgName, int sequence);
    int addVsInfo(const TSK_VS_INFO * vs_info, int64_t parObjId,
        int64_t & objId);
    int addVolumeInfo(const TSK_VS_PART_INFO * vs_part, int64_t parObjId,
        int64_t & objId);
    int addFsInfo(const TSK_FS_INFO * fs_info, int64_t parObjId,
        int64_t & objId);
    int addFsFile(TSK_FS_FILE * fs_file, const TSK_FS_ATTR * fs_attr,
        const char *path, const unsigned char *const md5,
        const TSK_AUTO_CASE_KNOWN_FILE_ENUM known, int64_t fsObjId,
        int64_t & objId);
    int addFsBlockInfo(int64_t a_fsObjId, int64_t a_fileObjId,
        uint64_t a_byteStart, uint64_t a_byteLen, int a_sequence);
    
    bool dbExist() const;
    int createSavepoint(const char *name);
    int revertSavepoint(const char *name);
    int releaseSavepoint(const char *name);
    bool inTransaction();
    

  private:
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
    int addObject(DB_OBJECT_TYPES type, int64_t parObjId, int64_t & objId);
    int addFile(TSK_FS_FILE * fs_file, const TSK_FS_ATTR * fs_attr,
        const char *path, const unsigned char *const md5,
        const TSK_AUTO_CASE_KNOWN_FILE_ENUM known, int64_t fsObjId,
        int64_t parObjId, int64_t & objId);
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
