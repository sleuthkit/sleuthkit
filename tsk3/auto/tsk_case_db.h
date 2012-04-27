#ifndef _TSK_AUTO_CASE_H
#define _TSK_AUTO_CASE_H


#include "tsk_auto_i.h"
#include "tsk_db_sqlite.h"
#include "tsk3/hashdb/tsk_hashdb.h"

#define TSK_ADD_IMAGE_SAVEPOINT "ADDIMAGE"

/** \internal
* C++ class that implements TskAuto to load file metadata into a database. 
*/
class TskAutoDb:public TskAuto {
  public:
    TskAutoDb(TskDbSqlite * a_db, TSK_HDB_INFO * a_NSRLDb, TSK_HDB_INFO * a_knownBadDb);
    virtual ~ TskAutoDb();
    virtual uint8_t openImage(int, const TSK_TCHAR * const images[],
        TSK_IMG_TYPE_ENUM, unsigned int a_ssize);
    virtual uint8_t openImageUtf8(int, const char *const images[],
        TSK_IMG_TYPE_ENUM, unsigned int a_ssize);
    virtual void closeImage();

    uint8_t addFilesInImgToDb();
    virtual TSK_FILTER_ENUM filterVs(const TSK_VS_INFO * vs_info);
    virtual TSK_FILTER_ENUM filterVol(const TSK_VS_PART_INFO * vs_part);
    virtual TSK_FILTER_ENUM filterFs(TSK_FS_INFO * fs_info);
    virtual TSK_RETVAL_ENUM processFile(TSK_FS_FILE * fs_file,
        const char *path);
    virtual void createBlockMap(bool flag);
    virtual void hashFiles(bool flag);
    virtual void setNoFatFsOrphans(bool noFatFsOrphans);

    uint8_t startAddImage(int numImg, const TSK_TCHAR * const imagePaths[],
        TSK_IMG_TYPE_ENUM imgType, unsigned int sSize);
#ifdef WIN32
    uint8_t startAddImage(int numImg, const char *const imagePaths[],
        TSK_IMG_TYPE_ENUM imgType, unsigned int sSize);
#endif
    void stopAddImage();
    int revertAddImage();
    int64_t commitAddImage();

  private:
    TskDbSqlite * m_db;
    int64_t m_curImgId;
    int64_t m_curVsId;
    int64_t m_curVolId;
    int64_t m_curFsId;
    int64_t m_curFileId;
    bool m_blkMapFlag;
    bool m_fileHashFlag;
    bool m_vsFound;
    bool m_volFound;
    bool m_stopped;
    bool m_imgTransactionOpen;
    TSK_HDB_INFO * m_NSRLDb;
    TSK_HDB_INFO * m_knownBadDb;
    bool m_noFatFsOrphans;


    uint8_t addImageDetails(const char *const images[], int);
    TSK_RETVAL_ENUM insertFileData(TSK_FS_FILE * fs_file,
        const TSK_FS_ATTR *, const char *path,
        const unsigned char *const md5,
        const TSK_AUTO_CASE_KNOWN_FILE_ENUM known);
    virtual TSK_RETVAL_ENUM processAttribute(TSK_FS_FILE *,
        const TSK_FS_ATTR * fs_attr, const char *path);
    static TSK_WALK_RET_ENUM md5HashCallback(TSK_FS_FILE * file,
        TSK_OFF_T offset, TSK_DADDR_T addr, char *buf, size_t size,
        TSK_FS_BLOCK_FLAG_ENUM a_flags, void *ptr);
    int md5HashAttr(unsigned char md5Hash[16], const TSK_FS_ATTR * fs_attr);
};


#define TSK_CASE_DB_TAG 0xB0551A33

class TskCaseDb {
  public:
    unsigned int m_tag;

    ~TskCaseDb();

    static TskCaseDb *newDb(const TSK_TCHAR * path);
    static TskCaseDb *openDb(const TSK_TCHAR * path);
    void clearLookupDatabases();
    uint8_t setNSRLHashDb(TSK_TCHAR * const indexFile);
    uint8_t setKnownBadHashDb(TSK_TCHAR * const indexFile);
    uint8_t addImage(int numImg, const TSK_TCHAR * const imagePaths[],
        TSK_IMG_TYPE_ENUM imgType, unsigned int sSize);
    TskAutoDb *initAddImage();

  private:
    TskCaseDb(TskDbSqlite * a_db);
    TskDbSqlite *m_db;
    TSK_HDB_INFO * m_NSRLDb;
    TSK_HDB_INFO * m_knownBadDb;
};

#endif
