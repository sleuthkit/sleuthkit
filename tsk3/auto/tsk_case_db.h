#ifndef _TSK_AUTO_CASE_H
#define _TSK_AUTO_CASE_H


#include "tsk_auto.h"
#include "tsk_db_sqlite.h"


#define TSK_ADD_IMAGE_SAVEPOINT "ADDIMAGE"

/** \internal
* C++ class that implements TskAuto to load file metadata into a database. 
*/
class TskAutoDb:public TskAuto {
public:
    TskAutoDb(TskDbSqlite * db);
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

    uint8_t runProcess(int numImg, const TSK_TCHAR *const imagePaths[],
        TSK_IMG_TYPE_ENUM imgType, unsigned int sSize);
#ifdef WIN32
    uint8_t runProcess(int numImg, const char *const imagePaths[],
        TSK_IMG_TYPE_ENUM imgType, unsigned int sSize);
#endif
    void stopProcess();
    void revertProcess();
    int64_t commitProcess();

private:
    TskDbSqlite * m_db;
    int64_t m_curImgId;
    int64_t m_curVsId;
    int64_t m_curVolId;
    int64_t m_curFsId;
    int64_t m_curFileId;
    bool m_blkMapFlag;
    bool m_vsFound;
    bool m_volFound;
    bool m_stopped;
    

    uint8_t addImageDetails(const char * const images[], int);
    TSK_RETVAL_ENUM insertFileData(TSK_FS_FILE * fs_file,
        const TSK_FS_ATTR *, const char *path);
    virtual TSK_RETVAL_ENUM processAttribute(TSK_FS_FILE *,
        const TSK_FS_ATTR * fs_attr, const char *path);
};


#define TSK_CASE_DB_TAG 0xB0551A33

class TskCaseDb {
public:
    unsigned int m_tag;
    
    ~ TskCaseDb();

    static TskCaseDb * newDb(const TSK_TCHAR * path);
    static TskCaseDb * openDb(const TSK_TCHAR * path);
    uint8_t addImage(int numImg, const TSK_TCHAR * const imagePaths[],
        TSK_IMG_TYPE_ENUM imgType, unsigned int sSize);
    TskAutoDb * initAddImage();

private:
    TskCaseDb(TskDbSqlite * a_db);
    TskDbSqlite * m_db;
};

#endif
