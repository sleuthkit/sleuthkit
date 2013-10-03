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
 * \file tsk_case_db.h
 * Contains the class that creates a case-level database of file system
 * data. 
 */

#ifndef _TSK_AUTO_CASE_H
#define _TSK_AUTO_CASE_H

#include <string>
using std::string;


#include "tsk_auto_i.h"
#include "tsk_db_sqlite.h"
#include "tsk/hashdb/tsk_hashdb.h"

#define TSK_ADD_IMAGE_SAVEPOINT "ADDIMAGE"

/** \internal
 * C++ class that implements TskAuto to load file metadata into a database. 
 * This is used by the TskCaseDb class. 
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
    virtual void setTz(string tzone);

    virtual TSK_FILTER_ENUM filterVs(const TSK_VS_INFO * vs_info);
    virtual TSK_FILTER_ENUM filterVol(const TSK_VS_PART_INFO * vs_part);
    virtual TSK_FILTER_ENUM filterFs(TSK_FS_INFO * fs_info);
    virtual TSK_RETVAL_ENUM processFile(TSK_FS_FILE * fs_file,
        const char *path);
    virtual void createBlockMap(bool flag);
    const std::string getCurDir();

    /**
     * Calculate hash values of files and add them to database.
     * Default is false.  Will be set to true if a Hash DB is configured.
     *
     * @param flag True to calculate hash values and look them up.
     */
    virtual void hashFiles(bool flag);

    /**
     * Skip processing of orphans on FAT filesystems.  
     * This will make the loading of the database much faster
     * but you will not have all deleted files.  Default value is false. 
     * @param noFatFsOrphans flag set to true if to skip processing orphans on FAT fs
     */
    virtual void setNoFatFsOrphans(bool noFatFsOrphans);

    /**
     * When enabled, records for unallocated file system space will be added to the database. Default value is false.
     * @param addUnallocSpace If true, create records for contigious unallocated file system sectors. 
     */
    virtual void setAddUnallocSpace(bool addUnallocSpace);

	/**
     * When enabled, records for unallocated file system space will be added to the database. Default value is false.
     * @param addUnallocSpace If true, create records for contigious unallocated file system sectors.
	 * @param chunkSize the number of bytes to group unallocated data into. A value of 0 will create
	 * one large chunk and group only on volume boundaries. A value of -1 will group each consecutive
	 * chunk.
     */
    virtual void setAddUnallocSpace(bool addUnallocSpace, int64_t chunkSize);

    uint8_t addFilesInImgToDb();

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
    int64_t m_curImgId;     ///< Object ID of image currently being processed
    int64_t m_curVsId;      ///< Object ID of volume system currently being processed
    int64_t m_curVolId;     ///< Object ID of volume currently being processed
    int64_t m_curFsId;      ///< Object ID of file system currently being processed
    int64_t m_curFileId;    ///< Object ID of file currently being processed
    int64_t m_curDirId;		///< Object ID of the directory currently being processed
    int64_t m_curUnallocDirId;	
    string m_curDirPath;		//< Path of the current directory being processed
    tsk_lock_t m_curDirPathLock; //< protects concurrent access to m_curDirPath
    string m_curImgTZone;
    bool m_blkMapFlag;
    bool m_fileHashFlag;
    bool m_vsFound;
    bool m_volFound;
    bool m_stopped;
    bool m_imgTransactionOpen;
    TSK_HDB_INFO * m_NSRLDb;
    TSK_HDB_INFO * m_knownBadDb;
    bool m_noFatFsOrphans;
    bool m_addUnallocSpace;
	int64_t m_chunkSize;
    bool m_foundStructure;  ///< Set to true when we find either a volume or file system

    // prevent copying until we add proper logic to handle it
    TskAutoDb(const TskAutoDb&);
    TskAutoDb & operator=(const TskAutoDb&);

    //internal structure to keep track of temp. unalloc block range
    typedef struct _UNALLOC_BLOCK_WLK_TRACK {
        _UNALLOC_BLOCK_WLK_TRACK(const TskAutoDb & tskAutoDb, const TSK_FS_INFO & fsInfo, const int64_t fsObjId, int64_t chunkSize)
            : tskAutoDb(tskAutoDb),fsInfo(fsInfo),fsObjId(fsObjId),curRangeStart(0), chunkSize(chunkSize), prevBlock(0), isStart(true) {}
        const TskAutoDb & tskAutoDb;
        const TSK_FS_INFO & fsInfo;
        const int64_t fsObjId;
		vector<TSK_DB_FILE_LAYOUT_RANGE> ranges;																																										
        TSK_DADDR_T curRangeStart;
		int64_t size;
		const int64_t chunkSize;
        TSK_DADDR_T prevBlock;
        bool isStart;
    } UNALLOC_BLOCK_WLK_TRACK;

    uint8_t addImageDetails(const char *const images[], int);
    TSK_RETVAL_ENUM insertFileData(TSK_FS_FILE * fs_file,
        const TSK_FS_ATTR *, const char *path,
        const unsigned char *const md5,
        const TSK_DB_FILES_KNOWN_ENUM known);
    virtual TSK_RETVAL_ENUM processAttribute(TSK_FS_FILE *,
        const TSK_FS_ATTR * fs_attr, const char *path);
    static TSK_WALK_RET_ENUM md5HashCallback(TSK_FS_FILE * file,
        TSK_OFF_T offset, TSK_DADDR_T addr, char *buf, size_t size,
        TSK_FS_BLOCK_FLAG_ENUM a_flags, void *ptr);
    int md5HashAttr(unsigned char md5Hash[16], const TSK_FS_ATTR * fs_attr);

    static TSK_WALK_RET_ENUM fsWalkUnallocBlocksCb(const TSK_FS_BLOCK *a_block, void *a_ptr);
    int8_t addFsInfoUnalloc(const TSK_DB_FS_INFO & dbFsInfo);
    uint8_t addUnallocFsSpaceToDb(size_t & numFs);
    uint8_t addUnallocVsSpaceToDb(size_t & numVsP);
    uint8_t addUnallocImageSpaceToDb();
    uint8_t addUnallocSpaceToDb();

};


#define TSK_CASE_DB_TAG 0xB0551A33

/**
 * Stores case-level information in a database on one or more disk images.
 */
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
    // prevent copying until we add proper logic to handle it
    TskCaseDb(const TskCaseDb&);
    TskCaseDb & operator=(const TskCaseDb&);

    TskCaseDb(TskDbSqlite * a_db);
    TskDbSqlite *m_db;
    TSK_HDB_INFO * m_NSRLDb;
    TSK_HDB_INFO * m_knownBadDb;
};

#endif
