/*
 *
 *  The Sleuth Kit
 *
 *  Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 *  Copyright (c) 2010-2011 Basis Technology Corporation. All Rights
 *  reserved.
 *
 *  This software is distributed under the Common Public License 1.0
 */

#ifndef _TSK_IMGDBSQLITE_H
#define _TSK_IMGDBSQLITE_H

#define IMGDB_SCHEMA_VERSION "1.0"

// System includes
#include <string> // to get std::wstring
#include <list>
#include <vector>
using namespace std;

// Framework includes
#include "framework_i.h"
#include "TskImgDB.h"
#include "Utilities/SectorRuns.h"
#include "Utilities/UnallocRun.h"

#include "tsk3/libtsk.h"
#include "tsk3/auto/sqlite3.h"

/** 
 * Implementation of TskImgDB that uses SQLite to store the data.
 * Do not use this in a distributed environment if multiple processes
 * will be accessing the database at the same time. 
 */
class TSK_FRAMEWORK_API TskImgDBSqlite : public TskImgDB
{
public:
    TskImgDBSqlite(const wchar_t * a_outpath);
    virtual ~ TskImgDBSqlite();

    virtual int initialize();
    virtual int open();

    virtual int close();

    virtual int begin();
    virtual int commit();

    virtual int addToolInfo(const char* name, const char* version);
    virtual int addImageInfo(int type, int sectorSize);
    virtual int addImageName(char const * imgName);
    virtual int addVolumeInfo(const TSK_VS_PART_INFO * vs_part);
    virtual int addFsInfo(int volId, int fsId, const TSK_FS_INFO * fs_info);
    virtual int addFsFileInfo(int fsId, const TSK_FS_FILE *fs_file, const char *name, int type, int idx, uint64_t & fileId, const char * path);
    virtual int addCarvedFileInfo(int vol_id, wchar_t * name, uint64_t size, uint64_t *runStarts, uint64_t *runLengths, int numRuns, uint64_t & fileId);
    virtual int addDerivedFileInfo(const std::string& name, const uint64_t parentId,
                                        const bool isDirectory, const uint64_t size, const std::string& details,
                                        const int ctime, const int crtime, const int atime, const int mtime, uint64_t & fileId, std::string path);
    virtual int addFsBlockInfo(int fsID, uint64_t a_mFileId, int count, uint64_t blk_addr, uint64_t len);
    virtual int addAllocUnallocMapInfo(int unallocVolID, int unallocImgID, uint64_t unallocImgStart, uint64_t length, uint64_t origImgStart);
    virtual int getSessionID() const;
    virtual int getFileIds(char *a_fileName, uint64_t *a_outBuffer, int a_buffSize) const;
    virtual int getMaxFileIdReadyForAnalysis(uint64_t a_lastFileId, uint64_t & maxFileId) const;
    virtual int getMinFileIdReadyForAnalysis(uint64_t & minFileId) const;
    virtual uint64_t getFileId(int fsId, uint64_t fs_file_id) const;
    virtual int getFileRecord(const uint64_t fileId, TskFileRecord& fileRecord) const;
    virtual SectorRuns * getFileSectors(uint64_t fileId) const;
    virtual std::vector<std::wstring> getImageNames() const;
    virtual int getFileUniqueIdentifiers(uint64_t a_fileId, uint64_t &a_fsOffset, uint64_t &a_fsFileId, int &a_attrType, int &a_attrId) const;
    virtual int getNumVolumes() const;
    virtual int getNumFiles() const;
    virtual int getImageInfo(int & type, int & sectorSize) const;
    virtual int getVolumeInfo(std::list<TskVolumeInfoRecord> & volumeInfoList) const;
    virtual int getFsInfo(std::list<TskFsInfoRecord> & fsInfoList) const;
    virtual int getFileInfoSummary(FILE_TYPES fileType, std::list<TskFileTypeRecord> & fileTypeInfoList) const;
    virtual int getKnownStatus(const uint64_t fileId) const;

    virtual UnallocRun * getUnallocRun(int file_id, int file_offset) const; 
    virtual SectorRuns * getFreeSectors() const;

    virtual int updateFileStatus(uint64_t a_file_id, int a_status);
    virtual int updateKnownStatus(uint64_t a_file_id, int a_status);
	virtual bool dbExist() const;

    // Blackboard access methods.
    virtual int getBlackboard(const uint64_t a_file_id, const string & attribute, vector<vector<unsigned char>> & values) const;
    virtual int getBlackboard(const uint64_t a_file_id, const string & attribute, vector<string> & values) const;
    virtual int getBlackboard(const uint64_t a_file_id, const string & attribute, vector<int32_t> & values) const;
    virtual int getBlackboard(const uint64_t a_file_id, const string & attribute, vector<int64_t> & values) const;
    virtual int getBlackboard(const uint64_t a_file_id, const string & attribute, vector<double> & values) const;

    virtual void getAllBlackboardRows(const uint64_t fileId, vector<TskBlackboardRecord> & bbRecords) const;
    virtual void getAllBlackboardRows(std::string& condition, vector<TskBlackboardRecord> & bbRecords) const;

    // Create a new artifact with the given record.
    virtual artifact_t addBlackboardInfo(const TskBlackboardRecord& blackboardRecord) const;

    // Get set of file ids that match the given condition (i.e. SQL where clause)
    virtual std::vector<uint64_t> getFileIds(std::string& condition) const;

    // Get the number of files that match the given condition
    virtual int getFileCount(std::string& condition) const;

    virtual std::vector<uint64_t> getUniqueCarvedFileIds(HASH_TYPE hashType) const;
    virtual std::vector<uint64_t> getCarvedFileIds() const;

    virtual std::vector<uint64_t> getUniqueFileIds(HASH_TYPE hashType) const;
    virtual std::vector<uint64_t> getFileIds() const;

    virtual int setHash(uint64_t a_file_id, TskImgDB::HASH_TYPE hashType, const std::string hash);
    virtual std::string getCfileName(uint64_t a_file_id) const;

    virtual int addModule(const std::string name, const std::string description, int & moduleId);
    virtual int setModuleStatus(uint64_t file_id, int module_id, int status);
    virtual int getModuleErrors(std::vector<TskModuleStatus> & moduleStatusList) const;
    virtual std::string getFileName(uint64_t file_id) const;

    virtual int addUnallocImg(int & unallocImgId);
    virtual int setUnallocImgStatus(int unallocImgId, TskImgDB::UNALLOC_IMG_STATUS status);
    virtual TskImgDB::UNALLOC_IMG_STATUS getUnallocImgStatus(int unallocImgId) const;
    virtual int getAllUnallocImgStatus(std::vector<TskUnallocImgStatusRecord> & unallocImgStatusList) const;

    virtual int addUnusedSectors(int unallocImgId, std::vector<TskUnusedSectorsRecord> & unusedSectorsList);
    virtual int getUnusedSector(uint64_t fileId, TskUnusedSectorsRecord & unusedSectorsRecord) const;

private:
    wchar_t m_outPath[256];
    wchar_t m_progPath[256];
    wchar_t m_dbFilePath[256];
    sqlite3 * m_db;

    int dropTables();

    static int busyHandler(void *, int);
    std::vector<uint64_t> getFileIdsWorker(std::string tableName, const std::string condition = "") const;
    int getModuleId(const std::string name, int & moduleId) const;
    void constructStmt(std::string& stmt, std::string& condition) const;
    int addUnusedSector(uint64_t sectStart, uint64_t sectEnd, int volId, std::vector<TskUnusedSectorsRecord> & unusedSectorsList);
};

#endif
