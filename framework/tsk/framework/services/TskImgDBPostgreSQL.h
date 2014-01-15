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

#ifndef _TSK_IMGDBPOSTGRESQL_H
#define _TSK_IMGDBPOSTGRESQL_H

// System includes
#include <string> // to get std::wstring
#include <list>
#include <vector>

// Framework includes
#include "tsk/framework/framework_i.h"
#include "tsk/framework/services/TskImgDB.h"
#include "tsk/framework/utilities/SectorRuns.h"
#include "tsk/framework/utilities/UnallocRun.h"
#include "tsk/framework/services/TskBlackboard.h"

#include "tsk/libtsk.h"

#include <iostream>
#include <stdlib.h>
#undef min
#undef max
#include <pqxx/pqxx>
using namespace std;
using namespace pqxx;

/// Framework data access layer the uses PostgreSQL as the back end.
class TskImgDBPostgreSQL : public TskImgDB
{
public:
    TskImgDBPostgreSQL(const std::string dbName);
    virtual ~ TskImgDBPostgreSQL();

    virtual int initialize();
    virtual int initializePreparedStatements();
    virtual int open();

    virtual int close();

    virtual int begin();
    virtual int commit();

    virtual int addToolInfo(const char* name, const char* version);
    virtual int addImageInfo(int type, int sectorSize);
    virtual int addImageName(char const * imgName);
    virtual int addVolumeInfo(const TSK_VS_PART_INFO * vs_part);
    virtual int addFsInfo(int volId, int fsId, const TSK_FS_INFO * fs_info);
    virtual int addFsFileInfo(int fileSystemID, const TSK_FS_FILE *fileSystemFile, const char *fileName, int fileSystemAttrType, int fileSystemAttrID, uint64_t &fileID, const char *filePath);
    virtual int addCarvedFileInfo(int vol_id, const char *name, uint64_t size, uint64_t *runStarts, uint64_t *runLengths, int numRuns, uint64_t & fileId);
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
    virtual std::string getImageBaseName() const;
    virtual std::vector<std::wstring> getImageNamesW() const;
    virtual std::vector<std::string>  getImageNames() const;
    virtual int getFileUniqueIdentifiers(uint64_t a_fileId, uint64_t &a_fsOffset, uint64_t &a_fsFileId, int &a_attrType, int &a_attrId) const;
    virtual int getNumVolumes() const;
    virtual int getNumFiles() const;
    virtual int getImageInfo(int & type, int & sectorSize) const;
    virtual int getVolumeInfo(std::list<TskVolumeInfoRecord> & volumeInfoList) const;
    virtual int getFsInfo(std::list<TskFsInfoRecord> & FsInfoList) const;
    virtual int getFileInfoSummary(std::list<TskFileTypeRecord> & fileTypeInfoList) const;
    virtual int getFileInfoSummary(FILE_TYPES fileType, std::list<TskFileTypeRecord> & fileTypeInfoList) const;
    virtual TskImgDB::KNOWN_STATUS getKnownStatus(const uint64_t fileId) const;

    virtual UnallocRun * getUnallocRun(int file_id, int file_offset) const; 
    virtual SectorRuns * getFreeSectors() const;

    virtual int updateFileStatus(uint64_t a_file_id, TskImgDB::FILE_STATUS a_status);
    virtual int updateKnownStatus(uint64_t a_file_id, TskImgDB::KNOWN_STATUS a_status);
	
    virtual bool dbExist() const;

    /// Get set of file ids that match the given condition (i.e. SQL where clause)
    virtual std::vector<uint64_t> getFileIds(const std::string& condition) const;
    virtual const std::vector<TskFileRecord> getFileRecords(const std::string& condition) const;

    /// Get the number of files that match the given condition
    virtual int getFileCount(const std::string& condition) const;

    virtual std::map<uint64_t, std::string> getUniqueCarvedFiles(HASH_TYPE hashType) const;
    virtual std::vector<TskCarvedFileInfo> getUniqueCarvedFilesInfo(HASH_TYPE hashType) const;
    virtual std::vector<uint64_t> getCarvedFileIds() const;

    virtual std::vector<uint64_t> getUniqueFileIds(HASH_TYPE hashType) const;
    virtual std::vector<uint64_t> getFileIds() const;

    virtual int setHash(const uint64_t a_file_id, const TskImgDB::HASH_TYPE hashType, const std::string& hash) const;
    virtual std::string getCfileName(const uint64_t a_file_id) const;

    virtual int addModule(const std::string& name, const std::string& description, int & moduleId);
    virtual int setModuleStatus(uint64_t file_id, int module_id, int status);
	virtual int getModuleInfo(std::vector<TskModuleInfo> & moduleInfoList) const;
    virtual int getModuleErrors(std::vector<TskModuleStatus> & moduleStatusList) const;
    virtual std::string getFileName(uint64_t file_id) const;

    virtual int addUnallocImg(int & unallocImgId);
    virtual int setUnallocImgStatus(int unallocImgId, TskImgDB::UNALLOC_IMG_STATUS status);
    virtual TskImgDB::UNALLOC_IMG_STATUS getUnallocImgStatus(int unallocImgId) const;
    virtual int getAllUnallocImgStatus(std::vector<TskUnallocImgStatusRecord> & unallocImgStatusList) const;
 
    virtual int addUnusedSectors(int unallocImgId, std::vector<TskUnusedSectorsRecord> & unusedSectorsList);
    virtual int getUnusedSector(uint64_t fileId, TskUnusedSectorsRecord & unusedSectorsRecord) const;

    friend class TskDBBlackboard;

protected:
   // Blackboard methods.
    virtual TskBlackboardArtifact createBlackboardArtifact(uint64_t file_id, int artifactTypeID);
    virtual void addBlackboardAttribute(TskBlackboardAttribute attr);
    
    virtual void addArtifactType(int typeID, string artifactTypeName, string displayName);
    virtual void addAttributeType(int typeID, string attributeTypeName, string displayName);

    virtual string getArtifactTypeDisplayName(int artifactTypeID);
    virtual int getArtifactTypeID(string artifactTypeString);
    virtual string getArtifactTypeName(int artifactTypeID);
    virtual vector<TskBlackboardArtifact> getMatchingArtifacts(string condition);

    virtual string getAttributeTypeDisplayName(int attributeTypeID);
    virtual int getAttributeTypeID(string attributeTypeString);
    virtual string getAttributeTypeName(int attributeTypeID);
    virtual vector<TskBlackboardAttribute> getMatchingAttributes(string condition);
    
    virtual vector<int> findAttributeTypes(int artifactTypeId);

	std::string quote(const std::string str) const;

private:
    std::string m_dbName;
    pqxx::connection * m_dbConnection;
    int m_artifactIDcounter;
    int m_attributeIDcounter;

    // Execute the given statement and return the result set.
	pqxx::result executeStatement(const std::string& stmt) const;

    bool initialized() const;
    std::vector<uint64_t> getFileIdsWorker(std::string tableName, const std::string condition = "") const;
    void constructStmt(std::string& stmt, std::string condition) const;
    int addUnusedSector(uint64_t sectStart, uint64_t sectEnd, int volId, std::vector<TskUnusedSectorsRecord> & unusedSectorsList);
    int getFileTypeRecords(std::string& stmt, std::list<TskFileTypeRecord>& fileTypeInfoList) const;
    vector<TskBlackboardArtifact> getArtifactsHelper(uint64_t file_id, int artifactTypeID, string artifactTypeName);
    void getCarvedFileInfo(const std::string& stmt, std::map<uint64_t, std::string>& results) const;
    int getModuleId(const std::string& name, int& moduleId) const;

    /**
     * A helper function for getUniqueCarvedFilesInfo() that executes a very specific SQL SELECT statement 
     * and returns the results as TskCarvedFileInfo objects.
     *
     * @param stmtToExecute The SQL statement
     * @param getHash A flag indicating whether the SELECT includes a hash value
     * @param carvedFileInfos The data returned by the query
     * @return Throws TskException
     */
    void getCarvedFileInfo(const std::string &stmtToExecute,  bool getHash, std::vector<TskCarvedFileInfo> &carvedFileInfos) const;
};

#endif
