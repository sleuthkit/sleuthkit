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


#ifndef _TSK_IMGDB_H
#define _TSK_IMGDB_H

#define IMGDB_SCHEMA_VERSION "1.0"

#include <string> // to get std::wstring
#include <list>
#include <vector>
#include "tsk3/libtsk.h"
#include "framework_i.h"
#include "Utilities/SectorRuns.h"
#include "Utilities/UnallocRun.h"

using namespace std;

typedef uint64_t artifact_t;

/**
 * Contains data from a file record in the database.
 */
struct TskFileRecord
{
    uint64_t fileId;
    int typeId;
    std::string name;
    uint64_t parentFileId;
    int dirType;
    int metaType;
    int dirFlags;
    int metaFlags;
    uint64_t size;
    int ctime;
    int crtime;
    int atime;
    int mtime;
    int mode;
    int uid;
    int gid;
    int status;
    std::string md5;
    std::string sha1;
    std::string sha2_256;
    std::string sha2_512;
    std::string fullPath;
};

/**
 * Contains data from a volume/partition record in the database.
 */
struct TskVolumeInfoRecord
{
    int vol_id;
    uint64_t sect_start;
    uint64_t sect_len;
    std::string description;
    int flags;
};

/**
 * Contains data from a file system record in the database.
 */
struct TskFsInfoRecord
{
    int fs_id;
    uint64_t img_byte_offset;
    int vol_id;
    int fs_type;
    int block_size;
    uint64_t block_count;
    uint64_t root_inum;
    uint64_t first_inum;
    uint64_t last_inum;
};

struct TskFileTypeRecord
{
    std::string suffix; // file extension, normalized to lowercase. If no extension, it is an empty string.
    std::string description; // descript of the file type.
    uint64_t count; // count of files with this extension.
};

/**
 * Contains data about the module return status for a given file (as recorded in the database)
 */
struct TskModuleStatus
{
    uint64_t file_id;
    std::string module_name;
    int status;
};

/**
 * Contains data for a blackboard entry for a given file and artifact ID
 */
struct TskBlackboardRecord
{
    artifact_t artifactId;
    uint64_t fileId;
    string attribute;
    string source;
    string context;
    int valueType; // determines which value below contains actual data
    int32_t valueInt32;
    int64_t valueInt64;
    string valueString;
    double valueDouble;
    vector<unsigned char> valueByte;

    TskBlackboardRecord(artifact_t a_artifactId, uint64_t a_fileId, string a_attribute, string a_source, string a_context)
        : artifactId(a_artifactId), fileId(a_fileId), attribute(a_attribute), source(a_source), context(a_context)
    {
    }
    TskBlackboardRecord() {}
};

/**
 * Contains data about the current status for an unallocated chunk of data.
 */
struct TskUnallocImgStatusRecord
{
    int unallocImgId;
    int status; // UNALLOC_IMG_STATUS
};

/**
 * Contains data about the mapping of data in the unallocated chunks back
 * to their original location in the disk image.
 */
struct TskAllocUnallocMapRecord
{
    int vol_id;
    int unalloc_img_id;
    uint64_t unalloc_img_sect_start;
    uint64_t sect_len;
    uint64_t orig_img_sect_start;
};

/**
 * contains data about the 'unused sectors', which did not have carvable data.
 */
struct TskUnusedSectorsRecord
{
    uint64_t fileId;
    uint64_t sectStart;
    uint64_t sectLen;
};

/**
 * Interface for class that implments database storage for an image.
 * The database will be used to store information about the data
 * being analyzed. 
 * Can be registered with and retrieved from TskServices.
 */
class TSK_FRAMEWORK_API TskImgDB
{
public:
    static enum FILE_TYPES
    {
        IMGDB_FILES_TYPE_FS = 0,
        IMGDB_FILES_TYPE_CARVED,
        IMGDB_FILES_TYPE_DERIVED,
        IMGDB_FILES_TYPE_UNUSED
    };

    static enum FILE_STATUS
    {
        IMGDB_FILES_STATUS_CREATED = 0,
        IMGDB_FILES_STATUS_READY_FOR_ANALYSIS,
        IMGDB_FILES_STATUS_ANALYSIS_IN_PROGRESS,
        IMGDB_FILES_STATUS_ANALYSIS_COMPLETE,
        IMGDB_FILES_STATUS_ANALYSIS_FAILED,
        IMGDB_FILES_STATUS_ANALYSIS_SKIPPED
    };
    static enum KNOWN_STATUS
    {
        IMGDB_FILES_KNOWN = 0,
        IMGDB_FILES_KNOWN_GOOD,
        IMGDB_FILES_KNOWN_BAD,
        IMGDB_FILES_UNKNOWN
    };

    static enum HASH_TYPE 
    {
        MD5 = 0,
        SHA1,
        SHA2_256,
        SHA2_512
    };

    static enum VALUE_TYPE
    {
        BB_VALUE_TYPE_BYTE = 0,
        BB_VALUE_TYPE_STRING,
        BB_VALUE_TYPE_INT32,
        BB_VALUE_TYPE_INT64,
        BB_VALUE_TYPE_DOUBLE
    };

    static enum UNALLOC_IMG_STATUS
    {
        IMGDB_UNALLOC_IMG_STATUS_CREATED = 0,
        IMGDB_UNALLOC_IMG_STATUS_SCHEDULE_OK,
        IMGDB_UNALLOC_IMG_STATUS_SCHEDULE_ERR,
        IMGDB_UNALLOC_IMG_STATUS_CARVED_OK,
        IMGDB_UNALLOC_IMG_STATUS_CARVED_ERR,
        IMGDB_UNALLOC_IMG_STATUS_CARVED_NOT_NEEDED,
    };

    TskImgDB();
    virtual ~ TskImgDB();

    virtual int initialize() = 0;
    virtual int open() = 0;

    virtual int close() = 0;

    virtual int begin() = 0;
    virtual int commit() = 0;

    virtual int addToolInfo(const char* name, const char* version) = 0;
    virtual int addImageInfo(int type, int sectorSize) = 0;
    virtual int addImageName(char const * imgName) = 0;
    virtual int addVolumeInfo(const TSK_VS_PART_INFO * vs_part) = 0;
    virtual int addFsInfo(int volId, int fsId, const TSK_FS_INFO * fs_info) = 0;
    virtual int addFsFileInfo(int fsId, const TSK_FS_FILE *fs_file, const char *name, int type, int idx, uint64_t & fileId, const char * path) = 0;
    virtual int addCarvedFileInfo(int vol_id, wchar_t * name, uint64_t size, uint64_t *runStarts, uint64_t *runLengths, int numRuns, uint64_t & fileId) = 0;
    virtual int addDerivedFileInfo(const std::string& name, const uint64_t parentId, 
                                        const bool isDirectory, const uint64_t size, const std::string& details,
                                        const int ctime, const int crtime, const int atime, const int mtime, uint64_t & fileId, std::string path) = 0;
    virtual int addFsBlockInfo(int fsID, uint64_t a_mFileId, int count, uint64_t blk_addr, uint64_t len) = 0;
    virtual int addAllocUnallocMapInfo(int unallocVolID, int unallocImgID, uint64_t unallocImgStart, uint64_t length, uint64_t origImgStart) = 0;
    virtual int getSessionID() const = 0;
    virtual int getFileIds(char *a_fileName, uint64_t *a_outBuffer, int a_buffSize) const = 0;
    virtual int getNumFiles() const = 0;
    virtual int getMaxFileIdReadyForAnalysis(uint64_t a_lastFileId, uint64_t & maxFileId) const = 0;
    virtual int getMinFileIdReadyForAnalysis(uint64_t & minFileId) const = 0;
    virtual uint64_t getFileId(int fsId, uint64_t fs_file_id) const = 0;
    virtual int getFileRecord(const uint64_t fileId, TskFileRecord& fileRecord) const = 0;
    virtual SectorRuns * getFileSectors(uint64_t fileId) const = 0;
    virtual std::vector<std::wstring> getImageNames() const = 0;
    virtual int getFileUniqueIdentifiers(uint64_t a_fileId, uint64_t &a_fsOffset, uint64_t &a_fsFileId, int &a_attrType, int &a_attrId) const = 0;
    virtual int getNumVolumes() const = 0;
    virtual int getImageInfo(int & type, int & sectorSize) const = 0;
    virtual int getVolumeInfo(std::list<TskVolumeInfoRecord> & volumeInfoList) const = 0;
    virtual int getFsInfo(std::list<TskFsInfoRecord> & fsInfoList) const = 0;
    virtual int getFileInfoSummary(FILE_TYPES fileType, std::list<TskFileTypeRecord> & fileTypeInfoList) const = 0;
    virtual int getKnownStatus(const uint64_t fileId) = 0;
    

    virtual UnallocRun * getUnallocRun(int file_id, int file_offset) const = 0; 
    virtual SectorRuns * getFreeSectors() const = 0;

    virtual int updateFileStatus(uint64_t a_file_id, int a_status) = 0;
    virtual int updateKnownStatus(uint64_t a_file_id, int a_status) = 0;
	virtual bool dbExist() const = 0;

    // Blackboard read/write methods.

    virtual int getBlackboard(const uint64_t a_file_id, const string & attribute, vector<vector<unsigned char>> & values) const = 0;
    virtual int getBlackboard(const uint64_t a_file_id, const string & attribute, vector<string> & values) const = 0;
    virtual int getBlackboard(const uint64_t a_file_id, const string & attribute, vector<int32_t> & values) const = 0;
    virtual int getBlackboard(const uint64_t a_file_id, const string & attribute, vector<int64_t> & values) const = 0;
    virtual int getBlackboard(const uint64_t a_file_id, const string & attribute, vector<double> & values) const = 0;

    /// Create a new artifact with the given record.
    virtual artifact_t addBlackboardInfo(const TskBlackboardRecord& blackboardRecord) const = 0;

    virtual void getAllBlackboardRows(const uint64_t fileId, vector<TskBlackboardRecord> & bbRecords ) const = 0;

    //// Convenience functions

    // return the valueString field, if valueType is BB_VALUE_TYPE_STRING, otherwise raise exception
    virtual string toString(const TskBlackboardRecord & rec) const;

    // return the valueInt32 field, if valueType is BB_VALUE_TYPE_INT32, otherwise raise exception
    virtual int32_t toInt32(const TskBlackboardRecord & rec) const;

    // return the valueInt64 field, if valueType is BB_VALUE_TYPE_INT64, otherwise raise exception
    virtual int64_t toInt64(const TskBlackboardRecord & rec) const;

    // return the valueDouble field, if valueType is BB_VALUE_TYPE_DOUBLE, otherwise raise exception
    virtual double toDouble(const TskBlackboardRecord & rec) const;

    ////// --------------------


    /// Get set of file ids that match the given condition (i.e. SQL where clause)
    virtual std::vector<uint64_t> getFileIds(std::string& condition) const = 0;

    /// Get the number of files that match the given condition
    virtual int getFileCount(std::string& condition) const = 0;

    virtual std::vector<uint64_t> getUniqueCarvedFileIds(HASH_TYPE hashType) const = 0;
    virtual std::vector<uint64_t> getCarvedFileIds() const = 0;

    virtual std::vector<uint64_t> getUniqueFileIds(HASH_TYPE hashType) const = 0;
    virtual std::vector<uint64_t> getFileIds() const = 0;

    virtual int setHash(uint64_t a_file_id, TskImgDB::HASH_TYPE hashType, const std::string hash) = 0;
    virtual std::string getCfileName(uint64_t a_file_id) const = 0;

    virtual int addModule(const std::string name, const std::string description, int & moduleId) = 0;
    virtual int setModuleStatus(uint64_t file_id, int module_id, int status) = 0;
    virtual int getModuleErrors(std::vector<TskModuleStatus> & moduleStatusList) const = 0;
    virtual std::string getFileName(uint64_t file_id) const = 0;

    virtual int addUnallocImg(int & unallocImgId) = 0;
    virtual int setUnallocImgStatus(int unallocImgId, TskImgDB::UNALLOC_IMG_STATUS status) = 0;
    virtual TskImgDB::UNALLOC_IMG_STATUS getUnallocImgStatus(int unallocImgId) const = 0;
    virtual int getAllUnallocImgStatus(std::vector<TskUnallocImgStatusRecord> & unallocImgStatusList) const = 0;

    virtual int addUnusedSectors(int unallocImgId, std::vector<TskUnusedSectorsRecord> & unusedSectorsList) = 0;
    virtual int getUnusedSector(uint64_t fileId, TskUnusedSectorsRecord & unusedSectorsRecord) const = 0;

private:
};

#endif
