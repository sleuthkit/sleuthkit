/*
 ** The Sleuth Kit
 **
 ** Brian Carrier [carrier <at> sleuthkit [dot] org]
 ** Copyright (c) 2020 Brian Carrier.  All Rights reserved
 **
 ** This software is distributed under the Common Public License 1.0
 **
 */

/**
 * \file auto_db_java.cpp
 * Contains code to populate database with volume and file system information from a specific image.
 */

#include "auto_db_java.h"
#include "jni.h"
#include "tsk/img/img_writer.h"
#if HAVE_LIBEWF
#include "tsk/img/ewf.h"
#include "tsk/img/tsk_img_i.h"
#endif
#include <string.h>

#include <algorithm>
#include <sstream>

using std::stringstream;
using std::for_each;

/**
 */
TskAutoDbJava::TskAutoDbJava()
{
    m_curImgId = 0;
    m_curVsId = 0;
    m_curVolId = 0;
    m_curFsId = 0;
    m_curFileId = 0;
    m_curUnallocDirId = 0;
    m_curDirAddr = 0;
    m_curDirPath = "";
    m_vsFound = false;
    m_volFound = false;
    m_poolFound = false;
    m_stopped = false;
    m_foundStructure = false;
    m_attributeAdded = false;
    m_addFileSystems = true;
    m_noFatFsOrphans = false;
    m_addUnallocSpace = false;
    m_minChunkSize = -1;
    m_maxChunkSize = -1;

    m_jniEnv = NULL;

    tsk_init_lock(&m_curDirPathLock);
}

TskAutoDbJava::~TskAutoDbJava()
{
    closeImage();
    tsk_deinit_lock(&m_curDirPathLock);
}

TSK_RETVAL_ENUM
TskAutoDbJava::initializeJni(JNIEnv * jniEnv, jobject jobj) {
    m_jniEnv = jniEnv;
    m_javaDbObj = m_jniEnv->NewGlobalRef(jobj); // TODO free this

    printf("\n#### initializeJni\n");
    fflush(stdout);

    jclass localCallbackClass = m_jniEnv->FindClass("org/sleuthkit/datamodel/JniDbHelper");
    if (localCallbackClass == NULL) {
        return TSK_ERR;
    }
    m_callbackClass = (jclass)m_jniEnv->NewGlobalRef(localCallbackClass);

    m_addImageMethodID = m_jniEnv->GetMethodID(m_callbackClass, "addImageInfo", "(IJLjava/lang/String;JLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)J");
    if (m_addImageMethodID == NULL) {
        printf("#### Error loading m_addImageMethodID\n");
        fflush(stdout);
        return TSK_ERR;
    }

    m_addImageNameMethodID = m_jniEnv->GetMethodID(m_callbackClass, "addImageName", "(JLjava/lang/String;J)I");
    if (m_addImageNameMethodID == NULL) {
        printf("#### Error loading m_addImageNameMethodID\n");
        fflush(stdout);
        return TSK_ERR;
    }

    printf("\n#### Yay found method IDs!\n");
    fflush(stdout);
    return TSK_OK;
}

////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////




TSK_RETVAL_ENUM
TskAutoDbJava::addImageInfo(int type, TSK_OFF_T ssize, int64_t & objId, const string & timezone, TSK_OFF_T size, const string &md5,
    const string& sha1, const string& sha256, const string& deviceId, const string& collectionDetails) {

    printf("addImageInfo - preparing all the jstrings\n");
    fflush(stdout);

    const char *tz_cstr = timezone.c_str();
    jstring tzj = m_jniEnv->NewStringUTF(tz_cstr);

    const char *md5_cstr = md5.c_str();
    jstring md5j = m_jniEnv->NewStringUTF(md5_cstr);

    const char *sha1_cstr = sha1.c_str();
    jstring sha1j = m_jniEnv->NewStringUTF(sha1_cstr);

    const char *sha256_cstr = sha256.c_str();
    jstring sha256j = m_jniEnv->NewStringUTF(sha256_cstr);

    const char *devId_cstr = deviceId.c_str();
    jstring devIdj = m_jniEnv->NewStringUTF(devId_cstr);

    const char *coll_cstr = collectionDetails.c_str();
    jstring collj = m_jniEnv->NewStringUTF(coll_cstr);
    // TODO TODO free strings?

    printf("addImageInfo - making JNI call\n");
    fflush(stdout);

    if (m_addImageMethodID == NULL) {
        printf("#### Yikes addImageMethodID is null...\n");
        return TSK_ERR;
    }

    jlong objIdj = m_jniEnv->CallLongMethod(m_javaDbObj, m_addImageMethodID,
        jint(type), jlong(ssize), tzj, jlong(size), md5j, sha1j, sha256j, devIdj, collj);
    objId = (int64_t)objIdj;

    return TSK_OK;
}

TSK_RETVAL_ENUM
TskAutoDbJava::addImageName(int64_t objId, char const* imgName, int sequence) {
    printf("addImageName\n");

    if (m_addImageNameMethodID == NULL) {
        printf("#### Yikes m_addImageNameMethodID is null...\n");
        return TSK_ERR;
    }

    jstring imgNamej = m_jniEnv->NewStringUTF(imgName);

    jint res = m_jniEnv->CallIntMethod(m_javaDbObj, m_addImageNameMethodID,
        jlong(objId), imgNamej, jlong(sequence));

    if (res == 0) {
        return TSK_OK;
    }
    else {
        return TSK_ERR;
    }
}

TSK_RETVAL_ENUM
TskAutoDbJava::addVsInfo(const TSK_VS_INFO* vs_info, int64_t parObjId, int64_t& objId) {
    printf("addVsInfo\n");
    return TSK_OK;
}

TSK_RETVAL_ENUM
TskAutoDbJava::addPoolInfoAndVS(const TSK_POOL_INFO *pool_info, int64_t parObjId, int64_t& objId) {
    printf("addPoolInfoAndVS\n");
    return TSK_OK;
}

TSK_RETVAL_ENUM
TskAutoDbJava::addPoolVolumeInfo(const TSK_POOL_VOLUME_INFO* pool_vol,
    int64_t parObjId, int64_t& objId) {
    printf("addPoolVolumeInfo\n");
    return TSK_OK;
}


TSK_RETVAL_ENUM
TskAutoDbJava::addVolumeInfo(const TSK_VS_PART_INFO* vs_part,
    int64_t parObjId, int64_t& objId) {
    printf("addVolumeInfo\n");
    return TSK_OK;
}

TSK_RETVAL_ENUM
TskAutoDbJava::addFsInfo(const TSK_FS_INFO* fs_info, int64_t parObjId,
    int64_t& objId) {
    printf("addFsInfo\n");
    return TSK_OK;
}

TSK_RETVAL_ENUM
TskAutoDbJava::addFsFile(TSK_FS_FILE* fs_file,
    const TSK_FS_ATTR* fs_attr, const char* path,
    const unsigned char*const md5, const TSK_DB_FILES_KNOWN_ENUM known,
    int64_t fsObjId, int64_t& objId, int64_t dataSourceObjId) {

    printf("addFsFile\n");
    return TSK_OK;
}

TSK_RETVAL_ENUM
addFileWithLayoutRange(const TSK_DB_FILES_TYPE_ENUM dbFileType, const int64_t parentObjId,
    const int64_t fsObjId, const uint64_t size,
    vector<TSK_DB_FILE_LAYOUT_RANGE>& ranges, int64_t& objId,
    int64_t dataSourceObjId) {
    printf("addFileWithLayoutRange\n");
    return TSK_OK;
}

TSK_RETVAL_ENUM
addUnallocBlockFile(const int64_t parentObjId, const int64_t fsObjId, const uint64_t size,
    vector<TSK_DB_FILE_LAYOUT_RANGE>& ranges, int64_t& objId,
    int64_t dataSourceObjId) {
    printf("addUnallocBlockFile\n");
    return addFileWithLayoutRange(TSK_DB_FILES_TYPE_UNALLOC_BLOCKS, parentObjId, fsObjId, size, ranges, objId,
        dataSourceObjId);
}

TSK_RETVAL_ENUM
addUnusedBlockFile(const int64_t parentObjId, const int64_t fsObjId, const uint64_t size,
    vector<TSK_DB_FILE_LAYOUT_RANGE>& ranges, int64_t& objId,
    int64_t dataSourceObjId) {
    printf("addUnusedBlockFile\n");
    return addFileWithLayoutRange(TSK_DB_FILES_TYPE_UNUSED_BLOCKS, parentObjId, fsObjId, size, ranges, objId,
        dataSourceObjId);
}



TSK_RETVAL_ENUM
TskAutoDbJava::addUnallocFsBlockFilesParent(const int64_t fsObjId, int64_t& objId,
    int64_t dataSourceObjId) {
    printf("addUnallocFsBlockfilesParent\n");
    return TSK_OK;
}



////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////

void
 TskAutoDbJava::closeImage()
{
    TskAuto::closeImage();
}

void TskAutoDbJava::setAddFileSystems(bool addFileSystems)
{
    m_addFileSystems = addFileSystems;
}

void TskAutoDbJava::setNoFatFsOrphans(bool noFatFsOrphans)
{
    m_noFatFsOrphans = noFatFsOrphans;
}

void TskAutoDbJava::setAddUnallocSpace(bool addUnallocSpace)
{
    setAddUnallocSpace(addUnallocSpace, -1);
}

void TskAutoDbJava::setAddUnallocSpace(bool addUnallocSpace, int64_t minChunkSize)
{
    m_addUnallocSpace = addUnallocSpace;
    m_minChunkSize = minChunkSize;
    m_maxChunkSize = -1;
}

void TskAutoDbJava::setAddUnallocSpace(int64_t minChunkSize, int64_t maxChunkSize)
{
    m_addUnallocSpace = true;
    m_minChunkSize = minChunkSize;
    m_maxChunkSize = maxChunkSize;
}

/**
 * Adds an image to the database.
 *
 * @param a_num Number of image parts
 * @param a_images Array of paths to the image parts
 * @param a_type Image type
 * @param a_ssize Size of device sector in bytes (or 0 for default)
 * @param a_deviceId An ASCII-printable identifier for the device associated with the data source that is intended to be unique across multiple cases (e.g., a UUID).
 * @return 0 for success, 1 for failure
 */
uint8_t
    TskAutoDbJava::openImageUtf8(int a_num, const char *const a_images[],
    TSK_IMG_TYPE_ENUM a_type, unsigned int a_ssize, const char* a_deviceId)
{
    uint8_t retval =
        TskAuto::openImageUtf8(a_num, a_images, a_type, a_ssize);
    if (retval != 0) {
        return retval;
    }

    if (addImageDetails(a_deviceId)) {
        return 1;
    }
    return 0;
}

/**
 * Adds an image to the database.
 *
 * @param a_num Number of image parts
 * @param a_images Array of paths to the image parts
 * @param a_type Image type
 * @param a_ssize Size of device sector in bytes (or 0 for default)
 * @param a_deviceId An ASCII-printable identifier for the device associated with the data source that is intended to be unique across multiple cases (e.g., a UUID).
 * @return 0 for success, 1 for failure
 */
uint8_t
    TskAutoDbJava::openImage(int a_num, const TSK_TCHAR * const a_images[],
    TSK_IMG_TYPE_ENUM a_type, unsigned int a_ssize, const char* a_deviceId)
{

#ifdef TSK_WIN32

    uint8_t retval = TskAuto::openImage(a_num, a_images, a_type, a_ssize);

    if (retval != 0) {
        return retval;
    }

    return (addImageDetails(a_deviceId));
#else
    return openImageUtf8(a_num, a_images, a_type, a_ssize, a_deviceId);
#endif
}

/**
* Adds an image to the database. Requires that m_img_info is already initialized
*
* @param a_deviceId An ASCII-printable identifier for the device associated with the data source that is intended to be unique across multiple cases (e.g., a UUID).
* @return 0 for success, 1 for failure
*/
uint8_t
TskAutoDbJava::openImage(const char* a_deviceId)
{
    if (m_img_info == NULL) {
        return 1;
    }

    return(addImageDetails(a_deviceId));
}

/**
 * Adds image details to the existing database tables.
 *
 * @param deviceId An ASCII-printable identifier for the device associated with the data source that is intended to be unique across multiple cases (e.g., a UUID).
 * @return Returns 0 for success, 1 for failure
 */
uint8_t
TskAutoDbJava::addImageDetails(const char* deviceId)
{
   string md5 = "";
   string sha1 = "";
   string collectionDetails = "";
#if HAVE_LIBEWF 
   if (m_img_info->itype == TSK_IMG_TYPE_EWF_EWF) {
     // @@@ This should really probably be inside of a tsk_img_ method
       IMG_EWF_INFO *ewf_info = (IMG_EWF_INFO *)m_img_info;
       if (ewf_info->md5hash_isset) {
           md5 = ewf_info->md5hash;
       }
       if (ewf_info->sha1hash_isset) {
           sha1 = ewf_info->sha1hash;
       }

       collectionDetails = ewf_get_details(ewf_info);   
   }
#endif

    string devId;
    if (NULL != deviceId) {
        devId = deviceId; 
    } else {
        devId = "";
    }
    if (TSK_ERR == addImageInfo(m_img_info->itype, m_img_info->sector_size,
          m_curImgId, m_curImgTZone, m_img_info->size, md5, sha1, "", devId, collectionDetails)) {
        registerError();
        return 1;
    }



    char **img_ptrs;
#ifdef TSK_WIN32
    // convert image paths to UTF-8
    img_ptrs = (char **)tsk_malloc(m_img_info->num_img * sizeof(char *));
    if (img_ptrs == NULL) {
        return 1;
    }

    for (int i = 0; i < m_img_info->num_img; i++) {
        char * img2 = (char*)tsk_malloc(1024 * sizeof(char));
        UTF8 *ptr8;
        UTF16 *ptr16;

        ptr8 = (UTF8 *)img2;
        ptr16 = (UTF16 *)m_img_info->images[i];

        uint8_t retval =
            tsk_UTF16toUTF8_lclorder((const UTF16 **)&ptr16, (UTF16 *)
                & ptr16[TSTRLEN(m_img_info->images[i]) + 1], &ptr8,
                (UTF8 *)((uintptr_t)ptr8 + 1024), TSKlenientConversion);
        if (retval != TSKconversionOK) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_AUTO_UNICODE);
            tsk_error_set_errstr("Error converting image to UTF-8\n");
            return 1;
        }
        img_ptrs[i] = img2;
    }
#else 
    img_ptrs = m_img_info->images;
#endif

    // Add the image names
    for (int i = 0; i < m_img_info->num_img; i++) {
        const char *img_ptr = img_ptrs[i];

        if (-1 == addImageName(m_curImgId, img_ptr, i)) {
            registerError();
            return 1;
        }
    }

#ifdef TSK_WIN32
    //cleanup
    for (int i = 0; i < m_img_info->num_img; ++i) {
        free(img_ptrs[i]);
    }
    free(img_ptrs);
#endif
    printf("Returning error from end of addImageDetails\n"); // TODO TODO
    fflush(stdout);
    return 1;
    //return 0;
}


TSK_FILTER_ENUM TskAutoDbJava::filterVs(const TSK_VS_INFO * vs_info)
{
    m_vsFound = true;
    if (-1 == addVsInfo(vs_info, m_curImgId, m_curVsId)) {
        registerError();
        return TSK_FILTER_STOP;
    }

    return TSK_FILTER_CONT;
}

TSK_FILTER_ENUM
TskAutoDbJava::filterPool(const TSK_POOL_INFO * pool_info)
{
    m_poolFound = true;

    if (m_volFound && m_vsFound) {
        // there's a volume system and volume
        if (-1 == addPoolInfoAndVS(pool_info, m_curVolId, m_curPoolVs)) {
            registerError();
            return TSK_FILTER_STOP;
        }
    }
    else {
        // pool doesn't live in a volume, use image as parent
        if (-1 == addPoolInfoAndVS(pool_info, m_curImgId, m_curPoolVs)) {
            registerError();
            return TSK_FILTER_STOP;
        }
    }

    

    return TSK_FILTER_CONT;
}

TSK_FILTER_ENUM
TskAutoDbJava::filterPoolVol(const TSK_POOL_VOLUME_INFO * pool_vol)
{

    if (-1 == addPoolVolumeInfo(pool_vol, m_curPoolVs, m_curPoolVol)) {
        registerError();
        return TSK_FILTER_STOP;
    }

    return TSK_FILTER_CONT;
}

TSK_FILTER_ENUM
TskAutoDbJava::filterVol(const TSK_VS_PART_INFO * vs_part)
{
    m_volFound = true;
    m_foundStructure = true;
    m_poolFound = false;

    if (-1 == addVolumeInfo(vs_part, m_curVsId, m_curVolId)) {
        registerError();
        return TSK_FILTER_STOP;
    }

    return TSK_FILTER_CONT;
}


TSK_FILTER_ENUM
TskAutoDbJava::filterFs(TSK_FS_INFO * fs_info)
{
    TSK_FS_FILE *file_root;
    m_foundStructure = true;

    if (m_poolFound) {
        // there's a pool
        if (-1 != addFsInfo(fs_info, m_curPoolVol, m_curFsId)) {
            registerError();
            return TSK_FILTER_STOP;
        }
    }
    else if (m_volFound && m_vsFound) {
        // there's a volume system and volume
        if (-1 != addFsInfo(fs_info, m_curVolId, m_curFsId)) {
            registerError();
            return TSK_FILTER_STOP;
        }
    }
    else {
        // file system doesn't live in a volume, use image as parent
        if (-1 != addFsInfo(fs_info, m_curImgId, m_curFsId)) {
            registerError();
            return TSK_FILTER_STOP;
        }
    }


    // We won't hit the root directory on the walk, so open it now 
    if ((file_root = tsk_fs_file_open(fs_info, NULL, "/")) != NULL) {
        processFile(file_root, "");
        tsk_fs_file_close(file_root);
        file_root = NULL;
    }


    // make sure that flags are set to get all files -- we need this to
    // find parent directory
     
    TSK_FS_DIR_WALK_FLAG_ENUM filterFlags = (TSK_FS_DIR_WALK_FLAG_ENUM)
        (TSK_FS_DIR_WALK_FLAG_ALLOC | TSK_FS_DIR_WALK_FLAG_UNALLOC);

    //check if to skip processing of FAT orphans
    if (m_noFatFsOrphans 
        && TSK_FS_TYPE_ISFAT(fs_info->ftype) ) {
            filterFlags = (TSK_FS_DIR_WALK_FLAG_ENUM) (filterFlags | TSK_FS_DIR_WALK_FLAG_NOORPHAN);
    }

    setFileFilterFlags(filterFlags);

    return TSK_FILTER_CONT;
}

/* Insert the file data into the file table.
 * @param md5 Binary MD5 value (i.e. 16 bytes) or NULL
 * Returns TSK_ERR on error.
 */
TSK_RETVAL_ENUM
    TskAutoDbJava::insertFileData(TSK_FS_FILE * fs_file,
    const TSK_FS_ATTR * fs_attr, const char *path)
{

    if (-1 == addFsFile(fs_file, fs_attr, path, NULL, TSK_DB_FILES_KNOWN_UNKNOWN, m_curFsId, m_curFileId,
            m_curImgId)) {
        registerError();
        return TSK_ERR;
    }

    return TSK_OK;
}

/**
 * Analyzes the open image and adds image info to a database.
 * Does not deal with transactions and such.  Refer to startAddImage()
 * for more control. 
 * @returns 1 if a critical error occurred (DB doesn't exist, no file system, etc.), 2 if errors occurred at some point adding files to the DB (corrupt file, etc.), and 0 otherwise.  Errors will have been registered.
 */
uint8_t TskAutoDbJava::addFilesInImgToDb()
{
    printf("\n#### addFilesInImgToDb...\n");
    fflush(stdout);

    // @@@ This seems bad because we are overriding what the user may
    // have set. We should remove the public API if we are going to 
    // override it -- presumably this was added so that we always have
    // unallocated volume space...
    setVolFilterFlags((TSK_VS_PART_FLAG_ENUM) (TSK_VS_PART_FLAG_ALLOC |
            TSK_VS_PART_FLAG_UNALLOC));

    uint8_t retVal = 0;
    if (findFilesInImg()) {
        // map the boolean return value from findFiles to the three-state return value we use
        // @@@ findFiles should probably return this three-state enum too
        if (m_foundStructure == false) {
            retVal = 1;
        }
        else {
            retVal = 2;
        }
    }

    TSK_RETVAL_ENUM addUnallocRetval = TSK_OK;
    if (m_addUnallocSpace)
        addUnallocRetval = addUnallocSpaceToDb();

    // findFiles return value trumps unalloc since it can return either 2 or 1.
    if (retVal) {
        return retVal;
    }
    else if (addUnallocRetval == TSK_ERR) {
        return 2;
    }
    else {
        return 0;
    }
}


/**
 * Start the process to add image/file metadata to database inside of a transaction. 
 * User must call either commitAddImage() to commit the changes,
 * or revertAddImage() to revert them.
 *
 * @param numImg Number of image parts
 * @param imagePaths Array of paths to the image parts
 * @param imgType Image type
 * @param sSize Size of device sector in bytes (or 0 for default)
 * @param deviceId An ASCII-printable identifier for the device associated with the data source that is intended to be unique across multiple cases (e.g., a UUID)
 * @return 0 for success, 1 for failure
 */
uint8_t
    TskAutoDbJava::startAddImage(int numImg, const TSK_TCHAR * const imagePaths[],
    TSK_IMG_TYPE_ENUM imgType, unsigned int sSize, const char* deviceId)
{
    if (tsk_verbose)
        tsk_fprintf(stderr, "TskAutoDbJava::startAddImage: Starting add image process\n");

    if (openImage(numImg, imagePaths, imgType, sSize, deviceId)) {
        tsk_error_set_errstr2("TskAutoDbJava::startAddImage");
        registerError();
        return 1;
    }

    if (m_imageWriterEnabled) {
        tsk_img_writer_create(m_img_info, m_imageWriterPath);
    }
    
    if (m_addFileSystems) {
        return addFilesInImgToDb();
    } else {
        return 0;
    }
}

/**
* Start the process to add image/file metadata to database inside of a transaction.
* User must call either commitAddImage() to commit the changes,
* or revertAddImage() to revert them.
*
* @param img_info Previously initialized TSK_IMG_INFO object
* @param deviceId An ASCII-printable identifier for the device associated with the data source that is intended to be unique across multiple cases (e.g., a UUID)
* @return 0 for success, 1 for failure
*/
uint8_t
TskAutoDbJava::startAddImage(TSK_IMG_INFO * img_info, const char* deviceId)
{
    openImageHandle(img_info);

    if (m_img_info == NULL) {
        return 1;
    }

    if (tsk_verbose)
        tsk_fprintf(stderr, "TskAutoDbJava::startAddImage: Starting add image process\n");

    if (openImage(deviceId)) {
        tsk_error_set_errstr2("TskAutoDbJava::startAddImage");
        registerError();
        return 1;
    }

    if (m_imageWriterEnabled) {
        if (tsk_img_writer_create(m_img_info, m_imageWriterPath)) {
            registerError();
            return 1;
        }
    }

    if (m_addFileSystems) {
        return addFilesInImgToDb();
    }
    else {
        return 0;
    }
}


#ifdef WIN32
/**
 * Start the process to add image/file metadata to database inside of a transaction. 
 * Same functionality as addFilesInImgToDb().  Reverts
 * all changes on error. User must call either commitAddImage() to commit the changes,
 * or revertAddImage() to revert them.
 *
 * @param numImg Number of image parts
 * @param imagePaths Array of paths to the image parts
 * @param imgType Image type
 * @param sSize Size of device sector in bytes (or 0 for default)
 * @param deviceId An ASCII-printable identifier for the device associated with the data source that is intended to be unique across multiple cases (e.g., a UUID)
 * @return 0 for success 1, for failure
 */
uint8_t
    TskAutoDbJava::startAddImage(int numImg, const char *const imagePaths[],
    TSK_IMG_TYPE_ENUM imgType, unsigned int sSize, const char* deviceId)
{
    if (tsk_verbose) 
        tsk_fprintf(stderr, "TskAutoDbJava::startAddImage_utf8: Starting add image process\n");

    if (openImageUtf8(numImg, imagePaths, imgType, sSize, deviceId)) {
        tsk_error_set_errstr2("TskAutoDbJava::startAddImage");
        registerError();
        return 1;
    }
    if (m_imageWriterEnabled) {
        tsk_img_writer_create(m_img_info, m_imageWriterPath);
    }

    if (m_addFileSystems) {
        return addFilesInImgToDb();
    } else {
        return 0;
    }
}
#endif


/**
 * Cancel the running process.  Will not be handled immediately. 
 */
void
 TskAutoDbJava::stopAddImage()
{
    if (tsk_verbose)
        tsk_fprintf(stderr, "TskAutoDbJava::stopAddImage: Stop request received\n");
    
    m_stopped = true;
    setStopProcessing();
    // flag is checked every time processFile() is called
}

/**
 * Set the current image's timezone
 */
void
TskAutoDbJava::setTz(string tzone)
{
    m_curImgTZone = tzone;
}

TSK_RETVAL_ENUM
TskAutoDbJava::processFile(TSK_FS_FILE * fs_file, const char *path)
{
    
    // Check if the process has been canceled
     if (m_stopped) {
        if (tsk_verbose)
            tsk_fprintf(stderr, "TskAutoDbJava::processFile: Stop request detected\n");
        return TSK_STOP;
    }

    /* Update the current directory, which can be used to show
     * progress.  If we get a directory, then use its name.  We
     * do this so that when we are searching for orphan files, then
     * we at least show $OrphanFiles as status.  The secondary check
     * is to grab the parent folder from files once we return back 
     * into a folder when we are doing our depth-first recursion. */
    if (isDir(fs_file)) {
        m_curDirAddr = fs_file->name->meta_addr;
        tsk_take_lock(&m_curDirPathLock);
        m_curDirPath = string(path) + fs_file->name->name;
        tsk_release_lock(&m_curDirPathLock);
    }
    else if (m_curDirAddr != fs_file->name->par_addr) {
        m_curDirAddr = fs_file->name->par_addr;
        tsk_take_lock(&m_curDirPathLock);
        m_curDirPath = path;
        tsk_release_lock(&m_curDirPathLock);
    }

    /* process the attributes.  The case of having 0 attributes can occur
     * with virtual / sparse files and HFS directories.  
     * At some point, this can probably be cleaned
     * up if TSK is more consistent about if there should always be an 
     * attribute or not.  Sometimes, none of the attributes are added
     * because of their type and we always want to add a reference to 
     * every file. */
    TSK_RETVAL_ENUM retval = TSK_OK;
    m_attributeAdded = false;
    if (tsk_fs_file_attr_getsize(fs_file) > 0) {
        retval = processAttributes(fs_file, path);
    }

    // insert a general row if we didn't add a specific attribute one
    if ((retval == TSK_OK) && (m_attributeAdded == false)) {
        retval = insertFileData(fs_file, NULL, path);
    }
    
    // reset the file id
    m_curFileId = 0;

    if (retval == TSK_STOP)
        return TSK_STOP;
    else 
        return TSK_OK;
}


// we return only OK or STOP -- errors are registered only and OK is returned. 
TSK_RETVAL_ENUM
TskAutoDbJava::processAttribute(TSK_FS_FILE * fs_file,
    const TSK_FS_ATTR * fs_attr, const char *path)
{
    // add the file metadata for the default attribute type
    if (isDefaultType(fs_file, fs_attr)) {

        if (insertFileData(fs_attr->fs_file, fs_attr, path) == TSK_ERR) {
            registerError();
            return TSK_OK;
        }
        else {
            m_attributeAdded = true;
        }
    }

    return TSK_OK;
}


/**
* Callback invoked per every unallocated block in the filesystem
* Creates file ranges and file entries 
* A single file entry per consecutive range of blocks
* @param a_block block being walked
* @param a_ptr a pointer to an UNALLOC_BLOCK_WLK_TRACK struct
* @returns TSK_WALK_CONT if continue, otherwise TSK_WALK_STOP if stop processing requested
*/
TSK_WALK_RET_ENUM TskAutoDbJava::fsWalkUnallocBlocksCb(const TSK_FS_BLOCK *a_block, void *a_ptr) {
    UNALLOC_BLOCK_WLK_TRACK * unallocBlockWlkTrack = (UNALLOC_BLOCK_WLK_TRACK *) a_ptr;

    if (unallocBlockWlkTrack->tskAutoDbJava.m_stopAllProcessing)
        return TSK_WALK_STOP;

    // initialize if this is the first block
    if (unallocBlockWlkTrack->isStart) {
        unallocBlockWlkTrack->isStart = false;
        unallocBlockWlkTrack->curRangeStart = a_block->addr;
        unallocBlockWlkTrack->prevBlock = a_block->addr;
        unallocBlockWlkTrack->size = unallocBlockWlkTrack->fsInfo.block_size;
        unallocBlockWlkTrack->nextSequenceNo = 0;
        return TSK_WALK_CONT;
    }

    // We want to keep consecutive blocks in the same run, so simply update prevBlock and the size
    // if this one is consecutive with the last call. But, if we have hit the max chunk
    // size, then break up this set of consecutive blocks.
    if ((a_block->addr == unallocBlockWlkTrack->prevBlock + 1) && ((unallocBlockWlkTrack->maxChunkSize <= 0) ||
            (unallocBlockWlkTrack->size < unallocBlockWlkTrack->maxChunkSize))) {
        unallocBlockWlkTrack->prevBlock = a_block->addr;
		unallocBlockWlkTrack->size += unallocBlockWlkTrack->fsInfo.block_size;
        return TSK_WALK_CONT;
    }

    // this block is not contiguous with the previous one or we've hit the maximum size; create and add a range object
    const uint64_t rangeStartOffset = unallocBlockWlkTrack->curRangeStart * unallocBlockWlkTrack->fsInfo.block_size 
        + unallocBlockWlkTrack->fsInfo.offset;
    const uint64_t rangeSizeBytes = (1 + unallocBlockWlkTrack->prevBlock - unallocBlockWlkTrack->curRangeStart) 
        * unallocBlockWlkTrack->fsInfo.block_size;
    unallocBlockWlkTrack->ranges.push_back(TSK_DB_FILE_LAYOUT_RANGE(rangeStartOffset, rangeSizeBytes, unallocBlockWlkTrack->nextSequenceNo++));

    // Return (instead of adding this run) if we are going to:
    // a) Make one big file with all unallocated space (minChunkSize == 0)
    // or
    // b) Only make an unallocated file once we have at least chunkSize bytes
    // of data in our current run (minChunkSize > 0)
    // In either case, reset the range pointers and add this block to the size
    if ((unallocBlockWlkTrack->minChunkSize == 0) ||
        ((unallocBlockWlkTrack->minChunkSize > 0) &&
        (unallocBlockWlkTrack->size < unallocBlockWlkTrack->minChunkSize))) {

        unallocBlockWlkTrack->size += unallocBlockWlkTrack->fsInfo.block_size;
        unallocBlockWlkTrack->curRangeStart = a_block->addr;
        unallocBlockWlkTrack->prevBlock = a_block->addr;
        return TSK_WALK_CONT;
    }
    
    // at this point we are either chunking and have reached the chunk limit
    // or we're not chunking. Either way we now add what we've got to the DB
    int64_t fileObjId = 0;
    if (-1 == addUnallocBlockFile(unallocBlockWlkTrack->tskAutoDbJava.m_curUnallocDirId,
        unallocBlockWlkTrack->fsObjId, unallocBlockWlkTrack->size, unallocBlockWlkTrack->ranges, fileObjId, unallocBlockWlkTrack->tskAutoDbJava.m_curImgId) == TSK_ERR) {
            // @@@ Handle error -> Don't have access to registerError() though...
    }

    // reset
    unallocBlockWlkTrack->curRangeStart = a_block->addr;
    unallocBlockWlkTrack->prevBlock = a_block->addr;
    unallocBlockWlkTrack->size = unallocBlockWlkTrack->fsInfo.block_size; // The current block is part of the new range
    unallocBlockWlkTrack->ranges.clear();
    unallocBlockWlkTrack->nextSequenceNo = 0;

    //we don't know what the last unalloc block is in advance
    //and will handle the last range in addFsInfoUnalloc()
    
    return TSK_WALK_CONT;
}


/**
* Add unallocated space for the given file system to the database.
* Create files for consecutive unalloc block ranges.
* @param dbFsInfo fs to process
* @returns TSK_OK on success, TSK_ERR on error
*/
TSK_RETVAL_ENUM TskAutoDbJava::addFsInfoUnalloc(const TSK_DB_FS_INFO & dbFsInfo) {

    // Unalloc space is not yet implemented for APFS
    if (dbFsInfo.fType == TSK_FS_TYPE_APFS) {
        return TSK_OK;
    }

    //open the fs we have from database
    TSK_FS_INFO * fsInfo = tsk_fs_open_img(m_img_info, dbFsInfo.imgOffset, dbFsInfo.fType);
    if (fsInfo == NULL) {
        tsk_error_set_errstr2("TskAutoDbJava::addFsInfoUnalloc: error opening fs at offset %" PRIdOFF, dbFsInfo.imgOffset);
        registerError();
        return TSK_ERR;
    }

    //create a "fake" dir to hold the unalloc files for the fs
    if (-1 == addUnallocFsBlockFilesParent(dbFsInfo.objId, m_curUnallocDirId, m_curImgId) == TSK_ERR) {
        tsk_error_set_errstr2("addFsInfoUnalloc: error creating dir for unallocated space");
        registerError();
        return TSK_ERR;
    }

    //walk unalloc blocks on the fs and process them
    //initialize the unalloc block walk tracking 
    UNALLOC_BLOCK_WLK_TRACK unallocBlockWlkTrack(*this, *fsInfo, dbFsInfo.objId, m_minChunkSize, m_maxChunkSize);
    uint8_t block_walk_ret = tsk_fs_block_walk(fsInfo, fsInfo->first_block, fsInfo->last_block, (TSK_FS_BLOCK_WALK_FLAG_ENUM)(TSK_FS_BLOCK_WALK_FLAG_UNALLOC | TSK_FS_BLOCK_WALK_FLAG_AONLY), 
        fsWalkUnallocBlocksCb, &unallocBlockWlkTrack);

    if (block_walk_ret == 1) {
        stringstream errss;
        tsk_fs_close(fsInfo);
        errss << "TskAutoDbJava::addFsInfoUnalloc: error walking fs unalloc blocks, fs id: ";
        errss << unallocBlockWlkTrack.fsObjId;
        tsk_error_set_errstr2("%s", errss.str().c_str());
        registerError();
        return TSK_ERR;
    }

    if(m_stopAllProcessing) {
        tsk_fs_close(fsInfo);
        return TSK_OK;
    }

    // handle creation of the last range
    // make range inclusive from curBlockStart to prevBlock
    const uint64_t byteStart = unallocBlockWlkTrack.curRangeStart * fsInfo->block_size + fsInfo->offset;
    const uint64_t byteLen = (1 + unallocBlockWlkTrack.prevBlock - unallocBlockWlkTrack.curRangeStart) * fsInfo->block_size;
    unallocBlockWlkTrack.ranges.push_back(TSK_DB_FILE_LAYOUT_RANGE(byteStart, byteLen, unallocBlockWlkTrack.nextSequenceNo++));
    int64_t fileObjId = 0;

    if (-1 == addUnallocBlockFile(m_curUnallocDirId, dbFsInfo.objId, unallocBlockWlkTrack.size, unallocBlockWlkTrack.ranges, fileObjId, m_curImgId) == TSK_ERR) {
        registerError();
        tsk_fs_close(fsInfo);
        return TSK_ERR;
    }
    
    //cleanup 
    tsk_fs_close(fsInfo);

    return TSK_OK; 
}

/**
* Process all unallocated space for this disk image and create "virtual" files with layouts
* @returns TSK_OK on success, TSK_ERR on error
*/
TSK_RETVAL_ENUM TskAutoDbJava::addUnallocSpaceToDb() {
    if (m_stopAllProcessing) {
        return TSK_OK;
    }

    size_t numVsP = 0;
    size_t numFs = 0;

    TSK_RETVAL_ENUM retFsSpace = addUnallocFsSpaceToDb(numFs);
    TSK_RETVAL_ENUM retVsSpace = addUnallocVsSpaceToDb(numVsP);

    //handle case when no fs and no vs partitions
    TSK_RETVAL_ENUM retImgFile = TSK_OK;
    if (numVsP == 0 && numFs == 0) {
        retImgFile = addUnallocImageSpaceToDb();
    }
    
    
    if (retFsSpace == TSK_ERR || retVsSpace == TSK_ERR || retImgFile == TSK_ERR)
        return TSK_ERR;
    else
        return TSK_OK;
}


/**
* Process each file system in the database and add its unallocated sectors to virtual files. 
* @param numFs (out) number of filesystems found
* @returns TSK_OK on success, TSK_ERR on error (if some or all fs could not be processed)
*/
TSK_RETVAL_ENUM TskAutoDbJava::addUnallocFsSpaceToDb(size_t & numFs) {

    vector<TSK_DB_FS_INFO> fsInfos;

    if(m_stopAllProcessing) {
        return TSK_OK;
    }


    printf("SKIPPING addUnallocFsSpaceToDb!!!!\n"); // TODO TODO
/*
    uint16_t ret = m_db->getFsInfos(m_curImgId, fsInfos);
    if (ret) {
        tsk_error_set_errstr2("addUnallocFsSpaceToDb: error getting fs infos from db");
        registerError();
        return TSK_ERR;
    }

    numFs = fsInfos.size();

    TSK_RETVAL_ENUM allFsProcessRet = TSK_OK;
    for (vector<TSK_DB_FS_INFO>::iterator it = fsInfos.begin(); it!= fsInfos.end(); ++it) {
        if (m_stopAllProcessing) {
            break;
        }
        if (addFsInfoUnalloc(*it) == TSK_ERR)
            allFsProcessRet = TSK_ERR;
    }

    //TODO set parent_path for newly created virt dir/file hierarchy for consistency

    return allFsProcessRet;*/
    return TSK_OK;
}

/**
* Process each volume in the database and add its unallocated sectors to virtual files. 
* @param numVsP (out) number of vs partitions found
* @returns TSK_OK on success, TSK_ERR on error
*/
TSK_RETVAL_ENUM TskAutoDbJava::addUnallocVsSpaceToDb(size_t & numVsP) {

    vector<TSK_DB_VS_PART_INFO> vsPartInfos;


    printf("SKIPPING addUnallocVsSpaceToDb!!!!\n"); // TODO TODO
    /*
    TSK_RETVAL_ENUM retVsPartInfos = m_db->getVsPartInfos(m_curImgId, vsPartInfos);
    if (retVsPartInfos == TSK_ERR) {
        tsk_error_set_errstr2("addUnallocVsSpaceToDb: error getting vs part infos from db");
        registerError();
        return TSK_ERR;
    }
    numVsP = vsPartInfos.size();

    //get fs infos to see if this vspart has fs
    vector<TSK_DB_FS_INFO> fsInfos;
    uint16_t retFsInfos = m_db->getFsInfos(m_curImgId, fsInfos);
    if (retFsInfos) {
        tsk_error_set_errstr2("addUnallocVsSpaceToDb: error getting fs infos from db");
        registerError();
        return TSK_ERR;
    }

    for (vector<TSK_DB_VS_PART_INFO>::const_iterator it = vsPartInfos.begin();
            it != vsPartInfos.end(); ++it) {
        if (m_stopAllProcessing) {
            break;
        }
        const TSK_DB_VS_PART_INFO &vsPart = *it;

        //interested in unalloc, meta, or alloc and no fs
        if ( (vsPart.flags & (TSK_VS_PART_FLAG_UNALLOC | TSK_VS_PART_FLAG_META)) == 0 ) {
            //check if vspart has no fs
            bool hasFs = false;
            for (vector<TSK_DB_FS_INFO>::const_iterator itFs = fsInfos.begin();
               itFs != fsInfos.end(); ++itFs) {
               const TSK_DB_FS_INFO & fsInfo = *itFs;

               TSK_DB_OBJECT fsObjInfo;
               if (m_db->getObjectInfo(fsInfo.objId, fsObjInfo) == TSK_ERR ) {
                   stringstream errss;
                   errss << "addUnallocVsSpaceToDb: error getting object info for fs from db, objId: " << fsInfo.objId;
                   tsk_error_set_errstr2("%s", errss.str().c_str());
                   registerError();
                   return TSK_ERR;
               }

               if (fsObjInfo.parObjId == vsPart.objId) {
                   hasFs = true;
                   break;
               }
            }
        
            if (hasFs == true) {
                //skip processing this vspart
                continue;
            }
        } //end checking vspart flags

        //get sector size and image offset from parent vs info

        //get parent id of this vs part
        TSK_DB_OBJECT vsPartObj;     
        if (m_db->getObjectInfo(vsPart.objId, vsPartObj) == TSK_ERR) {
            stringstream errss;
            errss << "addUnallocVsSpaceToDb: error getting object info for vs part from db, objId: " << vsPart.objId;
            tsk_error_set_errstr2("%s", errss.str().c_str());
            registerError();
            return TSK_ERR;
        }

        TSK_DB_VS_INFO vsInfo;
        if (m_db->getVsInfo(vsPartObj.parObjId, vsInfo) ) {
            stringstream errss;
            errss << "addUnallocVsSpaceToDb: error getting volume system info from db, objId: " << vsPartObj.parObjId;
            tsk_error_set_errstr2("%s", errss.str().c_str());
            registerError();
            return TSK_ERR;
        }

        //create an unalloc file with unalloc part, with vs part as parent
        vector<TSK_DB_FILE_LAYOUT_RANGE> ranges;
        const uint64_t byteStart = vsInfo.offset + vsInfo.block_size * vsPart.start;
        const uint64_t byteLen = vsInfo.block_size * vsPart.len; 
        TSK_DB_FILE_LAYOUT_RANGE tempRange(byteStart, byteLen, 0);
        ranges.push_back(tempRange);
        int64_t fileObjId = 0;
        if (m_db->addUnallocBlockFile(vsPart.objId, 0, tempRange.byteLen, ranges, fileObjId, m_curImgId) == TSK_ERR) {
            registerError();
            return TSK_ERR;
        }
    }*/

    return TSK_OK;
}


/**
* Adds unalloc space for the image if there is no volumes and no file systems.
*
* @returns TSK_OK on success, TSK_ERR on error
*/
TSK_RETVAL_ENUM TskAutoDbJava::addUnallocImageSpaceToDb() {

    const TSK_OFF_T imgSize = getImageSize();
    if (imgSize == -1) {
        tsk_error_set_errstr("addUnallocImageSpaceToDb: error getting current image size, can't create unalloc block file for the image.");
        registerError();
        return TSK_ERR;
    }
    else {
        TSK_DB_FILE_LAYOUT_RANGE tempRange(0, imgSize, 0);
        //add unalloc block file for the entire image
        vector<TSK_DB_FILE_LAYOUT_RANGE> ranges;
        ranges.push_back(tempRange);
        int64_t fileObjId = 0;
        if (-1 == addUnallocBlockFile(m_curImgId, 0, imgSize, ranges, fileObjId, m_curImgId)) {
            return TSK_ERR;
        }
    }
    return TSK_OK;
}

/**
* Returns the directory currently being analyzed by processFile().
* Safe to use from another thread than processFile().
*
* @returns curDirPath string representing currently analyzed directory
*/
const std::string TskAutoDbJava::getCurDir() {
    string curDirPath;
    tsk_take_lock(&m_curDirPathLock);
    curDirPath = m_curDirPath;
    tsk_release_lock(&m_curDirPathLock);
    return curDirPath;
}
