/*
 ** The Sleuth Kit
 **
 ** Brian Carrier [carrier <at> sleuthkit [dot] org]
 ** Copyright (c) 2010-2013 Brian Carrier.  All Rights reserved
 **
 ** This software is distributed under the Common Public License 1.0
 **
 */

/**
 * \file auto_db.cpp
 * Contains code to populate SQLite database with volume and file system information from a specific image.
 */

#include "tsk_case_db.h"
#include "tsk/img/img_writer.h"
#if HAVE_LIBEWF
#include "tsk/img/ewf.h"
#endif
#include <string.h>

#include <algorithm>
#include <sstream>

using std::stringstream;
using std::for_each;

/**
 * @param a_db Database to add an image to
 * @param a_NSRLDb Database of "known" files (can be NULL)
 * @param a_knownBadDb Database of "known bad" files (can be NULL)
 */
TskAutoDb::TskAutoDb(TskDb * a_db, TSK_HDB_INFO * a_NSRLDb, TSK_HDB_INFO * a_knownBadDb)
{
    m_db = a_db;
    m_curImgId = 0;
    m_curVsId = 0;
    m_curVolId = 0;
    m_curFsId = 0;
    m_curFileId = 0;
    m_curUnallocDirId = 0;
    m_curDirId = 0;
    m_curDirPath = "";
    m_blkMapFlag = false;
    m_vsFound = false;
    m_volFound = false;
    m_stopped = false;
    m_foundStructure = false;
    m_imgTransactionOpen = false;
    m_attributeAdded = false;
    m_NSRLDb = a_NSRLDb;
    m_knownBadDb = a_knownBadDb;
    if ((m_NSRLDb) || (m_knownBadDb)) {
        m_fileHashFlag = true;
    }
    else {
        m_fileHashFlag = false;
    }
    m_addFileSystems = true;
    m_noFatFsOrphans = false;
    m_addUnallocSpace = false;
    m_minChunkSize = -1;
    m_maxChunkSize = -1;
    tsk_init_lock(&m_curDirPathLock);
}

TskAutoDb::~TskAutoDb()
{
    // if they didn't commit / revert, then revert
    if (m_imgTransactionOpen) {
        revertAddImage();
    }

    closeImage();
    tsk_deinit_lock(&m_curDirPathLock);
}

void
 TskAutoDb::closeImage()
{
    TskAuto::closeImage();
    m_NSRLDb = NULL;
    m_knownBadDb = NULL;
}


void
 TskAutoDb::createBlockMap(bool flag)
{
    m_blkMapFlag = flag;
}

void
 TskAutoDb::hashFiles(bool flag)
{
    m_fileHashFlag = flag;
}

void TskAutoDb::setAddFileSystems(bool addFileSystems)
{
    m_addFileSystems = addFileSystems;
}

void TskAutoDb::setNoFatFsOrphans(bool noFatFsOrphans)
{
    m_noFatFsOrphans = noFatFsOrphans;
}

void TskAutoDb::setAddUnallocSpace(bool addUnallocSpace)
{
    setAddUnallocSpace(addUnallocSpace, -1);
}

void TskAutoDb::setAddUnallocSpace(bool addUnallocSpace, int64_t minChunkSize)
{
    m_addUnallocSpace = addUnallocSpace;
    m_minChunkSize = minChunkSize;
    m_maxChunkSize = -1;
}

void TskAutoDb::setAddUnallocSpace(int64_t minChunkSize, int64_t maxChunkSize)
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
    TskAutoDb::openImageUtf8(int a_num, const char *const a_images[],
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
    TskAutoDb::openImage(int a_num, const TSK_TCHAR * const a_images[],
    TSK_IMG_TYPE_ENUM a_type, unsigned int a_ssize, const char* a_deviceId)
{

// make name of database
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
TskAutoDb::openImage(const char* a_deviceId)
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
TskAutoDb::addImageDetails(const char* deviceId)
{
   string md5 = "";
#if HAVE_LIBEWF 
   if (m_img_info->itype == TSK_IMG_TYPE_EWF_EWF) {
     // @@@ This should really probably be inside of a tsk_img_ method
       IMG_EWF_INFO *ewf_info = (IMG_EWF_INFO *)m_img_info;
       if (ewf_info->md5hash_isset) {
           md5 = ewf_info->md5hash;
       }
   }
#endif

    string devId;
    if (NULL != deviceId) {
        devId = deviceId; 
    } else {
        devId = "";
    }
    if (m_db->addImageInfo(m_img_info->itype, m_img_info->sector_size,
          m_curImgId, m_curImgTZone, m_img_info->size, md5, devId)) {
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

        if (m_db->addImageName(m_curImgId, img_ptr, i)) {
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

    return 0;
}


TSK_FILTER_ENUM TskAutoDb::filterVs(const TSK_VS_INFO * vs_info)
{
    m_vsFound = true;
    if (m_db->addVsInfo(vs_info, m_curImgId, m_curVsId)) {
        registerError();
        return TSK_FILTER_STOP;
    }

    return TSK_FILTER_CONT;
}

TSK_FILTER_ENUM
TskAutoDb::filterVol(const TSK_VS_PART_INFO * vs_part)
{
    m_volFound = true;
    m_foundStructure = true;

    if (m_db->addVolumeInfo(vs_part, m_curVsId, m_curVolId)) {
        registerError();
        return TSK_FILTER_STOP;
    }

    return TSK_FILTER_CONT;
}


TSK_FILTER_ENUM
TskAutoDb::filterFs(TSK_FS_INFO * fs_info)
{
    TSK_FS_FILE *file_root;
    m_foundStructure = true;

    if (m_volFound && m_vsFound) {
        // there's a volume system and volume
        if (m_db->addFsInfo(fs_info, m_curVolId, m_curFsId)) {
            registerError();
            return TSK_FILTER_STOP;
        }
    }
    else {
        // file system doesn't live in a volume, use image as parent
        if (m_db->addFsInfo(fs_info, m_curImgId, m_curFsId)) {
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
    TskAutoDb::insertFileData(TSK_FS_FILE * fs_file,
    const TSK_FS_ATTR * fs_attr, const char *path,
    const unsigned char *const md5,
    const TSK_DB_FILES_KNOWN_ENUM known)
{

    if (m_db->addFsFile(fs_file, fs_attr, path, md5, known, m_curFsId, m_curFileId,
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
uint8_t TskAutoDb::addFilesInImgToDb()
{
    if (m_db == NULL || m_db->isDbOpen() == false) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr("addFilesInImgToDb: m_db not open");
        registerError();
        return 1;
    }

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
    TskAutoDb::startAddImage(int numImg, const TSK_TCHAR * const imagePaths[],
    TSK_IMG_TYPE_ENUM imgType, unsigned int sSize, const char* deviceId)
{
    if (tsk_verbose)
        tsk_fprintf(stderr, "TskAutoDb::startAddImage: Starting add image process\n");

    if (m_db->releaseSavepoint(TSK_ADD_IMAGE_SAVEPOINT) == 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr("TskAutoDb::startAddImage(): An add-image savepoint already exists");
        registerError();
        return 1;
    }

    // @@@ This check is a bit paranoid, and may need to be removed in the future
    if (m_db->inTransaction()) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr("TskAutoDb::startAddImage(): Already in a transaction, image might not be committed");
        registerError();
        return 1;
    }

    if (m_db->createSavepoint(TSK_ADD_IMAGE_SAVEPOINT)) {
        registerError();
        return 1;
    }

    m_imgTransactionOpen = true;
    if (openImage(numImg, imagePaths, imgType, sSize, deviceId)) {
        tsk_error_set_errstr2("TskAutoDb::startAddImage");
        registerError();
        if (revertAddImage())
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
TskAutoDb::startAddImage(TSK_IMG_INFO * img_info, const char* deviceId)
{
    openImageHandle(img_info);

    if (m_img_info == NULL) {
        return 1;
    }

    if (tsk_verbose)
        tsk_fprintf(stderr, "TskAutoDb::startAddImage: Starting add image process\n");

    if (m_db->releaseSavepoint(TSK_ADD_IMAGE_SAVEPOINT) == 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr("TskAutoDb::startAddImage(): An add-image savepoint already exists");
        registerError();
        return 1;
    }

    // @@@ This check is a bit paranoid, and may need to be removed in the future
    if (m_db->inTransaction()) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr("TskAutoDb::startAddImage(): Already in a transaction, image might not be committed");
        registerError();
        return 1;
    }

    if (m_db->createSavepoint(TSK_ADD_IMAGE_SAVEPOINT)) {
        registerError();
        return 1;
    }

    m_imgTransactionOpen = true;
    if (openImage(deviceId)) {
        tsk_error_set_errstr2("TskAutoDb::startAddImage");
        registerError();
        if (revertAddImage())
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
    TskAutoDb::startAddImage(int numImg, const char *const imagePaths[],
    TSK_IMG_TYPE_ENUM imgType, unsigned int sSize, const char* deviceId)
{
    if (tsk_verbose) 
        tsk_fprintf(stderr, "TskAutoDb::startAddImage_utf8: Starting add image process\n");
   

    if (m_db->releaseSavepoint(TSK_ADD_IMAGE_SAVEPOINT) == 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr("TskAutoDb::startAddImage(): An add-image savepoint already exists");
        registerError();
        return 1;
    }

    // @@@ This check is a bit paranoid, and may need to be removed in the future
    if (m_db->inTransaction()) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr("TskAutoDb::startAddImage(): Already in a transaction, image might not be committed");
        registerError();
        return 1;
    }


    if (m_db->createSavepoint(TSK_ADD_IMAGE_SAVEPOINT)) {
        registerError();
        return 1;
    }

    m_imgTransactionOpen = true;

    if (openImageUtf8(numImg, imagePaths, imgType, sSize, deviceId)) {
        tsk_error_set_errstr2("TskAutoDb::startAddImage");
        registerError();
        if (revertAddImage())
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
 TskAutoDb::stopAddImage()
{
    if (tsk_verbose)
        tsk_fprintf(stderr, "TskAutoDb::stopAddImage: Stop request received\n");
    
    m_stopped = true;
    setStopProcessing();
    // flag is checked every time processFile() is called
}

/**
 * Revert all changes after the startAddImage() process has run successfully.
 * @returns 1 on error (error was NOT registered in list), 0 on success
 */
int
 TskAutoDb::revertAddImage()
{
    if (tsk_verbose)
        tsk_fprintf(stderr, "TskAutoDb::revertAddImage: Reverting add image process\n");

    if (m_imgTransactionOpen == false) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr("revertAddImage(): transaction is already closed");
        return 1;
    }

    int retval = m_db->revertSavepoint(TSK_ADD_IMAGE_SAVEPOINT);
    if (retval == 0) {
        if (m_db->inTransaction()) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_AUTO_DB);
            tsk_error_set_errstr("TskAutoDb::revertAddImage(): Image reverted, but still in a transaction.");
            retval = 1;
        }
    }
    m_imgTransactionOpen = false;
    return retval;
}

/**
 * Finish the transaction after the startAddImage is finished.  
 * @returns Id of the image that was added or -1 on error (error was NOT registered in list)
 */
int64_t
TskAutoDb::commitAddImage()
{
    if (tsk_verbose)
        tsk_fprintf(stderr, "TskAutoDb::commitAddImage: Committing add image process\n");

    if (m_imgTransactionOpen == false) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr("commitAddImage(): transaction is already closed");
        return -1;
    }

    int retval = m_db->releaseSavepoint(TSK_ADD_IMAGE_SAVEPOINT);
    m_imgTransactionOpen = false;
    if (retval == 1) {
        return -1;
    } else {
        if (m_db->inTransaction()) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_AUTO_DB);
            tsk_error_set_errstr("TskAutoDb::revertAddImage(): Image savepoint released, but still in a transaction.");
            return -1;
        }
    }

    return m_curImgId;
}

/**
 * Set the current image's timezone
 */
void
TskAutoDb::setTz(string tzone)
{
    m_curImgTZone = tzone;
}

TSK_RETVAL_ENUM
TskAutoDb::processFile(TSK_FS_FILE * fs_file, const char *path)
{
    
    // Check if the process has been canceled
     if (m_stopped) {
        if (tsk_verbose)
            tsk_fprintf(stderr, "TskAutoDb::processFile: Stop request detected\n");
        return TSK_STOP;
    }

    /* Update the current directory, which can be used to show
     * progress.  If we get a directory, then use its name.  We
     * do this so that when we are searching for orphan files, then
     * we at least show $OrphanFiles as status.  The secondary check
     * is to grab the parent folder from files once we return back 
     * into a folder when we are doing our depth-first recursion. */
    if (isDir(fs_file)) {
        m_curDirId = fs_file->name->meta_addr;
        tsk_take_lock(&m_curDirPathLock);
        m_curDirPath = string(path) + fs_file->name->name;
        tsk_release_lock(&m_curDirPathLock);
    }
    else if (m_curDirId != fs_file->name->par_addr) {
        m_curDirId = fs_file->name->par_addr;
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
        retval = insertFileData(fs_file, NULL, path, NULL, TSK_DB_FILES_KNOWN_UNKNOWN);
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
TskAutoDb::processAttribute(TSK_FS_FILE * fs_file,
    const TSK_FS_ATTR * fs_attr, const char *path)
{
    // add the file metadata for the default attribute type
    if (isDefaultType(fs_file, fs_attr)) {

        // calculate the MD5 hash if the attribute is a file
        unsigned char hash[16];
        unsigned char *md5 = NULL;
        memset(hash, 0, 16);

        TSK_DB_FILES_KNOWN_ENUM file_known = TSK_DB_FILES_KNOWN_UNKNOWN;

        if (m_fileHashFlag && isFile(fs_file)) {
            if (md5HashAttr(hash, fs_attr)) {
                // error was registered
                return TSK_OK;
            }
            md5 = hash;

            if (m_NSRLDb != NULL) {
                int8_t retval = tsk_hdb_lookup_raw(m_NSRLDb, hash, 16, TSK_HDB_FLAG_QUICK, NULL, NULL);
                if (retval == -1) {
                    registerError();
                    return TSK_OK;
                } 
                else if (retval) {
                    file_known = TSK_DB_FILES_KNOWN_KNOWN;
                }
            }

            if (m_knownBadDb != NULL) {
                int8_t retval = tsk_hdb_lookup_raw(m_knownBadDb, hash, 16, TSK_HDB_FLAG_QUICK, NULL, NULL);
                if (retval == -1) {
                    registerError();
                    return TSK_OK;
                } 
                else if (retval) {
                    file_known = TSK_DB_FILES_KNOWN_KNOWN_BAD;
                }
            }
        }

        if (insertFileData(fs_attr->fs_file, fs_attr, path, md5, file_known) == TSK_ERR) {
            registerError();
            return TSK_OK;
        }
        else {
            m_attributeAdded = true;
        }

        // add the block map, if requested and the file is non-resident
        if ((m_blkMapFlag) && (isNonResident(fs_attr))
            && (isDotDir(fs_file) == 0)) {
            TSK_FS_ATTR_RUN *run;
            int sequence = 0;

            for (run = fs_attr->nrd.run; run != NULL; run = run->next) {
                unsigned int block_size = fs_file->fs_info->block_size;

                // ignore sparse blocks
                if (run->flags & TSK_FS_ATTR_RUN_FLAG_SPARSE)
                    continue;

                // @@@ We probably want to keep on going here
                if (m_db->addFileLayoutRange(m_curFileId,
                    run->addr * block_size, run->len * block_size, sequence++)) {
                    registerError();
                    return TSK_OK;
                }
            }
        }
    }

    return TSK_OK;
}


/**
 * Helper for md5HashAttr
 */
TSK_WALK_RET_ENUM
TskAutoDb::md5HashCallback(TSK_FS_FILE * file, TSK_OFF_T offset,
    TSK_DADDR_T addr, char *buf, size_t size,
    TSK_FS_BLOCK_FLAG_ENUM a_flags, void *ptr)
{
    TSK_MD5_CTX *md = (TSK_MD5_CTX *) ptr;
    if (md == NULL)
        return TSK_WALK_CONT;

    TSK_MD5_Update(md, (unsigned char *) buf, (unsigned int) size);

    return TSK_WALK_CONT;
}



/**
 * MD5 hash an attribute and put the result in the given array
 * @param md5Hash array to write the hash to
 * @param fs_attr attribute to hash the data of
 * @return Returns 1 on error (message has been registered)
 */
int
TskAutoDb::md5HashAttr(unsigned char md5Hash[16], const TSK_FS_ATTR * fs_attr)
{
    TSK_MD5_CTX md;

    TSK_MD5_Init(&md);

    if (tsk_fs_attr_walk(fs_attr, TSK_FS_FILE_WALK_FLAG_NONE,
            md5HashCallback, (void *) &md)) {
        registerError();
        return 1;
    }

    TSK_MD5_Final(md5Hash, &md);
    return 0;
}

/**
* Callback invoked per every unallocated block in the filesystem
* Creates file ranges and file entries 
* A single file entry per consecutive range of blocks
* @param a_block block being walked
* @param a_ptr a pointer to an UNALLOC_BLOCK_WLK_TRACK struct
* @returns TSK_WALK_CONT if continue, otherwise TSK_WALK_STOP if stop processing requested
*/
TSK_WALK_RET_ENUM TskAutoDb::fsWalkUnallocBlocksCb(const TSK_FS_BLOCK *a_block, void *a_ptr) {
    UNALLOC_BLOCK_WLK_TRACK * unallocBlockWlkTrack = (UNALLOC_BLOCK_WLK_TRACK *) a_ptr;

    if (unallocBlockWlkTrack->tskAutoDb.m_stopAllProcessing)
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
    if (unallocBlockWlkTrack->tskAutoDb.m_db->addUnallocBlockFile(unallocBlockWlkTrack->tskAutoDb.m_curUnallocDirId, 
        unallocBlockWlkTrack->fsObjId, unallocBlockWlkTrack->size, unallocBlockWlkTrack->ranges, fileObjId, unallocBlockWlkTrack->tskAutoDb.m_curImgId) == TSK_ERR) {
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
TSK_RETVAL_ENUM TskAutoDb::addFsInfoUnalloc(const TSK_DB_FS_INFO & dbFsInfo) {
    //open the fs we have from database
    TSK_FS_INFO * fsInfo = tsk_fs_open_img(m_img_info, dbFsInfo.imgOffset, dbFsInfo.fType);
    if (fsInfo == NULL) {
        tsk_error_set_errstr2("TskAutoDb::addFsInfoUnalloc: error opening fs at offset %" PRIuOFF, dbFsInfo.imgOffset);
        registerError();
        return TSK_ERR;
    }

    //create a "fake" dir to hold the unalloc files for the fs
    if (m_db->addUnallocFsBlockFilesParent(dbFsInfo.objId, m_curUnallocDirId, m_curImgId) == TSK_ERR) {
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
        errss << "TskAutoDb::addFsInfoUnalloc: error walking fs unalloc blocks, fs id: ";
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

    if (m_db->addUnallocBlockFile(m_curUnallocDirId, dbFsInfo.objId, unallocBlockWlkTrack.size, unallocBlockWlkTrack.ranges, fileObjId, m_curImgId) == TSK_ERR) {
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
TSK_RETVAL_ENUM TskAutoDb::addUnallocSpaceToDb() {
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
TSK_RETVAL_ENUM TskAutoDb::addUnallocFsSpaceToDb(size_t & numFs) {

    vector<TSK_DB_FS_INFO> fsInfos;

    if(m_stopAllProcessing) {
        return TSK_OK;
    }

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

    return allFsProcessRet;
}

/**
* Process each volume in the database and add its unallocated sectors to virtual files. 
* @param numVsP (out) number of vs partitions found
* @returns TSK_OK on success, TSK_ERR on error
*/
TSK_RETVAL_ENUM TskAutoDb::addUnallocVsSpaceToDb(size_t & numVsP) {

    vector<TSK_DB_VS_PART_INFO> vsPartInfos;

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
    }

    return TSK_OK;
}


/**
* Adds unalloc space for the image if there is no volumes and no file systems.
*
* @returns TSK_OK on success, TSK_ERR on error
*/
TSK_RETVAL_ENUM TskAutoDb::addUnallocImageSpaceToDb() {
    TSK_RETVAL_ENUM retImgFile = TSK_OK;

    const TSK_OFF_T imgSize = getImageSize();
    if (imgSize == -1) {
        tsk_error_set_errstr("addUnallocImageSpaceToDb: error getting current image size, can't create unalloc block file for the image.");
        registerError();
        retImgFile = TSK_ERR;
    }
    else {
        TSK_DB_FILE_LAYOUT_RANGE tempRange(0, imgSize, 0);
        //add unalloc block file for the entire image
        vector<TSK_DB_FILE_LAYOUT_RANGE> ranges;
        ranges.push_back(tempRange);
        int64_t fileObjId = 0;
        retImgFile = m_db->addUnallocBlockFile(m_curImgId, 0, imgSize, ranges, fileObjId, m_curImgId);
    }
    return retImgFile;
}

/**
* Returns the directory currently being analyzed by processFile().
* Safe to use from another thread than processFile().
*
* @returns curDirPath string representing currently analyzed directory
*/
const std::string TskAutoDb::getCurDir() {
    string curDirPath;
    tsk_take_lock(&m_curDirPathLock);
    curDirPath = m_curDirPath;
    tsk_release_lock(&m_curDirPathLock);
    return curDirPath;
}


bool TskAutoDb::isDbOpen() {
    if(m_db!=NULL) {
        return m_db->isDbOpen();
    }
    return false;
}
