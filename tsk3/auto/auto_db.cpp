/*
 ** The Sleuth Kit
 **
 ** Brian Carrier [carrier <at> sleuthkit [dot] org]
 ** Copyright (c) 2010-2011 Brian Carrier.  All Rights reserved
 **
 ** This software is distributed under the Common Public License 1.0
 **
 */

/**
 * \file auto_db.cpp
 * Contains code to populate SQLite database with volume and file system information from a specific image.
 */

#include "tsk_case_db.h"
#include <string.h>


/**
 * @param a_db Database to add an image to
 * @param a_NSRLDb Database of "known" files (can be NULL)
 * @param a_knownBadDb Database of "known bad" files (can be NULL)
 */
TskAutoDb::TskAutoDb(TskDbSqlite * a_db, TSK_HDB_INFO * a_NSRLDb, TSK_HDB_INFO * a_knownBadDb)
{
    m_db = a_db;
    m_curFsId = 0;
    m_curVsId = 0;
    m_blkMapFlag = false;
    m_fileHashFlag = false;
    m_vsFound = false;
    m_volFound = false;
    m_stopped = false;
    m_imgTransactionOpen = false;
    m_NSRLDb = a_NSRLDb;
    m_knownBadDb = a_knownBadDb;
    m_noFatFsOrphans = false;
}

TskAutoDb::~TskAutoDb()
{
    // if they didn't commit / revert, then revert
    if (m_imgTransactionOpen)
        revertAddImage();

    closeImage();
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

/**
* Skip processing of orphans on FAT filesystems.  
* This will make the loading of the database much faster
* but you will not have all deleted files.
* @param noFatFsOrphans flag set to true if to skip processing orphans on FAT fs
*/
void TskAutoDb::setNoFatFsOrphans(bool noFatFsOrphans)
{
    m_noFatFsOrphans = noFatFsOrphans;
}

/**
 * Open the image to be analyzed.  Use the startAddImage() method if you want
 * savepoints and the ability to rollback. Uses the
 * utf8 functions even in windows.
 * @param a_num Number of images
 * @param a_images Images to open
 * @param a_type Image file format
 * @param a_ssize Sector size in bytes
 * @return Resturns 1 on error
 */
uint8_t
    TskAutoDb::openImageUtf8(int a_num, const char *const a_images[],
    TSK_IMG_TYPE_ENUM a_type, unsigned int a_ssize)
{
    uint8_t retval =
        TskAuto::openImageUtf8(a_num, a_images, a_type, a_ssize);
    if (retval != 0) {
        return retval;
    }

    if (addImageDetails(a_images, a_num)) {
        return 1;
    }
    return 0;
}

/**
 * Open the image to be analyzed. Use the startAddImage() method if you want 
 * savepoints and the ability to rollback.
 * @param a_num Number of images
 * @param a_images Images to open
 * @param a_type Image file format
 * @param a_ssize Sector size in bytes
 * @return Resturns 1 on error
 */
uint8_t
    TskAutoDb::openImage(int a_num, const TSK_TCHAR * const a_images[],
    TSK_IMG_TYPE_ENUM a_type, unsigned int a_ssize)
{

// make name of database
#ifdef TSK_WIN32

    uint8_t retval = TskAuto::openImage(a_num, a_images, a_type, a_ssize);

    if (retval != 0) {
        return retval;
    }


    // convert image paths to UTF-8
    char **img_ptrs = (char **) tsk_malloc(sizeof(char **));

    for (int i = 0; i < a_num; i++) {
        char img2[1024];
        UTF8 *ptr8;
        UTF16 *ptr16;

        ptr8 = (UTF8 *) img2;
        ptr16 = (UTF16 *) a_images[i];

        retval =
            tsk_UTF16toUTF8_lclorder((const UTF16 **) &ptr16, (UTF16 *)
            & ptr16[TSTRLEN(a_images[i]) + 1], &ptr8,
            (UTF8 *) ((uintptr_t) ptr8 + 1024), TSKlenientConversion);
        if (retval != TSKconversionOK) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_AUTO_UNICODE);
            tsk_error_set_errstr("Error converting image to UTF-8\n");
            return 1;
        }
        img_ptrs[i] = img2;
    }

    if (addImageDetails(img_ptrs, a_num)) {
        return 1;
    }

    return 0;
#else
    return openImageUtf8(a_num, a_images, a_type, a_ssize);
#endif
}

/**
 * Adds image details to the existing database tables.
 * @param img_ptrs The paths to the image splits
 * @return Returns 1 on error
 */

uint8_t
TskAutoDb::addImageDetails(const char *const img_ptrs[], int a_num)
{
    if (m_db->addImageInfo(m_img_info->itype, m_img_info->sector_size,
            m_curImgId)) {
        return 1;
    }

    // Add the image names
    for (int i = 0; i < a_num; i++) {
        const char *img_ptr = NULL;
        img_ptr = img_ptrs[i];

        //// get only the file name (ignore the directory name)
        //for (a = strlen(img_ptr) - 1; a > 0; a--) {
        //    if ((img_ptr[a] == '/') || (img_ptr[a] == '\\')) {
        //        a++;
        //        break;
        //    }
        //}

        if (m_db->addImageName(m_curImgId, img_ptr, i)) {
            return 1;
        }
    }

    return 0;
}


/**
 * Analyzes the open image and adds image info to a database.
 * @returns 1 if an error occured (error will have been registered)
 */
uint8_t TskAutoDb::addFilesInImgToDb()
{
    if (m_db == NULL || !m_db->dbExist()) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr("addFilesInImgToDb: m_db not open");
        registerError();
        return 1;
    }

    setVolFilterFlags((TSK_VS_PART_FLAG_ENUM) (TSK_VS_PART_FLAG_ALLOC |
            TSK_VS_PART_FLAG_UNALLOC));

    uint8_t
        retval = findFilesInImg();
    if (retval)
        return retval;

    return 0;
}

TSK_FILTER_ENUM TskAutoDb::filterVs(const TSK_VS_INFO * vs_info)
{
    m_vsFound = true;
    if (m_db->addVsInfo(vs_info, m_curImgId, m_curVsId)) {
        return TSK_FILTER_STOP;
    }

    return TSK_FILTER_CONT;
}

TSK_FILTER_ENUM
TskAutoDb::filterVol(const TSK_VS_PART_INFO * vs_part)
{
    m_volFound = true;

    if (m_db->addVolumeInfo(vs_part, m_curVsId, m_curVolId)) {
        return TSK_FILTER_STOP;
    }

    return TSK_FILTER_CONT;
}


TSK_FILTER_ENUM
TskAutoDb::filterFs(TSK_FS_INFO * fs_info)
{
    TSK_FS_FILE *file_root;

    if (m_volFound && m_vsFound) {
        // there's a volume system and volume
        if (m_db->addFsInfo(fs_info, m_curVolId, m_curFsId)) {
            return TSK_FILTER_STOP;
        }
    }
    else {
        // file system doesn't live in a volume, use image as parent
        if (m_db->addFsInfo(fs_info, m_curImgId, m_curFsId)) {
            return TSK_FILTER_STOP;
        }
    }


    // We won't hit the root directory on the walk, so open it now 
    if ((file_root = tsk_fs_file_open(fs_info, NULL, "/")) != NULL) {
        processAttributes(file_root, "");
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
    const TSK_AUTO_CASE_KNOWN_FILE_ENUM known)
{
    if (m_db->addFsFile(fs_file, fs_attr, path, md5, known, m_curFsId,
            m_curFileId)) {
        return TSK_ERR;
    }

    return TSK_OK;
}


/**
 * Start the process to add image/file metadata to database. Reverts
 * all changes on error. When runProcess()
 * returns, user must call either commitAddImage() to commit the changes,
 * or revertAddImage() to revert them.
 * @returns 1 if any error occured (messages will be registered in list) and 0 on success
 */
uint8_t
    TskAutoDb::startAddImage(int numImg, const TSK_TCHAR * const imagePaths[],
    TSK_IMG_TYPE_ENUM imgType, unsigned int sSize)
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
        tsk_error_set_errstr("TskAutoDb::startAddImage(): Already in a transaction, image might not be commited");
        registerError();
        return 1;
    }

    if (m_db->createSavepoint(TSK_ADD_IMAGE_SAVEPOINT)) {
        registerError();
        return 1;
    }

    m_imgTransactionOpen = true;

    if (openImage(numImg, imagePaths, imgType, sSize)) {
        tsk_error_set_errstr2("TskAutoDb::startAddImage");
        registerError();
        if (revertAddImage())
            registerError();
        return 1;
    }
    
    if (addFilesInImgToDb()) {
        if (revertAddImage())
            registerError();
        return 1;
    }
    return 0;
}

#ifdef WIN32
uint8_t
    TskAutoDb::startAddImage(int numImg, const char *const imagePaths[],
    TSK_IMG_TYPE_ENUM imgType, unsigned int sSize)
{
    if (tsk_verbose)
        tsk_fprintf(stderr, "TskAutoDb::startAddImage: Starting add image process\n");
   

    if (m_db->releaseSavepoint(TSK_ADD_IMAGE_SAVEPOINT) == 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr("TskAutoDb::startAddImage(): An add-image savepoint already exists");
        return 1;
    }

    // @@@ This check is a bit paranoid, and may need to be removed in the future
    if (m_db->inTransaction()) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr("TskAutoDb::startAddImage(): Already in a transaction, image might not be commited");
        return 1;
    }


    if (m_db->createSavepoint(TSK_ADD_IMAGE_SAVEPOINT))
        return 1;

    m_imgTransactionOpen = true;

    if (openImageUtf8(numImg, imagePaths, imgType, sSize)
        || addFilesInImgToDb()) {
        // rollback on error

        // rollbackSavepoint can throw errors too, need to make sure original
        // error message is preserved;
        const char *prior_msg = tsk_error_get();
        if (revertAddImage()) {
            if (prior_msg) {
                tsk_error_set_errstr("%s caused: %s", prior_msg,
                    tsk_error_get());
            }
        }
        return 1;
    }
    return 0;
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
 * Revert all changes after the process has run sucessfully.
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
 * Finish the process after it has run sucessfully by committing the changes.
 * @returns Id of the image that was added or -1 on error (error was NOT registered in list)
 */
int64_t
TskAutoDb::commitAddImage()
{
    if (tsk_verbose)
        tsk_fprintf(stderr, "TskAutoDb::commitAddImage: Commiting add image process\n");

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

TSK_RETVAL_ENUM
TskAutoDb::processFile(TSK_FS_FILE * fs_file, const char *path)
{

    // Check if the process has been canceled
    if (m_stopped) {
        if (tsk_verbose)
            tsk_fprintf(stderr, "TskAutoDb::processFile: Stop request detected\n");
        return TSK_STOP;
    }

    /* process the attributes.  The case of having 0 attributes can occur
     * with virtual / sparse files.  At some point, this can probably be cleaned
     * up if TSK is more consistent about if there should always be an attribute or not */
    TSK_RETVAL_ENUM retval;
    if (tsk_fs_file_attr_getsize(fs_file) == 0)
        retval = insertFileData(fs_file, NULL, path, NULL, TSK_AUTO_CASE_FILE_KNOWN_UNKNOWN);
    else
        retval = processAttributes(fs_file, path);

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

        TSK_AUTO_CASE_KNOWN_FILE_ENUM file_known = TSK_AUTO_CASE_FILE_KNOWN_UNKNOWN;

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
                } else if (retval) {
                    file_known = TSK_AUTO_CASE_FILE_KNOWN_KNOWN;
                }
            }

            if (m_knownBadDb != NULL) {
                int8_t retval = tsk_hdb_lookup_raw(m_knownBadDb, hash, 16, TSK_HDB_FLAG_QUICK, NULL, NULL);
                if (retval == -1) {
                    registerError();
                    return TSK_OK;
                } else if (retval) {
                    file_known = TSK_AUTO_CASE_FILE_KNOWN_BAD;
                }
            }
        }

        if (insertFileData(fs_attr->fs_file, fs_attr, path, md5, file_known) == TSK_ERR) {
            registerError();
            return TSK_OK;
        }
    }

    // add the block map, if requested and the file is non-resident
    if ((m_blkMapFlag) && (isNonResident(fs_attr))
        && (isDotDir(fs_file, path) == 0)) {
        TSK_FS_ATTR_RUN *run;
        int sequence = 0;

        for (run = fs_attr->nrd.run; run != NULL; run = run->next) {
            unsigned int block_size = fs_file->fs_info->block_size;

            // ignore sparse blocks
            if (run->flags & TSK_FS_ATTR_RUN_FLAG_SPARSE)
                continue;

            // @@@ We probaly want ot keep on going here
            if (m_db->addFsBlockInfo(m_curFsId, m_curFileId,
                    run->addr * block_size, run->len * block_size, sequence++)) {
                registerError();
                return TSK_OK;
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
