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
 * Contains code to populate SQLite database with volume and file system information.
 */

#include "tsk_case_db.h"
#include <string.h>



TskAutoDb::TskAutoDb(TskDbSqlite * a_db)
{
    m_db = a_db;
    m_curFsId = 0;
    m_curVsId = 0;
    m_blkMapFlag = false;
    m_vsFound = false;
    m_volFound = false;
    m_stopped = false;
}

TskAutoDb::~TskAutoDb()
{
    closeImage();

    delete m_db;
    m_db = NULL;
}

void
 TskAutoDb::closeImage()
{
    TskAuto::closeImage();
}



void
 TskAutoDb::createBlockMap(bool flag)
{
    m_blkMapFlag = flag;
}

/**
 * Open the image to be analyzed.  Creates the database in the same
 * directory as the image (with .db appended to the name). Uses the
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
 * Open the image to be analyzed.
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
        int a;
        const char *img_ptr = NULL;
        img_ptr = img_ptrs[i];

        // get only the file name (ignore the directory name)
        for (a = strlen(img_ptr) - 1; a > 0; a--) {
            if ((img_ptr[a] == '/') || (img_ptr[a] == '\\')) {
                a++;
                break;
            }
        }

        if (m_db->addImageName(m_curImgId, &img_ptr[a], i)) {
            return 1;
        }
    }

    return 0;
}


/**
 * Analyzes the open image and adds image info to a database.
 * @returns 1 on error
 */
uint8_t TskAutoDb::addFilesInImgToDb()
{
    if (m_db == NULL || !m_db->dbExist()) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr("addFilesInImgToDb: m_db not open\n");
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
    setFileFilterFlags((TSK_FS_DIR_WALK_FLAG_ENUM)
        (TSK_FS_DIR_WALK_FLAG_ALLOC | TSK_FS_DIR_WALK_FLAG_UNALLOC));

    return TSK_FILTER_CONT;
}

/* Insert the file data into the file table.
 * Returns 1 on error.
 */
TSK_RETVAL_ENUM
    TskAutoDb::insertFileData(TSK_FS_FILE * fs_file,
    const TSK_FS_ATTR * fs_attr, const char *path)
{
    if (m_db->addFsFile(fs_file, fs_attr, path, m_curFsId, m_curFileId)) {
        return TSK_ERR;
    }

    return TSK_OK;
}


/**
 * Start the process to add image/file metadata to database. Reverts
 * all changes on error or TSK_STOP flag. When runProcess()
 * returns, user must call either commitProcess() to commit the changes,
 * or revertProcess() to revert them.
 */
uint8_t
TskAutoDb::runProcess(int numImg, const TSK_TCHAR * const imagePaths[],
    TSK_IMG_TYPE_ENUM imgType, unsigned int sSize)
{
    if (m_db->savepoint(TSK_ADD_IMAGE_SAVEPOINT))
        return 1;
    if (openImage(numImg, imagePaths, imgType, sSize)
        || addFilesInImgToDb()) {
        m_db->rollbackSavepoint(TSK_ADD_IMAGE_SAVEPOINT);
        return 1;
    }

    return 0;
}

#ifdef WIN32
uint8_t
TskAutoDb::runProcess(int numImg, const char *const imagePaths[],
    TSK_IMG_TYPE_ENUM imgType, unsigned int sSize)
{
    if (m_db->savepoint(TSK_ADD_IMAGE_SAVEPOINT))
        return 1;
    if (openImageUtf8(numImg, imagePaths, imgType, sSize)
        || addFilesInImgToDb()) {
        // rollback on stop command or error
        m_db->rollbackSavepoint(TSK_ADD_IMAGE_SAVEPOINT);
    }

    return 0;
}
#endif


/**
 * Cancel (and subesquently revert) the running process.
 */
void
TskAutoDb::stopProcess()
{
    m_stopped = true;
    // flag is checked every time processFile() is called
}

/**
 * Revert all changes after the process has run sucessfully.
 */
void
TskAutoDb::revertProcess()
{
    m_db->rollbackSavepoint(TSK_ADD_IMAGE_SAVEPOINT);
}

/**
 * Finish the process after it has run sucessfully by committing the changes.
 * Returns the id of the image that was added.
 */
int64_t
TskAutoDb::commitProcess()
{
    m_db->releaseSavepoint(TSK_ADD_IMAGE_SAVEPOINT);
    return m_curImgId;
}



TSK_RETVAL_ENUM
    TskAutoDb::processFile(TSK_FS_FILE * fs_file, const char *path)
{

    // Check if the process has been canceled
    if (m_stopped)
        return TSK_STOP;

    if (m_db->savepoint("PROCESSFILE")) {
        return TSK_ERR;
    }

    TSK_RETVAL_ENUM retval;
    // process the attributes if there are more than 1
    if (tsk_fs_file_attr_getsize(fs_file) == 0)
        retval = insertFileData(fs_file, NULL, path);
    else
        retval = processAttributes(fs_file, path);

    if (m_db->releaseSavepoint("PROCESSFILE")) {
        return TSK_ERR;
    }

    return retval;
}


TSK_RETVAL_ENUM
    TskAutoDb::processAttribute(TSK_FS_FILE * fs_file,
    const TSK_FS_ATTR * fs_attr, const char *path)
{
    // add the file metadata for the default attribute type
    if (isDefaultType(fs_file, fs_attr)) {
        if (insertFileData(fs_attr->fs_file, fs_attr, path))
            return TSK_ERR;
    }



    // add the block map, if requested and the file is non-resident
    if ((m_blkMapFlag) && (isNonResident(fs_attr))
        && (isDotDir(fs_file, path) == 0)) {
        TSK_FS_ATTR_RUN *run;
        for (run = fs_attr->nrd.run; run != NULL; run = run->next) {
            unsigned int block_size = fs_file->fs_info->block_size;

            // ignore sparse blocks
            if (run->flags & TSK_FS_ATTR_RUN_FLAG_SPARSE)
                continue;

            if (m_db->addFsBlockInfo(m_curFsId, m_curFileId,
                    run->addr * block_size, run->len * block_size)) {
                return TSK_ERR;
            }
        }
    }

    return TSK_OK;
}
