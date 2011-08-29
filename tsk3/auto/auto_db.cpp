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

#include "tsk_auto_i.h"
#include <string.h>


TskAutoDb::TskAutoDb()
{
    m_db = NULL;
    m_curFsId = 0;
    m_curVsId = 0;
    m_blkMapFlag = false;
    m_vsFound = false;
    m_volFound = false;
}

TskAutoDb::~TskAutoDb()
{
    closeImage();
}

void
 TskAutoDb::createBlockMap(bool flag)
{
    m_blkMapFlag = flag;
}

/**
 * Open the image to be analyzed.  Creates the database in the same
 * directory as the image (with .db appended to the name).
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
    return openImage(a_num, a_images, a_type, a_ssize, NULL);
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
    return openImageUtf8(a_num, a_images, a_type, a_ssize, NULL);
}

/**
 * Open the image to be analyzed.  Creates the database in the specified
 * directory (with .db appended to the name). Always uses utf8 functions
 * even in windows.
 * @param a_num Number of images
 * @param a_images Images to open
 * @param a_type Image file format
 * @param a_ssize Sector size in bytes
 * @param a_output_dir Output directory to place database into or NULL to place it in the same directory as the image. 
 * @return Resturns 1 on error
 */
uint8_t
    TskAutoDb::openImageUtf8(int a_num, const char *const a_images[],
    TSK_IMG_TYPE_ENUM a_type, unsigned int a_ssize, char *a_output_dir)
{
    char dbFile[1024];

    if (m_db) {
        m_db->close();
        m_db = NULL;
    }
    m_curFsId = 0;
    m_curVsId = 0;

    uint8_t retval =
        TskAuto::openImageUtf8(a_num, a_images, a_type, a_ssize);
    // open the DB
    if (retval != 0) {
        return retval;
    }

    if (a_output_dir != NULL) {
        strncpy(dbFile, a_output_dir, 1024);
#ifdef WIN32
        if (dbFile[strlen(dbFile) - 1] != '\\')
            strncat(dbFile, "\\", 1024 - strlen(dbFile));
#else
        if (dbFile[strlen(dbFile) - 1] != '/')
            strncat(dbFile, "/", 1024 - strlen(dbFile));
#endif
        // get the image name
        size_t j;
        for (j = strlen(a_images[0]) - 1; j > 0; j--) {
            if ((a_images[0][j] == '/') || (a_images[0][j] == '\\')) {
                j++;
                break;
            }
        }

        strncat(dbFile, &a_images[0][j], 1024 - strlen(dbFile));
        strncat(dbFile, ".db", 1024 - strlen(dbFile));
    }
    else {
        snprintf(dbFile, 1024, "%s.db", a_images[0]);
    }

    struct stat stat_buf;
    if (stat(dbFile, &stat_buf) == 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr
            ("Database %s already exists.  Must be deleted first.",
            dbFile);
        return 1;
    }

    m_db = (new TskImgDBSqlite(dbFile, m_blkMapFlag));

    if (initDatabase((char **) a_images, a_num)) {
        return 1;
    }
    return 0;
}

/**
 * Open the image to be analyzed.  Creates the database in the specified
 * directory (with .db appended to the name).
 * @param a_num Number of images
 * @param a_images Images to open
 * @param a_type Image file format
 * @param a_ssize Sector size in bytes
 * @param a_output_dir Output directory to place database into or NULL to place it in the same directory as the image. 
 * @return Resturns 1 on error
 */
uint8_t
    TskAutoDb::openImage(int a_num, const TSK_TCHAR * const a_images[],
    TSK_IMG_TYPE_ENUM a_type, unsigned int a_ssize,
    TSK_TCHAR * a_output_dir)
{
    // make name of database
#ifdef TSK_WIN32
    TSK_TCHAR dbFile[1024];

    if (m_db) {
        m_db->close();
        m_db = NULL;
    }
    m_curFsId = 0;
    m_curVsId = 0;

    uint8_t retval = TskAuto::openImage(a_num, a_images, a_type, a_ssize);
    // open the DB
    if (retval != 0) {
        return retval;
    }
    if (a_output_dir != NULL) {
        wcsncpy(dbFile, a_output_dir, 1024);

        if (dbFile[wcslen(dbFile) - 1] != '/'
            && dbFile[wcslen(dbFile) - 1] != '\\')
            wcsncat(dbFile, L"\\", 1024 - wcslen(dbFile));

        // get the image name w/out the path
        size_t j;
        for (j = wcslen(a_images[0]) - 1; j > 0; j--) {
            if ((a_images[0][j] == '/') || (a_images[0][j] == '\\')) {
                j++;
                break;
            }
        }

        wcsncat(dbFile, &a_images[0][j], 1024 - wcslen(dbFile));
        wcsncat(dbFile, L".db", 1024 - wcslen(dbFile));
    }
    else {
        wcsncpy(dbFile, a_images[0], 1024);
        wcsncat(dbFile, L".db", 1024 - wcslen(dbFile));
    }

    struct STAT_STR stat_buf;
    if (TSTAT(dbFile, &stat_buf) == 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr
            ("Database %S already exists.  Must be deleted first.",
            dbFile);
        return 1;
    }

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
    if (initDatabase(img_ptrs, a_num)) {
        return 1;
    }

    return 0;
#else
    return openImageUtf8(a_num, a_images, a_type, a_ssize, a_output_dir);
#endif
}

/**
 * Creates the basic database tables for the created database (m_db) then populates the image tables
 * @param img_ptrs The paths to the image splits
 * @return Resturns 1 on error
 */

uint8_t TskAutoDb::initDatabase(const char * const img_ptrs[], int a_num)
{
    m_db->initialize();

    if(m_db->addImageInfo(m_img_info->itype, m_img_info->sector_size)) {
        return 1;
    }

    // Add the image names
    for (int i = 0; i < a_num; i++) {
        int
            a;
        const char *
            img_ptr = NULL;
        img_ptr = img_ptrs[i];
        // get only the file name (ignore the directory name)
        for (a = strlen(img_ptr) - 1; a > 0; a--) {
            if ((img_ptr[a] == '/') || (img_ptr[a] == '\\')) {
                a++;
                break;
            }
        }

        if (m_db->addImageName(&img_ptr[a])) {
            return 1;
        }
    }

    return 0;
}

void
 TskAutoDb::closeImage()
{
    TskAuto::closeImage();
    if (m_db) {
        delete m_db;
        m_db = NULL;
    }
}



/**
 * Analyzes the open image and adds image info to a database.
 * @returns 1 on error
 */
uint8_t
TskAutoDb::addFilesInImgToDB()
{
    if (m_db == NULL || !m_db->dbExist()) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr("addFilesInImgToDB: m_db not open\n");
        return 1;
    }

    setVolFilterFlags((TSK_VS_PART_FLAG_ENUM) (TSK_VS_PART_FLAG_ALLOC |
            TSK_VS_PART_FLAG_UNALLOC));

    uint8_t retval = findFilesInImg();
    if (retval)
        return retval;

    //if (m_db->createParentDirIndex()) {
    //    tsk_error_print(stderr);
    //    return 1;
    //}
    return 0;
}

TSK_FILTER_ENUM
TskAutoDb::filterVs(const TSK_VS_INFO * vs_info)
{
    m_vsFound = true;
    if(m_db->addVsInfo(vs_info)) {
        return TSK_FILTER_STOP;
    }

    return TSK_FILTER_CONT;
}

TSK_FILTER_ENUM TskAutoDb::filterVol(const TSK_VS_PART_INFO * vs_part)
{
    m_volFound = true;

    if (m_db->addVolumeInfo(vs_part)) {
        return TSK_FILTER_STOP;
    }

    m_curVsId = vs_part->addr;

    return TSK_FILTER_CONT;
}


TSK_FILTER_ENUM TskAutoDb::filterFs(TSK_FS_INFO * fs_info)
{
    TSK_FS_FILE *
        file_root;

    m_curFsId++;

    /* if we have a disk with no volume system, make a dummy entry.
     * we only do this so that we can have a dummy volume in vs_part so that
     * programs that use this can assume that there will be at least one 
     * volume. */
    if (!m_vsFound) {
        TSK_VS_INFO
            dummy;


        m_vsFound = true;

        dummy.vstype = TSK_VS_TYPE_DBFILLER;
        dummy.offset = fs_info->offset;
        dummy.block_size = 512;
        
        if (m_db->addVsInfo(&dummy)) {
            return TSK_FILTER_STOP;
        }
    }

    if (!m_volFound) {
        TSK_VS_PART_INFO dummy;

        m_volFound = true;

        dummy.addr = 0;
        dummy.start = fs_info->offset;
        dummy.len = fs_info->block_count * fs_info->block_size;
        dummy.desc = NULL;
        dummy.flags = TSK_VS_PART_FLAG_ALLOC;

        m_curVsId = 0;

        if (m_db->addVolumeInfo(&dummy)) {
            return TSK_FILTER_STOP;
        }
    }

    if (m_db->addFsInfo(m_curVsId, m_curFsId, fs_info)) {
        return TSK_FILTER_STOP;
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
    if (m_db->addFsFile(fs_file, fs_attr, path, m_curFsId)) {

        return TSK_ERR;
    }
    return TSK_OK;
}





TSK_RETVAL_ENUM
    TskAutoDb::processFile(TSK_FS_FILE * fs_file, const char *path)
{
    if (m_db->begin()) {
        return TSK_ERR;
    }

    TSK_RETVAL_ENUM retval;
    // process the attributes if there are more than 1
    if (tsk_fs_file_attr_getsize(fs_file) == 0)
        retval = insertFileData(fs_file, NULL, path);
    else
        retval = processAttributes(fs_file, path);

    if (m_db->commit()) {
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
        int sequence = 0;
        for (run = fs_attr->nrd.run; run != NULL; run = run->next) {
            // ignore sparse blocks
            if (run->flags & TSK_FS_ATTR_RUN_FLAG_SPARSE)
                continue;

            if(m_db->addFsBlockInfo(m_curFsId, fs_file->meta->addr,
                sequence++, run->addr, run->len, fs_attr->type,
                fs_attr->id)) {
                return TSK_ERR;
            }
        }
    }

    return TSK_OK;
}
