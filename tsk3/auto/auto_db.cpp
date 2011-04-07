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
#include "sqlite3.h"
#include <string.h>

#define TSK_SCHEMA_VER 1

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
    TSK_IMG_TYPE_ENUM a_type, unsigned int a_ssize, TSK_TCHAR * a_output_dir)
{
    TSK_TCHAR dbFile[1024];
    char foo[1024];

    if (m_db) {
        sqlite3_close(m_db);
        m_db = NULL;
    }
    m_curFsId = 0;
    m_curVsId = 0;

    uint8_t retval = TskAuto::openImage(a_num, a_images, a_type, a_ssize);
    // open the DB
    if (retval != 0) {
        return retval;
    }

    // make name of database
#ifdef TSK_WIN32
    if (a_output_dir != NULL){
        wcsncpy(dbFile, a_output_dir, 1024);
        
        if(dbFile[wcslen(dbFile) - 1] != '/' && dbFile[wcslen(dbFile) - 1] != '\\')
            wcsncat(dbFile, L"\\", 1024-wcslen(dbFile));
        
        // get the image name w/out the path
        size_t j;
        for (j = wcslen(a_images[0]) - 1; j > 0; j--) {
            if ((a_images[0][j] == '/') || (a_images[0][j] == '\\')) {
                j++;
                break;
            }
        }
        
        wcsncat(dbFile, &a_images[0][j], 1024-wcslen(dbFile));
        wcsncat(dbFile, L".db", 1024-wcslen(dbFile));
    }
    else{
        wcsncpy(dbFile, a_images[0], 1024);
        wcsncat(dbFile, L".db", 1024-wcslen(dbFile));
    }

    struct STAT_STR stat_buf;
    if (TSTAT(dbFile, &stat_buf) == 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr( 
                "Database %S already exists.  Must be deleted first.", dbFile);
        return 1;
    }
    
    if (sqlite3_open16(dbFile, &m_db)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr( 
            "Can't open database: %s\n", sqlite3_errmsg(m_db));
        sqlite3_close(m_db);
        return 1;
    }
#else
    if (a_output_dir != NULL){
        strncpy(dbFile, a_output_dir, 1024);
        
        if(dbFile[strlen(dbFile) - 1] != '/')
            strncat(dbFile, "/", 1024-strlen(dbFile));
        
        // get the image name
        size_t j;
        for (j = strlen(a_images[0]) - 1; j > 0; j--) {
            if ((a_images[0][j] == '/') || (a_images[0][j] == '\\')) {
                j++;
                break;
            }
        }        
        
        strncat(dbFile, &a_images[0][j], 1024-strlen(dbFile));
        strncat(dbFile, ".db", 1024-strlen(dbFile));
    }
    else {
        snprintf(dbFile, 1024, "%s.db", a_images[0]);
    }

    struct STAT_STR stat_buf;
    if (TSTAT(dbFile, &stat_buf) == 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr( 
                "Database %s already exists.  Must be deleted first.", dbFile);
        return 1;
    }
    
    if (sqlite3_open(dbFile, &m_db)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr( 
            "Can't open database: %s\n", sqlite3_errmsg(m_db));
        sqlite3_close(m_db);
        return 1;
    }

#endif


    char *errmsg;
    // disable synchronous for loading the DB since we have no crash recovery anyway...
    if (sqlite3_exec(m_db,
                     "PRAGMA synchronous =  OFF;", NULL, NULL, &errmsg) != SQLITE_OK) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr(
                 "Error setting PRAGMA synchronous: %s\n", errmsg);
        sqlite3_free(errmsg);
        return 1;
    }
    // We don't care about the return values of inserts etc.
    if (sqlite3_exec(m_db,
                     "PRAGMA count_changes = false;", NULL, NULL, &errmsg) != SQLITE_OK) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr(
                 "Error setting PRAGMA count changes: %s\n", errmsg);
        sqlite3_free(errmsg);
        return 1;
    }

    if (sqlite3_exec(m_db,
            "CREATE TABLE tsk_db_info (schema_ver INTEGER, tsk_ver INTEGER);",
            NULL, NULL, &errmsg) != SQLITE_OK) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr(
            "Error creating tsk_db_info table: %s\n", errmsg);
        sqlite3_free(errmsg);
        return 1;
    }

    snprintf(foo, 1024,
        "INSERT INTO tsk_db_info (schema_ver, tsk_ver) VALUES (%d, %d);",
        TSK_SCHEMA_VER, TSK_VERSION_NUM);
    if (sqlite3_exec(m_db, foo, NULL, NULL, &errmsg) != SQLITE_OK) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr(
            "Error adding data to tsk_db_info table: %s\n", errmsg);
        sqlite3_free(errmsg);
        return 1;
    }

    if (sqlite3_exec(m_db,
            "CREATE TABLE tsk_image_info (type INTEGER, ssize INTEGER);",
            NULL, NULL, &errmsg) != SQLITE_OK) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr(
            "Error creating tsk_image_info table: %s\n", errmsg);
        sqlite3_free(errmsg);
        return 1;
    }

    snprintf(foo, 1024,
        "INSERT INTO tsk_image_info (type, ssize) VALUES (%d, %u);",
        (int) a_type, m_img_info->sector_size);
    if (sqlite3_exec(m_db, foo, NULL, NULL, &errmsg) != SQLITE_OK) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr(
            "Error adding data to tsk_image_info table: %s\n", errmsg);
        sqlite3_free(errmsg);
        return 1;
    }

    // Create the images table and add the image names
    if (sqlite3_exec(m_db, "CREATE TABLE tsk_image_names (name TEXT);",
            NULL, NULL, &errmsg) != SQLITE_OK) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr(
            "Error creating tsk_image_names table: %s\n", errmsg);
        sqlite3_free(errmsg);
        return 1;
    }

    for (int i = 0; i < a_num; i++) {
        int a;
        char *img_ptr = NULL;
#ifdef TSK_WIN32
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
            tsk_error_set_errstr(
                "Error converting image to UTF-8\n");
            return 1;
        }
        img_ptr = img2;
#else
        img_ptr = (char *) a_images[i];
#endif

        // get only the file name (ignore the directory name)
        for (a = strlen(img_ptr) - 1; a > 0; a--) {
            if ((img_ptr[a] == '/') || (img_ptr[a] == '\\')) {
                a++;
                break;
            }
        }
        snprintf(foo, 1024,
            "INSERT INTO tsk_image_names (name) VALUES ('%s')",
            &img_ptr[a]);
        if (sqlite3_exec(m_db, foo, NULL, NULL, &errmsg) != SQLITE_OK) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_AUTO_DB);
            tsk_error_set_errstr(
                "Error adding data to tsk_image_names table: %s\n",
                errmsg);
            sqlite3_free(errmsg);
            return 1;
        }
    }

    if (sqlite3_exec(m_db,
            "CREATE TABLE tsk_vs_info (vs_type INTEGER, img_offset INTEGER NOT NULL, block_size INTEGER NOT NULL);",
            NULL, NULL, &errmsg) != SQLITE_OK) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr(
            "Error creating tsk_vs_info table: %s\n", errmsg);
        sqlite3_free(errmsg);
        return 1;
    }

    if (sqlite3_exec(m_db,
            "CREATE TABLE tsk_vs_parts (vol_id INTEGER PRIMARY KEY, start INTEGER NOT NULL, length INTEGER NOT NULL, desc TEXT, flags INTEGER);",
            NULL, NULL, &errmsg) != SQLITE_OK) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr(
            "Error creating tsk_vol_info table: %s\n", errmsg);
        sqlite3_free(errmsg);
        return 1;
    }

    if (sqlite3_exec(m_db,
            "CREATE TABLE tsk_fs_info (fs_id INTEGER PRIMARY KEY, img_offset INTEGER, vol_id INTEGER NOT NULL, fs_type INTEGER, block_size INTEGER, block_count INTEGER, root_inum INTEGER, first_inum INTEGER, last_inum INTEGER);",
            NULL, NULL, &errmsg) != SQLITE_OK) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr(
            "Error creating tsk_fs_info table: %s\n", errmsg);
        sqlite3_free(errmsg);
        return 1;
    }

    if (sqlite3_exec(m_db,
            "CREATE TABLE tsk_fs_files (fs_id INTEGER NOT NULL, file_id INTEGER NOT NULL, attr_type INTEGER, attr_id INTEGER, name TEXT NOT NULL, par_file_id INTEGER, dir_type INTEGER, meta_type INTEGER, dir_flags INTEGER, meta_flags INTEGER, size INTEGER, ctime INTEGER, crtime INTEGER, atime INTEGER, mtime INTEGER, mode INTEGER, uid INTEGER, gid INTEGER);",
            NULL, NULL, &errmsg) != SQLITE_OK) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr(
            "Error creating tsk_fs_files table: %s\n", errmsg);
        sqlite3_free(errmsg);
        return 1;
    }

    if (m_blkMapFlag) {
        if (sqlite3_exec(m_db,
                "CREATE TABLE tsk_fs_blocks (fs_id INTEGER NOT NULL, blk_start INTEGER NOT NULL, blk_len INTEGER NOT NULL, file_id INTEGER NOT NULL, attr_type INTEGER, attr_id INTEGER);",
                NULL, NULL, &errmsg) != SQLITE_OK) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_AUTO_DB);
            tsk_error_set_errstr(
                "Error creating tsk_fs_blocks table: %s\n", errmsg);
            sqlite3_free(errmsg);
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
        sqlite3_close(m_db);
        m_db = NULL;
    }
}


uint8_t
TskAutoDb::createParentDirIndex()
{
    char *errmsg;
    if (sqlite3_exec(m_db,
            "CREATE INDEX parentDir ON tsk_fs_files(par_file_id, fs_id);",
            NULL, NULL, &errmsg) != SQLITE_OK) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr(
            "Error creating tsk_fs_files index on par_file_id: %s\n",
            errmsg);
        sqlite3_free(errmsg);
        return 1;
    }
    return 0;
}


/**
 * Analyzes the open image and adds image info to a database.
 * @returns 1 on error
 */
uint8_t TskAutoDb::addFilesInImgToDB()
{
    if (m_db == NULL) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr(
            "addFilesInImgToDB: m_db not open\n");
        return 1;
    }

    setVolFilterFlags((TSK_VS_PART_FLAG_ENUM)(TSK_VS_PART_FLAG_ALLOC | TSK_VS_PART_FLAG_UNALLOC));

    uint8_t
        retval = findFilesInImg();
    if (retval)
        return retval;

    if (createParentDirIndex()) {
        tsk_error_print(stderr);
        return 1;
    }
    return 0;
}

TSK_FILTER_ENUM TskAutoDb::filterVs(const TSK_VS_INFO * vs_info) {
    char statement[1024];
    char *errmsg;

    m_vsFound = true;
    snprintf(statement, 1024,
        "INSERT INTO tsk_vs_info (vs_type, img_offset, block_size) VALUES (%d,%"
        PRIuOFF ",%d)", vs_info->vstype, vs_info->offset, vs_info->block_size);

    if (sqlite3_exec(m_db, statement, NULL, NULL, &errmsg) != SQLITE_OK) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr(
            "Error adding data to tsk_vs_info table: %s\n", errmsg);
        sqlite3_free(errmsg);
        return TSK_FILTER_STOP;
    }
    
    return TSK_FILTER_CONT;
}

TSK_FILTER_ENUM
TskAutoDb::filterVol(const TSK_VS_PART_INFO * vs_part)
{
    char
     foo[1024];
    char *errmsg;

    m_volFound = true;
    snprintf(foo, 1024,
        "INSERT INTO tsk_vs_parts (vol_id, start, length, desc, flags) VALUES (%d,%"
        PRIuOFF ",%" PRIuOFF ",'%s',%d)", (int) vs_part->addr,
        vs_part->start, vs_part->len, vs_part->desc, vs_part->flags);

    if (sqlite3_exec(m_db, foo, NULL, NULL, &errmsg) != SQLITE_OK) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr(
            "Error adding data to tsk_vol_info table: %s\n", errmsg);
        sqlite3_free(errmsg);
        return TSK_FILTER_STOP;
    }

    m_curVsId = vs_part->addr;

    return TSK_FILTER_CONT;
}


TSK_FILTER_ENUM
TskAutoDb::filterFs(TSK_FS_INFO * fs_info)
{
    char
     foo[1024];
    char *errmsg;
    TSK_FS_FILE *file_root;

    m_curFsId++;

    /* if we have a disk with no volume system, make a dummy entry.
     * we only do this so that we can have a dummy volume in vs_part so that
     * programs that use this can assume that there will be at least one 
     * volume. */
    if(!m_vsFound){
        m_vsFound = true;
        snprintf(foo, 1024,
            "INSERT INTO tsk_vs_info (vs_type, img_offset, block_size) VALUES (%d,%"
            PRIuOFF ", 512)", TSK_VS_TYPE_DBFILLER, fs_info->offset);

        if (sqlite3_exec(m_db, foo, NULL, NULL, &errmsg) != SQLITE_OK) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_AUTO_DB);
            tsk_error_set_errstr(
                "Error adding data to tsk_vs_info table: %s\n", errmsg);
            sqlite3_free(errmsg);
            return TSK_FILTER_STOP;
        }
    }

    if(!m_volFound){
        m_volFound = true;
        snprintf(foo, 1024,
            "INSERT INTO tsk_vs_parts (vol_id, start, length, desc, flags) VALUES (%d,%"
            PRIuOFF ",%" PRIuOFF ",'%s',%d)", 0,
            fs_info->offset, fs_info->block_count * fs_info->block_size, "", TSK_VS_PART_FLAG_ALLOC);

        m_curVsId = 0;
        if (sqlite3_exec(m_db, foo, NULL, NULL, &errmsg) != SQLITE_OK) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_AUTO_DB);
            tsk_error_set_errstr(
                "Error adding data to tsk_vs_parts table: %s\n", errmsg);
            sqlite3_free(errmsg);
            return TSK_FILTER_STOP;
        }
    }

    snprintf(foo, 1024,
        "INSERT INTO tsk_fs_info (fs_id, img_offset, vol_id, fs_type, block_size, "
        "block_count, root_inum, first_inum, last_inum) VALUES (%d,%"
        PRIuOFF ",%d,'%d',%d,%" PRIuDADDR ",%" PRIuINUM ",%" PRIuINUM ",%"
        PRIuINUM ")", m_curFsId, fs_info->offset, m_curVsId,
        (int) fs_info->ftype, fs_info->block_size, fs_info->block_count,
        fs_info->root_inum, fs_info->first_inum, fs_info->last_inum);

    if (sqlite3_exec(m_db, foo, NULL, NULL, &errmsg) != SQLITE_OK) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr(
            "Error adding data to tsk_fs_info table: %s\n", errmsg);
        sqlite3_free(errmsg);
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
    char
     foo[1024];
    char *errmsg;
    int
     mtime = 0;
    int
     crtime = 0;
    int
     ctime = 0;
    int
     atime = 0;
    TSK_OFF_T size = 0;
    int
     meta_type = 0;
    int
     meta_flags = 0;
    int
     meta_mode = 0;
    int
     gid = 0;
    int
     uid = 0;
    int type = 0;
    int idx = 0;

    if (fs_file->name == NULL)
        return TSK_OK;

    if (fs_file->meta) {
        mtime = fs_file->meta->mtime;
        atime = fs_file->meta->atime;
        ctime = fs_file->meta->ctime;
        crtime = fs_file->meta->crtime;
        size = fs_file->meta->size;
        meta_type = fs_file->meta->type;
        meta_flags = fs_file->meta->flags;
        meta_mode = fs_file->meta->mode;
        gid = fs_file->meta->gid;
        uid = fs_file->meta->uid;
    }

    size_t attr_nlen = 0;
    if (fs_attr) {
        type = fs_attr->type;
        idx = fs_attr->id;
        if (fs_attr->name) {
            if ((fs_attr->type != TSK_FS_ATTR_TYPE_NTFS_IDXROOT) ||
                (strcmp(fs_attr->name, "$I30") != 0)) {
                attr_nlen = strlen(fs_attr->name);
            }
        }
    }

    // clean up special characters in name before we insert
    size_t len = strlen(fs_file->name->name);
    char *name;
    size_t nlen = 2 * (len + attr_nlen);
    if ((name = (char *) tsk_malloc(nlen + 1)) == NULL) {
        return TSK_ERR;
    }

    size_t j = 0;
    for (size_t i = 0; i < len && j < nlen; i++) {
        // ' is special in SQLite
        if (fs_file->name->name[i] == '\'') {
            name[j++] = '\'';
            name[j++] = '\'';
        }
        else {
            name[j++] = fs_file->name->name[i];
        }
    }

    // Add the attribute name
    if (attr_nlen > 0) {
        name[j++] = ':';

        for (unsigned i = 0; i < attr_nlen && j < nlen; i++) {
            // ' is special in SQLite
            if (fs_attr->name[i] == '\'') {
                name[j++] = '\'';
                name[j++] = '\'';
            }
            else {
                name[j++] = fs_attr->name[i];
            }
        }
    }

    snprintf(foo, 1024,
        "INSERT INTO tsk_fs_files (fs_id, file_id, attr_type, attr_id, name, par_file_id, dir_type, meta_type, dir_flags, meta_flags, size, crtime, ctime, atime, mtime, mode, gid, uid) VALUES (%d,%"
        PRIuINUM ",%d,%d,'%s',%" PRIuINUM ",%d,%d,%d,%d,%" PRIuOFF
        ",%d,%d,%d,%d,%d,%d,%d)", m_curFsId, fs_file->name->meta_addr,
        type, idx, name, fs_file->name->par_addr, fs_file->name->type, meta_type,
        fs_file->name->flags, meta_flags, size, crtime, ctime, atime,
        mtime, meta_mode, gid, uid);

    if (sqlite3_exec(m_db, foo, NULL, NULL, &errmsg) != SQLITE_OK) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr(
            "Error adding data to tsk_fs_files table: %s\n", errmsg);
        sqlite3_free(errmsg);
        free(name);
        return TSK_ERR;
    }

    free(name);
    return TSK_OK;
}





TSK_RETVAL_ENUM
    TskAutoDb::processFile(TSK_FS_FILE * fs_file, const char *path)
{
    char *errmsg;
    if (sqlite3_exec(m_db, "BEGIN", NULL, NULL, &errmsg) != SQLITE_OK) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr(
            "Error using BEGIN for insert transaction: %s\n", errmsg);
        sqlite3_free(errmsg);
        return TSK_ERR;
    }

    TSK_RETVAL_ENUM retval;
    // process the attributes if there are more than 1
    if (tsk_fs_file_attr_getsize(fs_file) == 0)
        retval = insertFileData(fs_file, NULL, path);
    else
        retval = processAttributes(fs_file, path);

    if (sqlite3_exec(m_db, "COMMIT", NULL, NULL, &errmsg) != SQLITE_OK) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr(
            "Error using COMMIT for insert transaction: %s\n", errmsg);
        sqlite3_free(errmsg);
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
    if ((m_blkMapFlag) && (isNonResident(fs_attr)) && (isDotDir(fs_file, path) == 0)) {
        TSK_FS_ATTR_RUN *run;
        for (run = fs_attr->nrd.run; run != NULL; run = run->next) {
            char foo[1024];
            char *errmsg;

            // ignore sparse blocks
            if (run->flags & TSK_FS_ATTR_RUN_FLAG_SPARSE)
                continue;

            snprintf(foo, 1024,
                     "INSERT INTO tsk_fs_blocks (fs_id, blk_start, blk_len, file_id, attr_type, attr_id) VALUES (%d,%"
                     PRIuDADDR ",%"PRIuDADDR ",%" PRIuINUM ",%d,%d)", m_curFsId, run->addr, run->len,
                     fs_file->meta->addr, fs_attr->type, fs_attr->id);

            if (sqlite3_exec(m_db, foo, NULL, NULL,
                             &errmsg) != SQLITE_OK) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_AUTO_DB);
                tsk_error_set_errstr(
                         "Error adding data to tsk_fs_info table: %s\n", errmsg);
                sqlite3_free(errmsg);
                return TSK_ERR;
            }
        }
    }

    return TSK_OK;
}
