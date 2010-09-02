/*
 ** The Sleuth Kit 
 **
 ** Brian Carrier [carrier <at> sleuthkit [dot] org]
 ** Copyright (c) 2010 Brian Carrier.  All Rights reserved
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
}

TskAutoDb::~TskAutoDb()
{

}

void
 TskAutoDb::createBlockMap(bool flag)
{
    m_blkMapFlag = flag;
}

uint8_t
    TskAutoDb::openImage(int num, const TSK_TCHAR * const images[],
    TSK_IMG_TYPE_ENUM type, unsigned int a_ssize)
{
    TSK_TCHAR img[1024];
    char foo[1024];

    if (m_db) {
        sqlite3_close(m_db);
        m_db = NULL;
    }
    m_par_inodes.clear();
    m_curFsId = 0;
    m_curVsId = 0;

    uint8_t retval = TskAuto::openImage(num, images, type, a_ssize);
    // open the DB
    if (retval != 0) {
        return retval;
    }

    // make name of database

#ifdef TSK_WIN32
    wcsncpy(img, images[0], 1024);
    wcsncat(img, L".db", 1024);
    if (sqlite3_open16(img, &m_db)) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(m_db));
        sqlite3_close(m_db);
        return 1;
    }
#else
    snprintf(img, 1024, "%s.db", images[0]);
    if (sqlite3_open(img, &m_db)) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(m_db));
        sqlite3_close(m_db);
        return 1;
    }
#endif
    // @@@ TEST IF IT EXISTS...



    char *errmsg;
    if (sqlite3_exec(m_db,
            "CREATE TABLE tsk_db_info (schema_ver INTEGER, tsk_ver INTEGER);",
            NULL, NULL, &errmsg) != SQLITE_OK) {
        fprintf(stderr, "Error creating tsk_db_info table: %s\n", errmsg);
        sqlite3_free(errmsg);
        return 1;
    }

    snprintf(foo, 1024,
        "INSERT INTO tsk_db_info (schema_ver, tsk_ver) VALUES (%d, %d);",
        TSK_SCHEMA_VER, TSK_VERSION_NUM);
    if (sqlite3_exec(m_db, foo, NULL, NULL, &errmsg) != SQLITE_OK) {
        fprintf(stderr, "Error adding data to tsk_db_info table: %s\n",
            errmsg);
        sqlite3_free(errmsg);
        return 1;
    }

    if (sqlite3_exec(m_db,
            "CREATE TABLE tsk_image_info (type INTEGER, ssize INTEGER);",
            NULL, NULL, &errmsg) != SQLITE_OK) {
        fprintf(stderr, "Error creating tsk_image_info table: %s\n",
            errmsg);
        sqlite3_free(errmsg);
        return 1;
    }

    snprintf(foo, 1024,
        "INSERT INTO tsk_image_info (type, ssize) VALUES (%d, %u);",
        (int) type, m_img_info->sector_size);
    if (sqlite3_exec(m_db, foo, NULL, NULL, &errmsg) != SQLITE_OK) {
        fprintf(stderr, "Error adding data to tsk_image_info table: %s\n",
            errmsg);
        sqlite3_free(errmsg);
        return 1;
    }

    // Create the images table and add the image names
    if (sqlite3_exec(m_db, "CREATE TABLE tsk_image_names (name TEXT);",
            NULL, NULL, &errmsg) != SQLITE_OK) {
        fprintf(stderr, "Error creating tsk_image_names table: %s\n",
            errmsg);
        sqlite3_free(errmsg);
        return 1;
    }

    for (int i = 0; i < num; i++) {
        int a;
        char *img_ptr = NULL;
#ifdef TSK_WIN32
        char img2[1024];
        UTF8 *ptr8;
        UTF16 *ptr16;

        ptr8 = (UTF8 *) img2;
        ptr16 = (UTF16 *) images[i];

        retval =
            tsk_UTF16toUTF8_lclorder((const UTF16 **) &ptr16, (UTF16 *)
            & ptr16[TSTRLEN(images[i]) + 1], &ptr8,
            (UTF8 *) ((uintptr_t) ptr8 + 1024), TSKlenientConversion);
        if (retval != TSKconversionOK) {
            fprintf(stderr, "Error converting image to UTF-8\n");
            return 1;
        }
        img_ptr = img2;
#else
        img_ptr = (char *) images[i];
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
            fprintf(stderr,
                "Error adding data to tsk_image_names table: %s\n",
                errmsg);
            sqlite3_free(errmsg);
            return 1;
        }
    }


    if (sqlite3_exec(m_db,
            "CREATE TABLE tsk_vol_info (vol_id INTEGER PRIMARY KEY, start INTEGER NOT NULL, length INTEGER NOT NULL, desc TEXT, flags INTEGER);",
            NULL, NULL, &errmsg) != SQLITE_OK) {
        fprintf(stderr, "Error creating tsk_vol_info table: %s\n", errmsg);
        sqlite3_free(errmsg);
        return 1;
    }

    if (sqlite3_exec(m_db,
            "CREATE TABLE tsk_fs_info (fs_id INTEGER PRIMARY KEY, img_offset INTEGER, vol_id INTEGER NOT NULL, fs_type INTEGER, block_size INTEGER, block_count INTEGER, root_inum INTEGER, first_inum INTEGER, last_inum INTEGER);",
            NULL, NULL, &errmsg) != SQLITE_OK) {
        fprintf(stderr, "Error creating tsk_fs_info table: %s\n", errmsg);
        sqlite3_free(errmsg);
        return 1;
    }

    if (sqlite3_exec(m_db,
            "CREATE TABLE tsk_fs_files (fs_id INTEGER NOT NULL, file_id INTEGER NOT NULL, attr_type INTEGER, attr_id INTEGER, name TEXT NOT NULL, par_file_id INTEGER, dir_type INTEGER, meta_type INTEGER, dir_flags INTEGER, meta_flags INTEGER, size INTEGER, ctime INTEGER, crtime INTEGER, atime INTEGER, mtime INTEGER, mode INTEGER, uid INTEGER, gid INTEGER);",
            NULL, NULL, &errmsg) != SQLITE_OK) {
        fprintf(stderr, "Error creating tsk_fs_files table: %s\n", errmsg);
        sqlite3_free(errmsg);
        return 1;
    }

    if (m_blkMapFlag) {
        if (sqlite3_exec(m_db,
                "CREATE TABLE tsk_fs_blocks (fs_id INTEGER NOT NULL, blk_addr INTEGER NOT NULL, file_id INTEGER NOT NULL, attr_type INTEGER, attr_id INTEGER);",
                NULL, NULL, &errmsg) != SQLITE_OK) {
            fprintf(stderr, "Error creating tsk_fs_files table: %s\n",
                errmsg);
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
    m_par_inodes.clear();
}


uint8_t TskAutoDb::createParentDirIndex()
{
    char *
        errmsg;
    if (sqlite3_exec(m_db,
            "CREATE INDEX parentDir ON tsk_fs_files(par_file_id, fs_id);",
            NULL, NULL, &errmsg) != SQLITE_OK) {
        fprintf(stderr,
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
uint8_t
TskAutoDb::addFilesInImgToDB()
{
    if (m_db == NULL) {
        fprintf(stderr, "addFilesInImgToDB: m_db not open\n");
        return 1;
    }

    uint8_t retval = findFilesInImg();
    if (retval)
        return retval;

    if (createParentDirIndex()) {
        tsk_error_print(stderr);
        return 1;
    }
    return 0;
}


TSK_FILTER_ENUM TskAutoDb::filterVol(const TSK_VS_PART_INFO * vs_part)
{
    char
     foo[1024];
    char *
        errmsg;

    snprintf(foo, 1024,
        "INSERT INTO tsk_vol_info (vol_id, start, length, desc, flags) VALUES (%d,%"
        PRIuOFF ",%" PRIuOFF ",'%s',%d)", (int) vs_part->addr,
        vs_part->start, vs_part->len, vs_part->desc, vs_part->flags);

    if (sqlite3_exec(m_db, foo, NULL, NULL, &errmsg) != SQLITE_OK) {
        fprintf(stderr, "Error adding data to tsk_vol_info table: %s\n",
            errmsg);
        sqlite3_free(errmsg);
        return TSK_FILTER_STOP;
    }

    m_curVsId = vs_part->addr;

    return TSK_FILTER_CONT;
}


TSK_FILTER_ENUM TskAutoDb::filterFs(TSK_FS_INFO * fs_info)
{
    char
     foo[1024];
    char *
        errmsg;

    m_curFsId++;

    snprintf(foo, 1024,
        "INSERT INTO tsk_fs_info (fs_id, img_offset, vol_id, fs_type, block_size, "
        "block_count, root_inum, first_inum, last_inum) VALUES (%d,%"
        PRIuOFF ",%d,'%d',%d,%" PRIuDADDR ",%" PRIuINUM ",%" PRIuINUM ",%"
        PRIuINUM ")", m_curFsId, fs_info->offset, m_curVsId,
        (int) fs_info->ftype, fs_info->block_size, fs_info->block_count,
        fs_info->root_inum, fs_info->first_inum, fs_info->last_inum);

    if (sqlite3_exec(m_db, foo, NULL, NULL, &errmsg) != SQLITE_OK) {
        fprintf(stderr, "Error adding data to tsk_fs_info table: %s\n",
            errmsg);
        sqlite3_free(errmsg);
        return TSK_FILTER_STOP;
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
uint8_t
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
    TSK_INUM_T par_inode;
    int type = 0;
    int idx = 0;

    if (fs_file->name == NULL)
        return 0;

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


        // add the info the parent dir record so that we can later find
        // this dir by name
        if ((meta_type & TSK_FS_META_TYPE_DIR)
            && (isDotDir(fs_file, path) == 0)) {
            std::string full = path;
            full += fs_file->name->name;
            full += "/";
            m_par_inodes[full] = fs_file->name->meta_addr;
        }
    }

    size_t attr_len = 0;
    if (fs_attr) {
        type = fs_attr->type;
        idx = fs_attr->id;
        if (((fs_attr->type == TSK_FS_ATTR_TYPE_NTFS_DATA) &&
                (strcmp(fs_attr->name, "$Data") != 0)) ||
            ((fs_attr->type == TSK_FS_ATTR_TYPE_NTFS_IDXROOT) &&
                (strcmp(fs_attr->name, "$I30") != 0))) {
            attr_len = strlen(fs_attr->name);
        }
    }

    // clean up special characters in name before we insert
    size_t len = strlen(fs_file->name->name);
    char *name;
    size_t nlen = 2 * (len + attr_len);
    if ((name = (char *) tsk_malloc(nlen + 1)) == NULL) {
        return 1;
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
    if (attr_len > 0) {
        name[j++] = ':';

        for (unsigned i = 0; i < attr_len && j < nlen; i++) {
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


    if ((path == NULL) || (strcmp(path, "") == 0)) {
        par_inode = fs_file->fs_info->root_inum;
    }
    else if (m_par_inodes.count(path) > 0) {
        par_inode = m_par_inodes[path];
    }
    else {
        fprintf(stderr,
            "Error finding parent directory info on %s for %s\n", path,
            fs_file->name->name);
        free(name);
        return 1;
    }


    snprintf(foo, 1024,
        "INSERT INTO tsk_fs_files (fs_id, file_id, attr_type, attr_id, name, par_file_id, dir_type, meta_type, dir_flags, meta_flags, size, crtime, ctime, atime, mtime, mode, gid, uid) VALUES (%d,%"
        PRIuINUM ",%d,%d,'%s',%" PRIuINUM ",%d,%d,%d,%d,%" PRIuOFF
        ",%d,%d,%d,%d,%d,%d,%d)", m_curFsId, fs_file->name->meta_addr,
        type, idx, name, par_inode, fs_file->name->type, meta_type,
        fs_file->name->flags, meta_flags, size, crtime, ctime, atime,
        mtime, meta_mode, gid, uid);

    if (sqlite3_exec(m_db, foo, NULL, NULL, &errmsg) != SQLITE_OK) {
        fprintf(stderr, "Error adding data to tsk_fs_files table: %s\n",
            errmsg);
        sqlite3_free(errmsg);
        free(name);
        return 1;
    }

    free(name);
    return 0;
}

// structure used to store data during file walk
typedef struct {
    sqlite3 *db;                // database to insert into
    int fsId;                   // ID of current file system
    uint16_t type;              // type of attribute being walked
    uint16_t id;                // id of attribute being walked
} FWALK_CB_STRUCT;


static TSK_WALK_RET_ENUM
file_walk_cb(TSK_FS_FILE * a_fs_file, TSK_OFF_T a_off, TSK_DADDR_T a_addr,
    char *a_buf, size_t a_len, TSK_FS_BLOCK_FLAG_ENUM a_flags, void *a_ptr)
{
    char foo[1024];
    char *errmsg;
    FWALK_CB_STRUCT *a_cb_struct = (FWALK_CB_STRUCT *) a_ptr;

    // ignore sparse blocks
    if (a_flags & TSK_FS_BLOCK_FLAG_SPARSE)
        return TSK_WALK_CONT;

    snprintf(foo, 1024,
        "INSERT INTO tsk_fs_blocks (fs_id, blk_addr, file_id, attr_type, attr_id) VALUES (%d,%"
        PRIuDADDR ",%" PRIuINUM ",%d,%d)", a_cb_struct->fsId, a_addr,
        a_fs_file->name->meta_addr, a_cb_struct->type, a_cb_struct->id);

    if (sqlite3_exec(a_cb_struct->db, foo, NULL, NULL,
            &errmsg) != SQLITE_OK) {
        fprintf(stderr, "Error adding data to tsk_fs_info table: %s\n",
            errmsg);
        sqlite3_free(errmsg);
        return TSK_WALK_ERROR;
    }

    return TSK_WALK_CONT;
}


/**
 * does an attribute walk and adds data to the block map table.
 */
uint8_t
TskAutoDb::insertBlockData(const TSK_FS_ATTR * fs_attr)
{
    FWALK_CB_STRUCT cb_struct;

    cb_struct.db = m_db;
    cb_struct.fsId = m_curFsId;
    cb_struct.type = fs_attr->type;
    cb_struct.id = fs_attr->id;

    if (tsk_fs_attr_walk(fs_attr, TSK_FS_FILE_WALK_FLAG_NONE,
            file_walk_cb, &cb_struct)) {
        fprintf(stderr, "Error walking file\n");
        tsk_error_print(stderr);
        return 1;
    }
    return 0;
}


uint8_t
TskAutoDb::processFile(TSK_FS_FILE * fs_file, const char *path)
{
    char *errmsg;
    if (sqlite3_exec(m_db, "BEGIN", NULL, NULL, &errmsg) != SQLITE_OK) {
        fprintf(stderr, "BEGIN Error: %s\n", errmsg);
        sqlite3_free(errmsg);
        return 1;
    }

    uint8_t retval;
    int
     count = tsk_fs_file_attr_getsize(fs_file);
    if (count > 0)
        retval = processAttributes(fs_file, path);
    else {
        retval = insertFileData(fs_file, NULL, path);
    }

    if (sqlite3_exec(m_db, "COMMIT", NULL, NULL, &errmsg) != SQLITE_OK) {
        fprintf(stderr, "COMMIT Error: %s\n", errmsg);
        sqlite3_free(errmsg);
        return 1;
    }

    return retval;
}

uint8_t
    TskAutoDb::processAttribute(TSK_FS_FILE * fs_file,
    const TSK_FS_ATTR * fs_attr, const char *path)
{
    // add the file metadata for the default attribute type
    if (isDefaultType(fs_file, fs_attr)) {
        if (insertFileData(fs_attr->fs_file, fs_attr, path))
            return 1;
    }

    // add the block map, if requested and the file is non-resident
    if ((m_blkMapFlag) && (isNonResident(fs_attr))) {
        if (insertBlockData(fs_attr))
            return 1;
    }

    return 0;
}
