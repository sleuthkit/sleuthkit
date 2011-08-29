#include "tsk_auto_i.h"
#include "sqlite3.h"
#include <string.h>

#define TSK_SCHEMA_VER 1

/**
 * Set the locations and logging object.  Must call
 * initialize() before the object can be used.
 */
TskImgDBSqlite::TskImgDBSqlite(const char * a_dbFilePathUtf8, bool a_blkMapFlag)
{
    strncpy(m_dbFilePathUtf8, a_dbFilePathUtf8, 1024);
    m_utf8 = true;
    m_blkMapFlag = a_blkMapFlag;
    m_db = NULL;
}

#if 0
@@@@
TskImgDBSqlite::TskImgDBSqlite(const TSK_TCHAR * a_dbFilePath, bool a_blkMapFlag)
{
    wcsncpy(m_dbFilePath, a_dbFilePath, 1024);
    m_utf8 = false;
    m_blkMapFlag = a_blkMapFlag;
    m_db = NULL;
}
#endif


TskImgDBSqlite::~TskImgDBSqlite()
{
    (void) close();
}

/*
 * Close the Sqlite database.
 * Return 0 on success, 1 on failure
 */
int TskImgDBSqlite::close()
{

    if (m_db) {
        if (sqlite3_close(m_db) == SQLITE_OK)
            m_db = NULL;
        else
            return 1;
    }
    return 0;
}

int TskImgDBSqlite::attempt_exec(const char *sql, const char *errfmt) {
    char * errmsg;

    if (sqlite3_exec(m_db, sql, NULL, NULL, &errmsg) != SQLITE_OK) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr(errfmt,
            errmsg);
        sqlite3_free(errmsg);
        tsk_error_print(stderr);
        return 1;
    }
    return 0;
}





/** 
 * Open the DB and create the tables.
 * @returns 1 on error
 */
int TskImgDBSqlite::initialize()
{
    char foo[1024];

    // Open the database.
    if (open() != 0)
    {
        // Error message will have been logged by open()
        return 1;
    }

    // disable synchronous for loading the DB since we have no crash recovery anyway...
    if (attempt_exec("PRAGMA synchronous =  OFF;",
        "Error setting PRAGMA synchronous: %s\n")) {
        return 1;
    }

    // We don't care about the return values of inserts etc.
    if (attempt_exec("PRAGMA count_changes = false;",
        "Error setting PRAGMA count changes: %s\n")) {
        return 1;
    }

    if (attempt_exec("CREATE TABLE tsk_db_info (schema_ver INTEGER, tsk_ver INTEGER);",
        "Error creating tsk_db_info table: %s\n")) {
        return 1;
    }

    snprintf(foo, 1024,
        "INSERT INTO tsk_db_info (schema_ver, tsk_ver) VALUES (%d, %d);",
        TSK_SCHEMA_VER, TSK_VERSION_NUM);
    if (attempt_exec(foo, "Error adding data to tsk_db_info table: %s\n")) {
        return 1;
    }

    if (attempt_exec("CREATE TABLE tsk_image_info (type INTEGER, ssize INTEGER);",
        "Error creating tsk_image_info table: %s\n")) {
        return 1;
    }

    // Create the images table
    if (attempt_exec("CREATE TABLE tsk_image_names (name TEXT);",
        "Error creating tsk_image_names table: %s\n")) {
        return 1;
    }

    if (attempt_exec("CREATE TABLE tsk_vs_info (vs_type INTEGER, img_offset INTEGER NOT NULL, block_size INTEGER NOT NULL);",
        "Error creating tsk_vs_info table: %s\n")) {
        return 1;
    }

    if (attempt_exec("CREATE TABLE tsk_vs_parts (vol_id INTEGER PRIMARY KEY, start INTEGER NOT NULL, length INTEGER NOT NULL, desc TEXT, flags INTEGER);",
        "Error creating tsk_vol_info table: %s\n")) {
        return 1;
    }

    if (attempt_exec("CREATE TABLE tsk_fs_info (fs_id INTEGER PRIMARY KEY, img_offset INTEGER, vol_id INTEGER NOT NULL, fs_type INTEGER, block_size INTEGER, block_count INTEGER, root_inum INTEGER, first_inum INTEGER, last_inum INTEGER);",
        "Error creating tsk_fs_info table: %s\n")) {
        return 1;
    }

    if (attempt_exec("CREATE TABLE tsk_fs_files (fs_id INTEGER NOT NULL, file_id INTEGER NOT NULL, attr_type INTEGER, attr_id INTEGER, name TEXT NOT NULL, par_file_id INTEGER, dir_type INTEGER, meta_type INTEGER, dir_flags INTEGER, meta_flags INTEGER, size INTEGER, ctime INTEGER, crtime INTEGER, atime INTEGER, mtime INTEGER, mode INTEGER, uid INTEGER, gid INTEGER);",
        "Error creating tsk_fs_files table: %s\n")) {
        return 1;
    }

    if (m_blkMapFlag) {
        if (attempt_exec("CREATE TABLE tsk_fs_blocks (fs_id INTEGER NOT NULL, blk_start INTEGER NOT NULL, blk_len INTEGER NOT NULL, file_id INTEGER NOT NULL, attr_type INTEGER, attr_id INTEGER);",
            "Error creating tsk_fs_blocks table: %s\n")) {
            return 1;
        }
    }
 
    return 0;
}

int TskImgDBSqlite::createParentDirIndex()
{
    return attempt_exec
        ("CREATE INDEX parentDir ON tsk_fs_files(par_file_id, fs_id);",
        "Error creating tsk_fs_files index on par_file_id: %s\n");
}



/*
 * If the database file exists this method will open it otherwise
 * it will create a new database. 
 */
int TskImgDBSqlite::open()
{
    if (m_utf8) {
        if (sqlite3_open(m_dbFilePathUtf8, &m_db) != SQLITE_OK) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_AUTO_DB);
            tsk_error_set_errstr("Can't open database: %s\n",
                sqlite3_errmsg(m_db));
            sqlite3_close(m_db);
            return 1;
        }
    }  else {
        if (sqlite3_open16(m_dbFilePath, &m_db) != SQLITE_OK) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_AUTO_DB);
            tsk_error_set_errstr("Can't open database: %s\n",
                sqlite3_errmsg(m_db));
            sqlite3_close(m_db);
            return 1;
        }
    }

    return 0;
}


int TskImgDBSqlite::addImageInfo(int type, int size)
{
    char stmt[1024];
    
    if (!m_db)
        return 1;

    snprintf(stmt, 1024,
        "INSERT INTO tsk_image_info (type, ssize) VALUES (%d, %u);",
        type, size);
    return attempt_exec(stmt,
        "Error adding data to tsk_image_info table: %s\n");
}

int TskImgDBSqlite::addImageName(char const * imgName)
{
    char stmt[1024];

    if (!m_db)
        return 1;

    snprintf(stmt, 1024,
        "INSERT INTO tsk_image_names (name) VALUES ('%s')",
        imgName);
    return attempt_exec(stmt,
        "Error adding data to tsk_image_names table: %s\n");
}


int TskImgDBSqlite::addVsInfo(const TSK_VS_INFO * vs_info)
{
    char statement[1024];

    if (!m_db)
        return 1;

    snprintf(statement, 1024,
        "INSERT INTO tsk_vs_info (vs_type, img_offset, block_size) VALUES (%d,%"
        PRIuOFF ",%d)", vs_info->vstype, vs_info->offset,
        vs_info->block_size);

    return attempt_exec(statement,
        "Error adding data to tsk_vs_info table: %s\n");
}





/**
 * Adds the sector addresses of the volumes into the db.
 */
int TskImgDBSqlite::addVolumeInfo(const TSK_VS_PART_INFO * vs_part)
{
    char stmt[1024];

    if (!m_db)
        return 1;

    snprintf(stmt, 1024,
        "INSERT INTO tsk_vs_parts (vol_id, start, length, desc, flags) VALUES (%d,%"
        PRIuOFF ",%" PRIuOFF ",'%s',%d)", (int) vs_part->addr,
        vs_part->start, vs_part->len, vs_part->desc, vs_part->flags);

    return attempt_exec(stmt,
        "Error adding data to tsk_vol_info table: %s\n");
}

int TskImgDBSqlite::addFsInfo(int volId, int fsId, const TSK_FS_INFO * fs_info)
{
    char stmt[1024];

    if (!m_db)
        return 1;

    snprintf(stmt, 1024,
        "INSERT INTO tsk_fs_info (fs_id, img_offset, vol_id, fs_type, block_size, "
        "block_count, root_inum, first_inum, last_inum) VALUES (%d,%"
        PRIuOFF ",%d,'%d',%d,%" PRIuDADDR ",%" PRIuINUM ",%" PRIuINUM ",%"
        PRIuINUM ")", fsId, fs_info->offset, volId,
        (int) fs_info->ftype, fs_info->block_size, fs_info->block_count,
        fs_info->root_inum, fs_info->first_inum, fs_info->last_inum);

    return attempt_exec(stmt,
        "Error adding data to tsk_fs_info table: %s\n");
}



/*
 * Add file data to the file table
 * Return 0 on success, 1 on error.
 */
int TskImgDBSqlite::addFsFile(TSK_FS_FILE * fs_file,
    const TSK_FS_ATTR * fs_attr, const char *path, int fs_id)
{
    char
     foo[1024];
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
        ",%d,%d,%d,%d,%d,%d,%d)", fs_id, fs_file->name->meta_addr,
        type, idx, name, fs_file->name->par_addr, fs_file->name->type,
        meta_type, fs_file->name->flags, meta_flags, size, crtime, ctime,
        atime, mtime, meta_mode, gid, uid);

    if (attempt_exec(foo,
        "Error adding data to tsk_fs_files table: %s\n")) {
        free(name);
        return 1;
    }

    free(name);
    return 0;
}

int TskImgDBSqlite::begin()
{
    if (!m_db)
        return 1;

    return attempt_exec("BEGIN",
        "Error using BEGIN for insert transaction: %s\n");
}

int TskImgDBSqlite::commit()
{
    if (!m_db)
        return 1;

    return attempt_exec("COMMIT",
        "Error using COMMIT for insert transaction: %s\n");
}



/**
 * Add block info to the database.  This table stores the run information for each file so that we
 * can map which blocks are used by what files.
 * @param a_fsId Id that the file is located in
 * @param a_fileId ID of the file
 * @param a_sequence The sequence number of this run in the file (0 for the first run, 1 for the second run, etc.)
 * @param a_blk_addr Block address (the address that the file system uses -- NOT the physical sector addr)
 * @param a_len The number of blocks in the run
 * @param a_attrType Type of file attribute
 * @param a_attrId Id of file attribute
 * @returns 1 on error
 */
int TskImgDBSqlite::addFsBlockInfo(int a_fsId, uint64_t a_fileId, int a_sequence, uint64_t a_blk_addr, uint64_t a_len, TSK_FS_ATTR_TYPE_ENUM a_attrType, uint16_t a_attrId)
{
    char foo[1024];

    snprintf(foo, 1024,
        "INSERT INTO tsk_fs_blocks (fs_id, blk_start, blk_len, file_id, attr_type, attr_id) VALUES (%d,%"
        PRIuDADDR ",%" PRIuDADDR ",%" PRIuINUM ",%d,%d)",
        a_fsId, a_blk_addr, a_len, a_fileId, a_attrType, a_attrId);

    return attempt_exec(foo, "Error adding data to tsk_fs_info table: %s\n");
}


bool TskImgDBSqlite::dbExist() const
{
    if (m_db)
        return true;
    else
        return false;
}
