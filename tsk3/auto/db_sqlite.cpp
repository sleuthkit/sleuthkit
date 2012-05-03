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
 * \file db_sqlite.cpp
 * Contains code to perform operations against SQLite database. 
 */

#include "tsk_db_sqlite.h"
#include "sqlite3.h"
#include <string.h>


#define TSK_SCHEMA_VER 2

/**
 * Set the locations and logging object.  Must call
 * open() before the object can be used.
 */
TskDbSqlite::TskDbSqlite(const char *a_dbFilePathUtf8, bool a_blkMapFlag)
{
    strncpy(m_dbFilePathUtf8, a_dbFilePathUtf8, 1024);
    m_utf8 = true;
    m_blkMapFlag = a_blkMapFlag;
    m_db = NULL;
    m_selectFilePreparedStmt = NULL;
}

#ifdef TSK_WIN32
//@@@@
TskDbSqlite::TskDbSqlite(const TSK_TCHAR * a_dbFilePath, bool a_blkMapFlag)
{
    wcsncpy(m_dbFilePath, a_dbFilePath, 1024);
    m_utf8 = false;
    m_blkMapFlag = a_blkMapFlag;
    m_db = NULL;
    m_selectFilePreparedStmt = NULL;
}
#endif

TskDbSqlite::~TskDbSqlite()
{
    (void) close();
}

/*
 * Close the Sqlite database.
 * Return 0 on success, 1 on failure
 */
int
 TskDbSqlite::close()
{

    if (m_db) {
        cleanupFilePreparedStmt();
        sqlite3_close(m_db);
        m_db = NULL;
    }
    return 0;
}


int
 TskDbSqlite::attempt(int resultCode, int expectedResultCode,
    const char *errfmt)
{
    if (resultCode != expectedResultCode) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr(errfmt, sqlite3_errmsg(m_db), resultCode);
        return 1;
    }
    return 0;
}


int
 TskDbSqlite::attempt(int resultCode, const char *errfmt)
{
    return attempt(resultCode, SQLITE_OK, errfmt);
}



/**
 * Execute a statement and sets TSK error values on error 
 * @returns 1 on error, 0 on success
 */
int
 TskDbSqlite::attempt_exec(const char *sql, int (*callback) (void *, int,
        char **, char **), void *callback_arg, const char *errfmt)
{
    char *
        errmsg;

    if (!m_db)
        return 1;

    if (sqlite3_exec(m_db, sql, callback, callback_arg,
            &errmsg) != SQLITE_OK) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr(errfmt, errmsg);
        sqlite3_free(errmsg);
        return 1;
    }
    return 0;
}

/**
 * Execute a statement.  
 * @returns 1 on error, 0 on success
 */
int
 TskDbSqlite::attempt_exec(const char *sql, const char *errfmt)
{
    return attempt_exec(sql, NULL, NULL, errfmt);
}


/**
 * @returns 1 on error, 0 on success
 */
int
 TskDbSqlite::prepare_stmt(const char *sql, sqlite3_stmt ** ppStmt)
{
    if (sqlite3_prepare_v2(m_db, sql, -1, ppStmt, NULL) != SQLITE_OK) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr("Error preparing SQL statement: %s\n", sql);
        tsk_error_print(stderr);
        return 1;
    }
    return 0;
}



/**
 * @returns 1 on error, 0 on success
 */
int
 TskDbSqlite::addObject(DB_OBJECT_TYPES type, int64_t parObjId,
    int64_t & objId)
{
    char
     stmt[1024];

    snprintf(stmt, 1024,
        "INSERT INTO tsk_objects (obj_id, par_obj_id, type) VALUES (NULL, %lld, %d);",
        parObjId, type);
    if (attempt_exec(stmt, "Error adding data to tsk_objects table: %s\n")) {
        return 1;
    }

    objId = sqlite3_last_insert_rowid(m_db);

    return 0;
}





/** 
 * Initialize the open DB: set PRAGMAs, create tables and indexes
 * @returns 1 on error
 */
int
 TskDbSqlite::initialize()
{
    char
     foo[1024];

    // disable synchronous for loading the DB since we have no crash recovery anyway...
    if (attempt_exec("PRAGMA synchronous =  OFF;",
            "Error setting PRAGMA synchronous: %s\n")) {
        return 1;
    }

    if (attempt_exec
        ("CREATE TABLE tsk_db_info (schema_ver INTEGER, tsk_ver INTEGER);",
            "Error creating tsk_db_info table: %s\n")) {
        return 1;
    }

    snprintf(foo, 1024,
        "INSERT INTO tsk_db_info (schema_ver, tsk_ver) VALUES (%d, %d);",
        TSK_SCHEMA_VER, TSK_VERSION_NUM);
    if (attempt_exec(foo, "Error adding data to tsk_db_info table: %s\n")) {
        return 1;
    }

    if (attempt_exec
        ("CREATE TABLE tsk_objects (obj_id INTEGER PRIMARY KEY, par_obj_id INTEGER, type INTEGER);",
            "Error creating tsk_objects table: %s\n")
        ||
        attempt_exec
        ("CREATE TABLE tsk_image_info (obj_id INTEGER, type INTEGER, ssize INTEGER);",
            "Error creating tsk_image_info table: %s\n")
        ||
        attempt_exec
        ("CREATE TABLE tsk_image_names (obj_id INTEGER, name TEXT, sequence INTEGER);",
            "Error creating tsk_image_names table: %s\n")
        ||
        attempt_exec
        ("CREATE TABLE tsk_vs_info (obj_id INTEGER, vs_type INTEGER, img_offset INTEGER NOT NULL, block_size INTEGER NOT NULL);",
            "Error creating tsk_vs_info table: %s\n")
        ||
        attempt_exec
        ("CREATE TABLE tsk_vs_parts (obj_id INTEGER PRIMARY KEY, addr INTEGER, start INTEGER NOT NULL, length INTEGER NOT NULL, desc TEXT, flags INTEGER);",
            "Error creating tsk_vol_info table: %s\n")
        ||
        attempt_exec
        ("CREATE TABLE tsk_fs_info (obj_id INTEGER PRIMARY KEY, img_offset INTEGER, fs_type INTEGER, block_size INTEGER, block_count INTEGER, root_inum INTEGER, first_inum INTEGER, last_inum INTEGER);",
            "Error creating tsk_fs_info table: %s\n")
        ||
        attempt_exec
        ("CREATE TABLE tsk_files (fs_obj_id INTEGER NOT NULL, obj_id INTEGER NOT NULL UNIQUE, attr_type INTEGER, attr_id INTEGER, name TEXT NOT NULL, meta_addr INTEGER, type INTEGER, has_layout INTEGER, has_path INTEGER, dir_type INTEGER, meta_type INTEGER, dir_flags INTEGER, meta_flags INTEGER, size INTEGER, ctime INTEGER, crtime INTEGER, atime INTEGER, mtime INTEGER, mode INTEGER, uid INTEGER, gid INTEGER, md5 TEXT, known INTEGER, parent_path TEXT);",
            "Error creating tsk_fs_files table: %s\n")
        ||
        attempt_exec
        ("CREATE TABLE tsk_files_path (obj_id INTEGER, path TEXT)",
            "Error creating tsk_files_path table: %s\n")
        ||
        attempt_exec
        ("CREATE TABLE tsk_files_derived (obj_id INTEGER UNIQUE, derived_id INTEGER, rederive TEXT)",
            "Error creating tsk_files_derived table: %s\n")
        ||
        attempt_exec
        ("CREATE TABLE tsk_files_derived_method (derived_id INTEGER PRIMARY KEY, tool_name TEXT, tool_version TEXT, other TEXT)",
            "Error creating tsk_files_derived_method table: %s\n")
        ||
        attempt_exec
        ("CREATE TABLE blackboard_artifacts (artifact_id INTEGER PRIMARY KEY, obj_id INTEGER NOT NULL, artifact_type_id INTEGER)",
            "Error creating blackboard_artifact table: %s\n")
        ||
        attempt_exec
        ("CREATE TABLE blackboard_attributes (artifact_id INTEGER NOT NULL, source TEXT, context TEXT, attribute_type_id INTEGER NOT NULL, value_type INTEGER NOT NULL, "
        "value_byte BLOB, value_text TEXT, value_int32 INTEGER, value_int64 INTEGER, value_double NUMERIC(20, 10))",
            "Error creating blackboard_attribute table: %s\n")
        ||
        attempt_exec
        ("CREATE TABLE blackboard_artifact_types (artifact_type_id INTEGER PRIMARY KEY, type_name TEXT, display_name TEXT)",
            "Error creating blackboard_artifact_types table: %s\n")
        ||
        attempt_exec
        ("CREATE TABLE blackboard_attribute_types (attribute_type_id INTEGER PRIMARY KEY, type_name TEXT, display_name TEXT)",
            "Error creating blackboard_attribute_types table: %s\n")) {
        return 1;
    }

    if (m_blkMapFlag) {
        if (attempt_exec
            ("CREATE TABLE tsk_file_layout (fs_id INTEGER NOT NULL, byte_start INTEGER NOT NULL, byte_len INTEGER NOT NULL, obj_id INTEGER, sequence INTEGER);",
                "Error creating tsk_fs_blocks table: %s\n")) {
            return 1;
        }
    }

    if (createIndexes())
        return 1;


    return 0;
}

/**
 * @returns 1 on error, 0 on success
 */
int
 TskDbSqlite::createIndexes()
{
    return
        attempt_exec("CREATE INDEX parObjId ON tsk_objects(par_obj_id);",
        "Error creating tsk_objects index on par_obj_id: %s\n")||
        attempt_exec("CREATE INDEX objID ON blackboard_artifacts(obj_id);",
        "Error creating objID index on blackboard_artifacts: %s\n")||
        attempt_exec("CREATE INDEX artifactID ON blackboard_artifacts(artifact_id);",
        "Error creating artifact_id index on blackboard_artifacts: %s\n")||
        attempt_exec("CREATE INDEX attrsArtifactID ON blackboard_attributes(artifact_id);",
        "Error creating artifact_id index on blackboard_attributes: %s\n");

    
}


/*
 * Open the database (will create file if it does not exist).
 * @param a_toInit Set to true if this is a new database that needs to have the tables created
 * @ returns 1 on error and 0 on success
 */
int
 TskDbSqlite::open(bool a_toInit)
{

    if (m_utf8) {
        if (attempt(sqlite3_open(m_dbFilePathUtf8, &m_db),
                "Can't open database: %s\n")) {
            sqlite3_close(m_db);
            return 1;
        }
    }
    else {
        if (attempt(sqlite3_open16(m_dbFilePath, &m_db),
                "Can't open database: %s\n")) {
            sqlite3_close(m_db);
            return 1;
        }
    }

    // enable finer result codes
    sqlite3_extended_result_codes(m_db, true);
    
    // create the tables if we need to
    if (a_toInit) {
        if (initialize())
            return 1;
    }
    
    if (setupFilePreparedStmt()) {
        return 1;
    }

    return 0;
}

/**
 * Must be called on an intialized database, before adding any content to it.
 */
int
 TskDbSqlite::setupFilePreparedStmt()
{
    if (prepare_stmt
        ("SELECT obj_id FROM tsk_files WHERE meta_addr IS ? AND fs_obj_id IS ?",
            &m_selectFilePreparedStmt)) {
        return 1;
    }

    return 0;
}


/**
 * Must be called after adding content to the database.
 */
void
 TskDbSqlite::cleanupFilePreparedStmt()
{
    if (m_selectFilePreparedStmt != NULL) {
        sqlite3_finalize(m_selectFilePreparedStmt);
        m_selectFilePreparedStmt = NULL;
    }
}

/**
 * @returns 1 on error, 0 on success
 */
int
 TskDbSqlite::addImageInfo(int type, int size, int64_t & objId)
{
    char
     stmt[1024];

    snprintf(stmt, 1024,
        "INSERT INTO tsk_objects (obj_id, par_obj_id, type) VALUES (NULL, NULL, %d);",
        DB_OBJECT_TYPE_IMG);
    if (attempt_exec(stmt, "Error adding data to tsk_objects table: %s\n"))
        return 1;

    objId = sqlite3_last_insert_rowid(m_db);

    snprintf(stmt, 1024,
        "INSERT INTO tsk_image_info (obj_id, type, ssize) VALUES (%lld, %d, %d);",
        objId, type, size);
    return attempt_exec(stmt,
        "Error adding data to tsk_image_info table: %s\n");
}

/**
 * @returns 1 on error, 0 on success
 */
int
 TskDbSqlite::addImageName(int64_t objId, char const *imgName,
    int sequence)
{
    char
     stmt[1024];

    snprintf(stmt, 1024,
        "INSERT INTO tsk_image_names (obj_id, name, sequence) VALUES (%lld, '%s', %d)",
        objId, imgName, sequence);

    return attempt_exec(stmt,
        "Error adding data to tsk_image_names table: %s\n");
}


/**
 * @returns 1 on error, 0 on success
 */
int
 TskDbSqlite::addVsInfo(const TSK_VS_INFO * vs_info, int64_t parObjId,
    int64_t & objId)
{
    char
     stmt[1024];

    if (addObject(DB_OBJECT_TYPE_VS, parObjId, objId))
        return 1;

    snprintf(stmt, 1024,
        "INSERT INTO tsk_vs_info (obj_id, vs_type, img_offset, block_size) VALUES (%lld, %d,%"
        PRIuOFF ",%d)", objId, vs_info->vstype, vs_info->offset,
        vs_info->block_size);

    return attempt_exec(stmt,
        "Error adding data to tsk_vs_info table: %s\n");
}





/**
 * Adds the sector addresses of the volumes into the db.
 * @returns 1 on error, 0 on success
 */
int
 TskDbSqlite::addVolumeInfo(const TSK_VS_PART_INFO * vs_part,
    int64_t parObjId, int64_t & objId)
{
    char
     stmt[1024];

    if (addObject(DB_OBJECT_TYPE_VOL, parObjId, objId))
        return 1;

    snprintf(stmt, 1024,
        "INSERT INTO tsk_vs_parts (obj_id, addr, start, length, desc, flags)"
        "VALUES (%lld, %" PRIuPNUM ",%" PRIuOFF ",%" PRIuOFF ",'%s',%d)",
        objId, (int) vs_part->addr, vs_part->start, vs_part->len,
        vs_part->desc, vs_part->flags);

    return attempt_exec(stmt,
        "Error adding data to tsk_vs_parts table: %s\n");
}

/**
 * @returns 1 on error, 0 on success
 */
int
 TskDbSqlite::addFsInfo(const TSK_FS_INFO * fs_info, int64_t parObjId,
    int64_t & objId)
{
    char
     stmt[1024];

    if (addObject(DB_OBJECT_TYPE_FS, parObjId, objId))
        return 1;

    snprintf(stmt, 1024,
        "INSERT INTO tsk_fs_info (obj_id, img_offset, fs_type, block_size, block_count, "
        "root_inum, first_inum, last_inum) "
        "VALUES ("
        "%lld,%" PRIuOFF ",%d,%u,%" PRIuDADDR ","
        "%" PRIuINUM ",%" PRIuINUM ",%" PRIuINUM ")",
        objId, fs_info->offset, (int) fs_info->ftype, fs_info->block_size,
        fs_info->block_count, fs_info->root_inum, fs_info->first_inum,
        fs_info->last_inum);

    return attempt_exec(stmt,
        "Error adding data to tsk_fs_info table: %s\n");
}

// ?????
//int TskDbSqlite::addCarvedFile(TSK_FS_FILE * fs_file,
//    const TSK_FS_ATTR * fs_attr, const char *path, int64_t fsObjId, int64_t parObjId, int64_t & objId)
//{
//
//    return addFile(fs_file, fs_attr, path, fsObjId, parObjId, objId);
//}


/**
 * Add a file system file to the database
 * @param fs_file File structure to add
 * @param fs_attr Specific attribute to add
 * @param path Path of the file
 * @param md5 Binary value of MD5 (i.e. 16 bytes) or NULL 
 * @param known Status regarding if it was found in hash databse or not
 * @param fsObjId File system object of its file system
 * @param objId ID that was assigned to it from the objects table
 * @returns 1 on error and 0 on success
 */
int
 TskDbSqlite::addFsFile(TSK_FS_FILE * fs_file,
    const TSK_FS_ATTR * fs_attr, const char *path,
    const unsigned char *const md5, const TSK_AUTO_CASE_KNOWN_FILE_ENUM known,
    int64_t fsObjId, int64_t & objId)
{
    int64_t parObjId = 0;

    if (fs_file->name == NULL)
        return 0;

    if (fs_file->fs_info->root_inum == fs_file->name->meta_addr) {
        // this entry is for root directory
        parObjId = fsObjId;
    }
    else {
        parObjId = findParObjId(fs_file, fsObjId);
        if (parObjId == -1) {
            //error
            return 1;
        }    
    }

    return addFile(fs_file, fs_attr, path, md5, known, fsObjId, parObjId, objId);
}

/**
 * Store meta_addr to object id mapping of the directory in a local cache map
 * @param fsObjId fs id of this directory
 * @param meta_addr meta_addr of this directory
 * @param objId object id of this directory from the objects table
 */
void TskDbSqlite::storeObjId(const int64_t & fsObjId, const TSK_INUM_T & meta_addr, const int64_t & objId) {
    map<TSK_INUM_T,int64_t>::iterator it = m_parentDirIdCache[fsObjId].find(meta_addr);
    if (it == m_parentDirIdCache[fsObjId].end() )
        //store only if does not exist
        m_parentDirIdCache[fsObjId][meta_addr] = objId;
}

/**
 * Find parent object id of TSK_FS_FILE. Use local cache map, if not found, fall back to SQL
 * @param fs_file file to find parent obj id for
 * @param fsObjId fs id of this file
 * @returns parent obj id ( > 0), -1 on error
 */
int64_t TskDbSqlite::findParObjId(const TSK_FS_FILE * fs_file, const int64_t & fsObjId) {
    int64_t parObjId = -1;

    //get from cache by parent meta addr, if available
    map<TSK_INUM_T,int64_t>::iterator it = m_parentDirIdCache[fsObjId].find(fs_file->name->par_addr);
    if (it != m_parentDirIdCache[fsObjId].end() ) {
        parObjId = it->second;
    }
    
    if (parObjId > 0)
        //return cached
        return parObjId;

    // Find the parent file id in the database using the parent metadata address
    if (attempt(sqlite3_bind_int64(m_selectFilePreparedStmt, 1, fs_file->name->par_addr),
                "Error binding meta_addr to statment: %s (result code %d)\n")
        || attempt(sqlite3_bind_int64(m_selectFilePreparedStmt, 2, fsObjId),
            "Error binding fs_obj_id to statment: %s (result code %d)\n")
        || attempt(sqlite3_step(m_selectFilePreparedStmt), SQLITE_ROW,
            "Error selecting file id by meta_addr: %s (result code %d)\n"))
    {
        // Statement may be used again, even after error
        sqlite3_reset(m_selectFilePreparedStmt);
        return -1;
    }

    parObjId = sqlite3_column_int64(m_selectFilePreparedStmt, 0);

    if (attempt(sqlite3_reset(m_selectFilePreparedStmt),
        "Error resetting 'select file id by meta_addr' statement: %s\n")) {
            return -1;
    }

    return parObjId;
}

/**
 * Add file data to the file table
 * @param md5 binary value of MD5 (i.e. 16 bytes) or NULL
 * Return 0 on success, 1 on error.
 */
int
 TskDbSqlite::addFile(TSK_FS_FILE * fs_file,
    const TSK_FS_ATTR * fs_attr, const char *path,
    const unsigned char *const md5, const TSK_AUTO_CASE_KNOWN_FILE_ENUM known,
    int64_t fsObjId, int64_t parObjId,
    int64_t & objId)
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
    int
     type = 0;
    int
     idx = 0;

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
    char *
        name;
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


    // clean up path
    size_t path_len = strlen(path);
    size_t epath_len = path_len*2;
    char *
        escaped_path;
    if ((escaped_path = (char *) tsk_malloc(epath_len + 2)) == NULL) { // +2 = space for leading slash and terminating null
        return 1;
    }

    size_t k = 0;
    escaped_path[k++] = '/'; // add a leading slash
    for (size_t i = 0; i < path_len && k < epath_len; i++) {
        // ' is special in SQLite
        if (path[i] == '\'') {
            escaped_path[k++] = '\'';
            escaped_path[k++] = '\'';
        }
        else {
            escaped_path[k++] = path[i];
        }
    }


    char
     md5Text[1024] = "NULL";

    // if md5 hashes are being used
    if (md5 != NULL) {
        char
            md5TextBuff[16 * 2 + 1];
        memset(md5TextBuff, 0, 16*2+1);

        // copy the hash as hexidecimal into the buffer
        for (int i = 0; i < 16; i++) {
            sprintf(&(md5TextBuff[i * 2]), "%x%x", (md5[i] >> 4) & 0xf,
                md5[i] & 0xf);
        }
        snprintf(md5Text, 1024, "'%s'", md5TextBuff);
    }


    if (addObject(DB_OBJECT_TYPE_FILE, parObjId, objId))
        return 1;

    snprintf(foo, 1024,
        "INSERT INTO tsk_files (fs_obj_id, obj_id, type, attr_type, attr_id, name, meta_addr, dir_type, meta_type, dir_flags, meta_flags, size, crtime, ctime, atime, mtime, mode, gid, uid, md5, known, parent_path) "
        "VALUES ("
        "%lld,%lld,"
        "%d,"
        "%d,%d,'%s',"
        "%" PRIuINUM ","
        "%d,%d,%d,%d,"
        "%" PRIuOFF ","
        "%d,%d,%d,%d,%d,%d,%d,%s,%d,"
        "'%s')",
        fsObjId, objId,
        DB_FILES_TYPE_FS,
        type, idx, name,
        fs_file->name->meta_addr,
        fs_file->name->type, meta_type, fs_file->name->flags, meta_flags,
        size, crtime, ctime, atime, mtime, meta_mode, gid, uid, md5Text, known,
        escaped_path);

    if (attempt_exec(foo, "Error adding data to tsk_fs_files table: %s\n")) {
        free(name);
        return 1;
    }

    //if dir, update parent id cache
    if (meta_type == TSK_FS_META_TYPE_DIR) {
        storeObjId(fsObjId, fs_file->name->meta_addr, objId);
    }

    free(name);
    return 0;
}



/**
 * Create a savepoint.  Call revertSavepoint() or releaseSavepoint()
 * to revert or commit.
 * @param name Name to call savepoint
 * @returns 1 on error, 0 on success
 */
int
 TskDbSqlite::createSavepoint(const char *name)
{
    char
     buff[1024];

    snprintf(buff, 1024, "SAVEPOINT %s", name);

    return attempt_exec(buff, "Error setting savepoint: %s\n");
}

/**
 * Rollback to specified savepoint and release
 * @param name Name of savepoint
 * @returns 1 on error, 0 on success
 */
int
 TskDbSqlite::revertSavepoint(const char *name)
{
    char
     buff[1024];

    snprintf(buff, 1024, "ROLLBACK TO SAVEPOINT %s", name);

    if (attempt_exec(buff, "Error rolling back savepoint: %s\n"))
        return 1;

    return releaseSavepoint(name);
}

/**
 * Release a savepoint.  Commits if savepoint was not rollbacked.
 * @param name Name of savepoint
 * @returns 1 on error, 0 on success
 */
int
 TskDbSqlite::releaseSavepoint(const char *name)
{
    char
     buff[1024];

    snprintf(buff, 1024, "RELEASE SAVEPOINT %s", name);

    return attempt_exec(buff, "Error releasing savepoint: %s\n");
}





/**
 * Add block info to the database.  This table stores the run information for each file so that we
 * can map which blocks are used by what files.
 * @param a_fsObjId Id that the file is located in
 * @param a_fileObjId ID of the file
 * @param a_byteStart Byte address relative to the start of the image file
 * @param a_byteLen Length of the run in bytes
 * @param a_sequence Sequence of this run in the file
 * @returns 1 on error
 */
int
 TskDbSqlite::addFsBlockInfo(int64_t a_fsObjId, int64_t a_fileObjId,
    uint64_t a_byteStart, uint64_t a_byteLen, int a_sequence)
{
    char
     foo[1024];

    snprintf(foo, 1024,
        "INSERT INTO tsk_file_layout (fs_id, byte_start, byte_len, obj_id, sequence) VALUES (%lld, %lld, %llu, %llu, %d)",
        a_fsObjId, a_byteStart, a_byteLen, a_fileObjId, a_sequence);

    return attempt_exec(foo,
        "Error adding data to tsk_fs_info table: %s\n");
}


/**
 * Adds information about a carved file into the database.
 * @param size Number of bytes in file
 * @param runStarts Array with starting sector (relative to start of image) for each run in file.
 * @param runLengths Array with number of sectors in each run 
 * @param numRuns Number of entries in previous arrays
 * @param fileId Carved file Id (output)
 * @returns 0 on success or 1 on error.
 */
int
 TskDbSqlite::addCarvedFileInfo(int fsObjId, const char *fileName,
    uint64_t size, int64_t & objId)
{
    char
     foo[1024];

    // clean up special characters in name before we insert
    size_t len = strlen(fileName);
    char *
        name;
    size_t nlen = 2 * (len);
    if ((name = (char *) tsk_malloc(nlen + 1)) == NULL) {
        return 1;
    }

    size_t j = 0;
    for (size_t i = 0; i < len && j < nlen; i++) {
        // ' is special in SQLite
        if (fileName[i] == '\'') {
            name[j++] = '\'';
            name[j++] = '\'';
        }
        else {
            name[j++] = fileName[i];
        }
    }

    if (addObject(DB_OBJECT_TYPE_FILE, fsObjId, objId))
        return 1;

    snprintf(foo, 1024,
        "INSERT INTO tsk_files (fs_obj_id, obj_id, type, attr_type, attr_id, name, meta_addr, dir_type, meta_type, dir_flags, meta_flags, size, crtime, ctime, atime, mtime, mode, gid, uid) "
        "VALUES ("
        "%d,%lld,"
        "%d,"
        "NULL,NULL,'%s',"
        "NULL,"
        "%d,%d,%d,%d,"
        "%" PRIuOFF ","
        "NULL,NULL,NULL,NULL,NULL,NULL,NULL)",
        fsObjId, objId,
        DB_FILES_TYPE_CARVED,
        name,
        TSK_FS_NAME_TYPE_REG, TSK_FS_META_TYPE_REG,
        TSK_FS_NAME_FLAG_UNALLOC, TSK_FS_NAME_FLAG_UNALLOC, size);

    if (attempt_exec(foo, "Error adding data to tsk_fs_files table: %s\n")) {
        free(name);
        return 1;
    }

    free(name);
    return 0;
}



/** 
 * Returns true if database is opened.
 */
bool
TskDbSqlite::dbExist() const 
{
    if (m_db)
        return true;
    else
        return false;
}

bool
TskDbSqlite::inTransaction()
{
    return (sqlite3_get_autocommit(m_db) == 0);
}
