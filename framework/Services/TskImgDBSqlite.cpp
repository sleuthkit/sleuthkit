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

/**
 * \file TskImgDBSqlite.cpp
 * A SQLite based implementation of the framework data access layer.
 */

#include <stdio.h>
#include <cassert>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <map>

#include "TskImgDBSqlite.h"
#include "TskServices.h"
#include "Poco/UnicodeConverter.h"
#include "Utilities/TskException.h"

#define IMGDB_CHUNK_SIZE 1024*1024*1 // what size chunks should the database use when growing and shrinking
#define IMGDB_MAX_RETRY_COUNT 50    // how many times will we retry a SQL statement
#define IMGDB_RETRY_WAIT 100   // how long (in milliseconds) are we willing to wait between retries

/**
 * Set the database location.  Must call
 * initialize() before the object can be used.
 * @param a_outpath Directory to store the database in. This 
 * directory must already exist.
*/
TskImgDBSqlite::TskImgDBSqlite(const wchar_t * a_outpath)
{
    wcsncpy_s(m_outPath, a_outpath, 256);
    // ensure that the path ends with a '\'
    if (m_outPath[wcslen(m_outPath)-1] != '\\') {
        int len1 = wcslen(m_outPath);
        m_outPath[len1] = '\\';
        m_outPath[len1+1] = '\0';
    }
    wcsncpy_s(m_dbFilePath, m_outPath, 256);
    wcsncat_s(m_dbFilePath, L"image.db", 256);
    m_db = NULL;
}

TskImgDBSqlite::~TskImgDBSqlite()
{
    (void) close();
}

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

int TskImgDBSqlite::dropTables()
{
    if (!m_db)
        return 1;

    char * errmsg;
    // Drop all the tables. No error checking just Teutonic Destruction...
    sqlite3_exec(m_db, "DROP TABLE db_info",NULL, NULL, &errmsg);
    sqlite3_exec(m_db, "DROP TABLE image_info",NULL, NULL, &errmsg);
    sqlite3_exec(m_db, "DROP TABLE image_names",NULL, NULL, &errmsg);
    sqlite3_exec(m_db, "DROP TABLE vol_info",NULL, NULL, &errmsg);
    sqlite3_exec(m_db, "DROP TABLE fs_info",NULL, NULL, &errmsg);
    sqlite3_exec(m_db, "DROP TABLE fs_files",NULL, NULL, &errmsg);
    sqlite3_exec(m_db, "DROP TABLE fs_blocks",NULL, NULL, &errmsg);
    sqlite3_exec(m_db, "DROP TABLE files",NULL, NULL, &errmsg);
    sqlite3_exec(m_db, "DROP TABLE derived_files",NULL, NULL, &errmsg);
    sqlite3_exec(m_db, "DROP TABLE carved_files",NULL, NULL, &errmsg);
    sqlite3_exec(m_db, "DROP TABLE carved_sectors",NULL, NULL, &errmsg);
    sqlite3_exec(m_db, "DROP TABLE alloc_unalloc_map", NULL, NULL, &errmsg);
    sqlite3_exec(m_db, "DROP TABLE blackboard", NULL, NULL, &errmsg);
    sqlite3_exec(m_db, "DROP TABLE file_hashes", NULL, NULL, &errmsg);
    sqlite3_exec(m_db, "DROP TABLE modules", NULL, NULL, &errmsg);
    sqlite3_exec(m_db, "DROP TABLE module_status", NULL, NULL, &errmsg);
    sqlite3_exec(m_db, "DROP TABLE unalloc_img_status", NULL, NULL, &errmsg);
    sqlite3_exec(m_db, "DROP TABLE unused_sectors", NULL, NULL, &errmsg);

    return 0;
}

int TskImgDBSqlite::initialize()
{
    wchar_t infoMessage[MAX_BUFF_LENGTH];
    char * errmsg;

    // Open the database.
    if (open() != 0)
    {
        // Error message will have been logged by open()
        return 1;
    }

    // Clean up the whole database.
    dropTables();

    char * stmt;

    // ----- DB_INFO
    stmt = "CREATE TABLE db_info (name TEXT PRIMARY KEY, version TEXT)";
    if (sqlite3_exec(m_db, stmt, NULL, NULL, &errmsg) != SQLITE_OK) {
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::initialize - Error creating db_info table: %S", errmsg);
        LOGERROR(infoMessage);

        sqlite3_free(errmsg);
        return 1;
    }

    // ----- IMAGE_INFO
    stmt = "CREATE TABLE image_info (type INTEGER, ssize INTEGER)";
    if (sqlite3_exec(m_db, stmt, NULL, NULL, &errmsg) != SQLITE_OK) {
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::initialize - Error creating image_info table: %S", errmsg);
        LOGERROR(infoMessage);

        sqlite3_free(errmsg);
        return 1;
    }

    // ----- IMAGE_NAMES
    stmt = "CREATE TABLE image_names (seq INTEGER PRIMARY KEY, name TEXT)";
    if (sqlite3_exec(m_db, stmt, NULL, NULL, &errmsg) != SQLITE_OK) {
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::initialize - Error creating image_names table: %S", errmsg);
        LOGERROR(infoMessage);

        sqlite3_free(errmsg);
        return 1;
    }

    // ----- VOL_INFO
    stmt = "CREATE TABLE vol_info (vol_id INTEGER PRIMARY KEY, sect_start INTEGER NOT NULL, "
        "sect_len INTEGER NOT NULL, description TEXT, flags INTEGER)";
    if (sqlite3_exec(m_db, stmt, NULL, NULL, &errmsg) != SQLITE_OK) {
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::initialize - Error creating vol_info table: %S", errmsg);
        LOGERROR(infoMessage);

        sqlite3_free(errmsg);
        return 1;
    }

    // ----- FS_INFO
    stmt = "CREATE TABLE fs_info (fs_id INTEGER PRIMARY KEY, img_byte_offset INTEGER, "
        "vol_id INTEGER NOT NULL, fs_type INTEGER, block_size INTEGER, "
        "block_count INTEGER, root_inum INTEGER, first_inum INTEGER, last_inum INTEGER)";
    if (sqlite3_exec(m_db, stmt , NULL, NULL, &errmsg) != SQLITE_OK) {
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::initialize - Error creating fs_info table: %S", errmsg);
        LOGERROR(infoMessage);

        sqlite3_free(errmsg);
        return 1;
    }

    // ----- FILES
    stmt = "CREATE TABLE files (file_id INTEGER PRIMARY KEY, type_id INTEGER, "
        "name TEXT, par_file_id INTEGER, dir_type INTEGER, meta_type INTEGER, "
        "dir_flags INTEGER, meta_flags INTEGER, size INTEGER, ctime INTEGER, "
        "crtime INTEGER, atime INTEGER, mtime INTEGER, mode INTEGER, uid INTEGER, "
        "gid INTEGER, status INTEGER, full_path TEXT)";
    if (sqlite3_exec(m_db, stmt, NULL, NULL, &errmsg) != SQLITE_OK) {
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::initialize - Error creating files table: %S", errmsg);
        LOGERROR(infoMessage);

        sqlite3_free(errmsg);
        return 1;
    }

    // ----- FS_FILES
    stmt = "CREATE TABLE fs_files (file_id INTEGER NOT NULL, fs_id INTEGER, "
        "fs_file_id INTEGER, attr_type INTEGER, attr_id INTEGER)";
    if (sqlite3_exec(m_db, stmt, NULL, NULL, &errmsg) != SQLITE_OK)
    {
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::initialize - Error creating fs_files table: %S", errmsg);
        LOGERROR(infoMessage);

        sqlite3_free(errmsg);
        return 1;
    }

    // ----- FS_BLOCKS
    stmt = "CREATE TABLE fs_blocks (fs_id INTEGER NOT NULL, file_id INTEGER NOT NULL, seq INTEGER, "
        "blk_start INTEGER NOT NULL, blk_len INTEGER NOT NULL)";
    if (sqlite3_exec(m_db, stmt, NULL, NULL, &errmsg) != SQLITE_OK)
    {
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::initialize - Error creating fs_blocks table: %S", errmsg);
        LOGERROR(infoMessage);

        sqlite3_free(errmsg);
        return 1;
    }

    // ----- CARVED_FILES
    stmt = "CREATE TABLE carved_files (file_id INTEGER, vol_id INTEGER)";
    if (sqlite3_exec(m_db, stmt, NULL, NULL, &errmsg) != SQLITE_OK)
    {
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::initialize - Error creating carved_files table: %S", errmsg);
        LOGERROR(infoMessage);

        sqlite3_free(errmsg);
        return 1;
    }

    // ----- SECTOR_LIST
    stmt = "CREATE TABLE carved_sectors ("
        "file_id INTEGER, seq INTEGER, sect_start INTEGER, sect_len INTEGER)";
    if (sqlite3_exec(m_db, stmt, NULL, NULL, &errmsg) != SQLITE_OK)
    {
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::initialize - Error creating carved_sectors table: %S", errmsg);
        LOGERROR(infoMessage);

        sqlite3_free(errmsg);
        return 1;
    }

    // ----- DERIVED_FILES
    stmt = "CREATE TABLE derived_files (file_id INTEGER PRIMARY KEY, derivation_details TEXT)";
    if (sqlite3_exec(m_db, stmt, NULL, NULL, &errmsg) != SQLITE_OK)
    {
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::initialize - Error creating derived_files table: %S", errmsg);
        LOGERROR(infoMessage);

        sqlite3_free(errmsg);
        return 1;
    }

    // ----- ALLOC_UNALLOC_MAP
    stmt = "CREATE TABLE alloc_unalloc_map (vol_id, unalloc_img_id INTEGER, "
        "unalloc_img_sect_start INTEGER, sect_len INTEGER, orig_img_sect_start INTEGER)";
    if (sqlite3_exec(m_db, stmt, NULL, NULL, &errmsg) != SQLITE_OK)
    {
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::initialize - Error creating alloc_unalloc_map table: %S", errmsg);
        LOGERROR(infoMessage);

        sqlite3_free(errmsg);
        return 1;
    }

    // ----- BLACKBOARD
    stmt = "CREATE TABLE blackboard (artifact_id INTEGER NOT NULL, file_id INTEGER, source TEXT, context TEXT, attribute TEXT, value_type INTEGER, "
        "value_byte BLOB, value_text TEXT, value_int32 INTEGER, value_int64 INTEGER, value_double NUMERIC(20, 10), PRIMARY KEY (artifact_id, file_id, attribute))";
    if (sqlite3_exec(m_db, stmt, NULL, NULL, &errmsg) != SQLITE_OK) {
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::initialize - Error creating blackboard table: %S", errmsg);
        LOGERROR(infoMessage);

        sqlite3_free(errmsg);
        return 1;
    }

    // ----- FILE_HASHES
    stmt = "CREATE TABLE file_hashes (file_id INTEGER PRIMARY KEY, md5 TEXT, sha1 TEXT, sha2_256 TEXT, sha2_512 TEXT, known INTEGER)";
    if (sqlite3_exec(m_db, stmt, NULL, NULL, &errmsg) != SQLITE_OK) {
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::initialize - Error creating file_hashes table: %S", errmsg);
        LOGERROR(infoMessage);

        sqlite3_free(errmsg);
        return 1;
    }

    // ----- MODULES
    stmt = "CREATE TABLE modules (module_id INTEGER, name TEXT PRIMARY KEY, description TEXT)";
    if (sqlite3_exec(m_db, stmt, NULL, NULL, &errmsg) != SQLITE_OK) {
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::initialize - Error creating module table: %S", errmsg);
        LOGERROR(infoMessage);

        sqlite3_free(errmsg);
        return 1;
    }

    // ----- MODULE_STATUS
    stmt = "CREATE TABLE module_status (file_id INTEGER, module_id INTEGER, status INTEGER, PRIMARY KEY (file_id, module_id))";
    if (sqlite3_exec(m_db, stmt, NULL, NULL, &errmsg) != SQLITE_OK) {
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::initialize - Error creating module_status table: %S", errmsg);
        LOGERROR(infoMessage);

        sqlite3_free(errmsg);
        return 1;
    }

    // ----- UNALLOC_IMG_STATUS
    stmt = "CREATE TABLE unalloc_img_status (unalloc_img_id INTEGER PRIMARY KEY, status INTEGER)";
    if (sqlite3_exec(m_db, stmt, NULL, NULL, &errmsg) != SQLITE_OK) {
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::initialize - Error creating unalloc_img_status table: %S", errmsg);
        LOGERROR(infoMessage);

        sqlite3_free(errmsg);
        return 1;
    }

    // ----- UNUSED_SECTORS
    stmt = "CREATE TABLE unused_sectors (file_id INTEGER, sect_start INTEGER, sect_len INTEGER, vol_id INTEGER)";
    if (sqlite3_exec(m_db, stmt, NULL, NULL, &errmsg) != SQLITE_OK) {
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::initialize - Error creating unused_sectors table: %S", errmsg);
        LOGERROR(infoMessage);

        sqlite3_free(errmsg);
        return 1;
    }

    addToolInfo("DBSchema", IMGDB_SCHEMA_VERSION);
    LOGINFO(L"ImgDB Created.");

    return 0;
}

/*
 * If the database file exists this method will open it otherwise
 * it will create a new database. 
 * This method also configures the chunk size and the busy handler
 * for the newly opened database.
*/
int TskImgDBSqlite::open()
{
    wchar_t infoMessage[MAX_BUFF_LENGTH];

    if (sqlite3_open16(m_dbFilePath, &m_db)) 
    {
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::open - Can't create new database: %S", sqlite3_errmsg(m_db));
        LOGERROR(infoMessage);

        sqlite3_close(m_db);
        return 1;
    }

    // The chunk size setting defines by how much the database will grow
    // or shrink. The primary motivation behind this setting is to reduce
    // database file fragmentation and potential performance improvements.
    // We, however, are using this setting as a workaround for database
    // corruption issues we have been experiencing when the database is
    // updated by multiple concurrent processes.
    // Database corruption was occuring when SQLite determined that the 
    // number of database pages in the database was greater than a value
    // that it had previously cached. 
    // This workaround is a crude mechanism to get around that situation.
    int chunkSize = IMGDB_CHUNK_SIZE;

    if (sqlite3_file_control(m_db, NULL, SQLITE_FCNTL_CHUNK_SIZE, &chunkSize) != SQLITE_OK)
    {
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::open - Failed to set chunk size: %S", sqlite3_errmsg(m_db));
        LOGERROR(infoMessage);

        sqlite3_close(m_db);
        return 1;
    }

    // Register a busy handler that will retry statements in situations
    // where the database is locked by another process.
    if (sqlite3_busy_handler(m_db, TskImgDBSqlite::busyHandler, m_db) != SQLITE_OK)
    {
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::open - Failed to set busy handler: %S", sqlite3_errmsg(m_db));
        LOGERROR(infoMessage);

        sqlite3_close(m_db);
        return 1;
    }

    LOGINFO(L"ImgDB Opened.");

    return 0;
}

int TskImgDBSqlite::addToolInfo(const char* name, const char* version)
{
    char *errmsg;
    char stmt[1024];

    if (!m_db)
        return 1;

    sqlite3_snprintf(1024, stmt, 
        "INSERT INTO db_info (name, version) VALUES ('%q', '%q');",
        name, version);
    if (sqlite3_exec(m_db, stmt, NULL, NULL, &errmsg) != SQLITE_OK)
    {
        wchar_t infoMessage[MAX_BUFF_LENGTH];
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::addToolInfo - Error adding data to db_info table: %S", errmsg);
        LOGERROR(infoMessage);

        sqlite3_free(errmsg);
        return 1;
    }

    return 0;
}

int TskImgDBSqlite::addImageInfo(int type, int size)
{
    char *errmsg;
    char stmt[1024];

    if (!m_db)
        return 1;

    _snprintf_s(stmt, 1024, _TRUNCATE, 
        "INSERT INTO image_info (type, ssize) VALUES (%d, %u);",
        type, size);
    if (sqlite3_exec(m_db, stmt, NULL, NULL, &errmsg) != SQLITE_OK)
    {
        wchar_t infoMessage[MAX_BUFF_LENGTH];
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::addImageInfo - Error adding data to image_info table: %S", errmsg);
        LOGERROR(infoMessage);

        sqlite3_free(errmsg);
        return 1;
    }

    return 0;
}

int TskImgDBSqlite::addImageName(char const * imgName)
{
    char *errmsg;
    char stmt[1024];

    if (!m_db)
        return 1;

    sqlite3_snprintf(1024, stmt,
        "INSERT INTO image_names (seq, name) VALUES (NULL, '%q')",
        imgName);
    if (sqlite3_exec(m_db, stmt, NULL, NULL, &errmsg) != SQLITE_OK)
    {
        wchar_t infoMessage[MAX_BUFF_LENGTH];
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::addImageName - "
            L"Error adding data to image_names table: %S", errmsg);
        LOGERROR(infoMessage);

        sqlite3_free(errmsg);
        return 1;
    }
    return 0;
}

/*
 * Adds the sector addresses of the volumes into the db.
 */
int TskImgDBSqlite::addVolumeInfo(const TSK_VS_PART_INFO * vs_part)
{
    char stmt[1024];
    char * errmsg;

    if (!m_db)
        return 1;

    sqlite3_snprintf(1024, stmt,
        "INSERT INTO vol_info (vol_id, sect_start, sect_len, description, flags) VALUES (%d,%"
        PRIuOFF ",%" PRIuOFF ",'%q',%d)", (int)vs_part->addr,
        vs_part->start, vs_part->len, vs_part->desc, vs_part->flags);

    if (sqlite3_exec(m_db, stmt, NULL, NULL, &errmsg) != SQLITE_OK) {
        wchar_t infoMessage[MAX_BUFF_LENGTH];
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::addVolumeInfo - "
            L"Error adding data to vol_info table: %S", errmsg);
        LOGERROR(infoMessage);

        sqlite3_free(errmsg);
        return 1;
    }

    return 0;
}

int TskImgDBSqlite::addFsInfo(int volId, int fsId, const TSK_FS_INFO * fs_info)
{
    char stmt[1024];
    char * errmsg;

    if (!m_db)
        return 1;

    _snprintf_s(stmt, 1024, _TRUNCATE, 
        "INSERT INTO fs_info (fs_id, img_byte_offset, vol_id, fs_type, block_size, "
        "block_count, root_inum, first_inum, last_inum) VALUES (%d,%"
        PRIuOFF ",%d,'%d',%d,%" PRIuDADDR ",%" PRIuINUM ",%" PRIuINUM ",%"
        PRIuINUM ")", fsId, fs_info->offset, volId,
        (int)fs_info->ftype, fs_info->block_size, fs_info->block_count,
        fs_info->root_inum, fs_info->first_inum, fs_info->last_inum);

    if (sqlite3_exec(m_db, stmt, NULL, NULL, &errmsg) != SQLITE_OK) {
        wchar_t infoMessage[MAX_BUFF_LENGTH];
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::addFsInfo - "
            L"Error adding data to fs_info table: %S", errmsg);
        LOGERROR(infoMessage);

        sqlite3_free(errmsg);
        return 1;
    }

    return 0;
}


/**
 * Given a file system and fs_file_id, return the file_id.
 */
uint64_t TskImgDBSqlite::getFileId(int a_fsId, uint64_t a_fsFileId) const
{
    if (!m_db)
        return 0;

    sqlite3_stmt * statement;
    char stmt[1024];
    uint64_t fileId = 0;
    _snprintf_s(stmt, 1024, _TRUNCATE, "SELECT file_id FROM fs_files WHERE fs_id=%d and fs_file_id=%llu;", a_fsId, a_fsFileId);

    /********** FIND the unallocated volumes *************/
    if (sqlite3_prepare_v2(m_db, stmt, -1, &statement, 0) == SQLITE_OK) {
        int result = sqlite3_step(statement);
        if (result == SQLITE_ROW) {
            fileId = (uint64_t)sqlite3_column_int64(statement, 0);
        }
        sqlite3_finalize(statement);
    }
    else {
        wchar_t infoMessage[MAX_BUFF_LENGTH];
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::getFileId - Error querying fs_files table: %S", sqlite3_errmsg(m_db));
        LOGERROR(infoMessage);

        return 0;
    }
    return fileId;
}

/**
 * @returns the file record or -1 on error.
 */
int TskImgDBSqlite::getFileRecord(const uint64_t fileId, TskFileRecord& fileRecord) const
{
    if (!m_db)
        return -1;

    int ret = 0;

    sqlite3_stmt * statement;
    std::stringstream stmt;

    stmt << "SELECT f.file_id, f.type_id, f.name, f.par_file_id, f.dir_type, f.meta_type, f.dir_flags, "
        << "f.meta_flags, f.size, f.ctime, f.crtime, f.atime, f.mtime, f.mode, f.uid, f.gid, f.status, f.full_path, "
        << "fh.md5, fh.sha1, fh.sha2_256, fh.sha2_512 "
        << "FROM files f LEFT OUTER JOIN file_hashes fh ON f.file_id = fh.file_id WHERE f.file_id=" << fileId;

    if (sqlite3_prepare_v2(m_db, stmt.str().c_str(), -1, &statement, 0) == SQLITE_OK) 
    {
        int result = sqlite3_step(statement);

        if (result == SQLITE_ROW) 
        {
            fileRecord.fileId       = sqlite3_column_int64(statement, 0);
            fileRecord.typeId       = sqlite3_column_int(statement, 1);
            fileRecord.name         = (char *)sqlite3_column_text(statement, 2);
            fileRecord.parentFileId = sqlite3_column_int64(statement, 3);
            fileRecord.dirType      = sqlite3_column_int(statement, 4);
            fileRecord.metaType     = sqlite3_column_int(statement, 5);
            fileRecord.dirFlags     = sqlite3_column_int(statement, 6);
            fileRecord.metaFlags    = sqlite3_column_int(statement, 7);
            fileRecord.size         = sqlite3_column_int64(statement, 8);
            fileRecord.ctime        = sqlite3_column_int(statement, 9);
            fileRecord.crtime       = sqlite3_column_int(statement, 10);
            fileRecord.atime        = sqlite3_column_int(statement, 11);
            fileRecord.mtime        = sqlite3_column_int(statement, 12);
            fileRecord.mode         = sqlite3_column_int(statement, 13);
            fileRecord.uid          = sqlite3_column_int(statement, 14);
            fileRecord.gid          = sqlite3_column_int(statement, 15);
            fileRecord.status       = sqlite3_column_int(statement, 16);
            fileRecord.fullPath     = (char *)sqlite3_column_text(statement, 17);

            if (sqlite3_column_type(statement, 18) == SQLITE_TEXT)
                fileRecord.md5      = (char *)sqlite3_column_text(statement, 18);
            if (sqlite3_column_type(statement, 19) == SQLITE_TEXT)
                fileRecord.sha1     = (char *)sqlite3_column_text(statement, 19);
            if (sqlite3_column_type(statement, 20) == SQLITE_TEXT)
                fileRecord.sha2_256 = (char *)sqlite3_column_text(statement, 20);
            if (sqlite3_column_type(statement, 21) == SQLITE_TEXT)
                fileRecord.sha2_512 = (char *)sqlite3_column_text(statement, 21);
        }
        else 
        {
            std::wstringstream msg;
            msg << L"TskImgDBSqlite::getFileRecord - Error querying files table for file id: " << fileId;
            LOGERROR(msg.str());

            ret = -1;
        }
        sqlite3_finalize(statement);
    }
    else 
    {
        std::wstringstream msg;
        msg << L"TskImgDBSqlite::getFileRecord - Error querying files table for file id: " << fileId;
        LOGERROR(msg.str());

        ret = -1;
    }

    return ret;
}

/**
 * Assign fileId on success.
 * @returns 0 on success or -1 on error.
 */
int TskImgDBSqlite::addFsFileInfo(int fsId, TSK_FS_FILE const * fs_file, char const * name, int type, int idx, uint64_t & fileId, char const * path)
{
    char stmt[1024];
    char * errmsg;
    wchar_t infoMessage[MAX_BUFF_LENGTH];

    if (!m_db)
        return -1;

    fileId = 0;
    int mtime = 0;
    int crtime = 0;
    int ctime = 0;
    int atime = 0;
    TSK_OFF_T size = 0;
    int meta_type = 0;
    int meta_flags = 0;
    int meta_mode = 0;
    int gid = 0;
    int uid = 0;

    //char * fullpath = (char *) malloc(sizeof(char *));
    std::string fullpath;

    fullpath.append(path);
    fullpath.append(name);

    /*strncpy(fullpath, path, strlen(path));
    strncat(fullpath, name, strlen(name));
    fullpath[strlen(path)+strlen(name)] = '\0';*/

    if (fs_file->meta) {
        mtime = (int)fs_file->meta->mtime;
        atime = (int)fs_file->meta->atime;
        ctime = (int)fs_file->meta->ctime;
        crtime = (int)fs_file->meta->crtime;
        size = fs_file->meta->size;
        meta_type = fs_file->meta->type;
        meta_flags = fs_file->meta->flags;
        meta_mode = fs_file->meta->mode;
        gid = fs_file->meta->gid;
        uid = fs_file->meta->uid;
    }

    // Replace all single quotes by double single quotes for 'name' to comply with SQLLite syntax. Also, remove all the control characters that might be present in the file name.
    // Check whether the file name contains a single quote. If so replace it with a double single quote.
    std::string fileNameAsString(name);
    size_t found;

    found = fileNameAsString.find("'");
    if (found != std::string::npos) //Replace it and replace all its subsequent occurrences.
    {
        fileNameAsString.replace(found,1,"''");

        while ((found=fileNameAsString.find("'",found+2)) != std::string::npos)// found+2 because we want to move past the newly inserted single quote.
        {
            fileNameAsString.replace(found,1,"''");
        }
    }

    // Now remove all the control characters.
    for (int codePoint=1; codePoint < 32; codePoint++)
    {
        char codePointAsHex[10];
        codePointAsHex[0] = codePoint;
        codePointAsHex[1] = '\0';
        std::string stringToRemove(codePointAsHex);

        found = fileNameAsString.find(stringToRemove);
        if (found != std::string::npos) //Replace it and replace all its subsequent occurrences.
        {
            fileNameAsString.replace(found,1,"");

            while ((found=fileNameAsString.find(stringToRemove,found+1)) != std::string::npos)// found+1 because the control characters are just 1 character.
            {
                fileNameAsString.replace(found,1,"");
            }
        }
    }

    name = fileNameAsString.c_str();

    // insert into the files table
    // MAY-118 status=READY_FOR_ANALYSIS
    sqlite3_snprintf(1024, stmt,
        "INSERT INTO files (file_id, type_id, status, name, par_file_id, dir_type, meta_type, "
        "dir_flags, meta_flags, size, crtime, ctime, atime, mtime, mode, gid, uid, full_path) VALUES (NULL, %d, %d,"
        "'%q',%llu,%d,%d,%d,%d,%" PRIuOFF",%d,%d,%d,%d,%d,%d,%d,'%q')", 
        IMGDB_FILES_TYPE_FS, IMGDB_FILES_STATUS_READY_FOR_ANALYSIS, name, 
        getFileId(fsId, fs_file->name->par_addr), 
        fs_file->name->type, meta_type,
        fs_file->name->flags, meta_flags, size, crtime, ctime, atime,
        mtime, meta_mode, gid, uid, fullpath.c_str());

    if (sqlite3_exec(m_db, stmt, NULL, NULL, &errmsg) != SQLITE_OK) {
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::addFsFileInfo - Error adding data to files table: %S", errmsg);
        LOGERROR(infoMessage);

        sqlite3_free(errmsg);
        return -1;
    }

    // get the file_id from the last insert
    fileId = sqlite3_last_insert_rowid(m_db);

    // insert into the fs_files table
    _snprintf_s(stmt, 1024, _TRUNCATE, 
        "INSERT INTO fs_files (file_id, fs_id, fs_file_id, attr_type, attr_id) VALUES (%llu,%d,%"
        PRIuINUM ",%d,%d)", fileId, fsId, fs_file->name->meta_addr, type, idx);

    if (sqlite3_exec(m_db, stmt, NULL, NULL, &errmsg) != SQLITE_OK) {
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::addFsFileInfo - Error adding data to fs_files table: %S", errmsg);
        LOGERROR(infoMessage);

        sqlite3_free(errmsg);
        return -1;
    }

    return 0;
}

/**
 * Add block info to the database.  This table stores the run information for each file so that we
 * can map which blocks are used by what files.
 * @param a_fsId Id that the file is located in
 * @param a_fileId ID of the file
 * @param a_sequence The sequence number of this run in the file (0 for the first run, 1 for the second run, etc.)
 * @param a_blk_addr Block address (the address that the file system uses -- NOT the physical sector addr)
 * @param a_len The number of blocks in the run
 * @returns 1 on error
 */
int TskImgDBSqlite::addFsBlockInfo(int a_fsId, uint64_t a_fileId, int a_sequence, uint64_t a_blk_addr, uint64_t a_len)
{
    char stmt[1024];
    char * errmsg;

    if (!m_db)
        return 1;

    _snprintf_s(stmt, 1024, _TRUNCATE, 
        "INSERT INTO fs_blocks (fs_id, file_id, seq, blk_start, blk_len) VALUES (%d,%llu,%d,%"
        PRIuOFF ",%"PRIuOFF")", a_fsId, a_fileId, a_sequence, a_blk_addr, a_len);

    if (sqlite3_exec(m_db, stmt, NULL, NULL, &errmsg) != SQLITE_OK) {
        wchar_t infoMessage[MAX_BUFF_LENGTH];
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::addFsBlockInfo - Error adding data to fs_blocks table: %S", errmsg);
        LOGERROR(infoMessage);

        sqlite3_free(errmsg);
        return 1;
    }

    return 0;
}

/**
 * Add information about how the unallocated images were created so that we can later
 * map where data was recovered from.  
 * @param a_volID Volume ID that the data was extracted from.
 * @param unallocImgID ID of the unallocated image that was created.
 * @param unallocImgStart Sector offset of where in the unallocated image that the run starts.
 * @param length Number of sectors that are in the run.
 * @param origImgStart Sector offset in the original image (relative to start of image) where the run starts 
 * @returns 1 on errror
 */
int TskImgDBSqlite::addAllocUnallocMapInfo(int a_volID, int unallocImgID, 
                                           uint64_t unallocImgStart, uint64_t length, uint64_t origImgStart)
{
    char stmt[1024];
    char * errmsg;

    if (!m_db)
        return 1;

    _snprintf_s(stmt, 1024, _TRUNCATE, 
        "INSERT INTO alloc_unalloc_map (vol_id, unalloc_img_id, unalloc_img_sect_start, "
        "sect_len, orig_img_sect_start) VALUES (%d,%d,%"
        PRIuOFF ",%"PRIuOFF",%"PRIuOFF")", a_volID, unallocImgID, 
        unallocImgStart, length, origImgStart);

    if (sqlite3_exec(m_db, stmt, NULL, NULL, &errmsg) != SQLITE_OK) {
        wchar_t infoMessage[MAX_BUFF_LENGTH];
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::addAllocUnallocMapInfo - Error adding data to alloc_unalloc_map table: %S", errmsg);
        LOGERROR(infoMessage);

        sqlite3_free(errmsg);
        return 1;
    }

    return 0;
}

/**
 * Get information on all of the free sectors in an image.
 *
 * @return Info on unallocated runs (or NULL on error).  Caller must free this when done.
 */
SectorRuns * TskImgDBSqlite::getFreeSectors() const
{
    wchar_t infoMessage[MAX_BUFF_LENGTH];
    std::wstringstream msg;

    if (!m_db)
        return NULL;

    SectorRuns * sr = new SectorRuns();

    LOGINFO(L"TskImgDBSqlite::getFreeSectors - Identifying Unallocated Sectors");

    sqlite3_stmt * statement;

    /********** FIND the unallocated volumes *************/
    if (sqlite3_prepare_v2(m_db,
        "SELECT vol_id, sect_start, sect_len, flags FROM vol_info;",
        -1, &statement, 0) == SQLITE_OK) {
            while(true) {
                int result = sqlite3_step(statement);
                if (result == SQLITE_ROW) {
                    int flags = sqlite3_column_int(statement, 3);

                    int vol_id = sqlite3_column_int(statement,0);
                    int64_t start = sqlite3_column_int64(statement,1);
                    int64_t len = sqlite3_column_int64(statement,2);

                    // add the unallocated volumes
                    if (flags & TSK_VS_PART_FLAG_UNALLOC) {
                        sr->addRun(start, len, vol_id);
                    }
                    // add the allocated volumes that don't have a known file system
                    else {
                        char stmt[512];
                        sqlite3_stmt *statement2;
                        _snprintf_s(stmt, 512, _TRUNCATE, "SELECT fs_id FROM fs_info WHERE vol_id = %d;", vol_id);
                        if (sqlite3_prepare_v2(m_db, stmt , -1, &statement2, 0) == SQLITE_OK) {
                            if (sqlite3_step(statement2) != SQLITE_ROW) {
                                sr->addRun(start, len, vol_id);
                            }
                            sqlite3_finalize(statement2);
                        }
                    }
                }
                else {
                    break;  
                }
            }
            sqlite3_finalize(statement);
    }
    else {
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::getFreeSectors - Error querying vol_info table: %S", sqlite3_errmsg(m_db));
        LOGERROR(infoMessage);

        return NULL;
    }

    /*************** Find the unallocated blocks in each file system *************/
    // @@@ Need to make more dynamic
    int blk_size[32];
    memset(blk_size, 0, sizeof(blk_size));
    uint64_t blk_count[32];
    memset(blk_count, 0, sizeof(blk_count));
    int vol_id[32];
    uint64_t img_offset[32];

    // get basic info on each file system
    if (sqlite3_prepare_v2(m_db, "SELECT fs_id, vol_id, img_byte_offset, block_size, block_count FROM fs_info;", -1, &statement, 0) == SQLITE_OK) {
        LOGINFO(L"TskImgDBSqlite::getFreeSectors - START LOOP: Find the unallocated blocks in each file system.");
        while(true)
        {
            int result = sqlite3_step(statement);
            if (result == SQLITE_ROW)
            {
                int fs_id = sqlite3_column_int(statement, 0);
                if (fs_id > 32)
                {
                    _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::getFreeSectors - fs_id in fs_info is bigger than 32: %d", fs_id);
                    LOGERROR(infoMessage);
                    break;
                }
                vol_id[fs_id] = sqlite3_column_int(statement, 1);
                img_offset[fs_id] = sqlite3_column_int64(statement, 2) / 512;
                blk_size[fs_id] = sqlite3_column_int(statement, 3) / 512;
                blk_count[fs_id] = sqlite3_column_int64(statement, 4);
                // Debug Info
                msg.str(L"");
                msg << L"TskImgDBSqlite::getFreeSectors - fs_id=" << fs_id << " vol_id=" << vol_id[fs_id] << " img_offset=" << img_offset[fs_id] << " blk_size=" << blk_size[fs_id] <<
                    " blk_count=" << blk_count[fs_id];
                LOGINFO(msg.str().c_str());
            }
            else
            {
                break;
            }
        }
        sqlite3_finalize(statement);
        LOGINFO(L"TskImgDBSqlite::getFreeSectors - DONE: Find the unallocated blocks in each file system.");
    }
    else
    {
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::getFreeSectors - Error querying fs_info table: %S", sqlite3_errmsg(m_db));
        LOGERROR(infoMessage);

        return NULL;
    }

    // see what blocks have been used and add them to a list
    TSK_LIST *seen[32];
    memset(seen, 0, 32*sizeof(TSK_LIST *));

    if (sqlite3_prepare_v2(m_db, "SELECT fs_id, file_id, blk_start, blk_len FROM fs_blocks;", -1, &statement, 0) == SQLITE_OK) {
        LOGINFO(L"TskImgDBSqlite::getFreeSectors - START LOOP: see what blocks have been used and add them to a list.");
        while(true) {
            int result = sqlite3_step(statement);
            if (result == SQLITE_ROW) {
                int fs_id = sqlite3_column_int(statement, 0);
                if (fs_id > 32) {
                    _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::getFreeSectors - fs_id in fs_info is bigger than 32: %d", fs_id);
                    LOGERROR(infoMessage);
                    continue;
                }
                uint64_t file_id = (uint64_t)sqlite3_column_int64(statement, 1);
                int64_t addr = sqlite3_column_int64(statement, 2);
                int64_t len = sqlite3_column_int64(statement, 3);

                // We only want to consider the runs for files that we allocated.
                char stmt[1024];
                _snprintf_s(stmt, 1024, _TRUNCATE, "SELECT meta_flags from files WHERE file_id=%d;", file_id);

                sqlite3_stmt * statement2;
                if (sqlite3_prepare_v2(m_db, stmt, -1, &statement2, 0) != SQLITE_OK) {
                    _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::getFreeSectors - error finding flags for file %lld", file_id);
                    LOGERROR(infoMessage);
                    continue;
                }
                sqlite3_step(statement2);
                int flags = sqlite3_column_int(statement2, 0);
                sqlite3_finalize(statement2);

                if (flags & TSK_FS_META_FLAG_UNALLOC)
                    continue;

                // @@@ We can probably find a more effecient storage method than this...
                int error = 0;
                for (int64_t i = 0; i < len; i++) {
                    if (tsk_list_add(&seen[fs_id], addr+i)) {
                        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::getFreeSectors - Error adding seen block address to list");
                        LOGERROR(infoMessage);

                        error = 1;
                        break;
                    }
                }
                if (error)
                    break;
            }
            else {
                break;
            }
        }
        sqlite3_finalize(statement);
        LOGINFO(L"TskImgDBSqlite::getFreeSectors - DONE: see what blocks have been used and add them to a list.");
    }
    else {
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::getFreeSectors - Error querying fs_block table: %S", sqlite3_errmsg(m_db));
        LOGERROR(infoMessage);

        return NULL;
    }

    // cycle through each file system to find the unused blocks
    LOGINFO(L"TskImgDBSqlite::getFreeSectors - START LOOP: cycle through each file system to find the unused blocks.");
    for (int f = 0; f < 32; f++) {
        if (blk_count[f] == 0)
            continue;

        uint64_t st = 0;
        int len = 0;
        // we previously adjusted blk_size and img_offset to be in sectors

        msg.str(L"");
        msg << L"blk_count[" << f << "]=" << blk_count[f];
        LOGINFO(msg.str().c_str());

        for (uint64_t a = 0; a < blk_count[f]; a++) {
            // see if this addr was used in a file
            if (tsk_list_find(seen[f], a) == 0) {
                // we already have a run being defined
                if (len) {
                    // same run, so add on to it
                    if (st + len == a) {
                        len++;
                    }
                    // different run, make a new one
                    else {
                        sr->addRun(img_offset[f]+st*blk_size[f], len*blk_size[f], vol_id[f]);
                        st = a;
                        len = 1;
                    }
                }
                // start a new run
                else {
                    st = a;
                    len = 1;
                }
            }
        }
        // add the final run
        if (len) {
            sr->addRun(img_offset[f]+st*blk_size[f], len*blk_size[f], vol_id[f]);
        }
        tsk_list_free(seen[f]);
        seen[f] = NULL;
    }
    LOGINFO(L"TskImgDBSqlite::getFreeSectors - DONE: cycle through each file system to find the unused blocks.");

    return sr;
}

/**
 * Returns the list of image names that were stored in the database.
 * @returns empty list on error
 */
std::vector<std::wstring> TskImgDBSqlite::getImageNames() const
{
    std::vector<std::wstring> imgList;

    if (!m_db)
        return imgList;

    sqlite3_stmt *statement;

    if (sqlite3_prepare_v2(m_db, "SELECT name FROM image_names ORDER BY seq;",
        -1, &statement, 0) == SQLITE_OK) 
    {
        while(true)
        {
            int result = sqlite3_step(statement);
            if (result == SQLITE_ROW) {
                imgList.push_back((wchar_t *)sqlite3_column_text16(statement, 0));
            }
            else {
                break;
            }
        }

        sqlite3_finalize(statement);
    }

    if (imgList.empty()) 
    {
        LOGERROR(L"No images found in TskImgDBSqlite");
    }

    return imgList;
}

/**
 * @param a_fileId  File id to get information about
 * @param a_fsOffset Byte offset of start of file system that the file is located in
 * @param a_fsFileId File system-specific id of the file
 * @param a_attrType Type of attribute for this file
 * @param a_attrId The ID of the attribute for this file
 * @returns -1 on error
 */
int TskImgDBSqlite::getFileUniqueIdentifiers(uint64_t a_fileId, uint64_t &a_fsOffset, uint64_t &a_fsFileId, int &a_attrType, int &a_attrId) const
{
    if (!m_db)
        return -1;

    sqlite3_stmt * statement;
    char stmt[MAX_BUFF_LENGTH];

    _snprintf_s(stmt, MAX_BUFF_LENGTH, MAX_BUFF_LENGTH, 
        "SELECT fs_file_id, attr_type, attr_id, fs_info.img_byte_offset "
        "FROM fs_files, fs_info WHERE file_id=%llu AND fs_info.fs_id = fs_files.fs_id;",
        a_fileId);
    if (sqlite3_prepare_v2(m_db, stmt, -1, &statement, 0) == SQLITE_OK) {
        int result = sqlite3_step(statement);
        if (result == SQLITE_ROW) {
            a_fsFileId = sqlite3_column_int64(statement, 0);
            a_attrType = sqlite3_column_int(statement, 1);
            a_attrId = sqlite3_column_int(statement, 2);
            a_fsOffset = sqlite3_column_int64(statement, 3);
        }
        else {
            return -1;
        }
        sqlite3_finalize(statement);
    }
    else {
        wchar_t infoMessage[MAX_BUFF_LENGTH];
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::getFileUniqueIdentifiers - "
            L"Error querying fs_files table : ", sqlite3_errmsg(m_db));
        LOGERROR(infoMessage);
        return -1;
    }

    return 0;
}

/**
 * Get number of volumes in image.
 * @return Number of volumes in image or -1 on error
 */
int TskImgDBSqlite::getNumVolumes() const
{
    if (!m_db)
        return 0;

    int count = 0;
    sqlite3_stmt * statement;

    /********** Get the number of volumes *************/
    if (sqlite3_prepare_v2(m_db, "SELECT count(*) from vol_info;", -1, &statement, 0) == SQLITE_OK) 
    {
        int result = sqlite3_step(statement);
        if (result == SQLITE_ROW) 
        {
            count = (int)sqlite3_column_int(statement, 0);
        }
        sqlite3_finalize(statement);
    }
    else 
    {
        std::wstringstream msg;
        msg << L"TskImgDBSqlite::getNumVolumes - Error querying vol_info table: " << sqlite3_errmsg(m_db);
        LOGERROR(msg.str());

        return -1;
    }

    return count;
}
/**
 * Get number of files in image.
 * @return Number of files in image or -1 on error
 */
int TskImgDBSqlite::getNumFiles() const
{
    if (!m_db)
        return 0;

    std::string condition("");
    return getFileCount(condition);
}

/**
 * @returns the session_id or -1 on error.
 */
int TskImgDBSqlite::getSessionID() const
{
    if (!m_db)
        return 0;

    sqlite3_stmt * statement;
    char stmt[1024];
    int sessionId;
    _snprintf_s(stmt, 1024, _TRUNCATE, "SELECT version from db_info WHERE name=%s;", "\"SID\"");

    /********** FIND the unallocated volumes *************/
    if (sqlite3_prepare_v2(m_db, stmt, -1, &statement, 0) == SQLITE_OK) {
        int result = sqlite3_step(statement);
        if (result == SQLITE_ROW) {
            sessionId = (int)sqlite3_column_int(statement, 0);
        }
        sqlite3_finalize(statement);
    }
    else {
        wchar_t infoMessage[MAX_BUFF_LENGTH];
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::getSessionID - Error querying db_info table for Session ID: %S", sqlite3_errmsg(m_db));
        LOGERROR(infoMessage);

        return -1;
    }
    return sessionId;
}

int TskImgDBSqlite::begin()
{
    char *errmsg;
    if (!m_db)
        return 1;

    if (sqlite3_exec(m_db, "BEGIN", NULL, NULL, &errmsg) != SQLITE_OK) {
        wchar_t infoMessage[MAX_BUFF_LENGTH];
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::begin - BEGIN Error: %S", errmsg);
        LOGERROR(infoMessage);

        sqlite3_free(errmsg);
        return 1;
    }
    return 0;
}

int TskImgDBSqlite::commit()
{
    char *errmsg;
    if (!m_db)
        return 1;

    if (sqlite3_exec(m_db, "COMMIT", NULL, NULL, &errmsg) != SQLITE_OK) {
        wchar_t infoMessage[MAX_BUFF_LENGTH];
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::commit - COMMIT Error: %S", errmsg);
        LOGERROR(infoMessage);

        sqlite3_free(errmsg);
        return 1;
    }
    return 0;
}

/**
 * Given an offset in an unallocated image that was created for carving, 
 * return information about where that data came from in the original image. 
 * This is used to map where a carved file is located in the original image. 
 *
 * @param a_unalloc_img_id ID of the unallocated image that you want data about
 * @param a_file_offset Sector offset where file was found in the unallocated image
 * @return NULL on error or a run descriptor. 
 */
UnallocRun * TskImgDBSqlite::getUnallocRun(int a_unalloc_img_id, int a_file_offset) const
{
    char stmt[1024];
    char * errmsg;
    if (!m_db)
        return NULL;

    _snprintf_s(stmt, 1024, _TRUNCATE, "SELECT vol_id, unalloc_img_sect_start, sect_len, orig_img_sect_start FROM "
        "alloc_unalloc_map WHERE unalloc_img_id = %d AND unalloc_img_sect_start <= %d ORDER BY unalloc_img_sect_start DESC",
        a_unalloc_img_id, a_file_offset);
    char **result;
    int nrow, ncol;
    if (sqlite3_get_table(m_db, stmt, &result, &nrow, &ncol, &errmsg) != SQLITE_OK)
    {
        wchar_t infoMessage[MAX_BUFF_LENGTH];
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::getUnallocRun - Error fetching data from alloc_unalloc_map table: %S", errmsg);

        LOGERROR(infoMessage);

        sqlite3_free(errmsg);

        return new UnallocRun(-1, -1, -1, -1, -1);
    }
    else
    {
        int vol_id;
        int unalloc_img_sect_start;
        int sect_len;
        int orig_img_sect_start;
        // skip the headers
        // @@@ DO SOME ERROR CHECKING HERE to make sure that results has data...
        sscanf_s(result[4], "%d", &vol_id);
        sscanf_s(result[5], "%d", &unalloc_img_sect_start);
        sscanf_s(result[6], "%d", &sect_len);
        sscanf_s(result[7], "%d", &orig_img_sect_start);
        sqlite3_free_table(result);
        return new UnallocRun(vol_id, a_unalloc_img_id, unalloc_img_sect_start, sect_len, orig_img_sect_start);
    }
}

/**
 * Adds information about a carved file into the database.  This includes the sector layout
 * information. 
 * 
 * @param vol_id Volume in which the carved file was found in
 * @param name Name of the file 
 * @param size Number of bytes in file
 * @param runStarts Array with starting sector (relative to start of image) for each run in file.
 * @param runLengths Array with number of sectors in each run 
 * @param numRuns Number of entries in previous arrays
 * @param fileId Carved file Id (output)
 * @returns 0 on success or -1 on error.
 */
int TskImgDBSqlite::addCarvedFileInfo(int vol_id, wchar_t * name, uint64_t size, 
                                      uint64_t *runStarts, uint64_t *runLengths, int numRuns, uint64_t & fileId)
{
    char stmt[1024];
    std::string utf8Name;
    char * errmsg;
    wchar_t infoMessage[MAX_BUFF_LENGTH];
    if (!m_db)
        return -1;

    Poco::UnicodeConverter::toUTF8(name, utf8Name); // needed for sqlite3_sprintf
    // insert into files table
    sqlite3_snprintf(1024, stmt,
        "INSERT INTO files (file_id, type_id, name, par_file_id, dir_type, meta_type,"
        "dir_flags, meta_flags, size, ctime, crtime, atime, mtime, mode, uid, gid, status, full_path) "
        "VALUES (NULL, %d, '%q', NULL, %d, %d, %d, %d, %llu, NULL, NULL, NULL, NULL, NULL, NULL, NULL, %d, '%q')",
        IMGDB_FILES_TYPE_CARVED, utf8Name.c_str(), (int)TSK_FS_NAME_TYPE_REG, (int)TSK_FS_META_TYPE_REG,
        (int)TSK_FS_NAME_FLAG_UNALLOC, (int)TSK_FS_META_FLAG_UNALLOC, size, IMGDB_FILES_STATUS_CREATED, utf8Name.c_str());
    // MAY-118 NOTE: addCarvedFileInfo insert entry into files table, but actual file on disk has not been created yet.
    if (sqlite3_exec(m_db, stmt, NULL, NULL, &errmsg) != SQLITE_OK) {
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::addCarvedFileInfo - Error adding data to file table for carved file: %S %S", errmsg, stmt);

        LOGERROR(infoMessage);

        sqlite3_free(errmsg);
        return -1;
    }

    // get the assigned file_id
    fileId = (uint64_t)sqlite3_last_insert_rowid(m_db);

    // insert into the carved_files_table
    _snprintf_s(stmt, 1024, _TRUNCATE, "INSERT INTO carved_files (file_id, vol_id)"
        "VALUES (%llu, %d)", fileId, vol_id);
    if (sqlite3_exec(m_db, stmt, NULL, NULL, &errmsg) != SQLITE_OK) {
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::addCarvedFileInfo - Error adding data to carved_files table: %S", errmsg);

        LOGERROR(infoMessage);
        sqlite3_free(errmsg);
        return -1;
    }

    // insert into carved_sectors table
    for (int i = 0; i < numRuns; i++)
    {
        _snprintf_s(stmt, 1024, _TRUNCATE, 
            "INSERT INTO carved_sectors (file_id, seq, sect_start, sect_len) "
            "VALUES (%llu, %d, %llu, %llu)",
            fileId, i, runStarts[i], runLengths[i]);
        if (sqlite3_exec(m_db, stmt, NULL, NULL, &errmsg) != SQLITE_OK) {
            _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::addCarvedFileInfo - Error adding data to carved_sectors table: %S", errmsg);

            LOGERROR(infoMessage);

            sqlite3_free(errmsg);
            return -1;
        }
    }

    return 0;
}

/**
 * Adds information about derived files to the database.  Derived files typically come
 * from archives and may be compressed.
 * 
 * @param name The name of the file.
 * @param parentId The id of the file from which this file is derived.
 * @param isDirectory True if entry is for a directory verus a file
 * @param size The size of the file.
 * @param details This is a string that may contain extra details related
 * to the particular type of mechanism that was used to derive this file, 
 * e.g. files derived from zip archives may have extra information about the
 * compressed size of the file.
 * @param ctime Time file system file entry was changed.
 * @param crtime Time the file was created.
 * @param atime Last access time.
 * @param mtime Last modified time.
 * @param fileId Reference to location where file_id for file can be assigned
 * @param path Path of file
 *
 * @returns 0 on success or -1 on error.
 */
int TskImgDBSqlite::addDerivedFileInfo(const std::string& name, const uint64_t parentId, 
                                       const bool isDirectory, const uint64_t size,
                                       const std::string& details,
                                       const int ctime, const int crtime, const int atime, const int mtime,
                                       uint64_t &fileId, std::string path)
{
    if (!m_db)
        return -1;

    char stmt[1024];
    char * errmsg;

    TSK_FS_NAME_TYPE_ENUM dirType = isDirectory ? TSK_FS_NAME_TYPE_DIR : TSK_FS_NAME_TYPE_REG;

    // insert into files table
    sqlite3_snprintf(1024, stmt,
        "INSERT INTO files (file_id, type_id, name, par_file_id, dir_type, size, ctime, crtime, atime, mtime, status, full_path) "
        "VALUES (NULL, %d, '%q', %llu, %d, %llu, %d, %d, %d, %d, %d, '%q')",
        IMGDB_FILES_TYPE_DERIVED, name.c_str(), parentId, dirType, size, ctime, crtime, atime, mtime, IMGDB_FILES_STATUS_CREATED, path.c_str());

    if (sqlite3_exec(m_db, stmt, NULL, NULL, &errmsg) != SQLITE_OK) 
    {
        std::wstringstream msg;
        msg << L"TskImgDBSqlite::addDerivedFileInfo - Error adding data to file table for derived file: "
            << errmsg << L" " << stmt;

        LOGERROR(msg.str());

        sqlite3_free(errmsg);
        return -1;
    }

    // get the assigned file_id
    fileId = sqlite3_last_insert_rowid(m_db);

    // insert into the derived_files table
    sqlite3_snprintf(1024, stmt, "INSERT INTO derived_files (file_id, derivation_details) "
        "VALUES (%llu, '%q')", fileId, details.c_str());
    if (sqlite3_exec(m_db, stmt, NULL, NULL, &errmsg) != SQLITE_OK) 
    {
        std::wstringstream msg;
        msg << L"TskImgDBSqlite::addDerivedFileInfo - Error adding data to derived_files table : "
            << errmsg;

        LOGERROR(msg.str());
        sqlite3_free(errmsg);
        return -1;
    }

    return 0;
}

/**
 * Fills outBuffer with file IDs that match the name fileName.
 * Returns the number of file IDs written into outBuffer or -1 on error.
 */
int TskImgDBSqlite::getFileIds(char *a_fileName, uint64_t *a_outBuffer, int a_buffSize) const
{

    if (!m_db)
        return -1;

    int outIdx = 0;

    sqlite3_stmt * statement;
    char stmt[MAX_BUFF_LENGTH];
    _snprintf_s(stmt, MAX_BUFF_LENGTH, MAX_BUFF_LENGTH, 
        "SELECT file_id FROM files WHERE name LIKE '%s';",
        a_fileName);
    if (sqlite3_prepare_v2(m_db, stmt, -1, &statement, 0) == SQLITE_OK) {
        while(sqlite3_step(statement) == SQLITE_ROW) {
            a_outBuffer[outIdx++] = (uint64_t)sqlite3_column_int64(statement, 0);
        }
        sqlite3_finalize(statement);
    }
    else {
        wchar_t infoMessage[MAX_BUFF_LENGTH];
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::getFileIds - "
            L"Error querying files table : %S", sqlite3_errmsg(m_db));
        LOGERROR(infoMessage);
        return -1;
    }

    return outIdx;
}

/*
 * Return the minimum file id with status = READY_FOR_ANALYSIS in minFileId.
 * Return 0 on success, -1 if failed.
 */
int TskImgDBSqlite::getMinFileIdReadyForAnalysis(uint64_t & minFileId) const
{
    if (!m_db)
        return -1;

    minFileId = 0;

    sqlite3_stmt * statement;
    char stmt[MAX_BUFF_LENGTH];
    _snprintf_s(stmt, MAX_BUFF_LENGTH, MAX_BUFF_LENGTH, 
        "SELECT min(file_id) FROM files WHERE status = %d;", TskImgDB::IMGDB_FILES_STATUS_READY_FOR_ANALYSIS);
    if (sqlite3_prepare_v2(m_db, stmt, -1, &statement, 0) == SQLITE_OK) {
        int result = sqlite3_step(statement);
        if (result == SQLITE_ROW) {
            minFileId = (uint64_t)sqlite3_column_int64(statement, 0);
        }
        sqlite3_finalize(statement);
    }
    else {
        wchar_t infoMessage[MAX_BUFF_LENGTH];
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::getMinFileIdReadyForAnalysis - "
            L"Error querying files table : %S", sqlite3_errmsg(m_db));
        LOGERROR(infoMessage);
        return -1;
    }
    return 0;
}

/**
 * Given the last file ID ready for analysis, find the largest file ID ready of analysis (in maxFileId)
 * Returns 0 on success or -1 on error.
 */
int TskImgDBSqlite::getMaxFileIdReadyForAnalysis(uint64_t a_lastFileId, uint64_t & maxFileId) const
{
    if (!m_db)
        return -1;

    maxFileId = 0;

    sqlite3_stmt * statement;
    char stmt[MAX_BUFF_LENGTH];
    _snprintf_s(stmt, MAX_BUFF_LENGTH, MAX_BUFF_LENGTH, 
        "SELECT max(file_id) FROM files WHERE status = %d AND file_id >= %d;", TskImgDB::IMGDB_FILES_STATUS_READY_FOR_ANALYSIS, a_lastFileId);
    if (sqlite3_prepare_v2(m_db, stmt, -1, &statement, 0) == SQLITE_OK) {
        int result = sqlite3_step(statement);
        if (result == SQLITE_ROW) {
            maxFileId = (uint64_t)sqlite3_column_int64(statement, 0);
        }
        sqlite3_finalize(statement);
    }
    else {
        wchar_t infoMessage[MAX_BUFF_LENGTH];
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::getMaxFileIdReadyForAnalysis - "
            L"Error querying files table : %S", sqlite3_errmsg(m_db));
        LOGERROR(infoMessage);
        return -1;
    }
    return 0;
}

SectorRuns * TskImgDBSqlite::getFileSectors(uint64_t a_fileId) const
{
    if (!m_db)
        return NULL;

    SectorRuns * sr = new SectorRuns();

    sqlite3_stmt * statement;
    char stmt[MAX_BUFF_LENGTH];
    int srCount = 0;
    _snprintf_s(stmt, MAX_BUFF_LENGTH, MAX_BUFF_LENGTH,
        "SELECT fs_blocks.blk_start, fs_blocks.blk_len, "
        "fs_info.block_size, fs_info.img_byte_offset, fs_info.vol_id "
        "FROM files "
        "JOIN fs_files ON files.file_id = fs_files.file_id "
        "JOIN fs_blocks ON files.file_id = fs_blocks.file_id "
        "JOIN fs_info ON fs_blocks.fs_id = fs_info.fs_id "
        "WHERE files.file_id = %u "
        "ORDER BY fs_blocks.seq;", 
        a_fileId);
    if (sqlite3_prepare_v2(m_db, stmt, -1, &statement, 0) == SQLITE_OK) {
        while(sqlite3_step(statement) == SQLITE_ROW) {
            uint64_t blkStart = (uint64_t)sqlite3_column_int64(statement, 0);
            uint64_t blkLength = (uint64_t)sqlite3_column_int64(statement, 1);
            int blkSize = sqlite3_column_int(statement, 2);
            uint64_t imgByteOffset = (uint64_t)sqlite3_column_int64(statement, 3);
            int volId = sqlite3_column_int(statement, 4);

            uint64_t start = (imgByteOffset + blkStart * blkSize) / 512;
            uint64_t len = (blkLength * blkSize) / 512;

            sr->addRun(start, len, volId);
            srCount++;
        }

        sqlite3_finalize(statement);
    }
    else {
        wchar_t infoMessage[MAX_BUFF_LENGTH];
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH,
            L"TskImgDBSqlite::getFileSectors - "
            L"Error finding block data for file_id=%u: %S",
            a_fileId,
            sqlite3_errmsg(m_db));
        LOGERROR(infoMessage);
        return NULL;
    }

    if (srCount < 1) {
        delete sr;
        sr = NULL;
    }
    return sr;
}

/**
 * This callback mechanism is registered with SQLite and is 
 * called whenever an operation would result in SQLITE_BUSY.
 * Each time this method is called we will back off IMGDB_RETRY_WAIT
 * x count milliseconds. A non zero return value tells SQLite to 
 * retry the statement and a zero return value tells SQLite to 
 * stop retrying, in which case it will return SQLITE_BUSY or
 * SQLITE_IOERR_BLOCKED to the caller.
 *
 * @param pDB - a pointer to the sqlite3 structure
 * @param count - the number of times this handler has been
 * called for this blocking event.
 */
int TskImgDBSqlite::busyHandler(void * pDB, int count)
{
    if (count < IMGDB_MAX_RETRY_COUNT)
    {
        Sleep(IMGDB_RETRY_WAIT * count);
        return 1;
    }

    return 0;
}


/**
 * update the status field in the database for a given file.
 * @param a_file_id File to update.
 * @param a_status Status flag to update to.
 * @returns 1 on error.
 */
int TskImgDBSqlite::updateFileStatus(uint64_t a_file_id, int a_status)
{
    if (!m_db)
        return 1;

    char stmt[MAX_BUFF_LENGTH];
    char * errmsg;

    _snprintf_s(stmt, MAX_BUFF_LENGTH, MAX_BUFF_LENGTH, 
        "UPDATE files SET status = %d WHERE file_id = %d;", a_status, a_file_id);
    if (sqlite3_exec(m_db, stmt, NULL, NULL, &errmsg) != SQLITE_OK) {
        wchar_t infoMessage[MAX_BUFF_LENGTH];
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::updateFileStatus - Error UPDATE file status: %S",
            sqlite3_errmsg(m_db));
        LOGERROR(infoMessage);
        return 1;
    }

    return 0;
}

/**
 * update the known status field in the database for a given file.
 * @param a_file_id File to update.
 * @param a_status Status flag to update to.
 * @returns 1 on error.
 */
int TskImgDBSqlite::updateKnownStatus(uint64_t a_file_id, int a_status)
{
    if (!m_db)
        return 1;

    char stmt[MAX_BUFF_LENGTH];
    char * errmsg;

    _snprintf_s(stmt, MAX_BUFF_LENGTH, MAX_BUFF_LENGTH, 
                "UPDATE file_hashes SET known = %d WHERE file_id = %d;", a_status, a_file_id);
    if (sqlite3_exec(m_db, stmt, NULL, NULL, &errmsg) != SQLITE_OK) {
        wchar_t infoMessage[MAX_BUFF_LENGTH];
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::updateFileStatus - Error UPDATE file status: %S",
            sqlite3_errmsg(m_db));
        LOGERROR(infoMessage);
        return 1;
    }

    return 0;
}

bool TskImgDBSqlite::dbExist() const
{
    if (m_db)
        return true;
    else
        return false;
}

/**
 * Given a file_id and attribute, get all the values from the blackboard table.
 * @param a_file_id The file.
 * @param attribute The attribute
 * @param values Values to be returned [OUTPUT].
 * @returns 0 on success, 1 on failure.
 */
int TskImgDBSqlite::getBlackboard(const uint64_t a_file_id, const string & attribute, vector<string> & values) const
{
    int rc = 1;

    if (!m_db)
        return rc;

    sqlite3_stmt * statement;
    char stmt[MAX_BUFF_LENGTH];

    sqlite3_snprintf(MAX_BUFF_LENGTH, stmt,
        "SELECT value_text FROM blackboard WHERE file_id = %llu AND attribute LIKE %Q;",
        a_file_id, attribute.c_str());

    values.clear();
    if (sqlite3_prepare_v2(m_db, stmt, -1, &statement, 0) == SQLITE_OK) {
        while (sqlite3_step(statement) == SQLITE_ROW) {
            string str = (char *)sqlite3_column_text(statement, 0);
            values.push_back(str);
        }
        sqlite3_finalize(statement);
        rc = 0;
    }
    else {
        wchar_t infoMessage[MAX_BUFF_LENGTH];
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::getBlackboard - "
            L"Error querying blackboard table : %S", sqlite3_errmsg(m_db));
        LOGERROR(infoMessage);
    }
    return rc;
#if 0
    if (!m_db)
        throw TskException("No database.");

    std::vector <unsigned char>a_value;
    sqlite3_stmt * statement;
    char stmt[MAX_BUFF_LENGTH];
    sqlite3_snprintf(MAX_BUFF_LENGTH, stmt,
        "SELECT value FROM blackboard WHERE file_id = %llu AND attribute LIKE '%q';",
        a_file_id, attribute);
    if (sqlite3_prepare_v2(m_db, stmt, -1, &statement, 0) == SQLITE_OK) {
        int result = sqlite3_step(statement);
        if (result == SQLITE_ROW) {
            const void *ptr = sqlite3_column_blob(statement, 0);
            if (!ptr) {
                sqlite3_finalize(statement);
                return a_value;
            } else {
                // return the blob
                int blobSize = sqlite3_column_bytes(statement, 0);
                const unsigned char *pBlob = (const unsigned char *)sqlite3_column_blob(statement, 0);
                std::vector<unsigned char>a_value;
                a_value.reserve(blobSize);
                for (int i = 0; i < blobSize; i++) {
                    a_value.push_back((unsigned char)pBlob[i]);
                }
                sqlite3_finalize(statement);
                return a_value;
            }
        } else {
            sqlite3_finalize(statement);
            throw TskException("No data.");
        }
        sqlite3_finalize(statement);
    }
    else {
        wchar_t infoMessage[MAX_BUFF_LENGTH];
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::getBlackboard - "
            L"Error querying blackboard table : %S", sqlite3_errmsg(m_db));
        LOGERROR(infoMessage);
        throw TskException("SQL failed.");
    }
#endif
}

int TskImgDBSqlite::getBlackboard(const uint64_t a_file_id, const string & attribute, vector<vector<unsigned char>> & values) const
{
    int rc = 1;

    if (!m_db)
        return rc;

    sqlite3_stmt * statement;
    char stmt[MAX_BUFF_LENGTH];

    sqlite3_snprintf(MAX_BUFF_LENGTH, stmt,
        "SELECT value_byte FROM blackboard WHERE file_id = %llu AND attribute LIKE %Q;",
        a_file_id, attribute.c_str());

    values.clear();
    if (sqlite3_prepare_v2(m_db, stmt, -1, &statement, 0) == SQLITE_OK) {
        while (sqlite3_step(statement) == SQLITE_ROW) {
            // return the blob
            int blobSize = sqlite3_column_bytes(statement, 0);
            const unsigned char *pBlob = (const unsigned char *)sqlite3_column_blob(statement, 0);
            vector<unsigned char>a_value;
            a_value.reserve(blobSize);
            for (int i = 0; i < blobSize; i++) {
                a_value.push_back((unsigned char)pBlob[i]);
            }
            values.push_back(a_value);
        }
        sqlite3_finalize(statement);
        rc = 0;
    }
    else {
        wchar_t infoMessage[MAX_BUFF_LENGTH];
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::getBlackboard - "
            L"Error querying blackboard table : %S", sqlite3_errmsg(m_db));
        LOGERROR(infoMessage);
    }
    return rc;
}

int TskImgDBSqlite::getBlackboard(const uint64_t a_file_id, const string & attribute, vector<int32_t> & values) const
{
    int rc = 1;

    if (!m_db)
        return rc;

    sqlite3_stmt * statement;
    char stmt[MAX_BUFF_LENGTH];

    sqlite3_snprintf(MAX_BUFF_LENGTH, stmt,
        "SELECT value_int32 FROM blackboard WHERE file_id = %llu AND attribute LIKE %Q;",
        a_file_id, attribute.c_str());

    values.clear();
    if (sqlite3_prepare_v2(m_db, stmt, -1, &statement, 0) == SQLITE_OK) {
        while (sqlite3_step(statement) == SQLITE_ROW) {
            int32_t value = (int32_t)sqlite3_column_int(statement, 0);
            values.push_back(value);
        }
        sqlite3_finalize(statement);
        rc = 0;
    }
    else {
        wchar_t infoMessage[MAX_BUFF_LENGTH];
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::getBlackboard - "
            L"Error querying blackboard table : %S", sqlite3_errmsg(m_db));
        LOGERROR(infoMessage);
    }
    return rc;
}

int TskImgDBSqlite::getBlackboard(const uint64_t a_file_id, const string & attribute, vector<int64_t> & values) const
{
    int rc = 1;

    if (!m_db)
        return rc;

    sqlite3_stmt * statement;
    char stmt[MAX_BUFF_LENGTH];

    sqlite3_snprintf(MAX_BUFF_LENGTH, stmt,
        "SELECT value_int64 FROM blackboard WHERE file_id = %llu AND attribute LIKE %Q;",
        a_file_id, attribute.c_str());

    values.clear();
    if (sqlite3_prepare_v2(m_db, stmt, -1, &statement, 0) == SQLITE_OK) {
        while (sqlite3_step(statement) == SQLITE_ROW) {
            int64_t value = (int64_t)sqlite3_column_int64(statement, 0);
            values.push_back(value);
        }
        sqlite3_finalize(statement);
        rc = 0;
    }
    else {
        wchar_t infoMessage[MAX_BUFF_LENGTH];
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::getBlackboard - "
            L"Error querying blackboard table : %S", sqlite3_errmsg(m_db));
        LOGERROR(infoMessage);
    }
    return rc;
}

int TskImgDBSqlite::getBlackboard(const uint64_t a_file_id, const string & attribute, vector<double> & values) const
{
    int rc = 1;

    if (!m_db)
        return rc;

    sqlite3_stmt * statement;
    char stmt[MAX_BUFF_LENGTH];

    sqlite3_snprintf(MAX_BUFF_LENGTH, stmt,
        "SELECT value_double FROM blackboard WHERE file_id = %llu AND attribute LIKE %Q;",
        a_file_id, attribute.c_str());

    values.clear();
    if (sqlite3_prepare_v2(m_db, stmt, -1, &statement, 0) == SQLITE_OK) {
        while (sqlite3_step(statement) == SQLITE_ROW) {
            double value = (double)sqlite3_column_double(statement, 0);
            values.push_back(value);
        }
        sqlite3_finalize(statement);
        rc = 0;
    }
    else {
        wchar_t infoMessage[MAX_BUFF_LENGTH];
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::getBlackboard - "
            L"Error querying blackboard table : %S", sqlite3_errmsg(m_db));
        LOGERROR(infoMessage);
    }
    return rc;
}

/**
 * Add blackboardRecord to the blackboard table.
 * If (artifact_id, file_id, attribute) already exist in the blackboard table, it will fail.
 */
artifact_t TskImgDBSqlite::addBlackboardInfo(const TskBlackboardRecord& blackboardRecord) const
{
    if (!m_db)
        throw TskException("No database.");

    if (blackboardRecord.attribute.empty())
        throw TskException("Attribute is empty.");

    artifact_t artifactId = 0;
    std::stringstream str;
    char *item;
    sqlite3_stmt * statement;

    str << "INSERT INTO blackboard (artifact_id, file_id, source, context, attribute, value_type, value_byte, value_text, value_int32, value_int64, value_double) VALUES (";
    if (blackboardRecord.artifactId)
        str << blackboardRecord.artifactId << ", ";
    else 
        str << "(select case when (select count(*) from blackboard) = 0 then 1 else (select max(artifact_id)+1 from blackboard) end)" << ", ";
    str << blackboardRecord.fileId << ", ";
    item = sqlite3_mprintf("%Q", blackboardRecord.source.c_str()); str << item << ", ";
    sqlite3_free(item);
    item = sqlite3_mprintf("%Q", blackboardRecord.context.c_str()); str << item << ", ";
    sqlite3_free(item);
    item = sqlite3_mprintf("%Q", blackboardRecord.attribute.c_str()); str << item << ", ";
    sqlite3_free(item);
    str << blackboardRecord.valueType << ", ";
    switch (blackboardRecord.valueType) {
        case TskImgDB::BB_VALUE_TYPE_BYTE:
            str << " ?, '', 0, 0, 0.0";
            break;
        case TskImgDB::BB_VALUE_TYPE_STRING:
            item = sqlite3_mprintf("%Q", blackboardRecord.valueString.c_str());
            str << " '', " << item << ", 0, 0, 0.0";
            sqlite3_free(item);
            break;
        case TskImgDB::BB_VALUE_TYPE_INT32:
            str << " '', '', " << blackboardRecord.valueInt32 << ",     0, 0.0";
            break;
        case TskImgDB::BB_VALUE_TYPE_INT64:
            str << " '', '', 0, " << blackboardRecord.valueInt64 << ",     0.0";
            break;
        case TskImgDB::BB_VALUE_TYPE_DOUBLE:
            str << " '', '', 0, 0, " << setprecision(20) << blackboardRecord.valueDouble;
            break;
    };
    str << ")";

    if (sqlite3_prepare_v2(m_db, str.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        int result = SQLITE_OK;
        unsigned char *pBuf = 0;
        if (blackboardRecord.valueType == TskImgDB::BB_VALUE_TYPE_BYTE) {
            // Bind the byte vector
            int a_size = blackboardRecord.valueByte.size();
            pBuf = new unsigned char[a_size];
            for (int i = 0; i < a_size; i++) {
                pBuf[i] = blackboardRecord.valueByte[i];
            }
            result = sqlite3_bind_blob(statement, 1, pBuf, a_size, SQLITE_STATIC);
        }
        if (result == SQLITE_OK) {
            result = sqlite3_step(statement);
            if (result == SQLITE_ROW || result == SQLITE_DONE) {
                // OK
                if (blackboardRecord.artifactId)
                    artifactId = blackboardRecord.artifactId;
                else {
                    // select max(artifact_id) from blackboard
                    str.str("");
                    str << "SELECT max(artifact_id) FROM blackboard";
                    sqlite3_finalize(statement);
                    if (sqlite3_prepare_v2(m_db, str.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
                        if (sqlite3_step(statement) == SQLITE_ROW) {
                            artifactId = (artifact_t)sqlite3_column_int64(statement, 0);
                        } else {
                            sqlite3_finalize(statement);
                            throw TskException("TskImgDBSqlite::addBlackboardInfo - Select failed");
                        }
                    } else {
                        sqlite3_finalize(statement);
                        throw TskException("TskImgDBSqlite::addBlackboardInfo - Select max(artifact_id) failed");
                    }
                }
            } else {
                sqlite3_finalize(statement);
                if (pBuf) delete [] pBuf;
                throw TskException("TskImgDBSqlite::addBlackboardInfo - Insert failed");
            }
        } else {
            wchar_t infoMessage[MAX_BUFF_LENGTH];
            _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::addBlackboardInfo - Error in sqlite3_bind_blob: %S", sqlite3_errmsg(m_db));
            LOGERROR(infoMessage);
            throw TskException("TskImgDBSqlite::addBlackboardInfo - Insert failed");
        }
        sqlite3_finalize(statement);
        if (pBuf) delete [] pBuf;
    } else {
        wchar_t infoMessage[MAX_BUFF_LENGTH];
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::addBlackboardInfo - Error adding data to blackboard table: %S", sqlite3_errmsg(m_db));
        LOGERROR(infoMessage);
        throw TskException("TskImgDBSqlite::addBlackboardInfo - Insert failed");
    }

    return artifactId;
}

std::vector<uint64_t> TskImgDBSqlite::getUniqueCarvedFileIds(HASH_TYPE hashType) const
{
    if (!m_db)
        throw TskException("No database.");

    std::vector<uint64_t> results;

    string hash;
    switch (hashType) {
    case TskImgDB::MD5:
        hash = "md5";
        break;
    case TskImgDB::SHA1:
        hash = "sha1";
        break;
    case TskImgDB::SHA2_256:
        hash = "sha2_256";
        break;
    case TskImgDB::SHA2_512:
        hash = "sha2_512";
        break;
    default:
        std::wstringstream errorMsg;
        errorMsg << L"TskImgDBSqlite::getUniqueCarvedFileIds - Unsupported hashType : " << hashType ;
        LOGERROR(errorMsg.str());
        return results;
    }

    stringstream stmt;

    // If the file_hashes table is empty, just return all of carve_files
    stmt << "SELECT count(*) FROM file_hashes;";

    sqlite3_stmt * statement;
    if (sqlite3_prepare_v2(m_db, stmt.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        if (sqlite3_step(statement) == SQLITE_ROW) {
            uint64_t counter = (uint64_t)sqlite3_column_int64(statement, 0);
            if (counter == 0) {
                sqlite3_finalize(statement);
                return getCarvedFileIds();
            }
        }
        sqlite3_finalize(statement);
    } else {
        wchar_t infoMessage[MAX_BUFF_LENGTH];
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::getUniqueCarvedFileIds - Error getting file_hashes count: %S", sqlite3_errmsg(m_db));
        LOGERROR(infoMessage);
    }

    stmt.str("");
    stmt << "SELECT h." 
        << hash 
        << ", min(h.file_id) FROM file_hashes h, carved_files f WHERE h.file_id = f.file_id AND h." 
        << hash 
        << " != '' group by h." << hash;

    if (sqlite3_prepare_v2(m_db, stmt.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        while (sqlite3_step(statement) == SQLITE_ROW) {
            uint64_t fileId = (uint64_t)sqlite3_column_int64(statement, 1);
            results.push_back(fileId);
        }
        sqlite3_finalize(statement);
    } else {
        wchar_t infoMessage[MAX_BUFF_LENGTH];
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::getUniqueCarvedFileIds - Error querying file_hashes table: %S", sqlite3_errmsg(m_db));
        LOGERROR(infoMessage);
    }

    // Get all carved_files with empty hash, if hash was not generated.
    stmt.str("");
    stmt << "SELECT f.file_id FROM carved_files f WHERE " 
        << "f.file_id NOT IN (SELECT f.file_id FROM file_hashes h, carved_files f WHERE h.file_id = f.file_id AND h." << hash << " != '') ";
    if (sqlite3_prepare_v2(m_db, stmt.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        uint64_t counter = 0;
        while (sqlite3_step(statement) == SQLITE_ROW) {
            uint64_t fileId = (uint64_t)sqlite3_column_int64(statement, 0);
            results.push_back(fileId);
            counter++;
        }
        sqlite3_finalize(statement);
        if (counter) {
            // There are some files without hash, generate a warning.
            std::wstringstream errorMsg;
            errorMsg << L"TskImgDBSqlite::getUniqueCarvedFileIds - Including " << counter << L" files with no hash value.";
            LOGWARN(errorMsg.str());
        }
    } else {
        wchar_t infoMessage[MAX_BUFF_LENGTH];
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::getUniqueCarvedFileIds - Error querying file_hashes table: %S", sqlite3_errmsg(m_db));
        LOGERROR(infoMessage);
    }
    return results;
}

std::vector<uint64_t> TskImgDBSqlite::getCarvedFileIds() const
{
    return getFileIdsWorker("carved_files");
}

std::vector<uint64_t> TskImgDBSqlite::getUniqueFileIds(HASH_TYPE hashType) const
{
    if (!m_db)
        throw TskException("No database.");

    std::vector<uint64_t> results;

    string hash;
    switch (hashType) {
    case TskImgDB::MD5:
        hash = "md5";
        break;
    case TskImgDB::SHA1:
        hash = "sha1";
        break;
    case TskImgDB::SHA2_256:
        hash = "sha2_256";
        break;
    case TskImgDB::SHA2_512:
        hash = "sha2_512";
        break;
    default:
        std::wstringstream errorMsg;
        errorMsg << L"TskImgDBSqlite::getUniqueFileIds - Unsupported hashType : " << hashType ;
        LOGERROR(errorMsg.str());
        return results;
    }

    stringstream stmt;

    stmt << "SELECT min(file_id) FROM file_hashes WHERE " << hash << " != '' group by " << hash ;

    sqlite3_stmt * statement;
    if (sqlite3_prepare_v2(m_db, stmt.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        while (sqlite3_step(statement) == SQLITE_ROW) {
            uint64_t fileId = (uint64_t)sqlite3_column_int64(statement, 0);
            results.push_back(fileId);
        }
        sqlite3_finalize(statement);
    } else {
        wchar_t infoMessage[MAX_BUFF_LENGTH];
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::getUniqueFileIds - Error querying file_hashes table: %S", sqlite3_errmsg(m_db));
        LOGERROR(infoMessage);
    }
    return results;
}

std::vector<uint64_t> TskImgDBSqlite::getFileIds() const
{
    return getFileIdsWorker("files");
}

std::vector<uint64_t> TskImgDBSqlite::getFileIdsWorker(std::string tableName, const std::string condition) const
{
    if (!m_db)
        throw TskException("No database.");

    std::vector<uint64_t> results;

    stringstream stmt;

    stmt << "SELECT file_id FROM " << tableName;
    if (condition.compare("") != 0)
        stmt << " WHERE " << condition;
    stmt <<  " ORDER BY file_id";

    sqlite3_stmt * statement;
    if (sqlite3_prepare_v2(m_db, stmt.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        while (sqlite3_step(statement) == SQLITE_ROW) {
            uint64_t fileId = (uint64_t)sqlite3_column_int64(statement, 0);
            results.push_back(fileId);
        }
        sqlite3_finalize(statement);
    } else {
        wchar_t infoMessage[MAX_BUFF_LENGTH];
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::getFileIdsWorker - Error getting file ids from table %s, %S", tableName.c_str(), sqlite3_errmsg(m_db));
        LOGERROR(infoMessage);
    }
    return results;
}

/**
 * Get the list of file ids that match the given criteria.
 * The given string will be appended to "select files.file_id from files".
 *
 * @param condition Must be a valid SQL string defining the selection criteria.
 * @returns The collection of file ids matching the selection criteria. Throws
 * TskException if database not initialized.
 */
std::vector<uint64_t> TskImgDBSqlite::getFileIds(std::string &condition) const
{
    if (!m_db)
        throw TskException("Database not initialized.");

    std::vector<uint64_t> results;

    std::string stmt("SELECT files.file_id FROM files");

    constructStmt(stmt, condition);

    sqlite3_stmt * statement;
    if (sqlite3_prepare_v2(m_db, stmt.c_str(), -1, &statement, 0) == SQLITE_OK) 
    {
        while (sqlite3_step(statement) == SQLITE_ROW) 
        {
            uint64_t fileId = (uint64_t)sqlite3_column_int64(statement, 0);
            results.push_back(fileId);
        }
        sqlite3_finalize(statement);
    } else 
    {
        std::wstringstream msg;
        msg << L"TskImgDBSqlite::getFilesIds - Error getting file ids: " << sqlite3_errmsg(m_db);
        LOGERROR(msg.str());
    }
    return results;
}

/**
 * Get the number of files that match the given criteria.
 * The given string will be appended to "select files.file_id from files".
 *
 * @param condition Must be a valid SQL string defining the selection criteria.
 * @returns The number of files matching the selection criteria. 
 */
int TskImgDBSqlite::getFileCount(std::string& condition) const
{
    if (!m_db)
        throw TskException("Database not initialized.");

    int result = 0;

    std::string stmt("SELECT COUNT(files.file_id) FROM files");

    constructStmt(stmt, condition);

    sqlite3_stmt * statement;
    if (sqlite3_prepare_v2(m_db, stmt.c_str(), -1, &statement, 0) == SQLITE_OK) 
    {
        while (sqlite3_step(statement) == SQLITE_ROW) 
        {
            result = (uint64_t)sqlite3_column_int(statement, 0);
        }
        sqlite3_finalize(statement);
    } else 
    {
        std::wstringstream msg;
        msg << L"TskImgDBSqlite::getFileCount - Error getting file count: " << sqlite3_errmsg(m_db);
        LOGERROR(msg.str());
    }
    return result;
}

void TskImgDBSqlite::constructStmt(std::string& stmt, std::string& condition) const
{
    if (!condition.empty())
    {
        // Remove leading whitespace from condition
        condition.erase(0, condition.find_first_not_of(' '));

        std::string whereClause("WHERE");
        std::string joinClause("JOIN");

        // If the condition doesn't start with a WHERE clause and it doesn't
        // start with a comma it is presumably extending the FROM clause with
        // one or more table names. In this case we need to add the comma to
        // the statement.
        if (strnicmp(condition.c_str(), whereClause.c_str(), whereClause.length()) != 0 &&
            strnicmp(condition.c_str(), joinClause.c_str(), joinClause.length()) != 0 &&
            condition[0] != ',')
        {
            stmt.append(",");
        }
    }

    stmt.append(" ");
    stmt.append(condition);
}

// Set file hash for hashType for a_file_id
// Return 1 on failure, 0 on success.
int TskImgDBSqlite::setHash(uint64_t a_file_id, TskImgDB::HASH_TYPE hashType, const std::string hash)
{
    if (!m_db)
        throw TskException("No database.");

    string hashTypeStr;
    switch (hashType) {
    case TskImgDB::MD5:
        hashTypeStr = "md5";
        break;
    case TskImgDB::SHA1:
        hashTypeStr = "sha1";
        break;
    case TskImgDB::SHA2_256:
        hashTypeStr = "sha2_256";
        break;
    case TskImgDB::SHA2_512:
        hashTypeStr = "sha2_512";
        break;
    default:
        std::wstringstream errorMsg;
        errorMsg << L"TskImgDBSqlite::setHash - Unsupported hashType : " << hashType ;
        LOGERROR(errorMsg.str());
        return 1;
    }

    stringstream stmt;
    bool found = false;
    std::string md5, sha1, sha2_256, sha2_512;
    int known = IMGDB_FILES_UNKNOWN;
    std::stringstream stream;

    stmt << "SELECT md5, sha1, sha2_256, sha2_512, known from file_hashes WHERE file_id = " << a_file_id;

    sqlite3_stmt * statement;
    if (sqlite3_prepare_v2(m_db, stmt.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        int result = sqlite3_step(statement);
        if (result == SQLITE_ROW) {
            md5 = (char *)sqlite3_column_text(statement, 0);
            sha1 = (char *)sqlite3_column_text(statement, 1);
            sha2_256 = (char *)sqlite3_column_text(statement, 2);
            sha2_512 = (char *)sqlite3_column_text(statement, 3);
            known = (int)sqlite3_column_int(statement, 4);
        } 
        sqlite3_finalize(statement);
    } else {
        ; // OK if not exists
    }

    // insert new record
    stmt.str("");
    stmt << "INSERT OR REPLACE INTO file_hashes (file_id, md5, sha1, sha2_256, sha2_512, known) VALUES (" << a_file_id;
    switch (hashType) {
    case TskImgDB::MD5:
        stmt << ", '" << hash << "'";
        stmt << ", '" << sha1 << "'";
        stmt << ", '" << sha2_256 << "'";
        stmt << ", '" << sha2_512 << "'";
        stream << known;
        stmt << ", " << stream.str();
        break;
    case TskImgDB::SHA1:
        stmt << ", '" << md5 << "'";
        stmt << ", '" << hash << "'";
        stmt << ", '" << sha2_256 << "'";
        stmt << ", '" << sha2_512 << "'";
        stream << known;
        stmt << ", " << stream.str();
        break;
    case TskImgDB::SHA2_256:
        stmt << ", '" << md5 << "'";
        stmt << ", '" << sha1 << "'";
        stmt << ", '" << hash << "'";
        stmt << ", '" << sha2_512 << "'";
        stream << known;
        stmt << ", " << stream.str();
        break;
    case TskImgDB::SHA2_512:
        stmt << ", '" << md5 << "'";
        stmt << ", '" << sha1 << "'";
        stmt << ", '" << sha2_256 << "'";
        stmt << ", '" << hash << "'";
        stream << known;
        stmt << ", " << stream.str();
        break;
    }
    stmt << ")";

    char *errmsg;
    if (sqlite3_exec(m_db, stmt.str().c_str(), NULL, NULL, &errmsg) != SQLITE_OK) {
        wchar_t infoMessage[MAX_BUFF_LENGTH];
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::setHash - Error adding hash to file_hashes table: %S", errmsg);
        LOGERROR(infoMessage);
        sqlite3_free(errmsg);
        return 1;
    }

    return 0;
}

std::string TskImgDBSqlite::getCfileName(uint64_t a_file_id) const
{
    if (!m_db)
        throw TskException("No database.");

    std::string cfileName;
    stringstream stmt;

    stmt << "select 'cfile_' || c.vol_id || '_' || cs.sect_start || '_' || f.file_id"
        " from files f, carved_files c, carved_sectors cs where f.file_id = c.file_id and c.file_id = cs.file_id and cs.seq = 0"
        " and f.file_id = " << a_file_id;

    sqlite3_stmt * statement;
    if (sqlite3_prepare_v2(m_db, stmt.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        int result = sqlite3_step(statement);
        if (result == SQLITE_ROW) {
            cfileName = (char *)sqlite3_column_text(statement, 0);
        }
        sqlite3_finalize(statement);
    } else {
        wchar_t infoMessage[MAX_BUFF_LENGTH];
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::getCfileName - Error querying tables: %S", sqlite3_errmsg(m_db));
        LOGERROR(infoMessage);
    }

    stmt.str("");
    stmt << "select f.name "
        " from files f, carved_files c, carved_sectors cs where f.file_id = c.file_id and c.file_id = cs.file_id and cs.seq = 0"
        " and f.file_id = " << a_file_id;

    std::string name;
    if (sqlite3_prepare_v2(m_db, stmt.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        int result = sqlite3_step(statement);
        if (result == SQLITE_ROW) {
            name = (char *)sqlite3_column_text(statement, 0);
        }
        sqlite3_finalize(statement);
        int pos = name.rfind('.');
        if (pos != string::npos)
            cfileName += name.substr(pos);
    } else {
        wchar_t infoMessage[MAX_BUFF_LENGTH];
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::getCfileName - Error querying tables: %S", sqlite3_errmsg(m_db));
        LOGERROR(infoMessage);
    }

    return cfileName;
}

/**
 * Return the ImageInfo
 * @param type Image Type (output)
 * @param sectorSize Image sector size (output)
 * @returns 0 on success or -1 on error.
 */
int TskImgDBSqlite::getImageInfo(int & type, int & sectorSize) const
{
    int rc = -1;
    if (!m_db)
        return rc;

    stringstream stmt;

    stmt << "SELECT type, ssize FROM image_info";

    sqlite3_stmt * statement;
    if (sqlite3_prepare_v2(m_db, stmt.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        int result = sqlite3_step(statement);
        if (result == SQLITE_ROW) {
            type = (int)sqlite3_column_int64(statement, 0);
            sectorSize = (int)sqlite3_column_int64(statement, 1);
            rc = 0;
        }
        sqlite3_finalize(statement);
    } else {
        wchar_t infoMessage[MAX_BUFF_LENGTH];
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::getImageInfo - Error querying image_info table: %S", sqlite3_errmsg(m_db));
        LOGERROR(infoMessage);
        return -1;
    }
    return rc;
}

/**
 * Return a list of TskVolumeInfoRecord
 * @param volumeInfoList A list of TskVolumeInfoRecord (output)
 * @returns 0 on success or -1 on error.
 */
int TskImgDBSqlite::getVolumeInfo(std::list<TskVolumeInfoRecord> & volumeInfoList) const
{
    std::list<TskVolumeInfoRecord> list;

    if (!m_db)
        return -1;

    stringstream stmt;
    stmt << "SELECT vol_id, sect_start, sect_len, description, flags FROM vol_info";

    sqlite3_stmt * statement;
    if (sqlite3_prepare_v2(m_db, stmt.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        while (sqlite3_step(statement) == SQLITE_ROW) {
            TskVolumeInfoRecord vol_info;
            vol_info.vol_id = sqlite3_column_int(statement,0);
            vol_info.sect_start = sqlite3_column_int64(statement,1);
            vol_info.sect_len = sqlite3_column_int64(statement,2);
            vol_info.description.assign((char *)sqlite3_column_text(statement, 3));
            vol_info.flags = sqlite3_column_int(statement, 4);
            volumeInfoList.push_back(vol_info);
        }
        sqlite3_finalize(statement);
    } else {
        wchar_t infoMessage[MAX_BUFF_LENGTH];
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::getVolumeInfo - Error getting from vol_info table: %S", sqlite3_errmsg(m_db));
        LOGERROR(infoMessage);
        return -1;
    }
    return 0;
}

/**
 * Return a list of TskFsInfoRecord
 * @param fsInfoList A list of TskFsInfoRecord (output)
 * @returns 0 on success or -1 on error.
 */
int TskImgDBSqlite::getFsInfo(std::list<TskFsInfoRecord> & fsInfoList) const
{
    std::list<TskFsInfoRecord> list;

    if (!m_db)
        return -1;

    stringstream stmt;
    stmt << "SELECT fs_id, img_byte_offset, vol_id, fs_type, block_size, block_count, root_inum, first_inum, last_inum FROM fs_info";

    sqlite3_stmt * statement;
    if (sqlite3_prepare_v2(m_db, stmt.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        while (sqlite3_step(statement) == SQLITE_ROW) {
            TskFsInfoRecord fs_info;
            fs_info.fs_id = sqlite3_column_int(statement,0);
            fs_info.img_byte_offset = sqlite3_column_int64(statement,1);
            fs_info.vol_id = sqlite3_column_int(statement,2);
            fs_info.fs_type = sqlite3_column_int(statement,3);
            fs_info.block_size = sqlite3_column_int(statement,4);
            fs_info.block_count = sqlite3_column_int64(statement,5);
            fs_info.root_inum = sqlite3_column_int64(statement,6);
            fs_info.first_inum = sqlite3_column_int64(statement,7);
            fs_info.last_inum = sqlite3_column_int64(statement,8);
            fsInfoList.push_back(fs_info);
        }
        sqlite3_finalize(statement);
    } else {
        wchar_t infoMessage[MAX_BUFF_LENGTH];
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::getFsInfo - Error getting from fs_info table: %S", sqlite3_errmsg(m_db));
        LOGERROR(infoMessage);
        return -1;
    }
    return 0;
}

typedef std::map<std::string, int> FileTypeMap_t;

static std::string getFileType(const char *name)
{
    std::string filename = name;
    int pos = filename.rfind('.');
    if (pos != std::string::npos) {
        std::string suffix = filename.substr(pos);
        std::string result;
        for (size_t i=0; i < suffix.size(); i++) {
            result += (char)tolower(suffix[i]);
        }
        return result;
    }
    else
        return std::string("");
}

/**
 * Return a list of TskFileTypeRecord for fileType
 * @param fileType FILE_TYPE to report
 * @param fileTypeInfoList A list of TskFileTypeRecord (output)
 * @returns 0 on success or -1 on error.
 */
int TskImgDBSqlite::getFileInfoSummary(FILE_TYPES fileType, std::list<TskFileTypeRecord> & fileTypeInfoList) const
{
    std::list<TskFileTypeRecord> list;

    if (!m_db)
        return -1;

    stringstream stmt;
    stmt << "SELECT name FROM files WHERE type_id = " << fileType << " AND dir_type = " << TSK_FS_NAME_TYPE_REG;

    sqlite3_stmt * statement;
    if (sqlite3_prepare_v2(m_db, stmt.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        FileTypeMap_t fileTypeMap;
        while (sqlite3_step(statement) == SQLITE_ROW) {
            char *name = (char *)sqlite3_column_text(statement, 0);
            std::string type = getFileType(name);
            FileTypeMap_t::iterator iter = fileTypeMap.find(type);
            if (iter != fileTypeMap.end()) {
                // increment file counter
                int count = iter->second;
                fileTypeMap[type] = ++count;
            } else {
                // add a new file type
                fileTypeMap.insert(pair<std::string, int>(type, 1));
            }
        }
        for (FileTypeMap_t::const_iterator iter=fileTypeMap.begin(); iter != fileTypeMap.end(); iter++) {
            TskFileTypeRecord info;
            info.suffix.assign((*iter).first.c_str());
            info.count = (*iter).second;
            info.description.assign("File Type Description");
            fileTypeInfoList.push_back(info);
        }
        sqlite3_finalize(statement);
    } else {
        wchar_t infoMessage[MAX_BUFF_LENGTH];
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::getFsInfo - Error getting from fs_info table: %S", sqlite3_errmsg(m_db));
        LOGERROR(infoMessage);
        return -1;
    }
    return 0;
}

/**
 * Get the module id by module name.
 * @param name Module name
 * @param moduleId Module Id (output)
 * @returns 0 on success, -1 on error.
 */
int TskImgDBSqlite::getModuleId(const std::string name, int & moduleId) const
{
    int rc = -1;

    if (!m_db)
        return rc;

    // Select existing module by name, if any
    sqlite3_stmt * statement;
    char stmt[1024];
    sqlite3_snprintf(1024, stmt, 
        "SELECT module_id FROM modules WHERE name LIKE '%q';",
        name.c_str());
    if (sqlite3_prepare_v2(m_db, stmt, -1, &statement, 0) == SQLITE_OK) {
        int result = sqlite3_step(statement);
        if (result == SQLITE_ROW) {
            // Already exists, return module_id
            moduleId = sqlite3_column_int(statement, 0);
            rc = 0;
        }
        sqlite3_finalize(statement);
    }
    else {
        wchar_t infoMessage[MAX_BUFF_LENGTH];
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::getModuleId - "
            L"Error querying module_id table : %S", sqlite3_errmsg(m_db));
        LOGERROR(infoMessage);
        throw TskException("SQL Failed.");
    }
    return rc;
}

/**
 * Insert the Module record, if module name does not already exist in modules table.
 * Returns Module Id associated with the Module record.
 * @param name Module name
 * @param description Module description
 * @param moduleId Module Id (output)
 * @returns 0 on success, -1 on error.
 */
int TskImgDBSqlite::addModule(const std::string name, const std::string description, int & moduleId)
{
    int rc = -1;

    if (!m_db)
        return rc;

    // Insert a new one
    char * errmsg;
    char stmt[1024];
    sqlite3_snprintf(1024, stmt, 
        "INSERT INTO modules (module_id, name, description) VALUES ((SELECT count(*) + 1 FROM modules), '%q', '%q');",
        name.c_str(), description.c_str());
    if (sqlite3_exec(m_db, stmt, NULL, NULL, &errmsg) == SQLITE_OK) {
        moduleId = sqlite3_last_insert_rowid(m_db);
        rc = 0;
    } else {
        if (getModuleId(name, moduleId) == 0) {
            rc = 0;
        } else {
            wchar_t infoMessage[MAX_BUFF_LENGTH];
            _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::addModule - Error adding data to modules table: %S", errmsg);
            LOGERROR(infoMessage);
            sqlite3_free(errmsg);
        }
    }
    return rc;
}

/**
 * Insert the module status record.
 * @param file_id file_id
 * @param module_id module_id
 * @param status Status of module
 * @returns 0 on success, -1 on error.
 */
int TskImgDBSqlite::setModuleStatus(uint64_t file_id, int module_id, int status)
{
    int rc = -1;

    if (!m_db)
        return rc;

    char * errmsg;
    std::stringstream stmt;
    stmt << "INSERT INTO module_status (file_id, module_id, status) VALUES (" <<
        file_id << ", " <<  module_id << ", " << status << ")";

    if (sqlite3_exec(m_db, stmt.str().c_str(), NULL, NULL, &errmsg) == SQLITE_OK) {
        rc = 0;
    } else {
        wchar_t infoMessage[MAX_BUFF_LENGTH];
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::setModuleStatus - Error adding data to module_status table: %S", errmsg);
        LOGERROR(infoMessage);
        sqlite3_free(errmsg);
    }
    return rc;
}

/**
 * Get a list of TskModuleStatus.
 * @param moduleStatusList A list of TskModuleStatus (output)
 * @returns 0 on success, -1 on error.
*/
int TskImgDBSqlite::getModuleErrors(std::vector<TskModuleStatus> & moduleStatusList) const
{
    int rc = -1;

    if (!m_db)
        return rc;

    stringstream stmt;
    stmt << "SELECT f.file_id, m.name, ms.status FROM module_status ms, files f, modules m"
        << " WHERE ms.status != 0 AND ms.file_id = f.file_id AND m.module_id = ms.module_id"
        << " ORDER BY f.file_id";

    sqlite3_stmt * statement;
    if (sqlite3_prepare_v2(m_db, stmt.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        TskModuleStatus moduleStatus;
        while (sqlite3_step(statement) == SQLITE_ROW) {
            moduleStatus.file_id = (uint64_t)sqlite3_column_int64(statement, 0);
            moduleStatus.module_name = (char *)sqlite3_column_text(statement, 1);
            moduleStatus.status = (int)sqlite3_column_int(statement, 2);
            moduleStatusList.push_back(moduleStatus);
        }
        sqlite3_finalize(statement);
        rc = 0;
    } else {
        wchar_t infoMessage[MAX_BUFF_LENGTH];
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::getModuleErrors - Error querying module_status table: %S", sqlite3_errmsg(m_db));
        LOGERROR(infoMessage);
    }
    // Find report module errors. These have file_id = 0.
    stmt.str("");
    stmt << "SELECT 0, m.name, ms.status FROM module_status ms, modules m"
         << " WHERE ms.status != 0 AND ms.file_id = 0 AND m.module_id = ms.module_id";

    if (sqlite3_prepare_v2(m_db, stmt.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        TskModuleStatus moduleStatus;
        while (sqlite3_step(statement) == SQLITE_ROW) {
            moduleStatus.file_id = (uint64_t)sqlite3_column_int64(statement, 0);
            moduleStatus.module_name = (char *)sqlite3_column_text(statement, 1);
            moduleStatus.status = (int)sqlite3_column_int(statement, 2);
            moduleStatusList.push_back(moduleStatus);
        }
        sqlite3_finalize(statement);
        rc = 0;
    } else {
        wchar_t infoMessage[MAX_BUFF_LENGTH];
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::getModuleErrors - Error querying module_status table: %S", sqlite3_errmsg(m_db));
        LOGERROR(infoMessage);
    }
    return rc;
}

/*
 * Return a file name associated with a file_id, prefer Cfilename, otherwise name in the files table.
 * @param file_id file id
 * @returns file name as std::string
 */
std::string TskImgDBSqlite::getFileName(uint64_t file_id) const
{
    std::string name;

    if (!m_db)
        return name;

    name = getCfileName(file_id);
    if (name == "") {
        TskFileRecord fileRecord;
        if (getFileRecord(file_id, fileRecord) == 0)
            name = fileRecord.name;
    }
    return name;
}

/**
 * Return the known status of the file with the given id
 * @param fileId id of the file to get the status of
 * @returns KNOWN_STATUS
 */
int TskImgDBSqlite::getKnownStatus(const uint64_t fileId) const
{
    int retval = -1;

    if (!m_db)
        return retval;
    
    stringstream stmt;
    stmt << "SELECT known FROM file_hashes WHERE file_id = " << fileId;

    sqlite3_stmt * statement;
    if (sqlite3_prepare_v2(m_db, stmt.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        if(sqlite3_step(statement) == SQLITE_ROW) {
            retval = (int)sqlite3_column_int(statement, 0);
        }
        sqlite3_finalize(statement);
    } else {
        wchar_t infoMessage[MAX_BUFF_LENGTH];
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::getKnownStatus - Error getting known status %S", sqlite3_errmsg(m_db));
        LOGERROR(infoMessage);
    }

    return retval;
}

void TskImgDBSqlite::getAllBlackboardRows(std::string& condition, vector<TskBlackboardRecord> & bbRecords)const{
    if (!m_db)
        throw TskException("No database.");
    
    int result = 0;
    std::string stmt("SELECT artifact_id, blackboard.file_id, source, context, attribute, value_type, value_byte, value_text, value_int32, value_int64, value_double FROM blackboard");

    constructStmt(stmt, condition);

    sqlite3_stmt * statement;
    if (sqlite3_prepare_v2(m_db, stmt.c_str(), -1, &statement, 0) == SQLITE_OK) 
    {
        while (sqlite3_step(statement) == SQLITE_ROW) 
        {
            TskBlackboardRecord record;

            record.artifactId = (artifact_t)sqlite3_column_int64(statement, 0);
            record.fileId = (uint64_t)sqlite3_column_int64(statement, 1);
            record.source = (char *)sqlite3_column_text(statement, 2);
            record.context = (char *)sqlite3_column_text(statement, 3);
            record.attribute = (char *)sqlite3_column_text(statement, 4);
            record.valueType = (int)sqlite3_column_int(statement, 5);
            switch (record.valueType) {
                case TskImgDB::BB_VALUE_TYPE_BYTE:
                    {
                        // return the blob
                        int blobSize = sqlite3_column_bytes(statement, 6);
                        const unsigned char *pBlob = (const unsigned char *)sqlite3_column_blob(statement, 6);
                        record.valueByte.reserve(blobSize);
                        for (int i = 0; i < blobSize; i++) {
                            record.valueByte.push_back((unsigned char)pBlob[i]);
                        }
                    }
                    break;
                case TskImgDB::BB_VALUE_TYPE_STRING:
                    record.valueString = (char *)sqlite3_column_text(statement, 7);
                    break;
                case TskImgDB::BB_VALUE_TYPE_INT32:
                    record.valueInt32 = (int32_t)sqlite3_column_int(statement, 8);
                    break;
                case TskImgDB::BB_VALUE_TYPE_INT64:
                    record.valueInt64 = (int64_t)sqlite3_column_int64(statement, 9);
                    break;
                case TskImgDB::BB_VALUE_TYPE_DOUBLE:
                    record.valueDouble = (double)sqlite3_column_double(statement, 10);
                    break;
            };
            bbRecords.push_back(record);
        }
        sqlite3_finalize(statement);
    } else 
    {
        std::wstringstream msg;
        msg << L"TskImgDBSqlite::getAllBlackboardRows - Error getting records: " << sqlite3_errmsg(m_db);
        LOGERROR(msg.str());
    }

}

void TskImgDBSqlite::getAllBlackboardRows(uint64_t fileId, vector<TskBlackboardRecord> & bbRecords) const
{
    if (!m_db)
        throw TskException("No database.");
    
    stringstream stmt;

    stmt << "SELECT artifact_id, file_id, source, context, attribute, value_type, value_byte, value_text, value_int32, value_int64, value_double FROM blackboard WHERE file_id=" << fileId;

    sqlite3_stmt * statement;
    if (sqlite3_prepare_v2(m_db, stmt.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        while (sqlite3_step(statement) == SQLITE_ROW) {
            TskBlackboardRecord record;

            record.artifactId = (artifact_t)sqlite3_column_int64(statement, 0);
            record.fileId = (uint64_t)sqlite3_column_int64(statement, 1);
            record.source = (char *)sqlite3_column_text(statement, 2);
            record.context = (char *)sqlite3_column_text(statement, 3);
            record.attribute = (char *)sqlite3_column_text(statement, 4);
            record.valueType = (int)sqlite3_column_int(statement, 5);
            switch (record.valueType) {
                case TskImgDB::BB_VALUE_TYPE_BYTE:
                    {
                        // return the blob
                        int blobSize = sqlite3_column_bytes(statement, 6);
                        const unsigned char *pBlob = (const unsigned char *)sqlite3_column_blob(statement, 6);
                        record.valueByte.reserve(blobSize);
                        for (int i = 0; i < blobSize; i++) {
                            record.valueByte.push_back((unsigned char)pBlob[i]);
                        }
                    }
                    break;
                case TskImgDB::BB_VALUE_TYPE_STRING:
                    record.valueString = (char *)sqlite3_column_text(statement, 7);
                    break;
                case TskImgDB::BB_VALUE_TYPE_INT32:
                    record.valueInt32 = (int32_t)sqlite3_column_int(statement, 8);
                    break;
                case TskImgDB::BB_VALUE_TYPE_INT64:
                    record.valueInt64 = (int64_t)sqlite3_column_int64(statement, 9);
                    break;
                case TskImgDB::BB_VALUE_TYPE_DOUBLE:
                    record.valueDouble = (double)sqlite3_column_double(statement, 10);
                    break;
            };
            bbRecords.push_back(record);
        }
        sqlite3_finalize(statement);
    } else {
        wchar_t infoMessage[MAX_BUFF_LENGTH];
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::getAllBlackboardRows - Error getting blackboard rows %S", sqlite3_errmsg(m_db));
        LOGERROR(infoMessage);
    }
}

/**
 * Add a new row to the unalloc_img_status table, returning the unalloc_img_id.
 * @param unallocImgId unalloc_img_id (output)
 * @returns -1 on error, 0 on success.
 */
int TskImgDBSqlite::addUnallocImg(int & unallocImgId)
{
    int rc = -1;

    if (!m_db)
        return rc;

    std::stringstream stmt;
    stmt << "INSERT INTO unalloc_img_status (unalloc_img_id, status) VALUES (NULL, " << TskImgDB::IMGDB_UNALLOC_IMG_STATUS_CREATED << ")";
    char * errmsg;
    if (sqlite3_exec(m_db, stmt.str().c_str(), NULL, NULL, &errmsg) == SQLITE_OK) {
        unallocImgId = sqlite3_last_insert_rowid(m_db);
        rc = 0;
    } else {
        wchar_t infoMessage[MAX_BUFF_LENGTH];
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::addUnallocImg - Error adding unalloc_img_status table: %S", errmsg);
        LOGERROR(infoMessage);
        sqlite3_free(errmsg);
    }
    return rc;
}

/**
 * Set the status in the unalloc_img_status table given the unalloc_img_id.
 * @param unallocImgId unalloc_img_id
 * @param status status of unalloc_img_id
 * @returns -1 on error, 0 on success.
 */
int TskImgDBSqlite::setUnallocImgStatus(int unallocImgId, TskImgDB::UNALLOC_IMG_STATUS status)
{
    int rc = -1;

    if (!m_db)
        return rc;

    std::stringstream stmt;
    stmt << "UPDATE unalloc_img_status SET status = " << status << " WHERE unalloc_img_id = " << unallocImgId;
    char * errmsg;
    if (sqlite3_exec(m_db, stmt.str().c_str(), NULL, NULL, &errmsg) == SQLITE_OK) {
        rc = 0;
    } else {
        wchar_t infoMessage[MAX_BUFF_LENGTH];
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::addUnallocImg - Error adding unalloc_img_status table: %S", errmsg);
        LOGERROR(infoMessage);
        sqlite3_free(errmsg);
    }
    return rc;
}

/**
 * Get the status of the unalloc_img_status table given the unalloc_img_id.
 * Can throws TskException.
 * @param unallocImgId unalloc_img_id
 * @returns TskImgDB::UNALLOC_IMG_STATUS
 */
TskImgDB::UNALLOC_IMG_STATUS TskImgDBSqlite::getUnallocImgStatus(int unallocImgId) const
{
    if (!m_db)
        throw TskException("Database not initialized.");

    int status;
    stringstream stmt;
    stmt << "SELECT status FROM unalloc_img_status WHERE unalloc_img_id = " << unallocImgId;

    sqlite3_stmt * statement;
    if (sqlite3_prepare_v2(m_db, stmt.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        if (sqlite3_step(statement) == SQLITE_ROW) {
            status = (int)sqlite3_column_int(statement, 0);
        }
        sqlite3_finalize(statement);
    } else {
        wchar_t infoMessage[MAX_BUFF_LENGTH];
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH,  L"TskImgDBSqlite::getUnallocImgStatus - Error getting unalloc_img_status: %S ", sqlite3_errmsg(m_db));
        LOGERROR(infoMessage);
    }
    return (TskImgDB::UNALLOC_IMG_STATUS)status;
}

/**
 * Get all the unalloc_img_status table.
 * @param unallocImgStatusList A vector of TskUnallocImgStatusRecord (output)
 * @returns -1 on error, 0 on success.
 */
int TskImgDBSqlite::getAllUnallocImgStatus(std::vector<TskUnallocImgStatusRecord> & unallocImgStatusList) const
{
    int rc = -1;
    unallocImgStatusList.clear();

    if (!m_db)
        return rc;

    stringstream stmt;
    stmt << "SELECT unalloc_img_id, status FROM unalloc_img_status";

    sqlite3_stmt * statement;
    if (sqlite3_prepare_v2(m_db, stmt.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        while (sqlite3_step(statement) == SQLITE_ROW) {
            TskUnallocImgStatusRecord record;
            record.unallocImgId = (int)sqlite3_column_int(statement, 0);
            record.status = (int)sqlite3_column_int(statement, 1);
            unallocImgStatusList.push_back(record);
        }
        rc = 0;
        sqlite3_finalize(statement);
    } else {
        wchar_t infoMessage[MAX_BUFF_LENGTH];
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH,  L"TskImgDBSqlite::getAllUnallocImgStatus - Error getting unalloc_img_status: %S ", sqlite3_errmsg(m_db));
        LOGERROR(infoMessage);
    }
    return rc;
}

/**
 * Find and add all the unused sectors (unallocated and uncarved bytes) in the given unallocImgId
 * @param unallocImgId The unalloc image id.
 * @param unusedSectorsList A vector of TskUnusedSectorsRecord
 * @returns -1 on error, 0 on success.
 */
int TskImgDBSqlite::addUnusedSectors(int unallocImgId, std::vector<TskUnusedSectorsRecord> & unusedSectorsList)
{
    assert(unallocImgId > 0);
    int rc = -1;
    if (!m_db)
        return rc;

    std::stringstream stmt;
    stmt << "SELECT vol_id, unalloc_img_sect_start, sect_len, orig_img_sect_start FROM alloc_unalloc_map "
        "WHERE unalloc_img_id = " << unallocImgId << " ORDER BY unalloc_img_sect_start ASC";

    sqlite3_stmt * statement;
    if (sqlite3_prepare_v2(m_db, stmt.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        vector<TskAllocUnallocMapRecord> allocUnallocMapList;

        while (sqlite3_step(statement) == SQLITE_ROW) {
            TskAllocUnallocMapRecord record;
            record.vol_id = (int)sqlite3_column_int(statement, 0);
            record.unalloc_img_id = unallocImgId;
            record.unalloc_img_sect_start = (uint64_t)sqlite3_column_int64(statement, 1);
            record.sect_len = (uint64_t)sqlite3_column_int64(statement, 2);
            record.orig_img_sect_start = (uint64_t)sqlite3_column_int64(statement, 3);
            allocUnallocMapList.push_back(record);
        }
        sqlite3_finalize(statement);

        uint64_t totalSectStart = allocUnallocMapList[0].unalloc_img_sect_start;
        uint64_t totalSectEnd = allocUnallocMapList[allocUnallocMapList.size() - 1].orig_img_sect_start +
                                allocUnallocMapList[allocUnallocMapList.size() - 1].sect_len;
        uint64_t unusedSectStart = totalSectStart;
        uint64_t unusedSectEnd = 0;

        stmt.str("");
        stmt << "SELECT c.file_id, s.sect_start, s.sect_len FROM carved_files c, carved_sectors s "
             << "WHERE c.file_id = s.file_id AND c.vol_id = " << allocUnallocMapList[0].vol_id << " ORDER BY s.sect_start ASC";

        uint64_t cfileSectStart;
        uint64_t cfileSectLen;
        uint64_t fileId;
        int count = 0;

        if (sqlite3_prepare_v2(m_db, stmt.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
            while (sqlite3_step(statement) == SQLITE_ROW) {
                count++;
                fileId = (uint64_t)sqlite3_column_int64(statement, 0);
                cfileSectStart = (uint64_t)sqlite3_column_int64(statement, 1);
                cfileSectLen = (uint64_t)sqlite3_column_int64(statement, 2);
                if (cfileSectStart > unusedSectEnd) {
                    // found an unused sector between unusedSectStart and cfileSectStart
                    if (addUnusedSector(unusedSectEnd, cfileSectStart, allocUnallocMapList[0].vol_id, unusedSectorsList)) {
                        // Log error
                        std::wstringstream msg;
                        msg << L"TskImgDBSqlite::addUnusedSectors - Error adding sector: sectorStart="
                            << unusedSectStart << " sectorEnd=" << cfileSectStart ;
                        LOGERROR(msg.str());
                        return rc;
                    }
                }
                // setup the next unusedSectEnd
                unusedSectEnd = cfileSectStart + cfileSectLen;
            }
            sqlite3_finalize(statement);
            // Handle the last one
            if (count && unusedSectEnd < totalSectEnd) {
               if (addUnusedSector(unusedSectEnd, totalSectEnd, allocUnallocMapList[0].vol_id, unusedSectorsList)) {
                    // Log error
                    std::wstringstream msg;
                    msg << L"TskImgDBSqlite::addUnusedSectors - Error adding sector: sectorStart="
                        << cfileSectStart + cfileSectLen << " sectorEnd=" << totalSectEnd ;
                    LOGERROR(msg.str());
                    return rc;
               }
            }
            rc = 0;
        } else {
            wchar_t infoMessage[MAX_BUFF_LENGTH];
            _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::addUnusedSectors - Error querying carved_files, carved_sectors table: %S", sqlite3_errmsg(m_db));
            LOGERROR(infoMessage);
        }
    } else {
        wchar_t infoMessage[MAX_BUFF_LENGTH];
        _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::addUnusedSectors - Error querying alloc_unalloc_map table: %S", sqlite3_errmsg(m_db));
        LOGERROR(infoMessage);
    }
    return rc;
}

/**
 * Add one unused sector to the database, add it to the files and unused_sectors tables.
 * @param sectStart Unused sector start.
 * @param sectEnd Unused sector end.
 * @param volId Volume Id of the unused sector.
 * @param unusedSectorsList A vector of TskUnusedSectorsRecord (output)
 * @returns -1 on error, 0 on success.
 */
int TskImgDBSqlite::addUnusedSector(uint64_t sectStart, uint64_t sectEnd, int volId, std::vector<TskUnusedSectorsRecord> & unusedSectorsList)
{
    assert(sectEnd > sectStart);
    int rc = -1;
    unusedSectorsList.clear();
    if (!m_db)
        return rc;

    char *ufilename = "ufile";
    std::stringstream stmt;

#define MIN(a,b) ((a) > (b) ? (b) : (a))
// 50 MB per unused sector
#define MAX_UNUSED_SECTOR_SIZE (50*1000000/512)

    uint64_t sectorIndex = 0;
    uint64_t sectorCount = (sectEnd - sectStart)/MAX_UNUSED_SECTOR_SIZE;

    while (sectorIndex <= sectorCount) {
        uint64_t thisSectStart = sectStart + (sectorIndex * MAX_UNUSED_SECTOR_SIZE);
        uint64_t thisSectEnd = thisSectStart + MIN(MAX_UNUSED_SECTOR_SIZE, sectEnd - thisSectStart);

        stmt.str("");
        stmt << "INSERT INTO files (file_id, type_id, name, par_file_id, dir_type, meta_type,"
            "dir_flags, meta_flags, size, ctime, crtime, atime, mtime, mode, uid, gid, status, full_path) "
            "VALUES (NULL, " << IMGDB_FILES_TYPE_UNUSED << ", " << "'ufile'" 
            << ", NULL, " <<  TSK_FS_NAME_TYPE_REG << ", " <<  TSK_FS_META_TYPE_REG << ", "
            << TSK_FS_NAME_FLAG_UNALLOC << ", " << TSK_FS_META_FLAG_UNALLOC << ", "
            << (thisSectEnd - thisSectStart) * 512 << ", NULL, NULL, NULL, NULL, NULL, NULL, NULL, " << IMGDB_FILES_STATUS_READY_FOR_ANALYSIS << "," << "'ufile'" << ")";

        if (sqlite3_exec(m_db, stmt.str().c_str(), NULL, NULL, NULL) == SQLITE_OK) {

            TskUnusedSectorsRecord record;

            // get the file_id from the last insert
            record.fileId = sqlite3_last_insert_rowid(m_db);
            record.sectStart = thisSectStart;
            record.sectLen = thisSectEnd - thisSectStart;

            std::stringstream name;
            name << "ufile_" << thisSectStart << "_" << thisSectEnd << "_" << record.fileId;
            stmt.str("");
            char *item;
            item = sqlite3_mprintf("%Q", name.str().c_str());
            stmt << "UPDATE files SET name = " << item << ", full_path = " 
                << item << " WHERE file_id = " << record.fileId;
            sqlite3_free(item);

            if (sqlite3_exec(m_db, stmt.str().c_str(), NULL, NULL, NULL) != SQLITE_OK) {
                wchar_t infoMessage[MAX_BUFF_LENGTH];
                _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::addUnusedSector - Error update into files table: %S", sqlite3_errmsg(m_db));
                LOGERROR(infoMessage);
                rc = -1;
                break;
            }

            stmt.str("");
            stmt << "INSERT INTO unused_sectors (file_id, sect_start, sect_len, vol_id) VALUES (" 
                 << record.fileId << ", " << record.sectStart << ", " << record.sectLen << ", " << volId << ")";

            if (sqlite3_exec(m_db, stmt.str().c_str(), NULL, NULL, NULL) != SQLITE_OK) {
                wchar_t infoMessage[MAX_BUFF_LENGTH];
                _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::addUnusedSector - Error insert into unused_sectors table: %S", sqlite3_errmsg(m_db));
                LOGERROR(infoMessage);
                rc = -1;
                break;
            }

            unusedSectorsList.push_back(record);
            rc = 0;

        } else {

            wchar_t infoMessage[MAX_BUFF_LENGTH];
            _snwprintf_s(infoMessage, MAX_BUFF_LENGTH, L"TskImgDBSqlite::addUnusedSector - Error insert into files table: %S", sqlite3_errmsg(m_db));
            LOGERROR(infoMessage);
            rc = -1;
            break;
        }
        sectorIndex++;
    } // while
    return rc;
}

/**
 * Get unused sector record given a file id.
 * @param fileId File id of the unused sector.
 * @param unusedSectorsRecord TskUnusedSectorsRecord (output)
 * @returns -1 on error, 0 on success.
 */
int TskImgDBSqlite::getUnusedSector(uint64_t fileId, TskUnusedSectorsRecord & unusedSectorsRecord) const
{
    int rc = -1;
    if (!m_db)
        return rc;

    std::stringstream stmt;
    stmt << "SELECT sect_start, sect_len FROM unused_sectors WHERE file_id = " << fileId;

    sqlite3_stmt * statement;
    if (sqlite3_prepare_v2(m_db, stmt.str().c_str(), -1, &statement, 0) == SQLITE_OK) {
        if (sqlite3_step(statement) == SQLITE_ROW) {
            unusedSectorsRecord.fileId = fileId;
            unusedSectorsRecord.sectStart = (uint64_t)sqlite3_column_int64(statement, 0);
            unusedSectorsRecord.sectLen = (uint64_t)sqlite3_column_int64(statement, 1);
            rc = 0;
        } else {
            std::wstringstream msg;
            msg << L"TskDBSqlite::getUnusedSector - Error querying unused_sectors table for file_id "
                << fileId ;
            LOGERROR(msg.str());
        }
    } else {
        std::wstringstream msg;
        msg << L"TskDBSqlite::getUnusedSector - Error querying unused_sectors table: "
            << sqlite3_errmsg(m_db) ;
        LOGERROR(msg.str());
    }
    return rc;
}
