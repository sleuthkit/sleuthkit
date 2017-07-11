/*
* The Sleuth Kit
*
* Brian Carrier [carrier <at> sleuthkit [dot] org]
* Copyright (c) 2003-2014 Brian Carrier.  All rights reserved
*
*
* This software is distributed under the Common Public License 1.0
*
*/

#include "tsk_hashdb_i.h"
#include "tsk_hash_info.h"

#include "tsk/auto/sqlite3.h"

/**
* \file sqlite_hdb.cpp
* Contains hash database functions for SQLite hash databases.
*/

static const char *SCHEMA_VERSION_PROP = "Schema Version";
static const char *SCHEMA_VERSION_NO = "1";
static const char *SQLITE_FILE_HEADER = "SQLite format 3";
static const size_t MD5_BLOB_LEN = ((TSK_HDB_HTYPE_MD5_LEN) / 2);
static const char hex_digits[] = "0123456789abcdef";

/**
 * Represents a TSK SQLite hash database (it doesn't need an external index).
 */
typedef struct TSK_SQLITE_HDB_INFO {
    TSK_HDB_INFO base;
    sqlite3 *db;

    sqlite3_stmt *insert_md5_into_hashes; ///< Once initialized, prepared statements are tied to a specific database
    sqlite3_stmt *insert_into_file_names;
    sqlite3_stmt *insert_into_comments;
    sqlite3_stmt *select_from_hashes_by_md5;
    sqlite3_stmt *select_from_file_names;
    sqlite3_stmt *select_from_comments;
} TSK_SQLITE_HDB_INFO;

static uint8_t 
    sqlite_hdb_attempt(int resultCode, int expectedResultCode, const char *errfmt, 
    sqlite3 *sqlite)
{
    if (resultCode != expectedResultCode) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr(errfmt, sqlite3_errmsg(sqlite), resultCode);
        return 1;
    }
    return 0;
}

static uint8_t 
    sqlite_hdb_attempt_exec(const char *sql, const char *errfmt, sqlite3 *sqlite)
{
    char *errmsg = NULL;
    if(sqlite3_exec(sqlite, sql, NULL, NULL, &errmsg) != SQLITE_OK) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB); 
        tsk_error_set_errstr(errfmt, errmsg);
        sqlite3_free(errmsg);
        return 1;
    }
    return 0;
}

static uint8_t 
    sqlite_hdb_create_tables(sqlite3 *db)
{
    if (sqlite_hdb_attempt_exec("CREATE TABLE db_properties (name TEXT NOT NULL, value TEXT);", "sqlite_hdb_create_tables: error creating db_properties table: %s\n", db)) {
        return 1;
    }

    char sql_stmt[1024];
    snprintf(sql_stmt, 1024, "INSERT INTO db_properties (name, value) VALUES ('%s', '%s');", SCHEMA_VERSION_PROP, SCHEMA_VERSION_NO);
    if (sqlite_hdb_attempt_exec(sql_stmt, "sqlite_hdb_create_tables: error adding schema info to db_properties: %s\n", db)) {
        return 1;
    }

    if (sqlite_hdb_attempt_exec ("CREATE TABLE hashes (id INTEGER PRIMARY KEY AUTOINCREMENT, md5 BINARY(16) UNIQUE, sha1 BINARY(20), sha2_256 BINARY(32));", "sqlite_hdb_create_tables: error creating hashes table: %s\n", db)) {
        return 1;
    }

    if (sqlite_hdb_attempt_exec("CREATE TABLE file_names (name TEXT NOT NULL, hash_id INTEGER NOT NULL, PRIMARY KEY(name, hash_id));", "sqlite_hdb_create_tables: error creating file_names table: %s\n", db)) {
        return 1;
    }

    if (sqlite_hdb_attempt_exec("CREATE TABLE comments (comment TEXT NOT NULL, hash_id INTEGER NOT NULL, PRIMARY KEY(comment, hash_id));", "sqlite_hdb_create_tables: error creating comments table: %s\n", db)) {
        return 1;
    }

    if (sqlite_hdb_attempt_exec("CREATE INDEX md5_index ON hashes(md5);", "sqlite_hdb_create_tables: error creating md5_index on md5: %s\n", db)) {
        return 1;
    }

    return 0;
}

static uint8_t 
    sqlite_hdb_prepare_stmt(const char *sql, sqlite3_stmt **stmt, sqlite3 *db)
{
    if (sqlite3_prepare_v2(db, sql, -1, stmt, NULL) != SQLITE_OK) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr("sqlite_hdb_prepare_stmt: error preparing SQL statement: %s: %s\n", sql, sqlite3_errmsg(db));
        return 1;
    }
    return 0;
}

static uint8_t 
    prepare_statements(TSK_SQLITE_HDB_INFO *hdb_info)
{
    if (sqlite_hdb_prepare_stmt("INSERT OR IGNORE INTO hashes (md5) VALUES (?)", &(hdb_info->insert_md5_into_hashes), hdb_info->db)) {
        return 1;
    }

    if (sqlite_hdb_prepare_stmt("INSERT OR IGNORE INTO file_names (name, hash_id) VALUES (?, ?)", &(hdb_info->insert_into_file_names), hdb_info->db)) {
        return 1;
    }

    if (sqlite_hdb_prepare_stmt("INSERT OR IGNORE INTO comments (comment, hash_id) VALUES (?, ?)", &(hdb_info->insert_into_comments), hdb_info->db)) {
        return 1;
    }

    if (sqlite_hdb_prepare_stmt("SELECT id, md5 from hashes where md5 = ? limit 1", &(hdb_info->select_from_hashes_by_md5), hdb_info->db)) {
        return 1;
    }

    if (sqlite_hdb_prepare_stmt("SELECT name from file_names where hash_id = ?", &(hdb_info->select_from_file_names), hdb_info->db)) {
        return 1;
    }

    if (sqlite_hdb_prepare_stmt("SELECT comment from comments where hash_id = ?", &(hdb_info->select_from_comments), hdb_info->db)) {
        return 1;
    }

    return 0;
}

static uint8_t 
    sqlite_hdb_finalize_stmt(sqlite3_stmt **stmt, sqlite3 *db)
{
    if ((NULL != *stmt) && (sqlite3_finalize(*stmt) != SQLITE_OK)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr("sqlite_hdb_finalize_stmt: error finalizing SQL statement: %s\n", sqlite3_errmsg(db));
        *stmt = NULL;
        return 1;
    }
    *stmt = NULL;
    return 0;
}

static void
    finalize_statements(TSK_SQLITE_HDB_INFO *hdb_info)
{
    sqlite_hdb_finalize_stmt(&(hdb_info->insert_md5_into_hashes), hdb_info->db);
    sqlite_hdb_finalize_stmt(&(hdb_info->insert_into_file_names), hdb_info->db);
    sqlite_hdb_finalize_stmt(&(hdb_info->insert_into_comments), hdb_info->db);
    sqlite_hdb_finalize_stmt(&(hdb_info->select_from_hashes_by_md5), hdb_info->db);
    sqlite_hdb_finalize_stmt(&(hdb_info->select_from_file_names), hdb_info->db);
    sqlite_hdb_finalize_stmt(&(hdb_info->select_from_comments), hdb_info->db);
}

static sqlite3 *sqlite_hdb_open_db(TSK_TCHAR *db_file_path, bool create_tables)
{
    sqlite3 *db = NULL;
#ifdef TSK_WIN32
    if (sqlite_hdb_attempt(sqlite3_open16(db_file_path, &db), SQLITE_OK, "Can't open hash database: %s (result code %d)\n", db)) {
        sqlite3_close(db);
        return NULL;
    }
#else
    if (sqlite_hdb_attempt(sqlite3_open(db_file_path, &db), SQLITE_OK, "Can't open hash database: %s (result code %d)\n", db)) {
        sqlite3_close(db);
        return NULL;
    }
#endif
    sqlite3_extended_result_codes(db, 1);

    if (sqlite_hdb_attempt_exec("PRAGMA synchronous = OFF;", "Error setting PRAGMA synchronous: %s\n", db)) {
        sqlite3_close(db);
        return NULL;
    }

    if (sqlite_hdb_attempt_exec("PRAGMA encoding = \"UTF-8\";", "Error setting PRAGMA encoding UTF-8: %s\n", db)) {
        sqlite3_close(db);
        return NULL;
    }

    if (sqlite_hdb_attempt_exec("PRAGMA read_uncommitted = True;", "Error setting PRAGMA read_uncommitted: %s\n", db)) {
        sqlite3_close(db);
        return NULL;
    }

    if (sqlite_hdb_attempt_exec("PRAGMA page_size = 4096;", "Error setting PRAGMA page_size: %s\n", db)) {
        sqlite3_close(db);
        return NULL;
    }

    // Configure the database to increase its size incrementally.    
    int chunkSize = 1024 * 1024;
    if (sqlite3_file_control(db, NULL, SQLITE_FCNTL_CHUNK_SIZE, &chunkSize) != SQLITE_OK) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr("sqlite_v1_initialize: error setting chunk size %s", sqlite3_errmsg(db));
        sqlite3_close(db);
        return NULL;
    }

    if (create_tables && sqlite_hdb_create_tables(db)) {
        sqlite3_close(db);
        return NULL;
    }

    return db;
}

/**
* \ingroup hashdblib
* \internal 
* Creates a new SQLite hash database.
* @param db_file_path A path for the new hash database.
* @return 0 on success, 1 on failure.
*/
uint8_t 
    sqlite_hdb_create_db(TSK_TCHAR *db_file_path)
{
    sqlite3 *db = sqlite_hdb_open_db(db_file_path, true);
    if (NULL == db) {
        return 1;
    }

    sqlite3_close(db);

    return 0;
}

/**
* \ingroup hashdblib
* \internal 
* Determines whether a file is a SQLite file.
* @param hFile_path A handle to the file to inspect.
* @return 1 if the file is a SQLite file, 0 if it is not.
*/
uint8_t
    sqlite_hdb_is_sqlite_file(FILE *hFile)
{
    const int header_size = 16;
    char header[header_size];
    if (1 != fread(header, header_size, 1, hFile)) {
        return 0;
    }
    else {
        return (strncmp(header, SQLITE_FILE_HEADER, strlen(SQLITE_FILE_HEADER)) == 0);
    }            
}

/**
* \ingroup hashdblib
* \internal 
* Opens an existing SQLite hash database.
* @param db_file_path A path for the new hash database.
* @return 0 on success, 1 on failure.
*/
TSK_HDB_INFO *sqlite_hdb_open(TSK_TCHAR *db_path)
{
    sqlite3 *db = sqlite_hdb_open_db(db_path, false);
    if (!db) {
        return NULL;
    }

    TSK_SQLITE_HDB_INFO *hdb_info = (TSK_SQLITE_HDB_INFO*)tsk_malloc(sizeof(TSK_SQLITE_HDB_INFO));
    if (!hdb_info) {
        sqlite3_close(db);
        return NULL;
    }

    if (hdb_info_base_open((TSK_HDB_INFO*)hdb_info, db_path)) {
        sqlite3_close(db);
        free(hdb_info);
        return NULL;
    }

    hdb_info->db = db;
    if (prepare_statements(hdb_info)) {
        finalize_statements(hdb_info);
        sqlite3_close(db);
        return NULL;
    }

    hdb_info->base.db_type = TSK_HDB_DBTYPE_SQLITE_ID;
    hdb_info->base.lookup_str = sqlite_hdb_lookup_str;
    hdb_info->base.lookup_raw = sqlite_hdb_lookup_bin;
    hdb_info->base.lookup_verbose_str = sqlite_hdb_lookup_verbose_str;
    hdb_info->base.add_entry = sqlite_hdb_add_entry;
    hdb_info->base.begin_transaction = sqlite_hdb_begin_transaction;
    hdb_info->base.commit_transaction = sqlite_hdb_commit_transaction;
    hdb_info->base.rollback_transaction = sqlite_hdb_rollback_transaction;
    hdb_info->base.close_db = sqlite_hdb_close;

    return (TSK_HDB_INFO*)hdb_info;
}

static uint8_t* 
    sqlite_hdb_str_to_blob(const char *str)
{
    const size_t len = strlen(str)/2;
    uint8_t *blob = (uint8_t *)tsk_malloc(len+1);
    if (NULL == blob) {
        return NULL;
    }

    const char *pos = str;
    for (size_t count = 0; count < len; ++count) {
        sscanf(pos, "%2hx", (short unsigned int *) &(blob[count]));
        pos += 2 * sizeof(char);
    }
    return blob;
}

static std::string 
    sqlite_hdb_blob_to_string(std::string binblob)
{
    size_t blobsize = binblob.size();
    if (blobsize <= TSK_HDB_MAX_BINHASH_LEN) {
        char hashbuf[TSK_HDB_HTYPE_SHA2_256_LEN + 1];
        for (size_t i = 0; i < blobsize; ++i) {
            hashbuf[2 * i] = hex_digits[(binblob[i] >> 4) & 0xf];
            hashbuf[2 * i + 1] = hex_digits[binblob[i] & 0xf];
        }
        hashbuf[2 * blobsize] = '\0';
        return std::string(&hashbuf[0]);
    } 
    else {
        return "";
    }
}

static int8_t  
    sqlite_hdb_hash_lookup_by_md5(uint8_t *md5Blob, size_t len, TSK_SQLITE_HDB_INFO *hdb_info, TskHashInfo &result)
{
    int8_t ret_val = -1;
    if (sqlite_hdb_attempt(sqlite3_bind_blob(hdb_info->select_from_hashes_by_md5, 1, md5Blob, (int)len, SQLITE_TRANSIENT), SQLITE_OK, "sqlite_hdb_hash_lookup_by_md5: error binding md5 hash blob: %s (result code %d)\n", hdb_info->db) == 0) {
        int result_code = sqlite3_step(hdb_info->select_from_hashes_by_md5);
        if (SQLITE_ROW == result_code) {
            // Found it.
            result.id = sqlite3_column_int64(hdb_info->select_from_hashes_by_md5, 0); 
            result.hashMd5 = sqlite_hdb_blob_to_string((const char*)sqlite3_column_text(hdb_info->select_from_hashes_by_md5, 1));
            ret_val = 1;
        }
        else if (SQLITE_DONE == result_code) {
            // Didn't find it, but no error.
            ret_val = 0;
        }
        else {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_AUTO_DB);
            tsk_error_set_errstr("sqlite_hdb_hash_lookup_by_md5: error executing SELECT: %s\n", sqlite3_errmsg(hdb_info->db));
        }
    }
    sqlite3_clear_bindings(hdb_info->select_from_hashes_by_md5);
    sqlite3_reset(hdb_info->select_from_hashes_by_md5);
    return ret_val;
}

static int64_t
    sqlite_hdb_insert_md5_hash(uint8_t *md5Blob, size_t len, TSK_SQLITE_HDB_INFO *hdb_info)
{
    int64_t row_id = 0;
    if (sqlite_hdb_attempt(sqlite3_bind_blob(hdb_info->insert_md5_into_hashes, 1, md5Blob, (int)len, SQLITE_TRANSIENT), SQLITE_OK, "sqlite_hdb_insert_md5_hash: error binding md5 hash blob: %s (result code %d)\n", hdb_info->db) == 0) {        
        int result = sqlite3_step(hdb_info->insert_md5_into_hashes);
        if (result == SQLITE_DONE) {
            row_id = sqlite3_last_insert_rowid(hdb_info->db);
        }
        else {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_AUTO_DB);
            tsk_error_set_errstr("sqlite_hdb_insert_md5_hash: error executing INSERT: %s\n", sqlite3_errmsg(hdb_info->db));
        }
    }
    sqlite3_clear_bindings(hdb_info->insert_md5_into_hashes);
    sqlite3_reset(hdb_info->insert_md5_into_hashes);
    return row_id;
}

static uint8_t 
    sqlite_hdb_insert_value_and_id(sqlite3_stmt *stmt, const char *value, int64_t id, sqlite3 *db)
{
    uint8_t ret_val = 1;
    if ((sqlite_hdb_attempt(sqlite3_bind_text(stmt, 1, value, (int)strlen(value), SQLITE_TRANSIENT), SQLITE_OK, "sqlite_hdb_insert_value_and_id: error binding value: %s (result code %d)\n", db) == 0) &&
        (sqlite_hdb_attempt(sqlite3_bind_int64(stmt, 2, id), SQLITE_OK, "sqlite_hdb_insert_value_and_id: error binding id: %s (result code %d)\n", db) == 0)) {        
            int result = sqlite3_step(stmt);
            if ((result != SQLITE_DONE) && (result != SQLITE_CONSTRAINT)) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_AUTO_DB);
                tsk_error_set_errstr("sqlite_hdb_insert_value_and_id: error executing INSERT: %s\n", sqlite3_errmsg(db));
            }
            else {
                // Either the INSERT succeeded or the value was a duplicate, which is o.k.
                ret_val = 0;
            }
    }
    sqlite3_clear_bindings(stmt);
    sqlite3_reset(stmt);        
    return ret_val;
}

/**
* \ingroup hashdblib
* \internal 
* Adds an entry to a SQLite hash database.
* @param hdb_info_base The struct that represents the database.
* @param filename A file name to associate with the hashes, may be NULL.
* @param md5 An md5 hash.
* @param sha1 A SHA-1 hash, may be NULL.
* @param sha256 A SHA-256 hash, may be NULL.
* @param comment A comment to associate with the hashes, may be NULL.
* @return 1 on error and 0 on success
*/
uint8_t
    sqlite_hdb_add_entry(TSK_HDB_INFO *hdb_info_base, const char *filename, 
    const char *md5, const char *sha1, const char *sha256, const char *comment)
{
    // Currently only supporting md5.
    const size_t md5_str_len = strlen(md5);
    if (TSK_HDB_HTYPE_MD5_LEN != md5_str_len) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_ARG);
        tsk_error_set_errstr("sqlite_hdb_add_entry: md5 length incorrect (=%" PRIuSIZE")", md5_str_len);
        return 1;
    }

    // Convert the md5 string to a binary blob, since that's how md5 hashes
    // are stored in the database.	
    uint8_t *hashBlob = sqlite_hdb_str_to_blob(md5);
    if (NULL == hashBlob) {
        return 1;
    }

    // Is this hash already in the database? 
    tsk_take_lock(&hdb_info_base->lock);
    TSK_SQLITE_HDB_INFO *hdb_info = (TSK_SQLITE_HDB_INFO*)hdb_info_base; 
    TskHashInfo lookup_result;
    int64_t row_id = -1;
    const size_t len = strlen(md5)/2; 
    int64_t result_code = sqlite_hdb_hash_lookup_by_md5(hashBlob, len, hdb_info, lookup_result);
    if (1 == result_code) {
        // Found it. 
        row_id = lookup_result.id;
    }
    else if (0 == result_code) {
        //If not, insert it. 
        row_id = sqlite_hdb_insert_md5_hash(hashBlob, len, hdb_info);
        if (row_id < 1) {
            // Did not get a valid row_id from the INSERT.
            free(hashBlob);
            tsk_release_lock(&hdb_info_base->lock);
            return 1;
        }
    }
    else {
        // Error querying database.
        free(hashBlob);
        tsk_release_lock(&hdb_info_base->lock);
        return 1;
    }

    free(hashBlob);

    // Insert the file name, if any.
    if (NULL != filename && sqlite_hdb_insert_value_and_id(hdb_info->insert_into_file_names, filename, row_id, hdb_info->db) == 1) {
        tsk_release_lock(&hdb_info_base->lock);
        return 1;
    }

    // Insert the comment, if any.
    if (NULL != comment && sqlite_hdb_insert_value_and_id(hdb_info->insert_into_comments, comment, row_id, hdb_info->db) == 1) {
        tsk_release_lock(&hdb_info_base->lock);
        return 1;
    }

    tsk_release_lock(&hdb_info_base->lock);
    return 0;
}

/**
* \ingroup hashdblib
* \internal 
* Looks up a hash in a SQLite hash database.
* @param hdb_info_base The struct that represents the database.
* @param hash Hash value to search for (NULL terminated string).
* @param flags Flags to use in lookup.
* @param action Callback function (not called if QUICK flag is given)
* @param ptr Pointer to data to pass to callback
* @return -1 on error, 0 if hash value not found, 1 if hash value found.
*/
int8_t
    sqlite_hdb_lookup_str(TSK_HDB_INFO * hdb_info_base, const char* hash,
    TSK_HDB_FLAG_ENUM flags, TSK_HDB_LOOKUP_FN action, void *ptr)
{
    // Currently only supporting lookups of md5 hashes.
    const size_t len = strlen(hash);
    if (TSK_HDB_HTYPE_MD5_LEN != len) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_ARG);
        tsk_error_set_errstr("sqlite_hdb_lookup_str: hash length incorrect (=%" PRIuSIZE"), expecting %d", len, TSK_HDB_HTYPE_MD5_LEN);
        return 1;
    }

    uint8_t *hashBlob = sqlite_hdb_str_to_blob(hash);
    if (!hashBlob) {
        return 1;
    }

    int8_t ret_val = sqlite_hdb_lookup_bin(hdb_info_base, hashBlob, MD5_BLOB_LEN, flags, action, ptr);
    free(hashBlob);
    return ret_val; 
}

/**
* \ingroup hashdblib
* \internal 
* Looks up a hash in a SQLite hash database.
* @param hdb_info_base The struct that represents the database.
* @param hash Hash value to search for (binary form, array of bytes).
* @param len Number of bytes in binary hash value
* @param flags Flags to use in lookup.
* @param action Callback function (not called if QUICK flag is given)
* @param ptr Pointer to data to pass to callback
* @return -1 on error, 0 if hash value not found, 1 if hash value found.
*/
int8_t
    sqlite_hdb_lookup_bin(TSK_HDB_INFO *hdb_info_base, uint8_t *hash, 
    uint8_t len, TSK_HDB_FLAG_ENUM flags, TSK_HDB_LOOKUP_FN action, void *ptr)
{
    // Currently only supporting lookups of md5 hashes.
    if (MD5_BLOB_LEN != len) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_ARG);
        tsk_error_set_errstr("sqlite_hdb_lookup_bin: len=%" PRIu8", expected %" PRIuSIZE, len, MD5_BLOB_LEN);
        return -1;
    }

    // Do the look up.
    TskHashInfo result;
    int8_t ret_val = sqlite_hdb_lookup_verbose_bin(hdb_info_base, hash, len, &result);

    // Do the callback, if warranted.
    if ((1 == ret_val) && !(flags & TSK_HDB_FLAG_QUICK) && (NULL != action)) {
        if (result.fileNames.size() > 0) {
            for (std::vector<std::string>::iterator it = result.fileNames.begin(); it != result.fileNames.end(); ++it) {
                action(hdb_info_base, result.hashMd5.c_str(), (*it).c_str(), ptr);
            }
        }
        else {
            action(hdb_info_base, result.hashMd5.c_str(), NULL, ptr);
        }
    }        

    return ret_val;
}

static uint8_t
    sqlite_hdb_get_assoc_strings(sqlite3 *db, sqlite3_stmt *stmt, int64_t hash_id, std::vector<std::string> &out)
{
    uint8_t ret_val = 1;
    if (sqlite_hdb_attempt(sqlite3_bind_int64(stmt, 1, hash_id), SQLITE_OK, "sqlite_hdb_get_assoc_strings: error binding hash_id: %s (result code %d)\n", db) == 0) {
        while(1) {
            int result_code = sqlite3_step(stmt);
            if (SQLITE_ROW == result_code) {
                out.push_back((const char*)sqlite3_column_text(stmt, 0));
                ret_val = 0;
            }
            else if (SQLITE_DONE == result_code) {
                ret_val = 0;
                break;
            }
            else {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_AUTO_DB);
                tsk_error_set_errstr("sqlite_hdb_get_assoc_strings: error executing SELECT: %s\n", sqlite3_errmsg(db));
                ret_val = 1;
                break;
            }            
        };
    }
    sqlite3_clear_bindings(stmt);
    sqlite3_reset(stmt);
    return ret_val;
}

/**
* \ingroup hashdblib
* \internal 
* Looks up a hash and any additional data associated with the hash in a 
* hash database.
* @param hdb_info_base A struct representing an open hash database.
* @param hash A hash value in string form.
* @param result A TskHashInfo struct to populate on success.
* @return -1 on error, 0 if hash value was not found, 1 if hash value
* was found.
*/
int8_t sqlite_hdb_lookup_verbose_str(TSK_HDB_INFO *hdb_info_base, const char *hash, void *result)
{
    // Currently only supporting lookups of md5 hashes.
    const size_t len = strlen(hash);
    if (TSK_HDB_HTYPE_MD5_LEN != len) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_ARG);
        tsk_error_set_errstr("sqlite_hdb_lookup_verbose_str: hash length incorrect (=%" PRIuSIZE"), expecting %d", len, TSK_HDB_HTYPE_MD5_LEN);
        return -1;
    }

    uint8_t *hashBlob = sqlite_hdb_str_to_blob(hash);
    if (!hashBlob) {
        return -1;
    }

    int8_t ret_val = sqlite_hdb_lookup_verbose_bin(hdb_info_base, hashBlob, MD5_BLOB_LEN, result);
    free(hashBlob);
    return ret_val; 
}

/**
* \ingroup hashdblib
* \internal 
* Looks up a hash and any additional data associated with the hash in a 
* hash database.
* @param hdb_info_base A struct representing an open hash database.
* @param hash A hash value in binary form.
* @param hash_len The length of the hash value in bytes.
* @param lookup_result A TskHashInfo struct to populate on success.
* @return -1 on error, 0 if hash value was not found, 1 if hash value
* was found.
*/
int8_t sqlite_hdb_lookup_verbose_bin(TSK_HDB_INFO *hdb_info_base, uint8_t *hash, uint8_t hash_len, void *lookup_result)
{
    // Currently only supporting lookups of md5 hashes.
    if (MD5_BLOB_LEN != hash_len) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_ARG);
        tsk_error_set_errstr("sqlite_hdb_lookup_verbose_bin: hash_len=%d, expected %d", hash_len, TSK_HDB_HTYPE_MD5_LEN / 2);
        return -1;
    }

    // Do the lookup.
    tsk_take_lock(&hdb_info_base->lock);
    TSK_SQLITE_HDB_INFO *hdb_info = (TSK_SQLITE_HDB_INFO*)hdb_info_base;     
    TskHashInfo *result = static_cast<TskHashInfo*>(lookup_result);
    int8_t ret_val = sqlite_hdb_hash_lookup_by_md5(hash, hash_len, hdb_info, *result);
    if (ret_val < 1) {
        tsk_release_lock(&hdb_info_base->lock);
        return ret_val;
    }

    // Get any file names associated with the hash. 
    if (sqlite_hdb_get_assoc_strings(hdb_info->db, hdb_info->select_from_file_names, result->id, result->fileNames)) {
        tsk_release_lock(&hdb_info_base->lock);
        return -1;
    }

    // Get any comments associated with the hash. 
    if (sqlite_hdb_get_assoc_strings(hdb_info->db, hdb_info->select_from_comments, result->id, result->comments)) {
        tsk_release_lock(&hdb_info_base->lock);
        return -1;
    }

    tsk_release_lock(&hdb_info_base->lock);
    return 1; 
}

/**
* \ingroup hashdblib
* \internal 
* Begins a transaction on a hash database.
* @param hdb_info A hash database info object
* @return 1 on error, 0 on success
*/
uint8_t sqlite_hdb_begin_transaction(TSK_HDB_INFO *hdb_info_base) 
{
    TSK_SQLITE_HDB_INFO *hdb_info = reinterpret_cast<TSK_SQLITE_HDB_INFO*>(hdb_info_base); 
    if (sqlite_hdb_attempt_exec("BEGIN", "sqlite_hdb_base_begin_transaction: %s\n", hdb_info->db)) {
        return 1;
    }
    else {
        return 0;
    }
}

/**
* \ingroup hashdblib
* \internal 
* Commits a transaction on a hash database.
* @param hdb_info A hash database info object
* @return 1 on error, 0 on success 
*/
uint8_t sqlite_hdb_commit_transaction(TSK_HDB_INFO *hdb_info_base)
{
    TSK_SQLITE_HDB_INFO *hdb_info = reinterpret_cast<TSK_SQLITE_HDB_INFO*>(hdb_info_base);
    if (sqlite_hdb_attempt_exec("COMMIT", "sqlite_hdb_commit_transaction: %s\n", hdb_info->db)) {
        return 1;
    }
    else {
        return 0;
    }
}

/**
* \ingroup hashdblib
* \internal 
* Rolls back a transaction on a hash database.
* @param hdb_info A hash database info object
* @return 1 on error, 0 on success 
*/
uint8_t sqlite_hdb_rollback_transaction(TSK_HDB_INFO *hdb_info_base)
{
    TSK_SQLITE_HDB_INFO *hdb_info = reinterpret_cast<TSK_SQLITE_HDB_INFO*>(hdb_info_base); 
    if (sqlite_hdb_attempt_exec("ROLLBACK", "sqlite_hdb_rollback_transaction: %s\n", hdb_info->db)) {
        return 1;
    }
    else {
        return 0;
    }
}

/*
* Closes an SQLite hash database.
* @param idx_info the index to close
*/
void
    sqlite_hdb_close(TSK_HDB_INFO *hdb_info_base)
{
    TSK_SQLITE_HDB_INFO *hdb_info = (TSK_SQLITE_HDB_INFO*)hdb_info_base; 
    if (hdb_info->db) {
        finalize_statements(hdb_info);
        sqlite3_close(hdb_info->db);
    }
    hdb_info->db = NULL;

    hdb_info_base_close(hdb_info_base);

    free(hdb_info);
}
