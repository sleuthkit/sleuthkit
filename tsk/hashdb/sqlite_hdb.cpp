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
#include "lookup_result.h"
#include <assert.h>

/**
 * \file sqlite_hdb.cpp
 * Contains hash database functions for SQLite hash databases.
 */

static const char *SQLITE_HDB_SCHEMA_VERSION_PROP = "Schema Version";
static const char *SQLITE_HDB_SCHEMA_VERSION_NO = "1";
static const char *SQLITE_FILE_HEADER = "SQLite format 3";
static sqlite3_stmt *select_id_from_hashes_by_md5 = NULL;
static sqlite3_stmt *select_from_hashes_by_md5 = NULL;
static sqlite3_stmt *insert_md5_into_hashes = NULL; 
static sqlite3_stmt *insert_into_file_names = NULL; 
static sqlite3_stmt *insert_into_comments = NULL; 
static const char hex[] = "0123456789abcdef";

// RJCTODO: Make sure format strings passed in are correct for all callers!!!
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
sqlite_hdb_attempt_exec(const char *sql, const char *errfmt, 
    sqlite3 *sqlite)
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
	if (sqlite_hdb_attempt_exec("CREATE TABLE db_properties (name TEXT NOT NULL, value TEXT);", "Error creating db_properties table %s\n", db)) {
        return 1;
	}

	char stmt[1024];
	snprintf(stmt, 1024, "INSERT INTO db_properties (name, value) VALUES ('%s', '%s');", SQLITE_HDB_SCHEMA_VERSION_PROP, SQLITE_HDB_SCHEMA_VERSION_NO);
	if (sqlite_hdb_attempt_exec(stmt, "Error adding schema info to db_properties: %s\n", db)) {
        return 1;
	}

	if (sqlite_hdb_attempt_exec ("CREATE TABLE hashes (id INTEGER PRIMARY KEY AUTOINCREMENT, md5 BINARY(16) UNIQUE, sha1 BINARY(20), sha2_256 BINARY(32));", "Error creating hashes table %s\n", db)) {
        return 1;
	}

	if (sqlite_hdb_attempt_exec("CREATE TABLE file_names (name TEXT NOT NULL, hash_id INTEGER NOT NULL);", "Error creating file_names table %s\n", db)) {
        return 1;
	}

	if (sqlite_hdb_attempt_exec("CREATE TABLE comments (comment TEXT NOT NULL, hash_id INTEGER NOT NULL);", "Error creating comments table %s\n", db)) {
        return 1;
	}

	if (sqlite_hdb_attempt_exec("CREATE INDEX md5_index ON hashes(md5);", "Error creating md5_index on md5: %s\n", db)) {
        return 1;
	}
	
	if (sqlite_hdb_attempt_exec("CREATE INDEX sha1_index ON hashes(sha1);", "Error creating sha1_index on sha1: %s\n", db)) {
        return 1;
    }

    return 0;
}

static uint8_t 
sqlite_hdb_prepare_stmt(const char *sql, sqlite3_stmt **stmt, sqlite3 *sqlite)
{
    ///@todo possible performance increase by using strlen(sql)+1 instead of -1 // RJCTODO: Resolve this
	if (sqlite3_prepare_v2(sqlite, sql, -1, stmt, NULL) != SQLITE_OK) {
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_AUTO_DB);
		tsk_error_set_errstr("sqlite_hdb_prepare_stmt: error preparing SQL statement: %s", sql);
        tsk_error_print(stderr);
		return 1;
	}
	return 0;
}

static uint8_t 
sqlite_hdb_finalize_stmt(sqlite3_stmt **stmt)
{
    uint8_t ret_val = 0;
    if ((NULL != *stmt) && (sqlite3_finalize(*stmt) != SQLITE_OK)) {
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_AUTO_DB);
		tsk_error_set_errstr("sqlite_hdb_finalize_stmt: error finalizing SQL statement");
        tsk_error_print(stderr);
        *stmt = NULL;
		return 1;
	}
    *stmt = NULL;
	return ret_val;
}

static uint8_t 
prepare_statements(sqlite3 *db)
{
    if (sqlite_hdb_prepare_stmt("SELECT id from hashes where md5=? limit 1", &select_id_from_hashes_by_md5, db)) {
        return 1;
    }

    if (sqlite_hdb_prepare_stmt("SELECT id, md5 from hashes where md5=? limit 1", &select_from_hashes_by_md5, db)) {
        return 1;
    }

    if (sqlite_hdb_prepare_stmt("INSERT INTO hashes (md5) VALUES (?)", &insert_md5_into_hashes, db)) {
        return 1;
    }

    if (sqlite_hdb_prepare_stmt("INSERT INTO file_names (name, hash_id) VALUES (?, ?)", &insert_into_file_names, db)) {
        return 1;
    }

    if (sqlite_hdb_prepare_stmt("INSERT INTO comments (comment, hash_id) VALUES (?, ?)", &insert_into_comments, db)) {
        return 1;
    }

    return 0;
}

static void
finalize_statements()
{
    sqlite_hdb_finalize_stmt(&select_id_from_hashes_by_md5);
    sqlite_hdb_finalize_stmt(&select_from_hashes_by_md5);
    sqlite_hdb_finalize_stmt(&insert_md5_into_hashes);
    sqlite_hdb_finalize_stmt(&insert_into_file_names);
    sqlite_hdb_finalize_stmt(&insert_into_comments);
}

static sqlite3 *sqlite_hdb_open_db(TSK_TCHAR *db_file_path, bool create_tables)
{
    sqlite3 *db = NULL;
#ifdef TSK_WIN32
    int opened = sqlite_hdb_attempt(sqlite3_open16(db_file_path, &db), SQLITE_OK, "Can't open hash database: %s\n", db);
#else
    int opened = sqlite_hdb_attempt(sqlite3_open(db_file_path, &db), SQLITE_OK, "Can't open hash database: %s\n", db);
#endif
    if (1 != opened) {
        // RJCTODO: No error checking?
	    sqlite3_extended_result_codes(db, 1);
		sqlite_hdb_attempt_exec("PRAGMA synchronous = OFF;", "Error setting PRAGMA synchronous: %s\n", db);
		sqlite_hdb_attempt_exec("PRAGMA encoding = \"UTF-8\";", "Error setting PRAGMA encoding UTF-8: %s\n", db);
		sqlite_hdb_attempt_exec("PRAGMA read_uncommitted = True;", "Error setting PRAGMA read_uncommitted: %s\n", db);
		sqlite_hdb_attempt_exec("PRAGMA page_size = 4096;", "Error setting PRAGMA page_size: %s\n", db);
    }
    else {
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

    if (create_tables && !sqlite_hdb_create_tables(db)) {
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
    assert(db_file_path);
    if (!db_file_path) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_ARG);
        tsk_error_set_errstr("sqlite_hdb_create_db: NULL db_file_path");
        return 1;
    }

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
    assert(hFile);
    if (!hFile) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_ARG);
        tsk_error_set_errstr("sqlite_hdb_is_sqlite_file: NULL hFile");
        return 0;
    }

    const int header_size = 16;
    char header[header_size];
    if (1 != fread(header, header_size, 1, hFile)) {
        return 0;
    }
    else {
        return (strncmp(header, SQLITE_FILE_HEADER, 
            strlen(SQLITE_FILE_HEADER)) == 0);
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
    assert(db_path);
    if (!db_path) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_ARG);
        tsk_error_set_errstr("sqlite_hdb_open: NULL db_path");
        return NULL;
    }

    sqlite3 *db = sqlite_hdb_open_db(db_path, false);
    if (!db) {
        return NULL;
    }

    if (prepare_statements(db)) {
        finalize_statements();
        sqlite3_close(db);
        return NULL;
    }

    TSK_SQLITE_HDB_INFO *hdb_info = (TSK_SQLITE_HDB_INFO*)tsk_malloc(sizeof(TSK_SQLITE_HDB_INFO));
    if (!hdb_info) {
        finalize_statements();
        sqlite3_close(db);
        return NULL;
    }

    if (hdb_info_base_open((TSK_HDB_INFO*)hdb_info, db_path)) {
        finalize_statements();
        sqlite3_close(db);
        free(hdb_info);
        return NULL;
    }

    hdb_info->db = db;
    hdb_info->base.db_type = TSK_HDB_DBTYPE_SQLITE_ID;
    hdb_info->base.updateable = 1;
    hdb_info->base.uses_external_indexes = 0;
    hdb_info->base.lookup_str = sqlite_hdb_lookup_str;
    hdb_info->base.lookup_raw = sqlite_hdb_lookup_bin;
    hdb_info->base.has_verbose_lookup = NULL; // RJCTODO
    hdb_info->base.lookup_verbose_str = sqlite_hdb_lookup_verbose_str;
    hdb_info->base.add_entry = sqlite_hdb_add_entry;
    hdb_info->base.close_db = sqlite_hdb_close;

    return (TSK_HDB_INFO*)hdb_info;
}

static int64_t
sqlite_hdb_select_id_by_md5_hash(uint8_t *md5Blob, size_t len, sqlite3 *db)
{
    int64_t row_id = -1;
    if (sqlite_hdb_attempt(sqlite3_bind_blob(select_id_from_hashes_by_md5, 1, md5Blob, len, free), SQLITE_OK, "sqlite_hdb_select_id_by_md5_hash: error binding md5 hash blob: %s\n", db) == 0) {
        int result = sqlite3_step(select_id_from_hashes_by_md5);
        if (SQLITE_ROW == result) {
            // Found it.
            row_id = sqlite3_column_int64(select_id_from_hashes_by_md5, 0);                    
        }
        else if (SQLITE_DONE == result) {
            // Didn't find it, but no error.
            row_id = 0;
        }
        else {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_AUTO_DB);
            tsk_error_set_errstr("sqlite_hdb_select_id_by_md5_hash: error executing SELECT: %s\n", sqlite3_errmsg(db), result);
        }
    }
    sqlite3_clear_bindings(select_id_from_hashes_by_md5);
    sqlite3_reset(select_id_from_hashes_by_md5);
    return row_id;
}

static int8_t
getStrings(sqlite3 *db, const char *selectStmt, std::vector<std::string> &out)
{
	int8_t ret = 0;
    sqlite3_stmt* stmt = NULL;
    int len = strlen(selectStmt);

    sqlite_hdb_prepare_stmt(selectStmt, &stmt, db);
        
	while (sqlite3_step(stmt) == SQLITE_ROW) {
		const char* value = (const char *)sqlite3_column_text(stmt, 0);
        if (value != NULL) {
            std::string s(value);
            out.push_back(s);
        }
	}

	sqlite3_reset(stmt);
    
    if (stmt) {
        sqlite_hdb_finalize_stmt(&stmt);
    }

	return ret;
}

// RJCTODO: Polish up
/**
 * Convert binary blob hash string to text hash string
 * Returns the input if compiled in text hash mode.
 */
static std::string 
blobToText(std::string binblob)
{
    unsigned int blobsize = binblob.size();
    if (blobsize <= TSK_HDB_MAX_BINHASH_LEN) {
        char hashbuf[TSK_HDB_HTYPE_SHA2_256_LEN + 1];

	    for (unsigned int i = 0; i < blobsize; i++) {
		    hashbuf[2 * i] = hex[(binblob[i] >> 4) & 0xf];
		    hashbuf[2 * i + 1] = hex[binblob[i] & 0xf];
	    }
	    hashbuf[2 * blobsize] = '\0';
        return std::string(&hashbuf[0]);
    } else {
        return "";
    }
}

static int64_t  
sqlite_hdb_hash_lookup_by_md5(uint8_t *md5Blob, size_t len, sqlite3 *db, TskHashLookupResult **result)
{
    int64_t ret_val = -1;
    *result = NULL;
    if (sqlite_hdb_attempt(sqlite3_bind_blob(select_from_hashes_by_md5, 1, md5Blob, len, free), SQLITE_OK, "sqlite_hdb_hash_lookup_by_md5: error binding md5 hash blob: %s\n", db) == 0) {
        int result_code = sqlite3_step(select_id_from_hashes_by_md5);
        if (SQLITE_ROW == result_code) {
            // Found it.
            *result = new TskHashLookupResult(); // RJCTODO: Need to be sure that clients delete rather than free!!!
            (*result)->id = sqlite3_column_int64(select_from_hashes_by_md5, 0); 
            (*result)->hashMd5 = blobToText((const char*)sqlite3_column_text(select_from_hashes_by_md5, 1));
        }
        else if (SQLITE_DONE == result_code) {
            // Didn't find it, but no error.
            ret_val = 0;
        }
        else {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_AUTO_DB);
            tsk_error_set_errstr("sqlite_hdb_select_id_by_md5_hash: error executing SELECT: %s\n", sqlite3_errmsg(db), result);
        }
    }
    sqlite3_clear_bindings(select_from_hashes_by_md5);
    sqlite3_reset(select_from_hashes_by_md5);
    return ret_val;
}

static int64_t
sqlite_hdb_insert_md5_hash(uint8_t *md5Blob, size_t len, sqlite3 *db)
{
    int64_t row_id = 0;
    if (sqlite_hdb_attempt(sqlite3_bind_blob(insert_md5_into_hashes, 1, md5Blob, len, SQLITE_TRANSIENT), SQLITE_OK, "sqlite_hdb_insert_md5_hash: error binding md5 hash blob: %s\n", db) == 0) {        
        int result = sqlite3_step(insert_md5_into_hashes);
        if (result == SQLITE_DONE) {
            row_id = sqlite3_last_insert_rowid(db);
        }
        else {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_AUTO_DB);
            tsk_error_set_errstr("sqlite_hdb_insert_md5_hash: error executing INSERT: %s\n", sqlite3_errmsg(db), result);
        }
    }
    sqlite3_clear_bindings(select_id_from_hashes_by_md5);
    sqlite3_reset(select_id_from_hashes_by_md5);
    return row_id;
}

static uint8_t 
sqlite_hdb_insert_val_and_id(sqlite3_stmt *stmt, const char *value, int64_t id, sqlite3 *db)
{
    uint8_t ret_val = 1;
    if ((sqlite_hdb_attempt(sqlite3_bind_text(stmt, 1, value, strlen(value), SQLITE_TRANSIENT), SQLITE_OK, "sqlite_hdb_insert_val_and_id: error binding value: %s\n", db) == 0) &&
        (sqlite_hdb_attempt(sqlite3_bind_int64(stmt, 2, id), SQLITE_OK, "sqlite_hdb_insert_val_and_id: error binding id: %s\n", db) == 0)) {        
        int result = sqlite3_step(stmt);
        if ((result != SQLITE_DONE) && (result != SQLITE_CONSTRAINT)) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_AUTO_DB);
            tsk_error_set_errstr("sqlite_hdb_insert_val_and_id: error executing INSERT: %s\n", sqlite3_errmsg(db), result);
        }
        else {
            // Either the INSERT succeeded or the value was a duplicate, which is o.k.
            ret_val = 0;
        }
        sqlite3_clear_bindings(stmt);
        sqlite3_reset(stmt);        
    }
    return ret_val;
}

/**
 * @return 1 on error and 0 on success
 */
uint8_t
sqlite_hdb_add_entry(TSK_HDB_INFO *hdb_info_base, const char *filename, 
    const char *md5, const char *sha1, const char *sha256, const char *comment)
{
    assert(NULL != hdb_info_base);
    if (!hdb_info_base) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_ARG);
        tsk_error_set_errstr("sqlite_hdb_add_entry: NULL db_path");
        return 1;
    }

    // Currently only supporting md5.
    assert(NULL != md5);
    if (!md5) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_ARG);
        tsk_error_set_errstr("sqlite_hdb_add_entry: NULL md5");
        return 1;
    }
    const size_t md5_str_len = strlen(md5);
    assert(TSK_HDB_HTYPE_MD5_LEN == md5_str_len);
    if (TSK_HDB_HTYPE_MD5_LEN != md5_str_len) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_ARG);
        tsk_error_set_errstr("sqlite_hdb_add_entry: md5 length incorrect (=%u)", md5_str_len);
        return 1;
    }

    // Convert the md5 string to a binary blob, since that's how md5s are
    // stored in the database.
	const size_t len = strlen(md5)/2;
	uint8_t *hashBlob = (uint8_t *)tsk_malloc(len+1);
	const char *pos = md5;
	for (size_t count = 0; count < len; ++count) {
		sscanf(pos, "%2hx", (short unsigned int *) &(hashBlob[count]));
		pos += 2 * sizeof(char);
	}

    // Is this hash already in the database? 
    TSK_SQLITE_HDB_INFO *hdb_info = (TSK_SQLITE_HDB_INFO*)hdb_info_base; 
    int64_t row_id = sqlite_hdb_select_id_by_md5_hash(hashBlob, len, hdb_info->db);
    if (-1 == row_id) {
        return 1;
    }
    
    //If not, insert it. 
    if (0 == row_id) {
        row_id = sqlite_hdb_insert_md5_hash(hashBlob, len, hdb_info->db);
        if (row_id < 1) {
            return 1;
        }
    }

    // Insert the file name, if any.
    if (NULL != filename && sqlite_hdb_insert_val_and_id(insert_into_file_names, filename, row_id, hdb_info->db) == 1) {
        return 1;
    }

    // Insert the comment, if any.
    if (NULL != comment && sqlite_hdb_insert_val_and_id(insert_into_comments, comment, row_id, hdb_info->db) == 1) {
        return 1;
    }

    return 0;
}

/**
 * \ingroup hashdblib
 * Search the index for a text/ASCII hash value
 *
 * @param hdb_info Open hash database (with index)
 * @param hash Hash value to search for (NULL terminated string)
 * @param flags Flags to use in lookup
 * @param action Callback function to call for each hash db entry 
 * (not called if QUICK flag is given)
 * @param ptr Pointer to data to pass to each callback
 *
 * @return -1 on error, 0 if hash value not found, and 1 if value was found.
 */
int8_t
sqlite_hdb_lookup_str(TSK_HDB_INFO * hdb_info_base, const char* hash,
    TSK_HDB_FLAG_ENUM flags, TSK_HDB_LOOKUP_FN action, void *ptr)
{
    assert(NULL != hdb_info_base);
    if (!hdb_info_base) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_ARG);
        tsk_error_set_errstr("sqlite_hdb_lookup_str: NULL hdb_info_base");
        return -1;
    }

    assert(NULL != hash);
    if (!hash) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_ARG);
        tsk_error_set_errstr("sqlite_hdb_lookup_str: NULL hash");
        return -1;
    }

    // Currently only supporting lookups of md5 hashes.
    const size_t len = strlen(hash);
    assert(TSK_HDB_HTYPE_MD5_LEN == md5_str_len);
    if (TSK_HDB_HTYPE_MD5_LEN != len) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_ARG);
        tsk_error_set_errstr("sqlite_hdb_add_entry: hash length incorrect (=%d), expecting %d", len, TSK_HDB_HTYPE_MD5_LEN);
        return 1;
    }
 
    // RJCTODO: Need utility for this
    // Convert the string into a binary blob.
    int8_t ret = 0;
    TSK_SQLITE_HDB_INFO *hdb_info = (TSK_SQLITE_HDB_INFO*)hdb_info_base; 
	uint8_t * hashBlob = (uint8_t *) tsk_malloc(len+1);
	const char *pos = hash;
	for (int i = 0; i < len; ++i) {
		sscanf(pos, "%2hx", (short unsigned int *) &(hashBlob[i]));
		pos += 2 * sizeof(char);
	}

    int8_t ret_val = sqlite_hdb_lookup_bin(hdb_info_base, hashBlob, len, flags, action, ptr);
    free(hashBlob);
    return ret_val; 
}

// RJCTODO: Fix comment
/**
 * \ingroup hashdblib
 * Search the index for the given hash value given (in binary form).
 *
 * @param hdb_info Open hash database (with index)
 * @param hash Array with binary hash value to search for
 * @param len Number of bytes in binary hash value
 * @param flags Flags to use in lookup
 * @param action Callback function to call for each hash db entry 
 * (not called if QUICK flag is given)
 * @param ptr Pointer to data to pass to each callback
 * @return -1 on error, 0 if hash value not found, and 1 if value was found.
 */
int8_t
sqlite_hdb_lookup_bin(TSK_HDB_INFO *hdb_info_base, uint8_t *hash, 
    uint8_t len, TSK_HDB_FLAG_ENUM flags, TSK_HDB_LOOKUP_FN action, void *ptr)
{
    assert(NULL != hdb_info_base);
    if (!hdb_info_base) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_ARG);
        tsk_error_set_errstr("sqlite_hdb_lookup_bin: NULL hdb_info_base");
        return -1;
    }

    assert(NULL != hash);
    if (!hash) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_ARG);
        tsk_error_set_errstr("sqlite_hdb_add_entry: NULL md5");
        return -1;
    }

    // Currently only supporting lookups of md5 hashes.
    assert(TSK_HDB_HTYPE_MD5_LEN / 2 == len);
    if (TSK_HDB_HTYPE_MD5_LEN / 2 != len) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_ARG);
        tsk_error_set_errstr("sqlite_hdb_lookup_bin: len=%d, expected %d", len, TSK_HDB_HTYPE_MD5_LEN * 2);
        return -1;
    }
 
    int8_t ret_val = 0;
    tsk_take_lock(&hdb_info_base->lock);
    TSK_SQLITE_HDB_INFO *hdb_info = (TSK_SQLITE_HDB_INFO*)hdb_info_base; 
    int64_t row_id = sqlite_hdb_select_id_by_md5_hash(hash, len, hdb_info->db);
    if (row_id > 0) {
        if (!(flags & TSK_HDB_FLAG_QUICK) && (NULL != action)) {
            // Make a string version of the hash for the callback.
            char hashbuf[TSK_HDB_HTYPE_MD5_LEN + 1];
            for (int i = 0; i < len; ++i) {
                hashbuf[2 * i] = hex[(hash[i] >> 4) & 0xf];
                hashbuf[2 * i + 1] = hex[hash[i] & 0xf];
            }
            hashbuf[2 * len] = '\0';

            // Do the callback.
            action(hdb_info_base, hashbuf, hdb_info_base->db_name, ptr);
        }
        ret_val = 1;
    }
    else if (row_id == 0) {
        ret_val = 0;
    }
    else {
        ret_val = -1;
    }
        
    tsk_release_lock(&hdb_info_base->lock);

	return ret_val;
}

// RJCTODO: Fix comment. 
/**
 * \ingroup hashdblib
 * Search the index for the given hash value given (in string form).
 *
 * @param hdb_info Open hash database (with index)
 * @param hashId   unique id of hash (corresponds to hashes.id)
 *
 * @return -1 on error, 0 if hash value not found, and 1 if value was found.
 */
int8_t sqlite_hdb_lookup_verbose_str(TSK_HDB_INFO *hdb_info_base, const char *hash, void **result)
{
    assert(NULL != hdb_info_base);
    if (!hdb_info_base) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_ARG);
        tsk_error_set_errstr("sqlite_hdb_lookup_verbose_str: NULL hdb_info_base");
        return -1;
    }

    assert(NULL != hash);
    if (!hash) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_ARG);
        tsk_error_set_errstr("sqlite_hdb_lookup_verbose_str: NULL hash");
        return -1;
    }

    // Currently only supporting lookups of md5 hashes.
    const size_t len = strlen(hash);
    assert(TSK_HDB_HTYPE_MD5_LEN == md5_str_len);
    if (TSK_HDB_HTYPE_MD5_LEN != len) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_ARG);
        tsk_error_set_errstr("sqlite_hdb_lookup_verbose_str: hash length incorrect (=%d), expecting %d", len, TSK_HDB_HTYPE_MD5_LEN);
        return -1;
    }
 
    *result = NULL;


    if (sqlite_hdb_attempt(sqlite3_bind_blob(select_id_from_hashes_by_md5, 1, md5Blob, len, free), SQLITE_OK, "sqlite_hdb_select_id_by_md5_hash: error binding md5 hash blob: %s\n", db) == 0) {
        int result = sqlite3_step(select_id_from_hashes_by_md5);
        if (SQLITE_ROW == result) {
            // Found it.
            row_id = sqlite3_column_int64(select_id_from_hashes_by_md5, 0);                    
        }
        else if (SQLITE_DONE == result) {
            // Didn't find it, but no error.
            row_id = 0;
        }
        else {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_AUTO_DB);
            tsk_error_set_errstr("sqlite_hdb_select_id_by_md5_hash: error executing SELECT: %s\n", sqlite3_errmsg(db), result);
        }
    }
    sqlite3_clear_bindings(select_id_from_hashes_by_md5);
    sqlite3_reset(select_id_from_hashes_by_md5);
    return row_id;






    TSK_SQLITE_HDB_INFO *hdb_info = (TSK_SQLITE_HDB_INFO*)hdb_info_base;

    tsk_take_lock(&hdb_info_base->lock);

    // RJCTODO: Need some sanity checking here.

    // RJCTODO: Need to construct some SQL that gets all of the fields, 
    // e.g., SELECT * FROM hashes WHERE <hash> = <value>
    // And need to convert the string into a blob

    // RJCTODO: Why are each of these done with separate selects?
    TskHashLookupResult *result = new TskHashLookupResult(); // RJCTODO: This should be a malloc
    {
        std::vector<std::string> temp;
        char selectStmt[1024];
        snprintf(selectStmt, 1024, "SELECT md5 from hashes where id=%d", hash);
        getStrings(hdb_info->db, selectStmt,  temp);
        if (temp.size() > 0) {
            result->hashMd5 = blobToText(temp.at(0));
        }
    }
    {
        std::vector<std::string> temp;
        char selectStmt[1024];
        snprintf(selectStmt, 1024, "SELECT sha1 from hashes where id=%d", hash);
        getStrings(hdb_info->db, selectStmt,  temp);
        if (temp.size() > 0) {
            result->hashSha1 = blobToText(temp.at(0));
        }
    }
    {
        std::vector<std::string> temp;
        char selectStmt[1024];
        snprintf(selectStmt, 1024, "SELECT sha2_256 from hashes where id=%d", hash);
        getStrings(hdb_info->db, selectStmt,  temp);
        if (temp.size() > 0) {
            result->hashSha2_256 = blobToText(temp.at(0));
        }
    }
    {
        char selectStmt[1024];
        snprintf(selectStmt, 1024, "SELECT name from file_names where hash_id=%d", hash);
        getStrings(hdb_info->db, selectStmt,  result->names);
    }
    {
        char selectStmt[1024];
        snprintf(selectStmt, 1024, "SELECT comment from comments where hash_id=%d", hash);
        getStrings(hdb_info->db, selectStmt,  result->comments);
    }

    tsk_release_lock(&hdb_info_base->lock);

    return (void*)result; // RJCTODO: Need to be sure that the struct is freed
}

/*
 * Closes an SQLite hash database.
 * @param idx_info the index to close
 */
void
sqlite_hdb_close(TSK_HDB_INFO *hdb_info_base)
{
    TSK_SQLITE_HDB_INFO *hdb_info = (TSK_SQLITE_HDB_INFO*)hdb_info_base; 

    finalize_statements();

    if (hdb_info->db) {
        sqlite3_close(hdb_info->db);
    }
    hdb_info->db = NULL;

    hdb_info_base_close(hdb_info_base);
}
