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
 * \file sqlite.cpp
 * Contains hash database functions for SQLite hash databases.
 */

static const char *SQLITE_HDB_SCHEMA_VERSION_PROP = "Schema Version";
static const char *SQLITE_HDB_SCHEMA_VERSION_NO = "1";
static const char *SQLITE_FILE_HEADER = "SQLite format 3";
static sqlite3_stmt *select_id_from_hashes_by_md5 = NULL; 
static sqlite3_stmt *insert_md5_into_hashes = NULL; 
static sqlite3_stmt *insert_into_file_names = NULL; 
static sqlite3_stmt *insert_into_comments = NULL; 

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
sqlite_hdb_prepare_stmt(const char *sql, sqlite3_stmt **ppStmt, sqlite3 *sqlite)
{
    ///@todo possible performance increase by using strlen(sql)+1 instead of -1 // RJCTODO: Resolve this
	if (sqlite3_prepare_v2(sqlite, sql, -1, ppStmt, NULL) != SQLITE_OK) {
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_AUTO_DB);
		tsk_error_set_errstr("sqlite_hdb_prepare_stmt: error preparing SQL statement: %s\n", sql);
        tsk_error_print(stderr);
		return 1;
	}
	return 0;
}

static uint8_t 
sqlite_hdb_finalize_stmt(sqlite3_stmt *stmt)
{
	if (sqlite3_finalize(stmt) != SQLITE_OK) {
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_AUTO_DB);
		tsk_error_set_errstr("Error finalizing SQL statement\n");
        tsk_error_print(stderr);
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
prepare_statements(sqlite3 *db)
{
    if (sqlite_hdb_prepare_stmt("SELECT id from hashes where md5=? limit 1", &select_id_from_hashes_by_md5, db)) {
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

static sqlite3 *sqlite_hdb_open_db(TSK_TCHAR *db_file_path, bool create_tables)
{
    assert(NULL != db_file_path);
    if (NULL == db_file_path) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_ARG);
        tsk_error_set_errstr("sqlite_hdb_open_db: NULL db_file_path");
        return NULL;
    }

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

    if (prepare_statements(db)) {
        sqlite3_close(db);
        return NULL;
    }

    return db;
}

// RJCTODO: Comment
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

// RJCTODO: Comment
uint8_t
sqlite3_test(FILE *hFile)
{
    const int header_size = 16;
    char header[header_size];
    if (hFile) {
        if (1 != fread(header, header_size, 1, hFile)) {
            ///@todo should this actually be an error? // RJCTODO: Probably
            return 0;
        }
        else if (strncmp(header, SQLITE_FILE_HEADER, 
            strlen(SQLITE_FILE_HEADER)) == 0) {
            return 1;
        }
    }

    return 0;
}

// RJCTODO: Comment
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

    TSK_SQLITE_HDB_INFO *hdb_info = (TSK_SQLITE_HDB_INFO*)tsk_malloc(sizeof(TSK_SQLITE_HDB_INFO));
    if (!hdb_info) {
        return NULL;
    }

    if (hdb_info_base_open((TSK_HDB_INFO*)hdb_info, db_path)) {
        free(hdb_info);
        return NULL;
    }

    hdb_info->db = db;
    hdb_info->base.db_type = TSK_HDB_DBTYPE_SQLITE_ID;
    hdb_info->base.updateable = 1;
    hdb_info->base.uses_external_indexes = 0;

    hdb_info->base.open_index = NULL; // RJCTODO
    hdb_info->base.get_index_path = NULL; // RJCTODO
    hdb_info->base.lookup_str = sqlite_hdb_lookup_str;
    hdb_info->base.lookup_raw = sqlite_hdb_lookup_bin; // RJCTODO
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

    // Sanity check the length of the md5 string.
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
sqlite_hdb_lookup_str(TSK_HDB_INFO * hdb_info_base, const char* hvalue,
    TSK_HDB_FLAG_ENUM flags, TSK_HDB_LOOKUP_FN action, void *ptr)
{
    int8_t ret = 0;
    TSK_SQLITE_HDB_INFO *hdb_info = (TSK_SQLITE_HDB_INFO*)hdb_info_base; 
    hdb_info->last_id = 0; // RJCTODO: I don't like this...
	const size_t len = strlen(hvalue)/2;
	uint8_t * hashBlob = (uint8_t *) tsk_malloc(len+1);
	const char * pos = hvalue;
	size_t count = 0;

    // Convert the string into a binary blob.
	for(count = 0; count < len; count++) {
		sscanf(pos, "%2hx", (short unsigned int *) &(hashBlob[count]));
		pos += 2 * sizeof(char);
	}

    ret = sqlite_hdb_lookup_bin(hdb_info_base, hashBlob, len, flags, action, ptr);

    // RJCTODO: Hmmmm, name needs to be provided?
    if ((ret == 1) && !(flags & TSK_HDB_FLAG_QUICK) && (action != NULL)) {
        //name is blank because we don't have a name in this case
        ///@todo query the file_names table for associations
        char * name = "";
        action(hdb_info_base, hvalue, name, ptr);
    }

	return ret;		
}

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
 *
 * @return -1 on error, 0 if hash value not found, and 1 if value was found.
 */
int8_t
sqlite_hdb_lookup_bin(TSK_HDB_INFO * hdb_info_base, uint8_t * hvalue, 
    uint8_t len, TSK_HDB_FLAG_ENUM flags, TSK_HDB_LOOKUP_FN action, void *ptr)
{
    TSK_SQLITE_HDB_INFO *hdb_info = (TSK_SQLITE_HDB_INFO*)hdb_info_base; 
	int8_t ret = 0;
    char * selectStmt;
    sqlite3_stmt* stmt = NULL;

    tsk_take_lock(&hdb_info_base->lock);

    // RJCTODO: So this code depends on the hash length and type stuff...
	/* Sanity check */
	if ((hdb_info_base->hash_len)/2 != len) {
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_HDB_ARG);
		tsk_error_set_errstr("sqlite_hdb_lookup_bin: Hash passed is different size than expected: %d vs %d",
			hdb_info_base->hash_len, (len * 2));
        tsk_release_lock(&hdb_info_base->lock);
		return -1;
	} 

    if (hdb_info_base->hash_type == TSK_HDB_HTYPE_MD5_ID) {
        selectStmt = "SELECT md5,database_offset,id from hashes where md5=? limit 1";
    } 
    else if (hdb_info_base->hash_type == TSK_HDB_HTYPE_SHA1_ID) {
        selectStmt = "SELECT sha1,database_offset,id from hashes where sha1=? limit 1";
    } 
    else {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_ARG);
        tsk_error_set_errstr("Unknown hash type: %d\n", hdb_info_base->hash_type);
        tsk_release_lock(&hdb_info_base->lock);
		return -1;
    }

    // RJCTODO: Why prepare a staement if it is not going to be reused?
    sqlite_hdb_prepare_stmt(selectStmt, &stmt, hdb_info->db);
        
	if (sqlite_hdb_attempt(sqlite3_bind_blob(stmt, 1, hvalue, len, free), SQLITE_OK, "Error binding binary blob: %s\n", hdb_info->db)) {
		ret = -1;
	} 
    else {
        // Found a match
	    if (sqlite3_step(stmt) == SQLITE_ROW) {
            // RJCTODO: I do not like this at all
            // save id
            hdb_info->last_id = sqlite3_column_int64(stmt, 2);
                    
            if (flags & TSK_HDB_FLAG_QUICK) {
                ret = 1;
		    } 
            else {
                // RJCTODO: Should have code to do the callback, if set up correctly. This code must be here, due to the delegation
                // Also, the callback seems to be the motivation for the name field.
                // This suggests that the name field shoudl be at the top level and the name API should be supported
		    }
        }
    }
        
    // RJCTODO: This probably only needs top be done if the stmt is reused; see above.
	sqlite3_reset(stmt);
    
    if (stmt) {
        sqlite_hdb_finalize_stmt(stmt);
    }

    tsk_release_lock(&hdb_info_base->lock);

	return ret;
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
        sqlite_hdb_finalize_stmt(stmt);
    }

	return ret;
}

/**
 * Convert binary blob hash string to text hash string
 * Returns the input if compiled in text hash mode.
 */
static std::string 
blobToText(std::string binblob)
{
    const char hex[] = "0123456789abcdef";

#ifdef IDX_SQLITE_STORE_TEXT
    return binblob; //already text
#else
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
#endif
}

/**
 * \ingroup hashdblib
 * Search the index for the given hash value given (in string form).
 *
 * @param hdb_info Open hash database (with index)
 * @param hashId   unique id of hash (corresponds to hashes.id)
 *
 * @return -1 on error, 0 if hash value not found, and 1 if value was found.
 */
void *sqlite_hdb_lookup_verbose_str(TSK_HDB_INFO *hdb_info_base, const char *hash)
{
    TSK_SQLITE_HDB_INFO *hdb_info = (TSK_SQLITE_HDB_INFO*)hdb_info_base;

    // RJCTODO: Need to take and release the lock here
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

    if (select_id_from_hashes_by_md5) {
        sqlite_hdb_finalize_stmt(select_id_from_hashes_by_md5);
    }
    select_id_from_hashes_by_md5 = NULL;

    if (insert_md5_into_hashes) {
        sqlite_hdb_finalize_stmt(insert_md5_into_hashes);
    }
    insert_md5_into_hashes = NULL;

    if (insert_into_file_names) {
        sqlite_hdb_finalize_stmt(insert_into_file_names);
    }
    insert_into_file_names = NULL;

    if (insert_into_comments) {
        sqlite_hdb_finalize_stmt(insert_into_comments);
    }
    insert_into_comments = NULL;

    if (hdb_info->db) {
        sqlite3_close(hdb_info->db);
    }
    hdb_info->db = NULL;

    hdb_info_base_close(hdb_info_base);
}
