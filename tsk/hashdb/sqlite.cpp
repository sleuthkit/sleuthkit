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

// RJCTODO: Name improvements are possible.
static const char *IDX_SCHEMA_VER = "Schema Version";
static const char *IDX_VERSION_NUM = "1";
static const char *IDX_SQLITE_V1_HEADER = "SQLite format 3";
static const int chunkSize = 1024 * 1024;
static sqlite3_stmt *m_stmt = NULL; // RJCTODO: Get rid of the m_
static const char hex[] = "0123456789abcdef";

static int attempt(int resultCode, int expectedResultCode, const char *errfmt, 
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

static int attempt_exec(const char *sql, 
    int (*callback) (void *, int, char **, char **), void *callback_arg, 
    const char *errfmt, sqlite3 * sqlite)
{
	char *errmsg = NULL;
	if(sqlite3_exec(sqlite, sql, callback, callback_arg, &errmsg) != SQLITE_OK) {
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_AUTO_DB);
		tsk_error_set_errstr(errfmt, errmsg);
		sqlite3_free(errmsg);
		return 1;
	}
	return 0;
}

static int attempt_exec_nocallback(const char *sql, const char *errfmt, 
    sqlite3 *sqlite)
{
	return attempt_exec(sql, NULL, NULL, errfmt, sqlite);
}

static int finalize_stmt(sqlite3_stmt * stmt)
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

// RJCTODO: May want to change name and add to error 
static int prepare_stmt(const char *sql, sqlite3_stmt ** ppStmt, sqlite3 * sqlite)
{
    ///@todo possible performance increase by using strlen(sql)+1 instead of -1 // RJCTODO: Resolve this
	if (sqlite3_prepare_v2(sqlite, sql, -1, ppStmt, NULL) != SQLITE_OK) {
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_AUTO_DB);
		tsk_error_set_errstr("Error preparing SQL statement: %s\n", sql);
        tsk_error_print(stderr);
		return 1;
	}
	return 0;
}

// RJCTODO: Comment
// RJCTODO: May want to change name and add to error 
uint8_t sqlite_hdb_create_db(TSK_TCHAR *db_file_path)
{
    assert(db_file_path);
    if (!db_file_path) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_ARG);
        tsk_error_set_errstr("sqlite_hdb_create_db: NULL db_file_path");
        return 1;
    }

	sqlite3 *db = sqlite_hdb_open_db(db_file_path);
	if (NULL == db) {
		return 1;
	}

    // Configure the database to increase its size incrementally.    
    if (sqlite3_file_control(db, NULL, SQLITE_FCNTL_CHUNK_SIZE, const_cast<int *>(&chunkSize)) != SQLITE_OK) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr("sqlite_v1_initialize: error setting chunk size %s", sqlite3_errmsg(db));
        return 1;
    }

	if (attempt_exec_nocallback("CREATE TABLE db_properties (name TEXT NOT NULL, value TEXT);", "Error creating db_properties table %s\n", db)) {
		return 1;
	}

	char stmt[1024];
	snprintf(stmt, 1024, "INSERT INTO db_properties (name, value) VALUES ('%s', '%s');", IDX_SCHEMA_VER, IDX_VERSION_NUM);
	if (attempt_exec_nocallback(stmt, "Error adding schema info to db_properties: %s\n", db)) {
		return 1;
	}

	if (attempt_exec_nocallback ("CREATE TABLE hashes (id INTEGER PRIMARY KEY AUTOINCREMENT, md5 BINARY(16) UNIQUE, sha1 BINARY(20), sha2_256 BINARY(32));", "Error creating hashes table %s\n", db)) {
		return 1;
	}

	if (attempt_exec_nocallback("CREATE TABLE file_names (name TEXT NOT NULL, hash_id INTEGER NOT NULL);", "Error creating file_names table %s\n", db)) {
		return 1;
	}

	if (attempt_exec_nocallback("CREATE TABLE comments (comment TEXT NOT NULL, hash_id INTEGER NOT NULL);", "Error creating comments table %s\n", db)) {
		return 1;
	}

	if (attempt_exec_nocallback("CREATE INDEX md5_index ON hashes(md5);", "Error creating md5_index on md5: %s\n", db)) {
		return 1;
	}
	
	if (attempt_exec_nocallback("CREATE INDEX sha1_index ON hashes(sha1);", "Error creating sha1_index on sha1: %s\n", db)) {
		return 1;
    }

    sqlite3_close(db);

	return 0;
}

// RJCTODO: Comment
sqlite3 *sqlite_hdb_open_db(TSK_TCHAR *db_file_path)
{
    assert(db_file_path);
    if (!db_file_path) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_ARG);
        tsk_error_set_errstr("sqlite_hdb_open_db: NULL db_file_path");
        return NULL;
    }

    sqlite3 *db = NULL;
    int opened = 1;
#ifdef TSK_WIN32
    opened = attempt(sqlite3_open16(db_file_path, &db), SQLITE_OK, "Can't open hash database: %s\n", db);
#else
    opened = attempt(sqlite3_open(db_file_path, &db), SQLITE_OK, "Can't open hash database: %s\n", db);
#endif
    if (1 != opened) {
	    sqlite3_extended_result_codes(db, 1);
		attempt_exec_nocallback("PRAGMA synchronous = OFF;", "Error setting PRAGMA synchronous: %s\n", db);
		attempt_exec_nocallback("PRAGMA encoding = \"UTF-8\";", "Error setting PRAGMA encoding UTF-8: %s\n", db);
		attempt_exec_nocallback("PRAGMA read_uncommitted = True;", "Error setting PRAGMA read_uncommitted: %s\n", db);
		attempt_exec_nocallback("PRAGMA page_size = 4096;", "Error setting PRAGMA page_size: %s\n", db);
    }
    else {
        sqlite3_close(db);
        db = NULL;
    }
    return db;
}

// RJCTODO: Comment
/**
 * Test the file to see if it is an sqlite database (== index only)
 * @param hFile File handle to hash database
 * @return 1 if sqlite and 0 if not
 */
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
        else if (strncmp(header, IDX_SQLITE_V1_HEADER, 
            strlen(IDX_SQLITE_V1_HEADER)) == 0) {
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

    TSK_SQLITE_HDB_INFO *hdb_info = (TSK_SQLITE_HDB_INFO*)tsk_malloc(sizeof(TSK_SQLITE_HDB_INFO));
    if (!hdb_info) {
        return NULL;
    }

    hdb_info->db = sqlite_hdb_open_db(db_path);
    if (!hdb_info->db) {
        free(hdb_info);
        return NULL;
    }

    size_t flen = TSTRLEN(db_path) + 8; // RJCTODO: Check this change from 32 with Brian; was change in older code? What is the point, anyway?
    hdb_info->base.db_fname = (TSK_TCHAR*)tsk_malloc(flen * sizeof(TSK_TCHAR));
    if (!hdb_info->base.db_fname) {
        sqlite3_close(hdb_info->db);
        free(hdb_info);
        return NULL;
    }
    TSTRNCPY(hdb_info->base.db_fname, db_path, flen);

    hdb_info->base.db_type = TSK_HDB_DBTYPE_SQLITE_ID;
    hdb_info->base.hash_type = TSK_HDB_HTYPE_INVALID_ID; // This will be set when the index is created/opened. // RJCTODO: Troubling, when is this used, hard code it, movr it?
    hdb_info->base.hash_len = 0; // This will be set when the index is created/opened. // RJCTODO: Troubling
    hdb_info->base.updateable = 1;
    hdb_info->base.uses_external_indexes = 0;
    tsk_init_lock(&hdb_info->base.lock);

    hdb_info->base.get_db_path = NULL; // RJCTODO
    hdb_info->base.get_db_name = NULL; // RJCTODO
    hdb_info->base.has_index = NULL; // RJCTODO
    hdb_info->base.make_index = sqlite_hdb_make_index;
    hdb_info->base.open_index = NULL; // RJCTODO
    hdb_info->base.get_index_path = NULL; // RJCTODO
    hdb_info->base.lookup_str = NULL; // RJCTODO
    hdb_info->base.lookup_raw = NULL; // RJCTODO
    hdb_info->base.has_verbose_lookup = NULL; // RJCTODO
    hdb_info->base.lookup_verbose_str = NULL; // RJCTODO
    hdb_info->base.add_hash = NULL; // RJCTODO
    hdb_info->base.close_db = NULL; // RJCTODO

    return (TSK_HDB_INFO*)hdb_info;
}

const TSK_TCHAR *sqlite_hdb_get_db_path(TSK_HDB_INFO *hdb_info)
{
    return hdb_info->db_fname;
}

const char *sqlite_hdb_get_db_name(TSK_HDB_INFO *hdb_info)
{
    return hdb_info->db_name;
}

/**
 * This function is a no-op for SQLite hash database. The index is "internal" to the RDBMS.
 * @return 1 on error and 0 on success
 */
uint8_t sqlite_hdb_make_index(TSK_HDB_INFO * hdb_info, TSK_TCHAR * htype)
{
    // RJCTODO: Add should not be called error stuff
    return 0;
}


/**
 * This function is a no-op for SQLite hash database. The index is "internal" to the RDBMS.
 * @return 1 on error and 0 on success
 */
//uint8_t
//sqlite_v1_addentry(TSK_HDB_INFO * hdb_info, char* hvalue,
//                    TSK_OFF_T offset)
//{
// RJCTODO: This needs to go into a separate add to hash database function, as opposed to an add to index function
//    hdb_info->idx_info->idx_struct.idx_sqlite_v1->lastId = 0;
//
//	if (strlen(hvalue) != hdb_info->hash_len) {
//		tsk_error_reset();
//		tsk_error_set_errno(TSK_ERR_AUTO_DB);
//		tsk_error_set_errstr("Hash length doesn't match index type: %s\n", hvalue);
//        tsk_error_print(stderr);
//		return 1;
//	}
//
//#ifdef IDX_SQLITE_STORE_TEXT
//    uint8_t ret = addentry_text(hdb_info, hvalue, offset);
//#else
//	const size_t len = (hdb_info->hash_len)/2;
//    uint8_t* hash = (uint8_t*) tsk_malloc(len+1);
//    
//	size_t count;
//
//    // We use an intermediate short to be compatible with Microsoft's implementation of the scanf family format
//    short unsigned int binval;
//    for (count = 0; count < len; count++) {
//		int r = sscanf(hvalue, "%2hx", &binval);
//        hash[count] = (uint8_t) binval;
//		hvalue += 2 * sizeof(char);
//	}
//    uint8_t ret = sqlite_v1_addentry_bin(hdb_info, hash, len, offset);
//
//    delete [] hash;
//#endif
//
//    if (ret == 0) {
//        // The current id can be used by subsequent add name or add comment operations
//	    hdb_info->idx_info->idx_struct.idx_sqlite_v1->lastId = sqlite3_last_insert_rowid(hdb_info->idx_info->idx_struct.idx_sqlite_v1->hIdx_sqlite);
//    }
//
//    return ret;
//}

/**
 * @return 1 on error and 0 on success
 */
uint8_t
sqlite_hdb_add_hash(TSK_HDB_INFO * hdb_info_base, const char *filename, 
    const char *md5, const char *sha1, const char *sha256, const char *comment)
{
    TSK_SQLITE_HDB_INFO *hdb_info = (TSK_SQLITE_HDB_INFO*)hdb_info_base;

    // RJCTODO: hash_len funk
    if (attempt(sqlite3_bind_blob(m_stmt, 1, md5, hdb_info_base->hash_len, SQLITE_TRANSIENT),
		SQLITE_OK,
		"Error binding binary blob: %s\n",
        hdb_info->db)) {
        return 1;
    }

    uint64_t row_id = 0;
    // RJCTODO: Need to do a query here, to get an id

    // RJCTODO: If no id found, add and get id
    // Don't report error on constraint -- we just will silently not add that duplicate hash
	    int r = sqlite3_step(m_stmt);
        if ((r != SQLITE_DONE) && (r != SQLITE_CONSTRAINT) ) {
		    tsk_error_reset();
		    tsk_error_set_errno(TSK_ERR_AUTO_DB);
		    tsk_error_set_errstr("Error stepping: %s\n", sqlite3_errmsg(hdb_info->db), r);
            return 1;
        }

        // RJCTODO: I guess this is needed, not done in other TSK/Autopsy code?
	    r = sqlite3_reset(m_stmt);
        if ((r != SQLITE_OK) && (r != SQLITE_CONSTRAINT) ) {
		    tsk_error_reset();
		    tsk_error_set_errno(TSK_ERR_AUTO_DB);
		    tsk_error_set_errstr("Error resetting: %s\n", sqlite3_errmsg(hdb_info->db), r);
            return 1;
        }
        row_id = sqlite3_last_insert_rowid(hdb_info->db);


    // RJCTODO: Insert 

//	snprintf(stmt, 1024,"INSERT INTO comments (comment, hash_id) VALUES ('%s', '%d');",	value, id);
//	if (attempt_exec_nocallback(stmt, "Error adding comment: %s\n", hdb_info->idx_info->idx_struct.idx_sqlite_v1->hIdx_sqlite)) {
//		return 1;
//	}
//    char stmt[1024];
//	snprintf(stmt, 1024, "INSERT INTO file_names (name, hash_id) VALUES ('%s', '%d');", value, id);
//	if (attempt_exec_nocallback(stmt, "Error adding comment: %s\n", hdb_info->idx_info->idx_struct.idx_sqlite_v1->hIdx_sqlite)) {
//		return 1;
//	}


    return 0;
}

/**
 * This function is a no-op for SQLite hash database. The index is "internal" to the RDBMS.
 * @return 1 on error and 0 on success
 */
//uint8_t
//addentry_text(TSK_HDB_INFO * hdb_info, char* hvalue, TSK_OFF_T offset)
//{
// RJCTODO: This needs to go into a separate add to hash database function, as opposed to an add to index function
 //   if (attempt(sqlite3_bind_text(m_stmt, 1, hvalue, strlen(hvalue), SQLITE_TRANSIENT),
	//	SQLITE_OK,
	//	"Error binding text: %s\n",
	//	hdb_info->idx_info->idx_struct.idx_sqlite_v1->hIdx_sqlite) ||
	//	attempt(sqlite3_bind_int64(m_stmt, 2, offset),
	//	    SQLITE_OK,
	//	    "Error binding entry offset: %s\n",
	//	    hdb_info->idx_info->idx_struct.idx_sqlite_v1->hIdx_sqlite) ) {
 //       return 1;
 //   }

 //   // Don't report error on constraint -- we just will silently not add that duplicate hash
	//int r = sqlite3_step(m_stmt);
 //   if ((r != SQLITE_DONE) && (r != SQLITE_CONSTRAINT) ) {
	//	tsk_error_reset();
	//	tsk_error_set_errno(TSK_ERR_AUTO_DB);
	//	tsk_error_set_errstr("Error stepping: %s\n", sqlite3_errmsg( hdb_info->idx_info->idx_struct.idx_sqlite_v1->hIdx_sqlite), r);
 //       return 1;
 //   }

	//r = sqlite3_reset(m_stmt);
 //   if ((r != SQLITE_OK) && (r != SQLITE_CONSTRAINT) ) {
	//	tsk_error_reset();
	//	tsk_error_set_errno(TSK_ERR_AUTO_DB);
	//	tsk_error_set_errstr("Error resetting: %s\n", sqlite3_errmsg( hdb_info->idx_info->idx_struct.idx_sqlite_v1->hIdx_sqlite), r);
 //       return 1;
 //   }

 //   return 0;
//    return 0;
//}

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
    prepare_stmt(selectStmt, &stmt, hdb_info->db);
        
	if (attempt(sqlite3_bind_blob(stmt, 1, hvalue, len, free), SQLITE_OK, "Error binding binary blob: %s\n", hdb_info->db)) {
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
        finalize_stmt(stmt);
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

    prepare_stmt(selectStmt, &stmt, db);
        
	while (sqlite3_step(stmt) == SQLITE_ROW) {
		const char* value = (const char *)sqlite3_column_text(stmt, 0);
        if (value != NULL) {
            std::string s(value);
            out.push_back(s);
        }
	}

	sqlite3_reset(stmt);
    
    if (stmt) {
        finalize_stmt(stmt);
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
void * sqlite_hdb_lookup_verbose_str(TSK_HDB_INFO *hdb_info_base, const char *hash)
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

    if (m_stmt) {
        finalize_stmt(m_stmt);
    }

    m_stmt = NULL;

    if (hdb_info->db) {
        sqlite3_close(hdb_info->db);
    }
    hdb_info->db = NULL;

    // RJCTODO: Cleanup the base stuff...
}

