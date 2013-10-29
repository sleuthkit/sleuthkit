
/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2003-2011 Brian Carrier.  All rights reserved
 *
 *
 * This software is distributed under the Common Public License 1.0
 *
 */

#include "tsk_hashdb_i.h"

/**
 * \file sqlite_index.c
 * Contains functions for creating a SQLite format hash index
 */

/**
 * Static sqlite statements, prepared initially and bound before each use
 */
static sqlite3_stmt *m_stmt = NULL;
static bool need_SQL_index = false;

/**
 * Prototypes 
 */
int8_t sqlite_v1_get_updateable(TSK_HDB_INFO * hdb_info);


static int attempt(int resultCode, int expectedResultCode,
		const char *errfmt, sqlite3 * sqlite)
{
	if (resultCode != expectedResultCode) {
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_AUTO_DB);
		tsk_error_set_errstr(errfmt, sqlite3_errmsg(sqlite), resultCode);
		return 1;
	}
	return 0;
}

static int attempt_exec(const char *sql, int (*callback) (void *, int, char **, char **),
						void *callback_arg, const char *errfmt, sqlite3 * sqlite)
{
	char * errmsg;

	if(sqlite3_exec(sqlite, sql, callback, callback_arg, &errmsg) != SQLITE_OK) {
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_AUTO_DB);
		tsk_error_set_errstr(errfmt, errmsg);
		sqlite3_free(errmsg);
		return 1;
	}
	return 0;
}

static int attempt_exec_nocallback(const char *sql, const char *errfmt, sqlite3 * sqlite)
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
static int prepare_stmt(const char *sql, sqlite3_stmt ** ppStmt, sqlite3 * sqlite)
{
	if (sqlite3_prepare_v2(sqlite, sql, -1, ppStmt, NULL) != SQLITE_OK) {
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_AUTO_DB);
		tsk_error_set_errstr("Error preparing SQL statement: %s\n", sql);
        tsk_error_print(stderr);
		return 1;
	}
	return 0;
}

static uint8_t tsk_hdb_begin_transaction(TSK_IDX_INFO * idx_info) {
	return attempt_exec_nocallback("BEGIN", "Error beginning transaction %s\n", idx_info->idx_struct.idx_sqlite_v1->hIdx_sqlite);
}

static uint8_t tsk_hdb_commit_transaction(TSK_IDX_INFO * idx_info) {
	return attempt_exec_nocallback("COMMIT", "Error committing transaction %s\n", idx_info->idx_struct.idx_sqlite_v1->hIdx_sqlite);
}

/** Init prepared statements. Call before adding to the database. Call finalize() when done.
 *
 * @param hdb_info Hash database state structure
 *
 * @return 1 on error and 0 on success
 *
 */
uint8_t
sqlite_v1_begin(TSK_HDB_INFO * hdb_info)
{
	char * insertStmt;

	if (hdb_info->hash_type == TSK_HDB_HTYPE_MD5_ID) {
		insertStmt = "INSERT INTO hashes (md5, database_offset) VALUES (?, ?)";
	} else if (hdb_info->hash_type == TSK_HDB_HTYPE_SHA1_ID) {
		insertStmt = "INSERT INTO hashes (sha1, database_offset) VALUES (?, ?)";
	} else {
        return 1;
    }

	prepare_stmt(insertStmt, &m_stmt, hdb_info->idx_info->idx_struct.idx_sqlite_v1->hIdx_sqlite);

	if (tsk_hdb_begin_transaction(hdb_info->idx_info)) {
		return 1;
	} else {
        return 0;
    }
}

/** Initialize the TSK hash DB index file by creating tables, etc..
 *
 * @param hdb_info Hash database state structure
 * @param htype String of index type to create
 *
 * @return 1 on error and 0 on success
 *
 */
uint8_t
sqlite_v1_initialize(TSK_HDB_INFO * hdb_info, TSK_TCHAR * htype)
{
	char stmt[1024];

	if (attempt_exec_nocallback("PRAGMA synchronous = OFF;",
		"Error setting PRAGMA synchronous: %s\n", hdb_info->idx_info->idx_struct.idx_sqlite_v1->hIdx_sqlite)) {
			return 1;
	}

	if (attempt_exec_nocallback
		("CREATE TABLE properties (name TEXT, value TEXT);",
		"Error creating properties table %s\n", hdb_info->idx_info->idx_struct.idx_sqlite_v1->hIdx_sqlite)) {
			return 1;
	}

	snprintf(stmt, 1024,
		"INSERT INTO properties (name, value) VALUES ('%s', '%s');",
		IDX_SCHEMA_VER, IDX_VERSION_NUM);
	if (attempt_exec_nocallback(stmt, "Error adding schema info to properties: %s\n", hdb_info->idx_info->idx_struct.idx_sqlite_v1->hIdx_sqlite)) {
		return 1;
	}

	snprintf(stmt, 1024,
		"INSERT INTO properties (name, value) VALUES ('%s', '%s');",
		IDX_HASHSET_NAME, hdb_info->db_name);
	if (attempt_exec_nocallback(stmt, "Error adding name to properties: %s\n", hdb_info->idx_info->idx_struct.idx_sqlite_v1->hIdx_sqlite)) {
		return 1;
	}

	snprintf(stmt, 1024,
		"INSERT INTO properties (name, value) VALUES ('%s', '%s');",
		IDX_HASHSET_UPDATEABLE, (hdb_info->idx_info->updateable == 1) ? "true" : "false");
	if (attempt_exec_nocallback(stmt, "Error adding updateable to properties: %s\n", hdb_info->idx_info->idx_struct.idx_sqlite_v1->hIdx_sqlite)) {
		return 1;
	}

	if (attempt_exec_nocallback
		("CREATE TABLE hashes (md5 BINARY(16) UNIQUE, sha1 BINARY(20), sha2_256 BINARY(32), database_offset INTEGER);",
		"Error creating hashes table %s\n", hdb_info->idx_info->idx_struct.idx_sqlite_v1->hIdx_sqlite)) {
			return 1;
	}

    // The names table enables the user to optionally map one or many names to each hash.
    // "name" should be the filename without the path.
	if (attempt_exec_nocallback
		("CREATE TABLE names (name TEXT, hash_id INTEGER);",
		"Error creating names table %s\n", hdb_info->idx_info->idx_struct.idx_sqlite_v1->hIdx_sqlite)) {
			return 1;
	}

    need_SQL_index = true;

	return sqlite_v1_begin(hdb_info);
}

/**
 * Add a string representation of a hash value to the index.
 *
 * @param hdb_info Hash database state info
 * @param hvalue String of hash value to add
 * @param offset Byte offset of hash entry in original database.
 * @return 1 on error and 0 on success
 */
uint8_t
sqlite_v1_addentry(TSK_HDB_INFO * hdb_info, char *hvalue,
                    TSK_OFF_T offset)
{
	const size_t len = (hdb_info->hash_len)/2;
    uint8_t* hash = (uint8_t*) tsk_malloc(len+1);
    
	size_t count;

	if (strlen(hvalue) != hdb_info->hash_len) {
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_AUTO_DB);
		tsk_error_set_errstr("Hash length doesn't match index type: %s\n", hvalue);
        tsk_error_print(stderr);
		return 1;
	}

    // We use an intermediate short to be compatible with Microsoft's implementation of the scanf family format
    short unsigned int binval;
    for (count = 0; count < len; count++) {
		int r = sscanf(hvalue, "%2hx", &binval);
        hash[count] = (uint8_t) binval;
		hvalue += 2 * sizeof(char);
	}

    uint8_t ret = tsk_hdb_idxaddentry_bin(hdb_info, hash, len, offset);

    delete [] hash;

	return ret;
}

/**
 * Add a binary representation of a hash value into the index.
 *
 * @param hdb_info Hash database state info
 * @param hvalue Array of integers of hash value to add
 * @param hlen Number of bytes in hvalue
 * @param offset Byte offset of hash entry in original database.
 * @return 1 on error and 0 on success
 */
uint8_t
sqlite_v1_addentry_bin(TSK_HDB_INFO * hdb_info, uint8_t* hvalue, int hlen,
                    TSK_OFF_T offset)
{
    if (attempt(sqlite3_bind_blob(m_stmt, 1, hvalue, hlen, SQLITE_TRANSIENT),
		SQLITE_OK,
		"Error binding binary blob: %s\n",
		hdb_info->idx_info->idx_struct.idx_sqlite_v1->hIdx_sqlite) ||
		attempt(sqlite3_bind_int64(m_stmt, 2, offset),
		SQLITE_OK,
		"Error binding entry offset: %s\n",
		hdb_info->idx_info->idx_struct.idx_sqlite_v1->hIdx_sqlite) ) {
        return 1;
    }

    // Don't report error on constraint -- we just will silently not add that duplicate hash
	int r = sqlite3_step(m_stmt);
    if ((r != SQLITE_DONE) && (r != SQLITE_CONSTRAINT) ) {
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_AUTO_DB);
		tsk_error_set_errstr("Error stepping: %s\n", sqlite3_errmsg( hdb_info->idx_info->idx_struct.idx_sqlite_v1->hIdx_sqlite), r);
        return 1;
    }

	r = sqlite3_reset(m_stmt);
    if ((r != SQLITE_OK) && (r != SQLITE_CONSTRAINT) ) {
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_AUTO_DB);
		tsk_error_set_errstr("Error resetting: %s\n", sqlite3_errmsg( hdb_info->idx_info->idx_struct.idx_sqlite_v1->hIdx_sqlite), r);
        return 1;
    }

    return 0;
}

/**
 * Finalize index creation process
 *
 * @param hdb_info Hash database state info structure.
 * @return 1 on error and 0 on success
 */
uint8_t
sqlite_v1_finalize(TSK_HDB_INFO * hdb_info)
{
	if (tsk_hdb_commit_transaction(hdb_info->idx_info)) {
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_AUTO_DB);
		tsk_error_set_errstr("Failed to commit transaction\n");
        tsk_error_print(stderr);
		return 1;
	}
	
    // We create the indexes at the end in order to make adding the initial batch of data (e.g. indexing an NSRL db)
    // faster. Updates after indexing can be slower since the index has to update as well.
    if (need_SQL_index) {
        need_SQL_index = false;
	    return attempt_exec_nocallback
		    ("CREATE INDEX hashset_md5_index ON hashes(md5);",
		    "Error creating hashset_md5_index on md5: %s\n", hdb_info->idx_info->idx_struct.idx_sqlite_v1->hIdx_sqlite) ||
		    attempt_exec_nocallback
		    ("CREATE INDEX hashset_sha1_index ON hashes(sha1);",
		    "Error creating hashset_sha1_index on sha1: %s\n", hdb_info->idx_info->idx_struct.idx_sqlite_v1->hIdx_sqlite);
    } else {
        return 0;
    }
}

/** \internal
 * Setup the internal variables to read an index or database. This
 * opens the index and sets the needed size information.
 *
 * @param hdb_info Hash database to analyze
 * @param htype The hash type that was used to make the index.
 *
 * @return 1 on error and 0 on success
 */
uint8_t
sqlite_v1_open(TSK_HDB_INFO * hdb_info, TSK_IDX_INFO * idx_info, uint8_t htype)
{
    sqlite3 * sqlite = NULL;

    if ((idx_info->idx_struct.idx_sqlite_v1 =
                (TSK_IDX_SQLITE_V1 *) tsk_malloc
                (sizeof(TSK_IDX_SQLITE_V1))) == NULL) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_ARG);
        tsk_error_set_errstr(
                 "sqlite_v1_open: Malloc error");
        return 1;
    }


    if ((htype != TSK_HDB_HTYPE_MD5_ID)
        && (htype != TSK_HDB_HTYPE_SHA1_ID)
        && (htype != TSK_HDB_HTYPE_SHA2_256_ID)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_ARG);
        tsk_error_set_errstr(
                 "hdb_setupindex: Invalid hash type : %d", htype);
        return 1;
    }

#ifdef TSK_WIN32
    {
        if (attempt(sqlite3_open16(idx_info->idx_fname, &sqlite),
                    SQLITE_OK,
                    "Can't open index: %s\n", sqlite)) {
            sqlite3_close(sqlite);
            return 1;
        }
    }
#else
    {
        if (attempt(sqlite3_open(idx_info->idx_fname, &sqlite),
                    SQLITE_OK,
                    "Can't open index: %s\n", sqlite)) {
            sqlite3_close(sqlite);
            return 1;
        }
    }
#endif

	sqlite3_extended_result_codes(sqlite, 1);

    idx_info->idx_struct.idx_sqlite_v1->hIdx_sqlite = sqlite;

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
sqlite_v1_lookup_str(TSK_HDB_INFO * hdb_info, const char *hash,
                   TSK_HDB_FLAG_ENUM flags, TSK_HDB_LOOKUP_FN action,
                   void *ptr)
{
	const size_t len = strlen(hash)/2;
	uint8_t * hashBlob = (uint8_t *) tsk_malloc(len+1);
	const char * pos = hash;
	size_t count = 0;

	for(count = 0; count < len; count++) {
		sscanf(pos, "%2hx", (short unsigned int *) &(hashBlob[count]));
		pos += 2 * sizeof(char);
	}

	return sqlite_v1_lookup_raw(hdb_info, hashBlob, len, flags, action, ptr);
			
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
sqlite_v1_lookup_raw(TSK_HDB_INFO * hdb_info, uint8_t * hash, uint8_t len,
                   TSK_HDB_FLAG_ENUM flags,
                   TSK_HDB_LOOKUP_FN action, void *ptr)
{
	char hashbuf[TSK_HDB_HTYPE_SHA1_LEN + 1];
	int i;
	static const char hex[] = "0123456789abcdef";
	TSK_OFF_T offset;
    char * selectStmt;

    tsk_take_lock(&hdb_info->lock);

	/* Sanity check */
	if ((hdb_info->hash_len)/2 != len) {
        tsk_release_lock(&hdb_info->lock);
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_HDB_ARG);
		tsk_error_set_errstr("hdb_lookup: Hash passed is different size than expected: %d vs %d",
			hdb_info->hash_len, len);
		return -1;
	}

    if (m_stmt == NULL) {
    	if (hdb_info->hash_type == TSK_HDB_HTYPE_MD5_ID) {
            selectStmt = "SELECT md5,database_offset from hashes where md5=? limit 1";
        } else if (hdb_info->hash_type == TSK_HDB_HTYPE_SHA1_ID) {
            selectStmt = "SELECT sha1,database_offset from hashes where sha1=? limit 1";
        } else {
            tsk_release_lock(&hdb_info->lock);
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_ARG);
            tsk_error_set_errstr("Unknown hash type: %d\n", hdb_info->hash_type);
            return 1;
        }
        prepare_stmt(selectStmt, &m_stmt, hdb_info->idx_info->idx_struct.idx_sqlite_v1->hIdx_sqlite);
    }

	if (attempt(sqlite3_bind_blob(m_stmt, 1, hash, len, free),
		SQLITE_OK,
		"Error binding binary blob: %s\n",
		hdb_info->idx_info->idx_struct.idx_sqlite_v1->hIdx_sqlite)) {
            tsk_release_lock(&hdb_info->lock);
			return -1;
	}

	if (sqlite3_step(m_stmt) == SQLITE_ROW) {
		if ((flags & TSK_HDB_FLAG_QUICK)
			|| (hdb_info->db_type == TSK_HDB_DBTYPE_IDXONLY_ID)) {
				sqlite3_reset(m_stmt);
                tsk_release_lock(&hdb_info->lock);
				return 1;
		} else {
			for (i = 0; i < len; i++) {
				hashbuf[2 * i] = hex[(hash[i] >> 4) & 0xf];
				hashbuf[2 * i + 1] = hex[hash[i] & 0xf];
			}
			hashbuf[2 * len] = '\0';

			offset = sqlite3_column_int64(m_stmt, 1);
			sqlite3_reset(m_stmt);

			if (hdb_info->getentry(hdb_info, hashbuf, offset, flags, action, ptr)) {
                tsk_release_lock(&hdb_info->lock);
				tsk_error_set_errstr2("hdb_lookup");
				return -1;
			}
			return 1;
		}
	}

	sqlite3_reset(m_stmt);
    
    tsk_release_lock(&hdb_info->lock);

	return 0;

}


/**
 * \ingroup hashdblib
 * Sets the updateable flag in the hdb_info argument based on querying the index props table.
 *
 * @param hdb_info Open hash database (with index)
 * @return -1 on error, 0 on success.
 */
int8_t
sqlite_v1_get_updateable(TSK_HDB_INFO * hdb_info)
{
    int8_t ret = 0;
	sqlite3_stmt* stmt = NULL;
    char selectStmt[1024];

    tsk_take_lock(&hdb_info->lock);
    
    snprintf(selectStmt, 1024, "SELECT value from properties where name='%s'", IDX_HASHSET_UPDATEABLE);
    prepare_stmt(selectStmt, &stmt, hdb_info->idx_info->idx_struct.idx_sqlite_v1->hIdx_sqlite);

	if (sqlite3_step(stmt) == SQLITE_ROW) {
		const char* value = (const char *)sqlite3_column_text(stmt, 0);

        if (value == NULL) {
            tsk_error_set_errstr2("sqlite_v1_get_updateable: null value");
            ret = -1;
        } else {
            // Set the updateable flag
            if (strcmp(value, "true") == 0) {
                hdb_info->idx_info->updateable = 1;
            }
        }
	} else {
        tsk_error_set_errstr2("sqlite_v1_get_updateable");
        ret = -1;
    }

	sqlite3_reset(stmt);
    
    if (stmt) {
        finalize_stmt(stmt);
    }

    tsk_release_lock(&hdb_info->lock);

	return ret;
}

/*
 * Close the sqlite index handle
 * @param idx_info the index to close
 */
void
sqlite_v1_close(TSK_IDX_INFO * idx_info)
{
    if (m_stmt) {
        finalize_stmt(m_stmt);
    }

    if (idx_info->idx_struct.idx_sqlite_v1->hIdx_sqlite) {
        sqlite3_close(idx_info->idx_struct.idx_sqlite_v1->hIdx_sqlite);
    }
}

/**
 * Test the file to see if it is an sqlite database (== index only)
 *
 * @param hFile File handle to hash database
 *
 * @return 1 if sqlite and 0 if not
 */
uint8_t
sqlite3_test(FILE * hFile)
{
    const int header_size = 16;
    char header[header_size];

    if (hFile) {
        if (1 != fread(header, header_size, 1, hFile)) {
            ///@todo should this actually be an error?
            return 0;
        }
        else if (strncmp(header,
                IDX_SQLITE_V1_HEADER,
                strlen(IDX_SQLITE_V1_HEADER)) == 0) {
            return 1;
        }
    }
}

