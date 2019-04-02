/*
** The Sleuth Kit
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2010-2013 Brian Carrier.  All Rights reserved
**
** This software is distributed under the Common Public License 1.0
**
*/

/**
* \file db_sqlite.cpp
* Contains code to perform operations against SQLite database. 
*/

#include "tsk_db_sqlite.h"
#include "guid.h"
#include <string.h>
#include <sstream>
#include <algorithm>
#include <unordered_set>

using std::stringstream;
using std::sort;
using std::for_each;

/**
* Set the locations and logging object.  Must call
* open() before the object can be used.
*/
TskDbSqlite::TskDbSqlite(const char* a_dbFilePathUtf8, bool a_blkMapFlag)
    : TskDb(a_dbFilePathUtf8, a_blkMapFlag)
{
    strncpy(m_dbFilePathUtf8, a_dbFilePathUtf8, 1024);
    m_utf8 = true;
    m_blkMapFlag = a_blkMapFlag;
    m_db = NULL;
    m_selectFilePreparedStmt = NULL;
    m_insertObjectPreparedStmt = NULL;
}

#ifdef TSK_WIN32
//@@@@
TskDbSqlite::TskDbSqlite(const TSK_TCHAR* a_dbFilePath, bool a_blkMapFlag)
    : TskDb(a_dbFilePath, a_blkMapFlag)
{
    wcsncpy(m_dbFilePath, a_dbFilePath, 1024);
    m_utf8 = false;
    m_blkMapFlag = a_blkMapFlag;
    m_db = NULL;
    m_selectFilePreparedStmt = NULL;
    m_insertObjectPreparedStmt = NULL;

    strcpy(m_dbFilePathUtf8, "");
}
#endif

TskDbSqlite::~TskDbSqlite()
{
    (void)close();
}

/*
* Close the Sqlite database.
* Return 0 on success, 1 on failure
*/
int
TskDbSqlite::close()
{
    if (m_db)
    {
        cleanupFilePreparedStmt();
        sqlite3_close(m_db);
        m_db = NULL;
    }
    return 0;
}


int
TskDbSqlite::attempt(int resultCode, int expectedResultCode,
                     const char* errfmt)
{
    if (resultCode != expectedResultCode)
    {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr(errfmt, sqlite3_errmsg(m_db), resultCode);
        return 1;
    }
    return 0;
}


int
TskDbSqlite::attempt(int resultCode, const char* errfmt)
{
    return attempt(resultCode, SQLITE_OK, errfmt);
}


/**
* Execute a statement and sets TSK error values on error 
* @returns 1 on error, 0 on success
*/
int
TskDbSqlite::attempt_exec(const char* sql, int (*callback)(void*, int,
                                                           char**, char**), void* callback_arg, const char* errfmt)
{
    char*
        errmsg;

    if (m_db == NULL)
    {
        return 1;
    }

    if (sqlite3_exec(m_db, sql, callback, callback_arg,
                     &errmsg) != SQLITE_OK)
    {
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
TskDbSqlite::attempt_exec(const char* sql, const char* errfmt)
{
    return attempt_exec(sql, NULL, NULL, errfmt);
}


/**
* @returns 1 on error, 0 on success
*/
int
TskDbSqlite::prepare_stmt(const char* sql, sqlite3_stmt** ppStmt)
{
    if (sqlite3_prepare_v2(m_db, sql, -1, ppStmt, NULL) != SQLITE_OK)
    {
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
uint8_t
TskDbSqlite::addObject(TSK_DB_OBJECT_TYPE_ENUM type, int64_t parObjId,
                       int64_t& objId)
{
    if (attempt(sqlite3_bind_int64(m_insertObjectPreparedStmt, 1, parObjId),
                "TskDbSqlite::addObj: Error binding parent to statement: %s (result code %d)\n")
        || attempt(sqlite3_bind_int(m_insertObjectPreparedStmt, 2, type),
                   "TskDbSqlite::addObj: Error binding type to statement: %s (result code %d)\n")
        || attempt(sqlite3_step(m_insertObjectPreparedStmt), SQLITE_DONE,
                   "TskDbSqlite::addObj: Error adding object to row: %s (result code %d)\n"))
    {
        // Statement may be used again, even after error
        sqlite3_reset(m_insertObjectPreparedStmt);
        return 1;
    }

    objId = sqlite3_last_insert_rowid(m_db);

    if (attempt(sqlite3_reset(m_insertObjectPreparedStmt),
                "TskDbSqlite::addObj: Error resetting 'insert object' statement: %s\n"))
    {
        return 1;
    }

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
                     "Error setting PRAGMA synchronous: %s\n"))
    {
        return 1;
    }

    // allow to read while in transaction
    if (attempt_exec("PRAGMA read_uncommitted = True;",
                     "Error setting PRAGMA read_uncommitted: %s\n"))
    {
        return 1;
    }

    if (attempt_exec("PRAGMA encoding = \"UTF-8\";",
                     "Error setting PRAGMA encoding UTF-8: %s\n"))
    {
        return 1;
    }

    if (attempt_exec("PRAGMA page_size = 4096;",
                     "Error setting PRAGMA page_size: %s\n"))
    {
        return 1;
    }

    if (attempt_exec("PRAGMA foreign_keys = ON;",
                     "Error setting PRAGMA foreign_keys: %s\n"))
    {
        return 1;
    }

    // increase the DB by 1MB at a time -- supposed to help performance when populating
    int chunkSize = 1024 * 1024;
    if (sqlite3_file_control(m_db, NULL, SQLITE_FCNTL_CHUNK_SIZE, &chunkSize) != SQLITE_OK)
    {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr("TskDbSqlite::initialize: error setting chunk size %s", sqlite3_errmsg(m_db));
        return 1;
    }

    if (attempt_exec
        ("CREATE TABLE tsk_db_info (schema_ver INTEGER, tsk_ver INTEGER, schema_minor_ver INTEGER);",
         "Error creating tsk_db_info table: %s\n"))
    {
        return 1;
    }

    snprintf(foo, 1024,
             "INSERT INTO tsk_db_info (schema_ver, tsk_ver, schema_minor_Ver) VALUES (%d, %d, %d);",
             TSK_SCHEMA_VER, TSK_VERSION_NUM, TSK_SCHEMA_MINOR_VER);
    if (attempt_exec(foo, "Error adding data to tsk_db_info table: %s\n"))
    {
        return 1;
    }

	if (attempt_exec("CREATE TABLE tsk_db_info_extended (name TEXT PRIMARY KEY, value TEXT NOT NULL);", "Error creating tsk_db_info_extended: %s\n")) {
		return 1;
	}

	snprintf(foo, 1024, "INSERT INTO tsk_db_info_extended (name, value) VALUES ('TSK_VERSION', '%d');", TSK_VERSION_NUM);
	if (attempt_exec(foo, "Error adding data to tsk_db_info table: %s\n")) {
		return 1;
	}

	snprintf(foo, 1024, "INSERT INTO tsk_db_info_extended (name, value) VALUES ('SCHEMA_MAJOR_VERSION', '%d');", TSK_SCHEMA_VER);
	if (attempt_exec(foo, "Error adding data to tsk_db_info table: %s\n")) {
		return 1;
	}

	snprintf(foo, 1024, "INSERT INTO tsk_db_info_extended (name, value) VALUES ('SCHEMA_MINOR_VERSION', '%d');", TSK_SCHEMA_MINOR_VER);
	if (attempt_exec(foo, "Error adding data to tsk_db_info table: %s\n")) {
		return 1;
	}

	snprintf(foo, 1024, "INSERT INTO tsk_db_info_extended (name, value) VALUES ('CREATED_SCHEMA_MAJOR_VERSION', '%d');", TSK_SCHEMA_VER);
	if (attempt_exec(foo, "Error adding data to tsk_db_info table: %s\n")) {
		return 1;
	}

	snprintf(foo, 1024, "INSERT INTO tsk_db_info_extended (name, value) VALUES ('CREATED_SCHEMA_MINOR_VERSION', '%d');", TSK_SCHEMA_MINOR_VER);
	if (attempt_exec(foo, "Error adding data to tsk_db_info table: %s\n")) {
		return 1;
	}

	if (attempt_exec
        ("CREATE TABLE tsk_objects (obj_id INTEGER PRIMARY KEY, par_obj_id INTEGER, type INTEGER NOT NULL);",
        "Error creating tsk_objects table: %s\n")
        ||
        attempt_exec
        ("CREATE TABLE tsk_image_info (obj_id INTEGER PRIMARY KEY, type INTEGER, ssize INTEGER, tzone TEXT, size INTEGER, md5 TEXT, sha1 TEXT, sha256 TEXT, display_name TEXT, FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id));",
            "Error creating tsk_image_info table: %s\n")
        ||
        attempt_exec
        ("CREATE TABLE tsk_image_names (obj_id INTEGER NOT NULL, name TEXT NOT NULL, sequence INTEGER NOT NULL, FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id));",
            "Error creating tsk_image_names table: %s\n")
        ||
        attempt_exec
        ("CREATE TABLE tsk_vs_info (obj_id INTEGER PRIMARY KEY, vs_type INTEGER NOT NULL, img_offset INTEGER NOT NULL, block_size INTEGER NOT NULL, FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id));",
            "Error creating tsk_vs_info table: %s\n")
        ||
        attempt_exec
        ("CREATE TABLE tsk_vs_parts (obj_id INTEGER PRIMARY KEY, addr INTEGER NOT NULL, start INTEGER NOT NULL, length INTEGER NOT NULL, desc TEXT, flags INTEGER NOT NULL, FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id));",
            "Error creating tsk_vol_info table: %s\n")
        ||
        attempt_exec
        ("CREATE TABLE tsk_fs_info (obj_id INTEGER PRIMARY KEY, img_offset INTEGER NOT NULL, fs_type INTEGER NOT NULL, block_size INTEGER NOT NULL, block_count INTEGER NOT NULL, root_inum INTEGER NOT NULL, first_inum INTEGER NOT NULL, last_inum INTEGER NOT NULL, display_name TEXT, FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id));",
            "Error creating tsk_fs_info table: %s\n")
        ||
        attempt_exec
        ("CREATE TABLE data_source_info (obj_id INTEGER PRIMARY KEY, device_id TEXT NOT NULL,  time_zone TEXT NOT NULL, acquisition_details TEXT, FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id));",
            "Error creating data_source_info table: %s\n")
        ||
        attempt_exec
        ("CREATE TABLE tsk_files (obj_id INTEGER PRIMARY KEY, fs_obj_id INTEGER, data_source_obj_id INTEGER NOT NULL, attr_type INTEGER, attr_id INTEGER, name TEXT NOT NULL, meta_addr INTEGER, meta_seq INTEGER, type INTEGER, has_layout INTEGER, has_path INTEGER, dir_type INTEGER, meta_type INTEGER, dir_flags INTEGER, meta_flags INTEGER, size INTEGER, ctime INTEGER, crtime INTEGER, atime INTEGER, mtime INTEGER, mode INTEGER, uid INTEGER, gid INTEGER, md5 TEXT, known INTEGER, parent_path TEXT, mime_type TEXT, extension TEXT , "
            "FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id), FOREIGN KEY(fs_obj_id) REFERENCES tsk_fs_info(obj_id), FOREIGN KEY(data_source_obj_id) REFERENCES data_source_info(obj_id));",
            "Error creating tsk_files table: %s\n")
        ||
        attempt_exec
        ("CREATE TABLE file_encoding_types (encoding_type INTEGER PRIMARY KEY, name TEXT NOT NULL);",
            "Error creating file_encoding_types table: %s\n")
        ||
        attempt_exec(
            "CREATE TABLE tsk_files_path (obj_id INTEGER PRIMARY KEY, path TEXT NOT NULL, encoding_type INTEGER NOT NULL, FOREIGN KEY(encoding_type) references file_encoding_types(encoding_type), FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id))",
            "Error creating tsk_files_path table: %s\n")
        ||
        attempt_exec
        ("CREATE TABLE tsk_files_derived (obj_id INTEGER PRIMARY KEY, derived_id INTEGER NOT NULL, rederive TEXT, FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id))",
            "Error creating tsk_files_derived table: %s\n")
        ||
        attempt_exec
        ("CREATE TABLE tsk_files_derived_method (derived_id INTEGER PRIMARY KEY, tool_name TEXT NOT NULL, tool_version TEXT NOT NULL, other TEXT)",
            "Error creating tsk_files_derived_method table: %s\n")
        ||
        attempt_exec
        ("CREATE TABLE tag_names (tag_name_id INTEGER PRIMARY KEY, display_name TEXT UNIQUE, description TEXT NOT NULL, color TEXT NOT NULL, knownStatus INTEGER NOT NULL)",
            "Error creating tag_names table: %s\n")
        ||
        attempt_exec("CREATE TABLE review_statuses (review_status_id INTEGER PRIMARY KEY, "
            "review_status_name TEXT NOT NULL, "
            "display_name TEXT NOT NULL)",
            "Error creating review_statuses table: %s\n")
        ||
        attempt_exec
        ("CREATE TABLE blackboard_artifacts (artifact_id INTEGER PRIMARY KEY, "
            "obj_id INTEGER NOT NULL, "
            "artifact_obj_id INTEGER NOT NULL, "
            "data_source_obj_id INTEGER NOT NULL, "
            "artifact_type_id INTEGER NOT NULL, "
            "review_status_id INTEGER NOT NULL, "
            "FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id), "
            "FOREIGN KEY(artifact_obj_id) REFERENCES tsk_objects(obj_id), "
            "FOREIGN KEY(data_source_obj_id) REFERENCES tsk_objects(obj_id), "
            "FOREIGN KEY(artifact_type_id) REFERENCES blackboard_artifact_types(artifact_type_id), "
            "FOREIGN KEY(review_status_id) REFERENCES review_statuses(review_status_id))",
            "Error creating blackboard_artifact table: %s\n")
        ||
        attempt_exec
        ("CREATE TABLE blackboard_attributes (artifact_id INTEGER NOT NULL, artifact_type_id INTEGER NOT NULL, source TEXT, context TEXT, attribute_type_id INTEGER NOT NULL, value_type INTEGER NOT NULL, "
            "value_byte BLOB, value_text TEXT, value_int32 INTEGER, value_int64 INTEGER, value_double NUMERIC(20, 10), "
            "FOREIGN KEY(artifact_id) REFERENCES blackboard_artifacts(artifact_id), FOREIGN KEY(artifact_type_id) REFERENCES blackboard_artifact_types(artifact_type_id), FOREIGN KEY(attribute_type_id) REFERENCES blackboard_attribute_types(attribute_type_id))",
            "Error creating blackboard_attribute table: %s\n")
        ||
        attempt_exec
        ("CREATE TABLE blackboard_artifact_types (artifact_type_id INTEGER PRIMARY KEY, type_name TEXT NOT NULL, display_name TEXT)",
            "Error creating blackboard_artifact_types table: %s\n")
        ||
        attempt_exec
        ("CREATE TABLE blackboard_attribute_types (attribute_type_id INTEGER PRIMARY KEY, type_name TEXT NOT NULL, display_name TEXT, value_type INTEGER NOT NULL)",
            "Error creating blackboard_attribute_types table: %s\n")
        ||
        attempt_exec
        ("CREATE TABLE ingest_module_types (type_id INTEGER PRIMARY KEY, type_name TEXT NOT NULL)",
            "Error creating ingest_module_types table: %s\n")
        ||
        attempt_exec
        ("CREATE TABLE ingest_job_status_types (type_id INTEGER PRIMARY KEY, type_name TEXT NOT NULL)",
            "Error creating ingest_job_status_types table: %s\n")
        ||
        attempt_exec
        ("CREATE TABLE ingest_modules (ingest_module_id INTEGER PRIMARY KEY, display_name TEXT NOT NULL, unique_name TEXT UNIQUE NOT NULL, type_id INTEGER NOT NULL, version TEXT NOT NULL, FOREIGN KEY(type_id) REFERENCES ingest_module_types(type_id));",
            "Error creating ingest_modules table: %s\n")
        ||
        attempt_exec
        ("CREATE TABLE ingest_jobs (ingest_job_id INTEGER PRIMARY KEY, obj_id INTEGER NOT NULL, host_name TEXT NOT NULL, start_date_time INTEGER NOT NULL, end_date_time INTEGER NOT NULL, status_id INTEGER NOT NULL, settings_dir TEXT, FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id), FOREIGN KEY(status_id) REFERENCES ingest_job_status_types(type_id));",
            "Error creating ingest_jobs table: %s\n")
        ||
        attempt_exec
        ("CREATE TABLE ingest_job_modules (ingest_job_id INTEGER, ingest_module_id INTEGER, pipeline_position INTEGER, PRIMARY KEY(ingest_job_id, ingest_module_id), FOREIGN KEY(ingest_job_id) REFERENCES ingest_jobs(ingest_job_id), FOREIGN KEY(ingest_module_id) REFERENCES ingest_modules(ingest_module_id));",
            "Error creating ingest_job_modules table: %s\n")
        ||
        attempt_exec
        ("CREATE TABLE reports (obj_id INTEGER PRIMARY KEY, path TEXT NOT NULL, crtime INTEGER NOT NULL, src_module_name TEXT NOT NULL, report_name TEXT NOT NULL, FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id));",
            "Error creating reports table: %s\n")
        ||
        attempt_exec
        ("CREATE TABLE account_types (account_type_id INTEGER PRIMARY KEY, type_name TEXT UNIQUE NOT NULL, display_name TEXT NOT NULL)",
            "Error creating account_types table: %s\n")
        ||
        attempt_exec
        ("CREATE TABLE accounts (account_id INTEGER PRIMARY KEY, account_type_id INTEGER NOT NULL, account_unique_identifier TEXT NOT NULL,  UNIQUE(account_type_id, account_unique_identifier) , FOREIGN KEY(account_type_id) REFERENCES account_types(account_type_id))",
            "Error creating accounts table: %s\n")
        ||
        attempt_exec
        ("CREATE TABLE account_relationships (relationship_id INTEGER PRIMARY KEY, account1_id INTEGER NOT NULL, account2_id INTEGER NOT NULL, relationship_source_obj_id INTEGER NOT NULL,  date_time INTEGER, relationship_type INTEGER NOT NULL, data_source_obj_id INTEGER NOT NULL, UNIQUE(account1_id, account2_id, relationship_source_obj_id), FOREIGN KEY(account1_id) REFERENCES accounts(account_id), FOREIGN KEY(account2_id) REFERENCES accounts(account_id), FOREIGN KEY(relationship_source_obj_id) REFERENCES tsk_objects(obj_id), FOREIGN KEY(data_source_obj_id) REFERENCES tsk_objects(obj_id))",
            "Error creating relationships table: %s\n")
        ||
        attempt_exec(
            "CREATE TABLE tsk_event_types ("
            " event_type_id INTEGER PRIMARY KEY,"
            " display_name TEXT UNIQUE NOT NULL,  "
			" super_type_id INTEGER REFERENCES tsk_event_types(event_type_id) )"
            , "Error creating event_types table: %s\n")
        ||
        attempt_exec(
            "insert into tsk_event_types(event_type_id, display_name, super_type_id) values(0, 'Event Types', null);"
            "insert into tsk_event_types(event_type_id, display_name, super_type_id) values(1, 'File System', 0);"
            "insert into tsk_event_types(event_type_id, display_name, super_type_id) values(2, 'Web Activity', 0);"
            "insert into tsk_event_types(event_type_id, display_name, super_type_id) values(3, 'Misc Types', 0);"
            "insert into tsk_event_types(event_type_id, display_name, super_type_id) values(4, 'Modified', 1);"
	        "insert into tsk_event_types(event_type_id, display_name, super_type_id) values(5, 'Accessed', 1);"
	        "insert into tsk_event_types(event_type_id, display_name, super_type_id) values(6, 'Created', 1);"
	        "insert into tsk_event_types(event_type_id, display_name, super_type_id) values(7, 'Changed', 1);"
	        , "Error initializing event_types table rows: %s\n")
	    ||
	    attempt_exec(
	        "CREATE TABLE tsk_event_descriptions ( "
	        " event_description_id INTEGER PRIMARY KEY, "
	        " full_description TEXT NOT NULL, "
	        " med_description TEXT, "
	        " short_description TEXT,"
	        " data_source_obj_id INTEGER NOT NULL REFERENCES data_source_info(obj_id), "
	        " file_obj_id INTEGER NOT NULL REFERENCES tsk_files(obj_id), "
	        " artifact_id INTEGER REFERENCES blackboard_artifacts(artifact_id), "
	        " hash_hit INTEGER NOT NULL, " //boolean 
	        " tagged INTEGER NOT NULL)", //boolean 
	        "Error creating tsk_event_event_types table: %4\n")
	    ||
	    attempt_exec(
	        "CREATE TABLE tsk_events ("
	        " event_id INTEGER PRIMARY KEY, "
	        " event_type_id BIGINT NOT NULL REFERENCES tsk_event_types(event_type_id) ,"
	        " event_description_id BIGINT NOT NULL REFERENCES tsk_event_descriptions(event_description_id) ,"
	        " time INTEGER NOT NULL) "
	        , "Error creating tsk_events table: %s\n")
	    ||
	    attempt_exec("CREATE TABLE db_info ( key TEXT,  value INTEGER, PRIMARY KEY (key))", //TODO: drop this table
	                 "Error creating db_info table: %s\n")
	    ||
        attempt_exec
        ("CREATE TABLE tsk_examiners (examiner_id INTEGER PRIMARY KEY, login_name TEXT NOT NULL, display_name TEXT, UNIQUE(login_name))",
         "Error creating tsk_examiners table: %s\n")
        ||
		attempt_exec
		("CREATE TABLE content_tags (tag_id INTEGER PRIMARY KEY, obj_id INTEGER NOT NULL, tag_name_id INTEGER NOT NULL, comment TEXT NOT NULL, begin_byte_offset INTEGER NOT NULL, end_byte_offset INTEGER NOT NULL, examiner_id INTEGER, "
			"FOREIGN KEY(examiner_id) REFERENCES tsk_examiners(examiner_id), FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id), FOREIGN KEY(tag_name_id) REFERENCES tag_names(tag_name_id))",
			"Error creating content_tags table: %s\n")
		||
		attempt_exec
		("CREATE TABLE blackboard_artifact_tags (tag_id INTEGER PRIMARY KEY, artifact_id INTEGER NOT NULL, tag_name_id INTEGER NOT NULL, comment TEXT NOT NULL, examiner_id INTEGER, "
			"FOREIGN KEY(examiner_id) REFERENCES tsk_examiners(examiner_id), FOREIGN KEY(artifact_id) REFERENCES blackboard_artifacts(artifact_id), FOREIGN KEY(tag_name_id) REFERENCES tag_names(tag_name_id))",
			"Error creating blackboard_artifact_tags table: %s\n")) {
        return 1;
    }

    if (m_blkMapFlag)
    {
        if (attempt_exec
            ("CREATE TABLE tsk_file_layout (obj_id INTEGER NOT NULL, byte_start INTEGER NOT NULL, byte_len INTEGER NOT NULL, sequence INTEGER NOT NULL, FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id));",
             "Error creating tsk_fs_blocks table: %s\n"))
        {
            return 1;
        }
    }

    if (createIndexes())
        return 1;

    return 0;
}

/**
* Create indexes for the columns that are not primary keys and that we query on. 
* @returns 1 on error, 0 on success
*/
int TskDbSqlite::createIndexes()
{
    return
        // tsk_objects index
        attempt_exec("CREATE INDEX parObjId ON tsk_objects(par_obj_id);",
            "Error creating tsk_objects index on par_obj_id: %s\n") ||
        // file layout index
        attempt_exec("CREATE INDEX layout_objID ON tsk_file_layout(obj_id);",
            "Error creating layout_objID index on tsk_file_layout: %s\n") ||
        // blackboard indexes
        attempt_exec("CREATE INDEX artifact_objID ON blackboard_artifacts(obj_id);",
            "Error creating artifact_objID index on blackboard_artifacts: %s\n") ||
        attempt_exec("CREATE INDEX artifact_artifact_objID ON blackboard_artifacts(artifact_obj_id);",
            "Error creating artifact_artifact_objID index on blackboard_artifacts: %s\n") ||
        attempt_exec("CREATE INDEX artifact_typeID ON blackboard_artifacts(artifact_type_id);",
            "Error creating artifact_objID index on blackboard_artifacts: %s\n") ||
        attempt_exec("CREATE INDEX attrsArtifactID ON blackboard_attributes(artifact_id);",
            "Error creating artifact_id index on blackboard_attributes: %s\n") ||
        //file type indexes
        attempt_exec("CREATE INDEX mime_type ON tsk_files(dir_type,mime_type,type);", //mime type
            "Error creating mime_type index on tsk_files: %s\n") ||
        attempt_exec("CREATE INDEX file_extension ON tsk_files(extension);", //file extenssion
            "Error creating file_extension index on tsk_files: %s\n") ||
        attempt_exec("CREATE INDEX relationships_account1  ON account_relationships(account1_id);",
            "Error creating relationships_account1 index on account_relationships: %s\n") ||
        attempt_exec("CREATE INDEX relationships_account2  ON account_relationships(account2_id);",
            "Error creating relationships_account2 index on account_relationships: %s\n") ||
        attempt_exec(
            "CREATE INDEX relationships_relationship_source_obj_id  ON account_relationships(relationship_source_obj_id);",
            "Error creating relationships_relationship_source_obj_id index on account_relationships: %s\n") ||
        attempt_exec("CREATE INDEX relationships_date_time  ON account_relationships(date_time);",
            "Error creating relationships_date_time index on account_relationships: %s\n") ||
        attempt_exec("CREATE INDEX relationships_relationship_type  ON account_relationships(relationship_type);",
            "Error creating relationships_relationship_type index on account_relationships: %s\n") ||
        attempt_exec("CREATE INDEX relationships_data_source_obj_id  ON account_relationships(data_source_obj_id);",
            "Error creating relationships_data_source_obj_id index on account_relationships: %s\n") ||
        //events indices
        attempt_exec("CREATE INDEX events_data_source_obj_id  ON tsk_event_descriptions(data_source_obj_id);",
                     "Error creating events_data_source_obj_id index on tsk_event_descriptions: %s\n") ||
        attempt_exec("CREATE INDEX events_file_obj_id  ON tsk_event_descriptions(file_obj_id);",
                     "Error creating events_file_obj_id index on tsk_event_descriptions: %s\n") ||
        attempt_exec("CREATE INDEX events_artifact_id  ON tsk_event_descriptions(artifact_id);",
                     "Error creating events_artifact_id index on tsk_event_descriptions: %s\n") ||
        attempt_exec(
            "CREATE INDEX events_sub_type_time ON tsk_events(event_type_id,  time);",
            "Error creating events_sub_type_time index on tsk_events: %s\n") ||
        attempt_exec("CREATE INDEX events_time  ON tsk_events(time);",
                     "Error creating events_time index on tsk_events: %s\n");
}


/*
* Open the database (will create file if it does not exist).
* @param a_toInit Set to true if this is a new database that needs to have the tables created
* @ returns 1 on error and 0 on success
*/
int
TskDbSqlite::open(bool a_toInit)
{
    if (m_utf8)
    {
        if (attempt(sqlite3_open(m_dbFilePathUtf8, &m_db),
                    "Can't open database: %s\n"))
        {
            sqlite3_close(m_db);
            return 1;
        }
    }
    else
    {
        if (attempt(sqlite3_open16(m_dbFilePath, &m_db),
                    "Can't open database: %s\n"))
        {
            sqlite3_close(m_db);
            return 1;
        }
    }

    // enable finer result codes
    sqlite3_extended_result_codes(m_db, true);

    // create the tables if we need to
    if (a_toInit)
    {
        if (initialize())
            return 1;
    }

    if (setupFilePreparedStmt())
    {
        return 1;
    }

    return 0;
}

/**
* Must be called on an initialized database, before adding any content to it.
*/
int
TskDbSqlite::setupFilePreparedStmt()
{
    if (prepare_stmt
        ("SELECT obj_id FROM tsk_files WHERE meta_addr IS ? AND fs_obj_id IS ? AND parent_path IS ? AND name IS ?",
         &m_selectFilePreparedStmt))
    {
        return 1;
    }
    if (prepare_stmt
        ("INSERT INTO tsk_objects (obj_id, par_obj_id, type) VALUES (NULL, ?, ?)",
         &m_insertObjectPreparedStmt))
    {
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
    if (m_selectFilePreparedStmt != NULL)
    {
        sqlite3_finalize(m_selectFilePreparedStmt);
        m_selectFilePreparedStmt = NULL;
    }
    if (m_insertObjectPreparedStmt != NULL)
    {
        sqlite3_finalize(m_insertObjectPreparedStmt);
        m_insertObjectPreparedStmt = NULL;
    }
}

/**
* deprecated
*/
int
TskDbSqlite::addImageInfo(int type, int size, int64_t& objId, const string& timezone)
{
    return addImageInfo(type, size, objId, timezone, 0, "", "", "");
}

/**
* @returns 1 on error, 0 on success
*/
int
    TskDbSqlite::addImageInfo(int type, int ssize, int64_t & objId, const string & timezone, TSK_OFF_T size, const string &md5, const string &sha1, const string &sha256)
{
    return addImageInfo(type, ssize, objId, timezone, size, md5, sha1, sha256, "", "");
}

/**
 * Adds image details to the existing database tables.
 *
 * @param type Image type
 * @param ssize Size of device sector in bytes (or 0 for default)
 * @param objId The object id assigned to the image (out param)
 * @param timezone The timezone the image is from
 * @param size The size of the image in bytes.
 * @param md5 MD5 hash of the image
 * @param deviceId An ASCII-printable identifier for the device associated with the data source that is intended to be unique across multiple cases (e.g., a UUID).
 * @returns 1 on error, 0 on success
 */
int TskDbSqlite::addImageInfo(int type, TSK_OFF_T ssize, int64_t & objId, const string & timezone, TSK_OFF_T size, const string &md5, 
    const string& sha1, const string& sha256, const string& deviceId, const string& collectionDetails)
{
    // Add the data source to the tsk_objects table.
    // We don't use addObject because we're passing in NULL as the parent
    char stmt[1024];
    snprintf(stmt, 1024,
             "INSERT INTO tsk_objects (obj_id, par_obj_id, type) VALUES (NULL, NULL, %d);",
             TSK_DB_OBJECT_TYPE_IMG);
    if (attempt_exec(stmt, "Error adding data to tsk_objects table: %s\n"))
    {
        return 1;
    }
    objId = sqlite3_last_insert_rowid(m_db);

    // Add the data source to the tsk_image_info table.
    char* sql;
    sql = sqlite3_mprintf("INSERT INTO tsk_image_info (obj_id, type, ssize, tzone, size, md5, sha1, sha256) VALUES (%lld, %d, %lld, '%q', %" PRIuOFF ", '%q', '%q', '%q');",
        objId, type, ssize, timezone.c_str(), size, md5.c_str(), sha1.c_str(), sha256.c_str());

    int ret = attempt_exec(sql, "Error adding data to tsk_image_info table: %s\n");
    sqlite3_free(sql);
    if (1 == ret)
    {
        return ret;
    }

    // Add the data source to the data_source_info table.
    stringstream deviceIdStr;
#ifdef GUID_WINDOWS
    if (deviceId.empty())
    {
        // Use a GUID as the default.
        GuidGenerator generator;
        Guid guid = generator.newGuid();
        deviceIdStr << guid;
    }
    else
    {
        deviceIdStr << deviceId;
    }
#else
    deviceIdStr << deviceId;
#endif
    sql = sqlite3_mprintf("INSERT INTO data_source_info (obj_id, device_id, time_zone, acquisition_details) VALUES (%lld, '%s', '%s', '%q');", objId, deviceIdStr.str().c_str(), timezone.c_str(), collectionDetails.c_str());
    ret = attempt_exec(sql, "Error adding data to tsk_image_info table: %s\n");
    sqlite3_free(sql);
    return ret;
}

/**
* @returns 1 on error, 0 on success
*/
int
TskDbSqlite::addImageName(int64_t objId, char const* imgName,
                          int sequence)
{
    char* zSQL;
    int ret;

    zSQL = sqlite3_mprintf("INSERT INTO tsk_image_names (obj_id, name, sequence) VALUES (%lld, '%q', %d)",
                           objId, imgName, sequence);

    ret = attempt_exec(zSQL,
                       "Error adding data to tsk_image_names table: %s\n");
    sqlite3_free(zSQL);
    return ret;
}

/**
* @returns 1 on error, 0 on success
*/
int
TskDbSqlite::addVsInfo(const TSK_VS_INFO* vs_info, int64_t parObjId,
                       int64_t& objId)
{
    char
        stmt[1024];

    if (addObject(TSK_DB_OBJECT_TYPE_VS, parObjId, objId))
        return 1;

    snprintf(stmt, 1024,
        "INSERT INTO tsk_vs_info (obj_id, vs_type, img_offset, block_size) VALUES (%" PRId64 ", %d,%" PRIuOFF ",%d)", objId, vs_info->vstype, vs_info->offset, vs_info->block_size);

    return attempt_exec(stmt,
                        "Error adding data to tsk_vs_info table: %s\n");
}


/**
* Adds the sector addresses of the volumes into the db.
* @returns 1 on error, 0 on success
*/
int
TskDbSqlite::addVolumeInfo(const TSK_VS_PART_INFO* vs_part,
                           int64_t parObjId, int64_t& objId)
{
    char* zSQL;
    int ret;

    if (addObject(TSK_DB_OBJECT_TYPE_VOL, parObjId, objId))
        return 1;

    zSQL = sqlite3_mprintf(
        "INSERT INTO tsk_vs_parts (obj_id, addr, start, length, desc, flags)"
        "VALUES (%lld, %" PRIuPNUM ",%" PRIuOFF ",%" PRIuOFF ",'%q',%d)",
        objId, (int)vs_part->addr, vs_part->start, vs_part->len,
        vs_part->desc, vs_part->flags);

    ret = attempt_exec(zSQL,
                       "Error adding data to tsk_vs_parts table: %s\n");
    sqlite3_free(zSQL);
    return ret;
}

/**
* @returns 1 on error, 0 on success
*/
int
TskDbSqlite::addFsInfo(const TSK_FS_INFO* fs_info, int64_t parObjId,
                       int64_t& objId)
{
    char
        stmt[1024];

    if (addObject(TSK_DB_OBJECT_TYPE_FS, parObjId, objId))
        return 1;

    snprintf(stmt, 1024,
             "INSERT INTO tsk_fs_info (obj_id, img_offset, fs_type, block_size, block_count, "
             "root_inum, first_inum, last_inum) "
             "VALUES ("
        "%" PRId64 ",%" PRIuOFF ",%d,%u,%" PRIuDADDR ","
             "%" PRIuINUM ",%" PRIuINUM ",%" PRIuINUM ")",
             objId, fs_info->offset, (int)fs_info->ftype, fs_info->block_size,
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
* @param path Path of parent folder
* @param md5 Binary value of MD5 (i.e. 16 bytes) or NULL 
* @param known Status regarding if it was found in hash database or not
* @param fsObjId File system object of its file system
* @param objId ID that was assigned to it from the objects table
* @param dataSourceObjId The object ID for the data source
* @returns 1 on error and 0 on success
*/
int
TskDbSqlite::addFsFile(TSK_FS_FILE* fs_file,
                       const TSK_FS_ATTR* fs_attr, const char* path,
                       const unsigned char*const md5, const TSK_DB_FILES_KNOWN_ENUM known,
                       int64_t fsObjId, int64_t& objId, int64_t dataSourceObjId)
{
    int64_t parObjId = 0;

    if (fs_file->name == NULL)
        return 0;

    // Find the object id for the parent folder.

    /* Root directory's parent should be the file system object.
     * Make sure it doesn't have a name, so that we don't pick up ".." entries */
    if ((fs_file->fs_info->root_inum == fs_file->name->meta_addr) &&
        ((fs_file->name->name == NULL) || (strlen(fs_file->name->name) == 0)))
    {
        parObjId = fsObjId;
    }
    else
    {
        parObjId = findParObjId(fs_file, path, fsObjId);
        if (parObjId == -1)
        {
            //error
            return 1;
        }
    }

    return addFile(fs_file, fs_attr, path, md5, known, fsObjId, parObjId, objId, dataSourceObjId);
}


/**
* return a hash of the passed in string. We use this
* for full paths. 
* From: http://www.cse.yorku.ca/~oz/hash.html
*/
uint32_t TskDbSqlite::hash(const unsigned char* str)
{
    uint32_t hash = 5381;
    int c;

    while ((c = *str++))
    {
        // skip slashes -> normalizes leading/ending/double slashes
        if (c == '/')
            continue;
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }

    return hash;
}

/**
* Store info about a directory in a complex map structure as a cache for the
* files who are a child of this directory and want to know its object id. 
*
* @param fsObjId fs id of this directory
* @param fs_file File for the directory to store
* @param path Full path (parent and this file) of the directory
* @param objId object id of the directory 
*/
void TskDbSqlite::storeObjId(const int64_t& fsObjId, const TSK_FS_FILE* fs_file, const char* path, const int64_t& objId)
{
    // skip the . and .. entries
    if ((fs_file->name) && (fs_file->name->name) && (TSK_FS_ISDOT(fs_file->name->name)))
    {
        return;
    }

    uint32_t seq;
    uint32_t path_hash = hash((const unsigned char *)path);

    /* NTFS uses sequence, otherwise we hash the path. We do this to map to the
    * correct parent folder if there are two from the root dir that eventually point to
    * the same folder (one deleted and one allocated) or two hard links. */
    if (TSK_FS_TYPE_ISNTFS(fs_file->fs_info->ftype))
    {
        /* Use the sequence stored in meta (which could be one larger than the name value
        * if the directory is deleted. We do this because the par_seq gets added to the
        * name structure when it is added to the directory based on teh value stored in 
        * meta. */
        seq = fs_file->meta->seq;
    }
    else
    {
        seq = path_hash;
    }

    map<TSK_INUM_T, map<uint32_t, map<uint32_t, int64_t> > >& fsMap = m_parentDirIdCache[fsObjId];
    if (fsMap.count(fs_file->name->meta_addr) == 0)
    {
        fsMap[fs_file->name->meta_addr][seq][path_hash] = objId;
    }
    else
    {
        map<uint32_t, map<uint32_t, int64_t> >& fileMap = fsMap[fs_file->name->meta_addr];
        if (fileMap.count(seq) == 0)
        {
            fileMap[seq][path_hash] = objId;
        }
    }
}

/**
* Find parent object id of TSK_FS_FILE. Use local cache map, if not found, fall back to SQL
* @param fs_file file to find parent obj id for
* @param parentPath Path of parent folder that we want to match
* @param fsObjId fs id of this file
* @returns parent obj id ( > 0), -1 on error
*/
int64_t TskDbSqlite::findParObjId(const TSK_FS_FILE* fs_file, const char* parentPath, const int64_t& fsObjId)
{
    uint32_t seq;
    uint32_t path_hash = hash((const unsigned char *)parentPath);

    /* NTFS uses sequence, otherwise we hash the path. We do this to map to the
    * correct parent folder if there are two from the root dir that eventually point to
    * the same folder (one deleted and one allocated) or two hard links. */
    if (TSK_FS_TYPE_ISNTFS(fs_file->fs_info->ftype))
    {
        seq = fs_file->name->par_seq;
    }
    else
    {
        seq = path_hash;
    }

    //get from cache by parent meta addr, if available
    map<TSK_INUM_T, map<uint32_t, map<uint32_t, int64_t> > >& fsMap = m_parentDirIdCache[fsObjId];
    if (fsMap.count(fs_file->name->par_addr) > 0)
    {
        map<uint32_t, map<uint32_t, int64_t> >& fileMap = fsMap[fs_file->name->par_addr];
        if (fileMap.count(seq) > 0)
        {
            map<uint32_t, int64_t>& pathMap = fileMap[seq];
            if (pathMap.count(path_hash) > 0)
            {
                return pathMap[path_hash];
            }
        }
        else
        {
            // printf("Miss: %zu\n", fileMap.count(seq));
        }
    }

    // fprintf(stderr, "Miss: %s (%" PRIu64  " - %" PRIu64 ")\n", fs_file->name->name, fs_file->name->meta_addr,
    //                fs_file->name->par_addr);

    // Need to break up 'path' in to the parent folder to match in 'parent_path' and the folder 
    // name to match with the 'name' column in tsk_files table
    const char *parent_name = "";
    const char *parent_path = "";
    if (TskDb::getParentPathAndName(parentPath, &parent_path, &parent_name))
    {
        return -1;
    }

    // Find the parent file id in the database using the parent metadata address
    // @@@ This should use sequence number when the new database supports it
    if (attempt(sqlite3_bind_int64(m_selectFilePreparedStmt, 1, fs_file->name->par_addr),
                "TskDbSqlite::findParObjId: Error binding meta_addr to statement: %s (result code %d)\n")
        || attempt(sqlite3_bind_int64(m_selectFilePreparedStmt, 2, fsObjId),
                   "TskDbSqlite::findParObjId: Error binding fs_obj_id to statement: %s (result code %d)\n")
        || attempt(sqlite3_bind_text(m_selectFilePreparedStmt, 3, parent_path, -1, SQLITE_STATIC),
                   "TskDbSqlite::findParObjId: Error binding path to statement: %s (result code %d)\n")
        || attempt(sqlite3_bind_text(m_selectFilePreparedStmt, 4, parent_name, -1, SQLITE_STATIC),
                   "TskDbSqlite::findParObjId: Error binding path to statement: %s (result code %d)\n")
        || attempt(sqlite3_step(m_selectFilePreparedStmt), SQLITE_ROW,
                   "TskDbSqlite::findParObjId: Error selecting file id by meta_addr: %s (result code %d)\n"))
    {
        // Statement may be used again, even after error
        sqlite3_reset(m_selectFilePreparedStmt);
        return -1;
    }

    int64_t parObjId = sqlite3_column_int64(m_selectFilePreparedStmt, 0);

    if (attempt(sqlite3_reset(m_selectFilePreparedStmt),
                "TskDbSqlite::findParObjId: Error resetting 'select file id by meta_addr' statement: %s\n"))
    {
        return -1;
    }

    return parObjId;
}

int TskDbSqlite::addMACTimeEvents(const int64_t data_source_obj_id, const int64_t file_obj_id,
                                  std::map<int64_t, time_t> timeMap, const char* full_description)
{
    int64_t event_description_id = -1;

    //for each  entry (type ->time)
    for (const auto entry : timeMap)
    {
        const long long time = entry.second;


        if (time == 0)
        {
            //we skip any MAC time events with time == 0 since 0 is usually a bogus time and not helpfull 
            continue;
        }
        if (event_description_id == -1)
        {
            //insert common description for file
            char* descriptionSql = sqlite3_mprintf(
                "INSERT INTO tsk_event_descriptions ( data_source_obj_id, file_obj_id , artifact_id,  full_description, hash_hit, tagged) "
                " VALUES ("
                "%" PRId64 "," // data_source_obj_id
                "%" PRId64 "," // file_obj_id
                "NULL," // fixed artifact_id
                "%Q," // full_description
                "0," // fixed hash_hit
                "0" // fixed tagged
                ")",
                data_source_obj_id,
                file_obj_id,
                full_description);

            if (attempt_exec(descriptionSql,
                             "TskDbSqlite::addMACTimeEvents: Error adding filesystem event to tsk_events table: %s\n")
            )
            {
                sqlite3_free(descriptionSql);
                return 1;
            }

            sqlite3_free(descriptionSql);
            event_description_id = sqlite3_last_insert_rowid(m_db);
        }
        //insert events time event
        char* eventSql = sqlite3_mprintf(
            "INSERT INTO tsk_events ( event_type_id, event_description_id , time) "
            " VALUES ("
            "%" PRId64 "," // event_type_id
            "%" PRId64 "," // event_description_id
            "%" PRIu64 ")", // time
            entry.first,
            event_description_id,
            time
        );

        if (attempt_exec(
                eventSql, "TskDbSqlite::addMACTimeEvents: Error adding filesystem event to tsk_events table: %s\n")
        )
        {
            sqlite3_free(eventSql);
            return 1;
        }
        sqlite3_free(eventSql);
    }

    return 0;
}

/**
* Add file data to the file table
* @param md5 binary value of MD5 (i.e. 16 bytes) or NULL
* @param dataSourceObjId The object ID for the data source
* Return 0 on success, 1 on error.
*/
int
TskDbSqlite::addFile(TSK_FS_FILE* fs_file,
    const TSK_FS_ATTR* fs_attr, const char* path,
    const unsigned char*const md5, const TSK_DB_FILES_KNOWN_ENUM known,
    int64_t fsObjId, int64_t parObjId,
    int64_t& objId, int64_t dataSourceObjId)
{
    time_t mtime = 0;
    time_t crtime = 0;
    time_t ctime = 0;
    time_t atime = 0;
    TSK_OFF_T size = 0;
    int meta_type = 0;
    int meta_flags = 0;
    int meta_mode = 0;
    int gid = 0;
    int uid = 0;
    int type = TSK_FS_ATTR_TYPE_NOT_FOUND;
    int idx = 0;
    char* zSQL;

    if (fs_file->name == NULL)
        return 0;

    if (fs_file->meta)
    {
        mtime = fs_file->meta->mtime;
        atime = fs_file->meta->atime;
        ctime = fs_file->meta->ctime;
        crtime = fs_file->meta->crtime;
        meta_type = fs_file->meta->type;
        meta_flags = fs_file->meta->flags;
        meta_mode = fs_file->meta->mode;
        gid = fs_file->meta->gid;
        uid = fs_file->meta->uid;
    }

    size_t attr_nlen = 0;
    if (fs_attr)
    {
        type = fs_attr->type;
        idx = fs_attr->id;
        size = fs_attr->size;
        if (fs_attr->name)
        {
            if ((fs_attr->type != TSK_FS_ATTR_TYPE_NTFS_IDXROOT) ||
                (strcmp(fs_attr->name, "$I30") != 0))
            {
                attr_nlen = strlen(fs_attr->name);
            }
        }
    }

    // combine name and attribute name
    size_t len = strlen(fs_file->name->name);
    char* name;
    size_t nlen = len + attr_nlen + 11; // Extra space for possible colon and '-slack'
    if ((name = (char *)tsk_malloc(nlen)) == NULL)
    {
        return 1;
    }

    strncpy(name, fs_file->name->name, nlen);

    char extension[24] = "";
    extractExtension(name, extension);

    // Add the attribute name
    if (attr_nlen > 0)
    {
        strncat(name, ":", nlen - strlen(name));
        strncat(name, fs_attr->name, nlen - strlen(name));
    }

    // clean up path
    // +2 = space for leading slash and terminating null
    size_t path_len = strlen(path) + 2;
    char* escaped_path;
    if ((escaped_path = (char *)tsk_malloc(path_len)) == NULL)
    {
        free(name);
        return 1;
    }

    strncpy(escaped_path, "/", path_len);
    strncat(escaped_path, path, path_len - strlen(escaped_path));

    char* md5TextPtr = NULL;
    char md5Text[48];

    // if md5 hashes are being used
    if (md5 != NULL)
    {
        // copy the hash as hexidecimal into the buffer
        for (int i = 0; i < 16; i++)
        {
            sprintf(&(md5Text[i * 2]), "%x%x", (md5[i] >> 4) & 0xf,
                md5[i] & 0xf);
        }
        md5TextPtr = md5Text;
    }


    if (addObject(TSK_DB_OBJECT_TYPE_FILE, parObjId, objId))
    {
        free(name);
        free(escaped_path);
        return 1;
    }

    zSQL = sqlite3_mprintf(
        "INSERT INTO tsk_files (fs_obj_id, obj_id, data_source_obj_id, type, attr_type, attr_id, name, meta_addr, meta_seq, dir_type, meta_type, dir_flags, meta_flags, size, crtime, ctime, atime, mtime, mode, gid, uid, md5, known, parent_path, extension) "
        "VALUES ("
        "%" PRId64 ",%" PRId64 ","
        "%" PRId64 ","
        "%d,"
        "%d,%d,'%q',"
        "%" PRIuINUM ",%d,"
        "%d,%d,%d,%d,"
        "%" PRIuOFF ","
        "%llu,%llu,%llu,%llu,"
        "%d,%d,%d,%Q,%d,"
        "'%q','%q')",
        fsObjId, objId,
        dataSourceObjId,
        TSK_DB_FILES_TYPE_FS,
        type, idx, name,
        fs_file->name->meta_addr, fs_file->name->meta_seq,
        fs_file->name->type, meta_type, fs_file->name->flags, meta_flags,
        size,
        (unsigned long long)crtime, (unsigned long long)ctime, (unsigned long long)atime, (unsigned long long)mtime,
        meta_mode, gid, uid, md5TextPtr, known,
        escaped_path, extension);

    if (attempt_exec(zSQL, "TskDbSqlite::addFile: Error adding data to tsk_files table: %s\n"))
    {
        free(name);
        free(escaped_path);
        sqlite3_free(zSQL);
        return 1;
    }


    if (!TSK_FS_ISDOT(name))
    {
        std::string full_description = std::string(escaped_path).append(name);

        // map from time to event type ids
        const std::map<int64_t, time_t> timeMap = {
            {4, mtime},
            {5, atime},
            {6, crtime},
            {7, ctime}
        };

        //insert MAC time events for the file
        if (addMACTimeEvents(dataSourceObjId, objId, timeMap, full_description.c_str()))
        {
            free(name);
            free(escaped_path);
            sqlite3_free(zSQL);
            return 1;
        };
    }

    //if dir, update parent id cache (do this before objId may be changed creating the slack file)
    if (TSK_FS_IS_DIR_META(meta_type))
    {
        std::string fullPath = std::string(path) + fs_file->name->name;
        storeObjId(fsObjId, fs_file, fullPath.c_str(), objId);
    }

    // Add entry for the slack space.
    // Current conditions for creating a slack file:
    //   - File name is not empty, "." or ".."
    //   - Data is non-resident
    //   - The allocated size is greater than the initialized file size
    //     See github issue #756 on why initsize and not size.
    //   - The data is not compressed
    if ((fs_attr != NULL)
        && ((strlen(name) > 0) && (! TSK_FS_ISDOT(name)))
        && (!(fs_file->meta->flags & TSK_FS_META_FLAG_COMP))
        && (fs_attr->flags & TSK_FS_ATTR_NONRES)
        && (fs_attr->nrd.allocsize > fs_attr->nrd.initsize))
    {
        strncat(name, "-slack", 6);
        if (strlen(extension) > 0)
        {
            strncat(extension, "-slack", 6);
        }
        TSK_OFF_T slackSize = fs_attr->nrd.allocsize - fs_attr->nrd.initsize;

        if (addObject(TSK_DB_OBJECT_TYPE_FILE, parObjId, objId))
        {
            free(name);
            free(escaped_path);
            return 1;
        }

        // Run the same insert with the new name, size, and type
        zSQL = sqlite3_mprintf(
            "INSERT INTO tsk_files (fs_obj_id, obj_id, data_source_obj_id, type, attr_type, attr_id, name, meta_addr, meta_seq, dir_type, meta_type, dir_flags, meta_flags, size, crtime, ctime, atime, mtime, mode, gid, uid, md5, known, parent_path,extension) "
            "VALUES ("
            "%" PRId64 ",%" PRId64 ","
            "%" PRId64 ","
            "%d,"
            "%d,%d,'%q',"
            "%" PRIuINUM ",%d,"
            "%d,%d,%d,%d,"
            "%" PRIuOFF ","
            "%llu,%llu,%llu,%llu,"
            "%d,%d,%d,NULL,%d,"
            "'%q','%q')",
            fsObjId, objId,
            dataSourceObjId,
            TSK_DB_FILES_TYPE_SLACK,
            type, idx, name,
            fs_file->name->meta_addr, fs_file->name->meta_seq,
            TSK_FS_NAME_TYPE_REG, TSK_FS_META_TYPE_REG, fs_file->name->flags, meta_flags,
            slackSize,
            (unsigned long long)crtime, (unsigned long long)ctime, (unsigned long long)atime, (unsigned long long)mtime,
            meta_mode, gid, uid, known,
            escaped_path, extension);

        if (attempt_exec(zSQL, "TskDbSqlite::addFile: Error adding data to tsk_files table: %s\n"))
        {
            free(name);
            free(escaped_path);
            sqlite3_free(zSQL);
            return 1;
        }
    }

    sqlite3_free(zSQL);

    free(name);
    free(escaped_path);

    return 0;
}


/**
* Create a savepoint.  Call revertSavepoint() or releaseSavepoint()
* to revert or commit.
* @param name Name to call savepoint
* @returns 1 on error, 0 on success
*/
int
TskDbSqlite::createSavepoint(const char* name)
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
TskDbSqlite::revertSavepoint(const char* name)
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
TskDbSqlite::releaseSavepoint(const char* name)
{
    char
        buff[1024];

    snprintf(buff, 1024, "RELEASE SAVEPOINT %s", name);

    return attempt_exec(buff, "Error releasing savepoint: %s\n");
}


/**
* Add file layout info to the database.  This table stores the run information for each file so that we
* can map which parts of an image are used by what files.
* @param a_fileObjId ID of the file
* @param a_byteStart Byte address relative to the start of the image file
* @param a_byteLen Length of the run in bytes
* @param a_sequence Sequence of this run in the file
* @returns 1 on error
*/
int
TskDbSqlite::addFileLayoutRange(int64_t a_fileObjId,
                                uint64_t a_byteStart, uint64_t a_byteLen, int a_sequence)
{
    char
        foo[1024];

    snprintf(foo, 1024,
        "INSERT INTO tsk_file_layout(obj_id, byte_start, byte_len, sequence) VALUES (%" PRId64 ", %" PRIu64 ", %" PRIu64 ", %d)",
             a_fileObjId, a_byteStart, a_byteLen, a_sequence);

    return attempt_exec(foo,
                        "Error adding data to tsk_file_layout table: %s\n");
}

/**
* Add file layout info to the database.  This table stores the run information for each file so that we
* can map which parts of an image are used by what files.
* @param fileLayoutRange TSK_DB_FILE_LAYOUT_RANGE object storing a single file layout range entry
* @returns 1 on error
*/
int TskDbSqlite::addFileLayoutRange(const TSK_DB_FILE_LAYOUT_RANGE& fileLayoutRange)
{
    return addFileLayoutRange(fileLayoutRange.fileObjId, fileLayoutRange.byteStart, fileLayoutRange.byteLen,
                              fileLayoutRange.sequence);
}


/**
* Adds entry for to tsk_files for a layout file into the database.
* @param parObjId parent obj id in the database
* @param fsObjId fs obj id in the database, or 0 if parent it not fs (NULL)
* @param dbFileType type (unallocated, carved, unused)
* @param fileName file name for the layout file
* @param size Number of bytes in file
* @param objId layout file Id (output)
* @param dataSourceObjId The object Id of the data source
* @returns TSK_OK on success or TSK_ERR on error.
*/
TSK_RETVAL_ENUM
TskDbSqlite::addLayoutFileInfo(const int64_t parObjId, const int64_t fsObjId, const TSK_DB_FILES_TYPE_ENUM dbFileType,
                               const char* fileName,
                               const uint64_t size, int64_t& objId, int64_t dataSourceObjId)
{
    char* zSQL;

    if (addObject(TSK_DB_OBJECT_TYPE_FILE, parObjId, objId))
        return TSK_ERR;

    //fsObjId can be NULL
    char* fsObjIdStrPtr = NULL;
    char fsObjIdStr[32];
    if (fsObjId != 0)
    {
        snprintf(fsObjIdStr, 32, "%" PRIu64, fsObjId);
        fsObjIdStrPtr = fsObjIdStr;
    }

    zSQL = sqlite3_mprintf(
        "INSERT INTO tsk_files (has_layout, fs_obj_id, obj_id, data_source_obj_id, type, attr_type, attr_id, name, meta_addr, meta_seq, dir_type, meta_type, dir_flags, meta_flags, size, crtime, ctime, atime, mtime, mode, gid, uid, known) "
        "VALUES ("
        "1, %Q, %lld,"
        "%" PRId64 ","
        "%d,"
        "NULL,NULL,'%q',"
        "NULL,NULL,"
        "%d,%d,%d,%d,"
        "%" PRIuOFF ","
        "NULL,NULL,NULL,NULL,NULL,NULL,NULL,%d)",
        fsObjIdStrPtr, objId,
        dataSourceObjId,
        dbFileType,
        fileName,
        TSK_FS_NAME_TYPE_REG, TSK_FS_META_TYPE_REG,
        TSK_FS_NAME_FLAG_UNALLOC, TSK_FS_META_FLAG_UNALLOC, size, TSK_DB_FILES_KNOWN_UNKNOWN);

    if (attempt_exec(zSQL, "TskDbSqlite::addLayoutFileInfo: Error adding data to tsk_files table: %s\n"))
    {
        sqlite3_free(zSQL);
        return TSK_ERR;
    }

    sqlite3_free(zSQL);
    return TSK_OK;
}


/** 
* Returns true if database is opened.
*/
bool
TskDbSqlite::isDbOpen()
{
    if (m_db)
        return true;
    else
        return false;
}

bool TskDbSqlite::dbExists()
{
    // Check if database file already exsists
    if (m_utf8)
    {
        struct stat stat_buf;
        if (stat(m_dbFilePathUtf8, &stat_buf) == 0)
        {
            return true;
        }
    }
    else
    {
        struct STAT_STR stat_buf;
        if (TSTAT(m_dbFilePath, &stat_buf) == 0)
        {
            return true;
        }
    }

    return false;
}

bool
TskDbSqlite::inTransaction()
{
    return (sqlite3_get_autocommit(m_db) == 0);
}


/**
* Adds information about a unallocated file with layout ranges into the database.
* Adds a single entry to tsk_files table with an auto-generated file name, tsk_objects table, and one or more entries to tsk_file_layout table
* @param parentObjId Id of the parent object in the database (fs, volume, or image)
* @param fsObjId parent fs, or NULL if the file is not associated with fs
* @param size Number of bytes in file
* @param ranges vector containing one or more TSK_DB_FILE_LAYOUT_RANGE layout ranges (in)
* @param objId object id of the file object created (output)
* @param dataSourceObjId The object ID for the data source
* @returns TSK_OK on success or TSK_ERR on error.
*/
TSK_RETVAL_ENUM TskDbSqlite::addUnallocBlockFile(const int64_t parentObjId, const int64_t fsObjId, const uint64_t size,
                                                 vector<TSK_DB_FILE_LAYOUT_RANGE>& ranges, int64_t& objId,
                                                 int64_t dataSourceObjId)
{
    return addFileWithLayoutRange(TSK_DB_FILES_TYPE_UNALLOC_BLOCKS, parentObjId, fsObjId, size, ranges, objId,
                                  dataSourceObjId);
}

/**
* Adds information about a unused file with layout ranges into the database.
* Adds a single entry to tsk_files table with an auto-generated file name, tsk_objects table, and one or more entries to tsk_file_layout table
* @param parentObjId Id of the parent object in the database (fs, volume, or image)
* @param fsObjId parent fs, or NULL if the file is not associated with fs
* @param size Number of bytes in file
* @param ranges vector containing one or more TSK_DB_FILE_LAYOUT_RANGE layout ranges (in)
* @param objId object id of the file object created (output)
* @param dataSourceObjId The object ID for the data source
* @returns TSK_OK on success or TSK_ERR on error.
*/
TSK_RETVAL_ENUM TskDbSqlite::addUnusedBlockFile(const int64_t parentObjId, const int64_t fsObjId, const uint64_t size,
                                                vector<TSK_DB_FILE_LAYOUT_RANGE>& ranges, int64_t& objId,
                                                int64_t dataSourceObjId)
{
    return addFileWithLayoutRange(TSK_DB_FILES_TYPE_UNUSED_BLOCKS, parentObjId, fsObjId, size, ranges, objId,
                                  dataSourceObjId);
}

/**
* Adds information about a carved file with layout ranges into the database.
* Adds a single entry to tsk_files table with an auto-generated file name, tsk_objects table, and one or more entries to tsk_file_layout table
* @param parentObjId Id of the parent object in the database (fs, volume, or image)
* @param fsObjId fs id associated with the file, or NULL
* @param size Number of bytes in file
* @param ranges vector containing one or more TSK_DB_FILE_LAYOUT_RANGE layout ranges (in)
* @param objId object id of the file object created (output)
* @param dataSourceObjId The object ID for the data source
* @returns TSK_OK on success or TSK_ERR on error.
*/
TSK_RETVAL_ENUM TskDbSqlite::addCarvedFile(const int64_t parentObjId, const int64_t fsObjId, const uint64_t size,
                                           vector<TSK_DB_FILE_LAYOUT_RANGE>& ranges, int64_t& objId,
                                           int64_t dataSourceObjId)
{
    return addFileWithLayoutRange(TSK_DB_FILES_TYPE_CARVED, parentObjId, fsObjId, size, ranges, objId, dataSourceObjId);
}

//internal function object to check for range overlap
typedef struct _checkFileLayoutRangeOverlap
{
    const vector<TSK_DB_FILE_LAYOUT_RANGE>& ranges;
    bool hasOverlap;

    explicit _checkFileLayoutRangeOverlap(const vector<TSK_DB_FILE_LAYOUT_RANGE>& ranges)
        : ranges(ranges), hasOverlap(false)
    {
    }

    bool getHasOverlap() const { return hasOverlap; }

    void operator()(const TSK_DB_FILE_LAYOUT_RANGE& range)
    {
        if (hasOverlap)
            return; //no need to check other

        uint64_t start = range.byteStart;
        uint64_t end = start + range.byteLen;

        vector<TSK_DB_FILE_LAYOUT_RANGE>::const_iterator it;
        for (it = ranges.begin(); it != ranges.end(); ++it)
        {
            const TSK_DB_FILE_LAYOUT_RANGE* otherRange = &(*it);
            if (&range == otherRange)
                continue; //skip, it's the same range
            uint64_t otherStart = otherRange->byteStart;
            uint64_t otherEnd = otherStart + otherRange->byteLen;
            if (start <= otherEnd && end >= otherStart)
            {
                hasOverlap = true;
                break;
            }
        }
    }
} checkFileLayoutRangeOverlap;

/**
* Add virtual dir of type TSK_DB_FILES_TYPE_VIRTUAL_DIR
* that can be a parent of other non-fs virtual files or directories, to organize them
* @param fsObjId (in) file system object id to associate with the virtual directory.
* @param parentDirId (in) parent dir object id of the new directory: either another virtual directory or root fs directory
* @param name name (int) of the new virtual directory
* @param objId (out) object id of the created virtual directory object
* @param dataSourceObjId The object Id of the data source
* @returns TSK_ERR on error or TSK_OK on success
*/
TSK_RETVAL_ENUM TskDbSqlite::addVirtualDir(const int64_t fsObjId, const int64_t parentDirId, const char* const name,
                                           int64_t& objId, int64_t dataSourceObjId)
{
    char* zSQL;

    if (addObject(TSK_DB_OBJECT_TYPE_FILE, parentDirId, objId))
        return TSK_ERR;
    zSQL = sqlite3_mprintf(
        "INSERT INTO tsk_files (attr_type, attr_id, has_layout, fs_obj_id, obj_id, data_source_obj_id, type, attr_type, "
        "attr_id, name, meta_addr, meta_seq, dir_type, meta_type, dir_flags, meta_flags, size, "
        "crtime, ctime, atime, mtime, mode, gid, uid, known, parent_path) "
        "VALUES ("
        "NULL, NULL,"
        "NULL,"
        "%lld,"
        "%lld,"
        "%" PRId64 ","
        "%d,"
        "NULL,NULL,'%q',"
        "NULL,NULL,"
        "%d,%d,%d,%d,"
        "0,"
        "NULL,NULL,NULL,NULL,NULL,NULL,NULL,%d,'/')",
        fsObjId,
        objId,
        dataSourceObjId,
        TSK_DB_FILES_TYPE_VIRTUAL_DIR,
        name,
        TSK_FS_NAME_TYPE_DIR, TSK_FS_META_TYPE_DIR,
        TSK_FS_NAME_FLAG_ALLOC, (TSK_FS_META_FLAG_ALLOC | TSK_FS_META_FLAG_USED), TSK_DB_FILES_KNOWN_UNKNOWN);

    if (attempt_exec(zSQL, "Error adding data to tsk_files table: %s\n"))
    {
        sqlite3_free(zSQL);
        return TSK_ERR;
    }
    sqlite3_free(zSQL);

    return TSK_OK;
}

/**
* Internal helper method to add a virtual root dir, a parent dir of files representing unalloc space within fs.
* The dir has is associated with its root dir parent for the fs.
* @param fsObjId (in) fs id to find root dir for and create $Unalloc dir for
* @param objId (out) object id of the $Unalloc dir created
* @param dataSourceObjId The object ID for the data source
* @returns TSK_ERR on error or TSK_OK on success
*/
TSK_RETVAL_ENUM TskDbSqlite::addUnallocFsBlockFilesParent(const int64_t fsObjId, int64_t& objId,
                                                          int64_t dataSourceObjId)
{
    const char* const unallocDirName = "$Unalloc";

    //get root dir
    TSK_DB_OBJECT rootDirObjInfo;
    if (getFsRootDirObjectInfo(fsObjId, rootDirObjInfo) == TSK_ERR)
    {
        return TSK_ERR;
    }

    return addVirtualDir(fsObjId, rootDirObjInfo.objId, unallocDirName, objId, dataSourceObjId);
}

/**
* Internal helper method to add unalloc, unused and carved files with layout ranges to db
* Generates file_name and populates tsk_files, tsk_objects and tsk_file_layout tables
* @param dataSourceObjId The object ID for the data source
* @returns TSK_ERR on error or TSK_OK on success
*/
TSK_RETVAL_ENUM TskDbSqlite::addFileWithLayoutRange(const TSK_DB_FILES_TYPE_ENUM dbFileType, const int64_t parentObjId,
                                                    const int64_t fsObjId, const uint64_t size,
                                                    vector<TSK_DB_FILE_LAYOUT_RANGE>& ranges, int64_t& objId,
                                                    int64_t dataSourceObjId)
{
    const size_t numRanges = ranges.size();

    if (numRanges < 1)
    {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr("Error addFileWithLayoutRange() - no ranges present");
        return TSK_ERR;
    }

    stringstream fileNameSs;
    switch (dbFileType)
    {
    case TSK_DB_FILES_TYPE_UNALLOC_BLOCKS:
        fileNameSs << "Unalloc";
        break;

    case TSK_DB_FILES_TYPE_UNUSED_BLOCKS:
        fileNameSs << "Unused";
        break;

    case TSK_DB_FILES_TYPE_CARVED:
        fileNameSs << "Carved";
        break;
    default:
        stringstream sserr;
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        sserr << "Error addFileWithLayoutRange() - unsupported file type for file layout range: ";
        sserr << (int)dbFileType;
        tsk_error_set_errstr("%s", sserr.str().c_str());
        return TSK_ERR;
    }

    //ensure layout ranges are sorted (to generate file name and to be inserted in sequence order)
    sort(ranges.begin(), ranges.end());

    //dome some checking
    //ensure there is no overlap and each range has unique byte range
    const checkFileLayoutRangeOverlap& overlapRes =
        for_each(ranges.begin(), ranges.end(), checkFileLayoutRangeOverlap(ranges));
    if (overlapRes.getHasOverlap())
    {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr("Error addFileWithLayoutRange() - overlap detected between ranges");
        return TSK_ERR;
    }

    //construct filename with parent obj id, start byte of first range, end byte of last range
    fileNameSs << "_" << parentObjId << "_" << ranges[0].byteStart;
    fileNameSs << "_" << (ranges[numRanges - 1].byteStart + ranges[numRanges - 1].byteLen);

    //insert into tsk files and tsk objects
    if (addLayoutFileInfo(parentObjId, fsObjId, dbFileType, fileNameSs.str().c_str(), size, objId, dataSourceObjId))
    {
        return TSK_ERR;
    }

    //fill in fileObjId and insert ranges
    for (vector<TSK_DB_FILE_LAYOUT_RANGE>::iterator it = ranges.begin();
         it != ranges.end(); ++it)
    {
        TSK_DB_FILE_LAYOUT_RANGE& range = *it;
        range.fileObjId = objId;
        if (this->addFileLayoutRange(range))
        {
            return TSK_ERR;
        }
    }

    return TSK_OK;
}

/**
* Query tsk_file_layout and return rows for every entry in tsk_file_layout table
* @param fileLayouts (out) TSK_DB_FILE_LAYOUT_RANGE row representations to return
* @returns TSK_ERR on error, TSK_OK on success
*/
TSK_RETVAL_ENUM TskDbSqlite::getFileLayouts(vector<TSK_DB_FILE_LAYOUT_RANGE>& fileLayouts)
{
    sqlite3_stmt* fileLayoutsStatement = NULL;
    if (prepare_stmt("SELECT obj_id, byte_start, byte_len, sequence FROM tsk_file_layout",
                     &fileLayoutsStatement))
    {
        return TSK_ERR;
    }

    //get rows
    TSK_DB_FILE_LAYOUT_RANGE rowData;

    while (sqlite3_step(fileLayoutsStatement) == SQLITE_ROW)
    {
        rowData.fileObjId = sqlite3_column_int64(fileLayoutsStatement, 0);
        rowData.byteStart = sqlite3_column_int64(fileLayoutsStatement, 1);
        rowData.byteLen = sqlite3_column_int64(fileLayoutsStatement, 2);
        rowData.sequence = sqlite3_column_int(fileLayoutsStatement, 3);

        //insert a copy of the rowData
        fileLayouts.push_back(rowData);
    }

    //cleanup
    if (fileLayoutsStatement != NULL)
    {
        sqlite3_finalize(fileLayoutsStatement);
        fileLayoutsStatement = NULL;
    }

    return TSK_OK;
}

ostream& operator <<(ostream& os, const TSK_DB_FILE_LAYOUT_RANGE& layoutRange)
{
    os << layoutRange.fileObjId << "," << layoutRange.byteStart << ","
        << layoutRange.byteLen << "," << layoutRange.sequence;
    os << std::endl;
    return os;
}

ostream& operator <<(ostream& os, const TSK_DB_FS_INFO& fsInfo)
{
    os << fsInfo.objId << "," << fsInfo.imgOffset << "," << (int)fsInfo.fType
        << "," << fsInfo.block_size << "," << fsInfo.block_count
        << "," << fsInfo.root_inum << "," << fsInfo.first_inum << "," << fsInfo.last_inum;
    os << std::endl;
    return os;
}

ostream& operator <<(ostream& os, const TSK_DB_VS_INFO& vsInfo)
{
    os << vsInfo.objId << "," << (int)vsInfo.vstype << "," << vsInfo.offset
        << "," << vsInfo.block_size;
    os << std::endl;
    return os;
}

ostream& operator <<(ostream& os, const TSK_DB_VS_PART_INFO& vsPartInfo)
{
    os << vsPartInfo.objId << "," << vsPartInfo.addr << "," << vsPartInfo.start
        << "," << vsPartInfo.len << "," << vsPartInfo.desc << "," << (int)vsPartInfo.flags;
    os << std::endl;
    return os;
}

ostream& operator <<(ostream& os, const TSK_DB_OBJECT& dbObject)
{
    os << dbObject.objId << "," << dbObject.parObjId << "," << (int)dbObject.type;
    os << std::endl;
    return os;
}

/**
* Query tsk_fs_info and return rows for every entry in tsk_fs_info table
* @param imgId the object id of the image to get filesystems for
* @param fsInfos (out) TSK_DB_FS_INFO row representations to return
* @returns TSK_ERR on error, TSK_OK on success
*/
TSK_RETVAL_ENUM TskDbSqlite::getFsInfos(int64_t imgId, vector<TSK_DB_FS_INFO>& fsInfos)
{
    sqlite3_stmt* fsInfosStatement = NULL;
    if (prepare_stmt(
        "SELECT obj_id, img_offset, fs_type, block_size, block_count, root_inum, first_inum, last_inum FROM tsk_fs_info",
        &fsInfosStatement))
    {
        return TSK_ERR;
    }

    //get rows
    TSK_DB_FS_INFO rowData;
    while (sqlite3_step(fsInfosStatement) == SQLITE_ROW)
    {
        int64_t fsObjId = sqlite3_column_int64(fsInfosStatement, 0);

        //ensure fs is (sub)child of the image requested, if not, skip it
        int64_t curImgId = 0;
        if (getParentImageId(fsObjId, curImgId) == TSK_ERR)
        {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_AUTO_DB);
            tsk_error_set_errstr("Error finding parent for: %" PRIu64, fsObjId);
            return TSK_ERR;
        }

        if (imgId != curImgId)
        {
            continue;
        }

        rowData.objId = fsObjId;
        rowData.imgOffset = sqlite3_column_int64(fsInfosStatement, 1);
        rowData.fType = (TSK_FS_TYPE_ENUM)sqlite3_column_int(fsInfosStatement, 2);
        rowData.block_size = sqlite3_column_int(fsInfosStatement, 3);
        rowData.block_count = sqlite3_column_int64(fsInfosStatement, 4);
        rowData.root_inum = sqlite3_column_int64(fsInfosStatement, 5);
        rowData.first_inum = sqlite3_column_int64(fsInfosStatement, 6);
        rowData.last_inum = sqlite3_column_int64(fsInfosStatement, 7);

        //insert a copy of the rowData
        fsInfos.push_back(rowData);
    }

    //cleanup
    if (fsInfosStatement != NULL)
    {
        sqlite3_finalize(fsInfosStatement);
        fsInfosStatement = NULL;
    }

    return TSK_OK;
}


/**
* Query tsk_vs_info and return rows for every entry in tsk_vs_info table
* @param imgId the object id of the image to get volumesystems for
* @param vsInfos (out) TSK_DB_VS_INFO row representations to return
* @returns TSK_ERR on error, TSK_OK on success
*/
TSK_RETVAL_ENUM TskDbSqlite::getVsInfos(int64_t imgId, vector<TSK_DB_VS_INFO>& vsInfos)
{
    sqlite3_stmt* vsInfosStatement = NULL;
    if (prepare_stmt("SELECT obj_id, vs_type, img_offset, block_size FROM tsk_vs_info",
                     &vsInfosStatement))
    {
        return TSK_ERR;
    }

    //get rows
    TSK_DB_VS_INFO rowData;
    while (sqlite3_step(vsInfosStatement) == SQLITE_ROW)
    {
        int64_t vsObjId = sqlite3_column_int64(vsInfosStatement, 0);

        int64_t curImgId = 0;
        if (getParentImageId(vsObjId, curImgId) == TSK_ERR)
        {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_AUTO_DB);
            tsk_error_set_errstr("Error finding parent for: %" PRIu64, vsObjId);
            return TSK_ERR;
        }

        if (imgId != curImgId)
        {
            //ensure vs is (sub)child of the image requested, if not, skip it
            continue;
        }

        rowData.objId = vsObjId;
        rowData.vstype = (TSK_VS_TYPE_ENUM)sqlite3_column_int(vsInfosStatement, 1);
        rowData.offset = sqlite3_column_int64(vsInfosStatement, 2);
        rowData.block_size = sqlite3_column_int(vsInfosStatement, 3);

        //insert a copy of the rowData
        vsInfos.push_back(rowData);
    }

    //cleanup
    if (vsInfosStatement != NULL)
    {
        sqlite3_finalize(vsInfosStatement);
        vsInfosStatement = NULL;
    }

    return TSK_OK;
}


/**
* Query tsk_vs_part and return rows for every entry in tsk_vs_part table
* @param imgId the object id of the image to get vs parts for
* @param vsPartInfos (out) TSK_DB_VS_PART_INFO row representations to return
* @returns TSK_ERR on error, TSK_OK on success
*/
TSK_RETVAL_ENUM TskDbSqlite::getVsPartInfos(int64_t imgId, vector<TSK_DB_VS_PART_INFO>& vsPartInfos)
{
    sqlite3_stmt* vsPartInfosStatement = NULL;
    if (prepare_stmt("SELECT obj_id, addr, start, length, desc, flags FROM tsk_vs_parts",
                     &vsPartInfosStatement))
    {
        return TSK_ERR;
    }

    //get rows
    TSK_DB_VS_PART_INFO rowData;
    while (sqlite3_step(vsPartInfosStatement) == SQLITE_ROW)
    {
        int64_t vsPartObjId = sqlite3_column_int64(vsPartInfosStatement, 0);

        int64_t curImgId = 0;
        if (getParentImageId(vsPartObjId, curImgId) == TSK_ERR)
        {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_AUTO_DB);
            tsk_error_set_errstr("Error finding parent for: %" PRIu64, vsPartObjId);
            return TSK_ERR;
        }

        if (imgId != curImgId)
        {
            //ensure vs is (sub)child of the image requested, if not, skip it
            continue;
        }

        rowData.objId = vsPartObjId;
        rowData.addr = sqlite3_column_int(vsPartInfosStatement, 1);
        rowData.start = sqlite3_column_int64(vsPartInfosStatement, 2);
        rowData.len = sqlite3_column_int64(vsPartInfosStatement, 3);
        const unsigned char* text = sqlite3_column_text(vsPartInfosStatement, 4);
        size_t textLen = sqlite3_column_bytes(vsPartInfosStatement, 4);
        const size_t copyChars = textLen < TSK_MAX_DB_VS_PART_INFO_DESC_LEN - 1
                                     ? textLen
                                     : TSK_MAX_DB_VS_PART_INFO_DESC_LEN - 1;
        strncpy(rowData.desc, (char*)text, copyChars);
        rowData.desc[copyChars] = '\0';
        rowData.flags = (TSK_VS_PART_FLAG_ENUM)sqlite3_column_int(vsPartInfosStatement, 5);
        //insert a copy of the rowData
        vsPartInfos.push_back(rowData);
    }

    //cleanup
    if (vsPartInfosStatement != NULL)
    {
        sqlite3_finalize(vsPartInfosStatement);
        vsPartInfosStatement = NULL;
    }

    return TSK_OK;
}

/**
* Query tsk_objects with given id and returns object info entry
* @param objId object id to query
* @param objectInfo (out) TSK_DB_OBJECT entry representation to return
* @returns TSK_ERR on error (or if not found), TSK_OK on success
*/
TSK_RETVAL_ENUM TskDbSqlite::getObjectInfo(int64_t objId, TSK_DB_OBJECT& objectInfo)
{
    sqlite3_stmt* objectsStatement = NULL;
    if (prepare_stmt("SELECT obj_id, par_obj_id, type FROM tsk_objects WHERE obj_id IS ?",
                     &objectsStatement))
    {
        return TSK_ERR;
    }

    if (attempt(sqlite3_bind_int64(objectsStatement, 1, objId),
                "TskDbSqlite::getObjectInfo: Error binding objId to statement: %s (result code %d)\n")
        || attempt(sqlite3_step(objectsStatement), SQLITE_ROW,
                   "TskDbSqlite::getObjectInfo: Error selecting object by objid: %s (result code %d)\n"))
    {
        sqlite3_finalize(objectsStatement);
        return TSK_ERR;
    }

    objectInfo.objId = sqlite3_column_int64(objectsStatement, 0);
    objectInfo.parObjId = sqlite3_column_int64(objectsStatement, 1);
    objectInfo.type = (TSK_DB_OBJECT_TYPE_ENUM)sqlite3_column_int(objectsStatement, 2);

    //cleanup
    if (objectsStatement != NULL)
    {
        sqlite3_finalize(objectsStatement);
        objectsStatement = NULL;
    }

    return TSK_OK;
}

/**
* Query tsk_vs_info with given id and returns TSK_DB_VS_INFO info entry
* @param objId vs id to query
* @param vsInfo (out) TSK_DB_VS_INFO entry representation to return
* @returns TSK_ERR on error (or if not found), TSK_OK on success
*/
TSK_RETVAL_ENUM TskDbSqlite::getVsInfo(int64_t objId, TSK_DB_VS_INFO& vsInfo)
{
    sqlite3_stmt* vsInfoStatement = NULL;
    if (prepare_stmt("SELECT obj_id, vs_type, img_offset, block_size FROM tsk_vs_info WHERE obj_id IS ?",
                     &vsInfoStatement))
    {
        return TSK_ERR;
    }

    if (attempt(sqlite3_bind_int64(vsInfoStatement, 1, objId),
                "TskDbSqlite::getVsInfo: Error binding objId to statement: %s (result code %d)\n")
        || attempt(sqlite3_step(vsInfoStatement), SQLITE_ROW,
                   "TskDbSqlite::getVsInfo: Error selecting object by objid: %s (result code %d)\n"))
    {
        sqlite3_finalize(vsInfoStatement);
        return TSK_ERR;
    }

    vsInfo.objId = sqlite3_column_int64(vsInfoStatement, 0);
    vsInfo.vstype = (TSK_VS_TYPE_ENUM)sqlite3_column_int(vsInfoStatement, 1);
    vsInfo.offset = sqlite3_column_int64(vsInfoStatement, 2);
    vsInfo.block_size = sqlite3_column_int(vsInfoStatement, 3);

    //cleanup
    if (vsInfoStatement != NULL)
    {
        sqlite3_finalize(vsInfoStatement);
        vsInfoStatement = NULL;
    }

    return TSK_OK;
}


/**
* Query tsk_objects to find the root image id for the object
* @param objId (in) object id to query
* @param imageId (out) root parent image id returned
* @returns TSK_ERR on error (or if not found), TSK_OK on success
*/
TSK_RETVAL_ENUM TskDbSqlite::getParentImageId(const int64_t objId, int64_t& imageId)
{
    TSK_DB_OBJECT objectInfo;
    TSK_RETVAL_ENUM ret = TSK_ERR;

    int64_t queryObjectId = objId;
    while (getObjectInfo(queryObjectId, objectInfo) == TSK_OK)
    {
        if (objectInfo.parObjId == 0)
        {
            //found root image
            imageId = objectInfo.objId;
            ret = TSK_OK;
            break;
        }
        else
        {
            //advance
            queryObjectId = objectInfo.parObjId;
        }
    }

    return ret;
}


/**
* Query tsk_objects and tsk_files given file system id and return the root directory object
* @param fsObjId (int) file system id to query root dir object for
* @param rootDirObjInfo (out) TSK_DB_OBJECT root dir entry representation to return
* @returns TSK_ERR on error (or if not found), TSK_OK on success
*/
TSK_RETVAL_ENUM TskDbSqlite::getFsRootDirObjectInfo(const int64_t fsObjId, TSK_DB_OBJECT& rootDirObjInfo)
{
    sqlite3_stmt* rootDirInfoStatement = NULL;
    if (prepare_stmt("SELECT tsk_objects.obj_id,tsk_objects.par_obj_id,tsk_objects.type "
                     "FROM tsk_objects,tsk_files WHERE tsk_objects.par_obj_id IS ? "
                     "AND tsk_files.obj_id = tsk_objects.obj_id AND tsk_files.name = ''",
                     &rootDirInfoStatement))
    {
        return TSK_ERR;
    }

    if (attempt(sqlite3_bind_int64(rootDirInfoStatement, 1, fsObjId),
                "TskDbSqlite::getFsRootDirObjectInfo: Error binding objId to statement: %s (result code %d)\n")
        || attempt(sqlite3_step(rootDirInfoStatement), SQLITE_ROW,
                   "TskDbSqlite::getFsRootDirObjectInfo: Error selecting object by objid: %s (result code %d)\n"))
    {
        sqlite3_finalize(rootDirInfoStatement);
        return TSK_ERR;
    }

    rootDirObjInfo.objId = sqlite3_column_int64(rootDirInfoStatement, 0);
    rootDirObjInfo.parObjId = sqlite3_column_int64(rootDirInfoStatement, 1);
    rootDirObjInfo.type = (TSK_DB_OBJECT_TYPE_ENUM)sqlite3_column_int(rootDirInfoStatement, 2);


    //cleanup
    if (rootDirInfoStatement != NULL)
    {
        sqlite3_finalize(rootDirInfoStatement);
        rootDirInfoStatement = NULL;
    }

    return TSK_OK;
}
