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
* \file db_postresql.cpp
* Contains code to perform operations against PostgreSQL database. 
*/

#ifdef HAVE_POSTGRESQL

#include "tsk_db_postgresql.h"

#ifdef TSK_WIN32

#define atoll(S) _atoi64(S)

#include <string.h>
#include <sstream>
#include <algorithm>

using std::stringstream;
using std::sort;
using std::for_each;

TskDbPostgreSQL::TskDbPostgreSQL(const TSK_TCHAR * a_dbFilePath, bool a_blkMapFlag)
    : TskDb(a_dbFilePath, a_blkMapFlag)
{
    conn = NULL;
    wcsncpy(m_dBName, a_dbFilePath, 256);
    m_blkMapFlag = a_blkMapFlag;
    setLogInInfo();
}

TskDbPostgreSQL::~TskDbPostgreSQL()
{
    if (conn) {
        PQfinish(conn);
        conn = NULL;
    }
}

TSK_RETVAL_ENUM TskDbPostgreSQL::setLogInInfo(){

    strncpy(userName, "postgres", sizeof(userName));
    strncpy(password, "simple41", sizeof(password));
    strncpy(hostIpAddr, "127.0.0.1", sizeof(hostIpAddr));
    strncpy(hostPort, "5432", sizeof(hostPort));
    return TSK_OK;
}

PGconn* TskDbPostgreSQL::connectToDatabase(TSK_TCHAR *dbName) {

    // Make a connection to postgres database server
    char connectionString[1024];
    // ELTODO: use char PQescapeLiteral for userName and password
    sprintf(connectionString, "user=%s password=%s dbname=%S hostaddr=%s port=%s", userName, password, dbName, hostIpAddr, hostPort);
    PGconn *dbConn = PQconnectdb(connectionString);

    // Check to see that the backend connection was successfully made 
    if (PQstatus(dbConn) != CONNECTION_OK)
    {
        ConnStatusType connStatus = PQstatus(dbConn);
        // ELTODO: replace printf with tsk_error_set_errstr. This will be done as part of implementing an equivalent to TskDbSqlite::attempt().
        printf("Connection to PostgreSQL database failed, %s", PQerrorMessage(conn));
        PQfinish(dbConn);
        return NULL;
    }
    return dbConn;
}


TSK_RETVAL_ENUM TskDbPostgreSQL::createDatabase(){

    TSK_RETVAL_ENUM result = TSK_OK;

    // Connect to PostgreSQL server first
    TSK_TCHAR defaultPostgresDb[32] = TEXT("postgres");
    PGconn *serverConn = connectToDatabase(&defaultPostgresDb[0]);
    if (!serverConn)
        return TSK_ERR;

    /* 
    http://www.postgresql.org/docs/9.4/static/manage-ag-templatedbs.html
    CREATE DATABASE actually works by copying an existing database. By default, it copies the standard system database named template1. 
    Thus that database is the "template" from which new databases are made. If you add objects to template1, these objects will be copied 
    into subsequently created user databases. This behavior allows site-local modifications to the standard set of objects in databases. 
    For example, if you install the procedural language PL/Perl in template1, it will automatically be available in user databases without 
    any extra action being taken when those databases are created.

    ELTODO: perhaps we should create a default template TSK database with all tables created and use that as template for creating new databases.
    This will require recognizing that a template might not exist (first time TSK is run with PostgreSQL) and creating it.
    */

    // IMPORTANT: PostgreSQL database names are case sensitive but ONLY if you surround the db name in double quotes.
    // If you use single quotes, PostgreSQL will convert db name to lower case. If database was created using double quotes 
    // you now need to always use double quotes when referring to it.
    char createDbString[512];
    sprintf(createDbString, "CREATE DATABASE \"%S\" WITH ENCODING='UTF8';", m_dBName);
    PGresult *res = PQexec(serverConn, createDbString);    
    if (PQresultStatus(res) != PGRES_COMMAND_OK)
    {
        printf("Database creation failed, %s", PQerrorMessage(conn));
        result = TSK_ERR;
    }

    PQclear(res);
    PQfinish(serverConn);
    return result;
}

/*
* Create or open the PostgreSQL database
* @param createDbFlag Set to true if this is a new database that needs to be created and have the tables created
* @ returns 1 on error and 0 on success
*/
int TskDbPostgreSQL::open(bool createDbFlag)
{
    if (createDbFlag) {
        // create new database first
        if (createDatabase() != TSK_OK) {
            printf("Unable to create database");
            return -1;
        }
    }

    // connect to existing database
    conn = connectToDatabase(&m_dBName[0]);
    if (!conn){
        printf("Database creation failed");
        return -1;
    }

    if (createDbFlag) {
        // initialize TSK tables
        initialize();
    }

    // ELTODO: delete this:
    //test();

    return 0;
}

/*
* Close PostgreSQL database.
* Return 0 on success, 1 on failure
*/
int TskDbPostgreSQL::close()
{
    // ELTODO need to surround this with try/catch. Otherwise if we close database second time an exception is thrown.
    if (conn) {
        PQfinish(conn);
        conn = NULL;
    }
    return 0;
}


bool TskDbPostgreSQL::dbExists() { 

    int numDb = 0;

    // Connect to PostgreSQL server first
    TSK_TCHAR defaultPostgresDb[32] = TEXT("postgres");
    PGconn *serverConn = connectToDatabase(&defaultPostgresDb[0]);
    if (!serverConn)
        return NULL;

    // Poll PostreSQL server for existing databases. 
    char selectString[512];
    sprintf(selectString, "select datname from pg_catalog.pg_database where datname = '%S';", m_dBName);

    PGresult *res = PQexec(serverConn, selectString);
    if (PQresultStatus(res) != PGRES_TUPLES_OK)
    {
        printf("Existing database lookup failed, %s", PQerrorMessage(conn));
        numDb = 0;
    } else {
        // number of existing databases that matched name (if search is case sensitive then max is 1)
        numDb = PQntuples(res);
    }

    PQclear(res);
    PQfinish(serverConn);

    if (numDb > 0)
        return true;

    return false;
}

/**
* Execute a statement and sets TSK error values on error 
* @returns 1 on error, 0 on success
*/
int TskDbPostgreSQL::attempt_exec(const char *sql, const char *errfmt)
{
    if (!conn)
        return 1;

    PGresult *res = PQexec(conn, sql); 
    // ELTODO: verify that there are no other acceptable return codes.
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        char * str = PQerrorMessage(conn);
        tsk_error_set_errstr(errfmt, PQerrorMessage(conn));
        PQclear(res);
        return 1;
    }
    PQclear(res);
    return 0;
}

/**
* Execute a statement and returns PostgreSQL result sets. Sets TSK error values on error.
* IMPORTANT: result set needs to be freed by caling PQclear(res) when no longer needed.
* @returns Result set on success, NULL on error
*/
PGresult* TskDbPostgreSQL::get_query_result_set(const char *sql, const char *errfmt)
{
    if (!conn)
        return NULL;

    PGresult *res = PQexec(conn, sql); 
    // ELTODO: verify that there are no other acceptable return codes. What about PGRES_EMPTY_QUERY?
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        char * str = PQerrorMessage(conn);
        tsk_error_set_errstr(errfmt, PQerrorMessage(conn));
        PQclear(res);
        return NULL;
    }
    return res;
}

/**
* Verifies if PGresult is valid and not empty. Frees result memory and sets TSK error values if result is invalid. 
* @returns true if result is valid and not empty, false if result is invalid or empty
*/
bool TskDbPostgreSQL::isQueryResultValid(PGresult *res, const char *errfmt)
{
    if (!res) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr(errfmt, "Result set pointer is NULL\n");
        return false;
    }

    if (!PQntuples(res)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr(errfmt, "No results returned for query\n");
        PQclear(res);
        return false;
    }
    return true;
}

int TskDbPostgreSQL::attempt(int resultCode, int expectedResultCode, const char *errfmt)
{
    if (resultCode != expectedResultCode) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr(errfmt, resultCode);
        return 1;
    }
    return 0;
}


int TskDbPostgreSQL::attempt(int resultCode, const char *errfmt)
{
    return attempt(resultCode, PGRES_COMMAND_OK, errfmt);
}

/** 
* Initialize the open DB: set PRAGMAs, create tables and indexes
* @returns 1 on error
*/
int TskDbPostgreSQL::initialize() { 

    char foo[1024];
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

    // ELTODO: SQLite determines appropriate num bytes to store int based on magnitude. PostgreSQL needs to be told byte size in advance! 
    // Need to adjust SQL statements below from INTEGER to appropriate format for each field.
    // http://www.postgresql.org/docs/current/interactive/datatype-numeric.html

    if (attempt_exec
        ("CREATE TABLE tsk_objects (obj_id BIGSERIAL PRIMARY KEY, par_obj_id BIGINT, type INTEGER NOT NULL);",
        "Error creating tsk_objects table: %s\n")
        ||
        attempt_exec
        ("CREATE TABLE tsk_image_info (obj_id BIGINT PRIMARY KEY, type INTEGER, ssize INTEGER, tzone TEXT, size BIGINT, md5 TEXT, display_name TEXT, FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id));",
        "Error creating tsk_image_info table: %s\n")
        ||
        attempt_exec
        ("CREATE TABLE tsk_image_names (obj_id BIGINT NOT NULL, name TEXT NOT NULL, sequence INTEGER NOT NULL, FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id));",
        "Error creating tsk_image_names table: %s\n")
        ||
        attempt_exec
        ("CREATE TABLE tsk_vs_info (obj_id BIGINT PRIMARY KEY, vs_type INTEGER NOT NULL, img_offset BIGINT NOT NULL, block_size BIGINT NOT NULL, FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id));",
        "Error creating tsk_vs_info table: %s\n")
        ||
        attempt_exec
        ("CREATE TABLE tsk_fs_info (obj_id BIGINT PRIMARY KEY, img_offset BIGINT NOT NULL, fs_type INTEGER NOT NULL, block_size BIGINT NOT NULL, block_count BIGINT NOT NULL, root_inum BIGINT NOT NULL, first_inum BIGINT NOT NULL, last_inum BIGINT NOT NULL, display_name TEXT, FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id));",
        "Error creating tsk_fs_info table: %s\n")
        ||
        attempt_exec
        ("CREATE TABLE tsk_files (obj_id BIGINT PRIMARY KEY, fs_obj_id BIGINT, attr_type INTEGER, attr_id INTEGER, name TEXT NOT NULL, meta_addr BIGINT, meta_seq BIGINT, type INTEGER, has_layout INTEGER, has_path INTEGER, dir_type INTEGER, meta_type INTEGER, dir_flags INTEGER, meta_flags INTEGER, size BIGINT, ctime BIGINT, crtime BIGINT, atime BIGINT, mtime BIGINT, mode INTEGER, uid INTEGER, gid INTEGER, md5 TEXT, known INTEGER, parent_path TEXT, "
        "FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id), FOREIGN KEY(fs_obj_id) REFERENCES tsk_fs_info(obj_id));",
        "Error creating tsk_files table: %s\n")
        ||
        attempt_exec
        ("CREATE TABLE tsk_files_path (obj_id BIGINT PRIMARY KEY, path TEXT NOT NULL, FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id))",
        "Error creating tsk_files_path table: %s\n")
        ||
        attempt_exec
        ("CREATE TABLE tsk_files_derived (obj_id BIGINT PRIMARY KEY, derived_id BIGINT NOT NULL, rederive TEXT, FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id))",
        "Error creating tsk_files_derived table: %s\n")
        ||
        attempt_exec
        ("CREATE TABLE tsk_files_derived_method (derived_id BIGINT PRIMARY KEY, tool_name TEXT NOT NULL, tool_version TEXT NOT NULL, other TEXT)",
        "Error creating tsk_files_derived_method table: %s\n")
        ||
        attempt_exec
        ("CREATE TABLE tag_names (tag_name_id BIGINT PRIMARY KEY, display_name TEXT UNIQUE, description TEXT NOT NULL, color TEXT NOT NULL)",
        "Error creating tag_names table: %s\n")
        ||
        attempt_exec
        ("CREATE TABLE content_tags (tag_id BIGINT PRIMARY KEY, obj_id BIGINT NOT NULL, tag_name_id BIGINT NOT NULL, comment TEXT NOT NULL, begin_byte_offset BIGINT NOT NULL, end_byte_offset BIGINT NOT NULL, "
        "FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id), FOREIGN KEY(tag_name_id) REFERENCES tag_names(tag_name_id))",
        "Error creating content_tags table: %s\n")
        ||
        attempt_exec
        ("CREATE TABLE blackboard_artifact_types (artifact_type_id BIGINT PRIMARY KEY, type_name TEXT NOT NULL, display_name TEXT)",
        "Error creating blackboard_artifact_types table: %s\n")
        ||
        attempt_exec
        ("CREATE TABLE blackboard_attribute_types (attribute_type_id BIGINT PRIMARY KEY, type_name TEXT NOT NULL, display_name TEXT)",
        "Error creating blackboard_attribute_types table: %s\n")
        ||
        attempt_exec
        ("CREATE TABLE blackboard_artifacts (artifact_id BIGINT PRIMARY KEY, obj_id BIGINT NOT NULL, artifact_type_id BIGINT NOT NULL, "
        "FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id), FOREIGN KEY(artifact_type_id) REFERENCES blackboard_artifact_types(artifact_type_id))",
        "Error creating blackboard_artifact table: %s\n")
        ||
        attempt_exec
        ("CREATE TABLE blackboard_artifact_tags (tag_id BIGINT PRIMARY KEY, artifact_id BIGINT NOT NULL, tag_name_id BIGINT NOT NULL, comment TEXT NOT NULL, "
        "FOREIGN KEY(artifact_id) REFERENCES blackboard_artifacts(artifact_id), FOREIGN KEY(tag_name_id) REFERENCES tag_names(tag_name_id))",
        "Error creating blackboard_artifact_tags table: %s\n")
        ||
        /* ELTODO: The binary representation of BYTEA is a bunch of bytes, which could
        * include embedded nulls so we have to pay attention to field length.
        * http://www.postgresql.org/docs/9.4/static/libpq-example.html
        */
        attempt_exec
        ("CREATE TABLE blackboard_attributes (artifact_id BIGINT NOT NULL, artifact_type_id BIGINT NOT NULL, source TEXT, context TEXT, attribute_type_id BIGINT NOT NULL, value_type INTEGER NOT NULL, "
        "value_byte BYTEA, value_text TEXT, value_int32 INTEGER, value_int64 BIGINT, value_double NUMERIC(20, 10), "
        "FOREIGN KEY(artifact_id) REFERENCES blackboard_artifacts(artifact_id), FOREIGN KEY(artifact_type_id) REFERENCES blackboard_artifact_types(artifact_type_id), FOREIGN KEY(attribute_type_id) REFERENCES blackboard_attribute_types(attribute_type_id))",
        "Error creating blackboard_attribute table: %s\n")
        ||
        /* In PostgreSQL "desc" indicates "descending order" so I had to rename "desc TEXT" to "descr TEXT" 
        ELTODO: make sure all insert queries have "descr". Should I also make this change for SQLite?*/
        attempt_exec
        ("CREATE TABLE tsk_vs_parts (obj_id BIGINT PRIMARY KEY, addr BIGINT NOT NULL, start BIGINT NOT NULL, length BIGINT NOT NULL, descr TEXT, flags INTEGER NOT NULL, FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id));",
        "Error creating tsk_vol_info table: %s\n")
        ||
        attempt_exec
        ("CREATE TABLE reports (report_id BIGINT PRIMARY KEY, path TEXT NOT NULL, crtime INTEGER NOT NULL, src_module_name TEXT NOT NULL, report_name TEXT NOT NULL)",
        "Error creating reports table: %s\n")) {
            return 1;
    }

    if (m_blkMapFlag) {
        if (attempt_exec
            ("CREATE TABLE tsk_file_layout (obj_id BIGINT NOT NULL, byte_start BIGINT NOT NULL, byte_len BIGINT NOT NULL, sequence INTEGER NOT NULL, FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id));",
            "Error creating tsk_fs_blocks table: %s\n")) {
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
int TskDbPostgreSQL::createIndexes()
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
        attempt_exec("CREATE INDEX artifact_typeID ON blackboard_artifacts(artifact_type_id);",
        "Error creating artifact_objID index on blackboard_artifacts: %s\n") ||
        attempt_exec("CREATE INDEX attrsArtifactID ON blackboard_attributes(artifact_id);",
        "Error creating artifact_id index on blackboard_attributes: %s\n") ;
    /*attempt_exec("CREATE INDEX attribute_artifactTypeId ON blackboard_attributes(artifact_type_id);",
    "Error creating artifact_type_id index on blackboard_attributes: %s\n");
    */
}


/**
* @returns TSK_ERR on error, 0 on success
*/
uint8_t TskDbPostgreSQL::addObject(TSK_DB_OBJECT_TYPE_ENUM type, int64_t parObjId, int64_t & objId)
{
    char stmt[1024];
    snprintf(stmt, 1024, "INSERT INTO tsk_objects (par_obj_id, type) VALUES (%" PRId64 ", %d) RETURNING obj_id", parObjId, type);

    PGresult *res = get_query_result_set(stmt, "TskDbPostgreSQL::addObj: Error adding object to row: %s (result code %d)\n");

    // check if a result set was returned
    if (!isQueryResultValid(res, "TskDbPostgreSQL::addObj: No result returned for INSERT INTO tsk_objects. Can't obtain objId\n")){
        return TSK_ERR;
    }

    // Returned value is objId
    objId = atoll(PQgetvalue(res, 0, 0));

    PQclear(res);
    return 0;
}


/**
* @returns 1 on error, 0 on success
*/
int TskDbPostgreSQL::addVsInfo(const TSK_VS_INFO * vs_info, int64_t parObjId, int64_t & objId)
{
    char stmt[1024];

    if (addObject(TSK_DB_OBJECT_TYPE_VS, parObjId, objId))
        return 1;

    snprintf(stmt, 1024, "INSERT INTO tsk_vs_info (obj_id, vs_type, img_offset, block_size) VALUES (%lld, %d,%"
        PRIuOFF ",%u)", objId, vs_info->vstype, vs_info->offset, vs_info->block_size);

    return attempt_exec(stmt, "Error adding data to tsk_vs_info table: %s\n");
}

/**
* Query tsk_vs_info with given id and returns TSK_DB_VS_INFO info entry
* @param objId vs id to query
* @param vsInfo (out) TSK_DB_VS_INFO entry representation to return
* @returns TSK_ERR on error (or if not found), TSK_OK on success
*/
TSK_RETVAL_ENUM TskDbPostgreSQL::getVsInfo(int64_t objId, TSK_DB_VS_INFO & vsInfo) {

    char stmt[1024];
    // ELTODO: note that for PostgreSQL we have to do "obj_id =" whereas for SQLite query is "obj_id IS"...
    snprintf(stmt, 1024, "SELECT obj_id, vs_type, img_offset, block_size FROM tsk_vs_info WHERE obj_id = %" PRId64 "", objId);

    PGresult *res = get_query_result_set(stmt, "TskDbPostgreSQL::getVsInfo: Error selecting object by objid: %s (result code %d)\n");

    // check if a result set was returned
    if (!isQueryResultValid(res, "TskDbPostgreSQL::getVsInfo: No result returned for SELECT FROM tsk_vs_info\n")){
        return TSK_ERR;
    }

    // ELTODO: use nFields = PQnfields(res); to verify number of fields in result
    // ELTODO: verify that atoi() handles unsigned int. IT DOESN'T! MUST USE ATOLL().
    // ELTODO: verify that atoll() handles uint64_t. Looks like it does. http://forums.codeguru.com/showthread.php?195538-Converting-string-to-UINT64
    vsInfo.objId = atoll(PQgetvalue(res, 0, 0));
    vsInfo.vstype = (TSK_VS_TYPE_ENUM)atoi(PQgetvalue(res, 0, 1));
    vsInfo.offset = atoll(PQgetvalue(res, 0, 2));
    vsInfo.block_size = (unsigned int)atoll(PQgetvalue(res, 0, 3));

    //cleanup
    PQclear(res);

    return TSK_OK;
}

/**
* deprecated
*/
int TskDbPostgreSQL::addImageInfo(int type, int size, int64_t & objId, const string & timezone)
{
    return addImageInfo(type, size, objId, timezone, 0, "");
}

/**
* @returns 1 on error, 0 on success
*/
int TskDbPostgreSQL::addImageInfo(int type, int ssize, int64_t & objId, const string & timezone, TSK_OFF_T size, const string &md5)
{
    char stmt[2048];
    int ret;

    // ELTODO: Verify this. SQLite code doesn't use addObject because we're passing in NULL as the parent
    if (addObject(TSK_DB_OBJECT_TYPE_IMG, NULL, objId)) {
        return 1;
    }

    // escape strings for use within an SQL command
    char *timezone_sql = PQescapeLiteral(conn, timezone.c_str(), strlen(timezone.c_str()));
    char *md5_sql = PQescapeLiteral(conn, md5.c_str(), strlen(md5.c_str()));
    snprintf(stmt, 2048, "INSERT INTO tsk_image_info (obj_id, type, ssize, tzone, size, md5) VALUES (%lld, %d, %d, %s, %"PRIuOFF", %s);",
        objId, type, ssize, timezone_sql, size, md5_sql);

    ret = attempt_exec(stmt, "Error adding data to tsk_image_info table: %s\n");

    // cleanup
    PQfreemem(timezone_sql);
    PQfreemem(md5_sql);
    return ret;
}

/**
* @returns 1 on error, 0 on success
*/
int TskDbPostgreSQL::addImageName(int64_t objId, char const *imgName, int sequence)
{
    char stmt[2048];
    int ret;

    char *imgName_sql = PQescapeLiteral(conn, imgName, strlen(imgName));
    snprintf(stmt, 2048, "INSERT INTO tsk_image_names (obj_id, name, sequence) VALUES (%lld, %s, %d)", objId, imgName_sql, sequence);
    ret = attempt_exec(stmt, "Error adding data to tsk_image_names table: %s\n");

    // cleanup
    PQfreemem(imgName_sql);

    return ret;
}


/**
* @returns 1 on error, 0 on success
*/
int TskDbPostgreSQL::addFsInfo(const TSK_FS_INFO * fs_info, int64_t parObjId, int64_t & objId)
{
    char stmt[1024];

    if (addObject(TSK_DB_OBJECT_TYPE_FS, parObjId, objId))
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

    return attempt_exec(stmt, "Error adding data to tsk_fs_info table: %s\n");
}

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
int TskDbPostgreSQL::addFsFile(TSK_FS_FILE * fs_file,
    const TSK_FS_ATTR * fs_attr, const char *path,
    const unsigned char *const md5, const TSK_DB_FILES_KNOWN_ENUM known,
    int64_t fsObjId, int64_t & objId)
{
    int64_t parObjId = 0;

    if (fs_file->name == NULL)
        return 0;

    /* we want the root directory to have its parent be the file system
    * object.  We need to have special care though because the ".." entries
    * in sub-folders of the root directory have a meta_addr of the root dir. */
    if ((fs_file->fs_info->root_inum == fs_file->name->meta_addr) && 
        ((fs_file->name->name == NULL) || (0 == TSK_FS_ISDOT(fs_file->name->name)))) {
            // this entry is for root directory
            parObjId = fsObjId;
    }
    else {
        parObjId = findParObjId(fs_file, path, fsObjId);
        if (parObjId == -1) {
            //error
            return 1;
        }    
    }

    return addFile(fs_file, fs_attr, path, md5, known, fsObjId, parObjId, objId);
}

/**
* Add file data to the file table
* @param md5 binary value of MD5 (i.e. 16 bytes) or NULL
* Return 0 on success, 1 on error.
*/
int TskDbPostgreSQL::addFile(TSK_FS_FILE * fs_file, const TSK_FS_ATTR * fs_attr, const char *path,
    const unsigned char *const md5, const TSK_DB_FILES_KNOWN_ENUM known, int64_t fsObjId, int64_t parObjId, int64_t & objId)
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

    if (fs_file->name == NULL)
        return 0;

    if (fs_file->meta) {
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
    if (fs_attr) {
        type = fs_attr->type;
        idx = fs_attr->id;
        size = fs_attr->size;
        if (fs_attr->name) {
            if ((fs_attr->type != TSK_FS_ATTR_TYPE_NTFS_IDXROOT) ||
                (strcmp(fs_attr->name, "$I30") != 0)) {
                    attr_nlen = strlen(fs_attr->name);
            }
        }
    }

    // combine name and attribute name
    size_t len = strlen(fs_file->name->name);
    char *name;
    size_t nlen = len + attr_nlen + 5;
    if ((name = (char *) tsk_malloc(nlen)) == NULL) {
        return 1;
    }

    strncpy(name, fs_file->name->name, nlen);

    // Add the attribute name
    if (attr_nlen > 0) {
        strncat(name, ":", nlen-strlen(name));
        strncat(name, fs_attr->name, nlen-strlen(name));
    }

    // clean up path
    // +2 = space for leading slash and terminating null
    size_t path_len = strlen(path) + 2;
    char *escaped_path;
    if ((escaped_path = (char *) tsk_malloc(path_len)) == NULL) { 
        free(name);
        return 1;
    }

    strncpy(escaped_path, "/", path_len);
    strncat(escaped_path, path, path_len - strlen(escaped_path));

    char *md5TextPtr = NULL;
    char md5Text[48];

    // if md5 hashes are being used
    if (md5 != NULL) {
        // copy the hash as hexidecimal into the buffer
        for (int i = 0; i < 16; i++) {
            sprintf(&(md5Text[i*2]), "%x%x", (md5[i] >> 4) & 0xf,
                md5[i] & 0xf);
        }
        md5TextPtr = md5Text;
    }


    if (addObject(TSK_DB_OBJECT_TYPE_FILE, parObjId, objId)) {
        free(name);
        free(escaped_path);
        return 1;
    }

    // escape strings for use within an SQL command
    char *name_sql = PQescapeLiteral(conn, name, strlen(name));
    char *escaped_path_sql = PQescapeLiteral(conn, escaped_path, strlen(escaped_path));
    char nullStr[8] = "NULL";
    if (!md5TextPtr) {
        md5TextPtr = &nullStr[0];
    }
    char *md5TextPtr_sql = PQescapeLiteral(conn, md5TextPtr, strlen(md5TextPtr));

    char zSQL[2048];
    snprintf(zSQL, 2048, "INSERT INTO tsk_files (fs_obj_id, obj_id, type, attr_type, attr_id, name, meta_addr, meta_seq, dir_type, meta_type, dir_flags, meta_flags, size, crtime, ctime, atime, mtime, mode, gid, uid, md5, known, parent_path) "
        "VALUES ("
        "%" PRId64 ",%" PRId64 ","
        "%d,"
        "%d,%d,%s,"
        "%" PRIuINUM ",%d,"
        "%d,%d,%d,%d,"
        "%" PRIuOFF ","
        "%llu,%llu,%llu,%llu,"
        "%d,%d,%d,%s,%d,"
        "%s)",
        fsObjId, objId,
        TSK_DB_FILES_TYPE_FS,
        type, idx, name_sql,
        fs_file->name->meta_addr, fs_file->name->meta_seq, 
        fs_file->name->type, meta_type, fs_file->name->flags, meta_flags,
        size, 
        (unsigned long long)crtime, (unsigned long long)ctime,(unsigned long long) atime,(unsigned long long) mtime, 
        meta_mode, gid, uid, md5TextPtr_sql, known,
        escaped_path_sql);

    if (attempt_exec(zSQL, "TskDbPostgreSQL::addFile: Error adding data to tsk_files table: %s\n")) {
        free(name);
        free(escaped_path);
        PQfreemem(name_sql);
        PQfreemem(escaped_path_sql);
        PQfreemem(md5TextPtr_sql);
        return 1;
    }

    //if dir, update parent id cache
    if (meta_type == TSK_FS_META_TYPE_DIR) {
        std::string fullPath = std::string(path) + fs_file->name->name;
        storeObjId(fsObjId, fs_file, fullPath.c_str(), objId);
    }

    // cleanup
    free(name);
    free(escaped_path);
    PQfreemem(name_sql);
    PQfreemem(escaped_path_sql);
    PQfreemem(md5TextPtr_sql);

    return 0;
}


/**
* Find parent object id of TSK_FS_FILE. Use local cache map, if not found, fall back to SQL
* @param fs_file file to find parent obj id for
* @param path Path of parent folder that we want to match
* @param fsObjId fs id of this file
* @returns parent obj id ( > 0), -1 on error
*/
int64_t TskDbPostgreSQL::findParObjId(const TSK_FS_FILE * fs_file, const char *path, const int64_t & fsObjId) {
    uint32_t seq;
    /* NTFS uses sequence, otherwise we hash the path. We do this to map to the
    * correct parent folder if there are two from the root dir that eventually point to
    * the same folder (one deleted and one allocated) or two hard links. */
    if (TSK_FS_TYPE_ISNTFS(fs_file->fs_info->ftype)) {
        seq = fs_file->name->par_seq;
    }
    else {
        seq = hash((const unsigned char *)path);
    }

    //get from cache by parent meta addr, if available
    map<TSK_INUM_T, map<uint32_t, int64_t> > &fsMap = m_parentDirIdCache[fsObjId];
    if (fsMap.count(fs_file->name->par_addr) > 0) {
        map<uint32_t, int64_t>  &fileMap = fsMap[fs_file->name->par_addr];
        if (fileMap.count(seq) > 0) {
            return fileMap[seq];
        }
        else {
            printf("Miss: %d\n", fileMap.count(seq));
        }
    }

    fprintf(stderr, "Miss: %s (%"PRIu64")\n", fs_file->name->name, fs_file->name->meta_addr);

    // Find the parent file id in the database using the parent metadata address
    // @@@ This should use sequence number when the new database supports it

    // ELTODO: use m_selectFilePreparedStmt prepared statement instead

    char zSQL[1024];
    // ELTODO: verify that using "=" instead of "IS ?" is equivalent
    snprintf(zSQL, 1024, "SELECT obj_id FROM tsk_files WHERE meta_addr = %" PRIu64 " AND fs_obj_id = %" PRId64 "", fs_file->name->par_addr, fsObjId);
    PGresult* res = get_query_result_set(zSQL, "TskDbPostgreSQL::findParObjId: Error selecting file id by meta_addr: %s (result code %d)\n");

    // check if a result set was returned
    if (!isQueryResultValid(res, "TskDbPostgreSQL::findParObjId: No result returned for SELECT obj_id. Can't obtain parObjId\n")){
        return TSK_ERR;
    }

    int64_t parObjId = atoll(PQgetvalue(res, 0, 0));
    PQclear(res);
    return parObjId;
}

/**
* return a hash of the passed in string. We use this
* for full paths. 
* From: http://www.cse.yorku.ca/~oz/hash.html
*/
uint32_t TskDbPostgreSQL::hash(const unsigned char *str) {
    uint32_t hash = 5381;
    int c;

    while ((c = *str++)) {
        // skip slashes -> normalizes leading/ending/double slashes
        if (c == '/')
            continue;
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }

    return hash;
}

/**
* Store meta_addr to object id mapping of the directory in a local cache map
* @param fsObjId fs id of this directory
* @param fs_file File for the directory to store
* @param path Full path (parent and this file) of this directory
* @param objId object id of this directory from the objects table
*/
void TskDbPostgreSQL::storeObjId(const int64_t & fsObjId, const TSK_FS_FILE *fs_file, const char *path, const int64_t & objId) {
    // skip the . and .. entries
    if ((fs_file->name) && (fs_file->name->name) && (TSK_FS_ISDOT(fs_file->name->name))) {
        return;
    }

    uint32_t seq;
    /* NTFS uses sequence, otherwise we hash the path. We do this to map to the
    * correct parent folder if there are two from the root dir that eventually point to
    * the same folder (one deleted and one allocated) or two hard links. */
    if (TSK_FS_TYPE_ISNTFS(fs_file->fs_info->ftype)) {
        /* Use the sequence stored in meta (which could be one larger than the name value
        * if the directory is deleted. We do this because the par_seq gets added to the
        * name structure when it is added to the directory based on teh value stored in 
        * meta. */
        seq = fs_file->meta->seq;
    }
    else {
        seq = hash((const unsigned char *)path);
    }

    map<TSK_INUM_T, map<uint32_t, int64_t> > &fsMap = m_parentDirIdCache[fsObjId];
    if (fsMap.count(fs_file->name->meta_addr) == 0) {
        fsMap[fs_file->name->meta_addr][seq] = objId;
    }
    else {
        map<uint32_t, int64_t> &fileMap = fsMap[fs_file->name->meta_addr];
        if (fileMap.count(seq) == 0) {
            fileMap[seq] = objId;
        }
    }
}


/**
* Query tsk_fs_info and return rows for every entry in tsk_fs_info table
* @param imgId the object id of the image to get filesystems for
* @param fsInfos (out) TSK_DB_FS_INFO row representations to return
* @returns TSK_ERR on error, TSK_OK on success
*/
TSK_RETVAL_ENUM TskDbPostgreSQL::getFsInfos(int64_t imgId, vector<TSK_DB_FS_INFO> & fsInfos) {

    // ELTODO: use prepared statement here
    char zSQL[1024];
    snprintf(zSQL, 1024,"SELECT obj_id, img_offset, fs_type, block_size, block_count, root_inum, first_inum, last_inum FROM tsk_fs_info");
    PGresult* res = get_query_result_set(zSQL, "TskDbPostgreSQL::getFsInfos: Error selecting from tsk_fs_info: %s (result code %d)\n");

    // check if a result set was returned
    if (!isQueryResultValid(res, "TskDbPostgreSQL::getFsInfos: No result returned for SELECT obj_id FROM tsk_fs_info\n")){
        return TSK_ERR;
    }

    //get rows
    TSK_DB_FS_INFO rowData;
    for (int i = 0; i < PQntuples(res); i++) {
        int64_t fsObjId = atoll(PQgetvalue(res, i, 0));

        //ensure fs is (sub)child of the image requested, if not, skip it
        int64_t curImgId = 0;
        if (getParentImageId(fsObjId, curImgId) == TSK_ERR) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_AUTO_DB);
            tsk_error_set_errstr("Error finding parent for: %"PRIu64, fsObjId);
            return TSK_ERR;
        }

        if (imgId != curImgId) {
            continue;
        }

        rowData.objId = fsObjId;
        rowData.imgOffset = atoll(PQgetvalue(res, i, 1));
        rowData.fType = (TSK_FS_TYPE_ENUM)atoi(PQgetvalue(res, i, 2));
        rowData.block_size = (unsigned int)atoll(PQgetvalue(res, i, 3));
        rowData.block_count = atoll(PQgetvalue(res, i, 4));
        rowData.root_inum = atoll(PQgetvalue(res, i, 5));
        rowData.first_inum = atoll(PQgetvalue(res, i, 6));
        rowData.last_inum = atoll(PQgetvalue(res, i, 7));

        //insert a copy of the rowData
        fsInfos.push_back(rowData);
    }

    //cleanup
    PQclear(res);

    return TSK_OK;
}


/**
* Query tsk_objects to find the root image id for the object
* @param objId (in) object id to query
* @param imageId (out) root parent image id returned
* @returns TSK_ERR on error (or if not found), TSK_OK on success
*/
TSK_RETVAL_ENUM TskDbPostgreSQL::getParentImageId(const int64_t objId, int64_t & imageId) {
    TSK_DB_OBJECT objectInfo;
    TSK_RETVAL_ENUM ret = TSK_ERR;

    int64_t queryObjectId = objId;
    while (getObjectInfo(queryObjectId, objectInfo) == TSK_OK) {
        if (objectInfo.parObjId == 0) {
            //found root image
            imageId = objectInfo.objId;
            ret = TSK_OK;
            break;
        }
        else {
            //advance
            queryObjectId = objectInfo.parObjId;
        }
    }

    return ret;

}

/**
* Query tsk_objects with given id and returns object info entry
* @param objId object id to query
* @param objectInfo (out) TSK_DB_OBJECT entry representation to return
* @returns TSK_ERR on error (or if not found), TSK_OK on success
*/
TSK_RETVAL_ENUM TskDbPostgreSQL::getObjectInfo(int64_t objId, TSK_DB_OBJECT & objectInfo) {

    // ELTODO: use objectsStatement prepared statement instead

    char zSQL[1024];
    // ELTODO: verify that using "=" instead of "IS ?" is equivalent
    snprintf(zSQL, 1024, "SELECT obj_id, par_obj_id, type FROM tsk_objects WHERE obj_id = %" PRId64 "", objId);

    PGresult* res = get_query_result_set(zSQL, "TskDbPostgreSQL::getObjectInfo: Error selecting object by objid: %s (result code %d)\n");

    // check if a result set was returned
    if (!isQueryResultValid(res, "TskDbPostgreSQL::getObjectInfo: No result returned for SELECT FROM tsk_objects\n")){
        return TSK_ERR;
    }

    // ELTODO: use nFields = PQnfields(res); to verify number of fields in result
    int nFields = PQnfields(res);
    objectInfo.objId = atoll(PQgetvalue(res, 0, 0));
    objectInfo.parObjId = atoll(PQgetvalue(res, 0, 1));
    objectInfo.type = (TSK_DB_OBJECT_TYPE_ENUM) atoi(PQgetvalue(res, 0, 2));

    //cleanup
    PQclear(res);

    return TSK_OK;
}


/**
* Add virtual dir of type TSK_DB_FILES_TYPE_VIRTUAL_DIR
* that can be a parent of other non-fs virtual files or directories, to organize them
* @param fsObjId (in) file system object id to associate with the virtual directory.
* @param parentDirId (in) parent dir object id of the new directory: either another virtual directory or root fs directory
* @param name name (int) of the new virtual directory
* @param objId (out) object id of the created virtual directory object
* @returns TSK_ERR on error or TSK_OK on success
*/
TSK_RETVAL_ENUM TskDbPostgreSQL::addVirtualDir(const int64_t fsObjId, const int64_t parentDirId, const char * const name, int64_t & objId) {
    char zSQL[2048];

    if (addObject(TSK_DB_OBJECT_TYPE_FILE, parentDirId, objId))
        return TSK_ERR;

    // escape strings for use within an SQL command
    char *name_sql = PQescapeLiteral(conn, name, strlen(name));

    snprintf(zSQL, 2048, "INSERT INTO tsk_files (attr_type, attr_id, has_layout, fs_obj_id, obj_id, type, attr_type, "
        "attr_id, name, meta_addr, meta_seq, dir_type, meta_type, dir_flags, meta_flags, size, "
        "crtime, ctime, atime, mtime, mode, gid, uid, known, parent_path) "
        "VALUES ("
        "NULL, NULL,"
        "NULL,"
        "%lld,"
        "%lld,"
        "%d,"
        "NULL,NULL,%s,"
        "NULL,NULL,"
        "%d,%d,%d,%d,"
        "0,"
        "NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,'/')",
        fsObjId,
        objId,
        TSK_DB_FILES_TYPE_VIRTUAL_DIR,
        name_sql,
        TSK_FS_NAME_TYPE_DIR, TSK_FS_META_TYPE_DIR,
        TSK_FS_NAME_FLAG_ALLOC, (TSK_FS_META_FLAG_ALLOC | TSK_FS_META_FLAG_USED));

    if (attempt_exec(zSQL, "Error adding data to tsk_files table: %s\n")) {
        PQfreemem(name_sql);
        return TSK_ERR;
    }

    //cleanup
    PQfreemem(name_sql);

    return TSK_OK;
}

/**
* Internal helper method to add a virtual root dir, a parent dir of files representing unalloc space within fs.
* The dir has is associated with its root dir parent for the fs.
* @param fsObjId (in) fs id to find root dir for and create $Unalloc dir for
* @param objId (out) object id of the $Unalloc dir created
* @returns TSK_ERR on error or TSK_OK on success
*/
TSK_RETVAL_ENUM TskDbPostgreSQL::addUnallocFsBlockFilesParent(const int64_t fsObjId, int64_t & objId) {

    const char * const unallocDirName = "$Unalloc";

    //get root dir
    TSK_DB_OBJECT rootDirObjInfo;
    if (getFsRootDirObjectInfo(fsObjId, rootDirObjInfo) == TSK_ERR) {
        return TSK_ERR;
    }

    return addVirtualDir(fsObjId, rootDirObjInfo.objId, unallocDirName, objId);
}

//internal function object to check for range overlap
typedef struct _checkFileLayoutRangeOverlap{
    const vector<TSK_DB_FILE_LAYOUT_RANGE> & ranges;
    bool hasOverlap;

    _checkFileLayoutRangeOverlap(const vector<TSK_DB_FILE_LAYOUT_RANGE> & ranges)
        : ranges(ranges),hasOverlap(false) {}

    bool getHasOverlap() const { return hasOverlap; }
    void operator() (const TSK_DB_FILE_LAYOUT_RANGE & range)  {
        if (hasOverlap)
            return; //no need to check other

        uint64_t start = range.byteStart;
        uint64_t end = start + range.byteLen;

        vector<TSK_DB_FILE_LAYOUT_RANGE>::const_iterator it;
        for (it = ranges.begin(); it != ranges.end(); ++it) {
            const TSK_DB_FILE_LAYOUT_RANGE * otherRange = &(*it);
            if (&range == otherRange)
                continue; //skip, it's the same range
            uint64_t otherStart = otherRange->byteStart;
            uint64_t otherEnd = otherStart + otherRange->byteLen;
            if (start <= otherEnd && end >= otherStart) {
                hasOverlap = true;
                break;
            }       
        }
    }

} checkFileLayoutRangeOverlap;

/**
* Adds information about a unallocated file with layout ranges into the database.
* Adds a single entry to tsk_files table with an auto-generated file name, tsk_objects table, and one or more entries to tsk_file_layout table
* @param parentObjId Id of the parent object in the database (fs, volume, or image)
* @param fsObjId parent fs, or NULL if the file is not associated with fs
* @param size Number of bytes in file
* @param ranges vector containing one or more TSK_DB_FILE_LAYOUT_RANGE layout ranges (in)
* @param objId object id of the file object created (output)
* @returns TSK_OK on success or TSK_ERR on error.
*/
TSK_RETVAL_ENUM TskDbPostgreSQL::addUnallocBlockFile(const int64_t parentObjId, const int64_t fsObjId, const uint64_t size, vector<TSK_DB_FILE_LAYOUT_RANGE> & ranges, int64_t & objId) {
    return addFileWithLayoutRange(TSK_DB_FILES_TYPE_UNALLOC_BLOCKS, parentObjId, fsObjId, size, ranges, objId);
}

/**
* Adds information about a unused file with layout ranges into the database.
* Adds a single entry to tsk_files table with an auto-generated file name, tsk_objects table, and one or more entries to tsk_file_layout table
* @param parentObjId Id of the parent object in the database (fs, volume, or image)
* @param fsObjId parent fs, or NULL if the file is not associated with fs
* @param size Number of bytes in file
* @param ranges vector containing one or more TSK_DB_FILE_LAYOUT_RANGE layout ranges (in)
* @param objId object id of the file object created (output)
* @returns TSK_OK on success or TSK_ERR on error.
*/
TSK_RETVAL_ENUM TskDbPostgreSQL::addUnusedBlockFile(const int64_t parentObjId, const int64_t fsObjId, const uint64_t size, vector<TSK_DB_FILE_LAYOUT_RANGE> & ranges, int64_t & objId) {
    return addFileWithLayoutRange(TSK_DB_FILES_TYPE_UNUSED_BLOCKS, parentObjId, fsObjId, size, ranges, objId);
}

/**
* Adds information about a carved file with layout ranges into the database.
* Adds a single entry to tsk_files table with an auto-generated file name, tsk_objects table, and one or more entries to tsk_file_layout table
* @param parentObjId Id of the parent object in the database (fs, volume, or image)
* @param fsObjId fs id associated with the file, or NULL
* @param size Number of bytes in file
* @param ranges vector containing one or more TSK_DB_FILE_LAYOUT_RANGE layout ranges (in)
* @param objId object id of the file object created (output)
* @returns TSK_OK on success or TSK_ERR on error.
*/
TSK_RETVAL_ENUM TskDbPostgreSQL::addCarvedFile(const int64_t parentObjId, const int64_t fsObjId, const uint64_t size, vector<TSK_DB_FILE_LAYOUT_RANGE> & ranges, int64_t & objId) {
    return addFileWithLayoutRange(TSK_DB_FILES_TYPE_CARVED, parentObjId, fsObjId, size, ranges, objId);
}

/**
* Internal helper method to add unalloc, unused and carved files with layout ranges to db
* Generates file_name and populates tsk_files, tsk_objects and tsk_file_layout tables
* @returns TSK_ERR on error or TSK_OK on success
*/
TSK_RETVAL_ENUM TskDbPostgreSQL::addFileWithLayoutRange(const TSK_DB_FILES_TYPE_ENUM dbFileType, const int64_t parentObjId, const int64_t fsObjId, const uint64_t size, vector<TSK_DB_FILE_LAYOUT_RANGE> & ranges, int64_t & objId) {
    const size_t numRanges = ranges.size();

    if (numRanges < 1) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr("Error addFileWithLayoutRange() - no ranges present");
        return TSK_ERR;
    }

    stringstream fileNameSs;
    switch (dbFileType) {
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
        sserr << (int) dbFileType;
        tsk_error_set_errstr("%s", sserr.str().c_str());
        return TSK_ERR;
    }

    //ensure layout ranges are sorted (to generate file name and to be inserted in sequence order)
    sort(ranges.begin(), ranges.end());

    //dome some checking
    //ensure there is no overlap and each range has unique byte range
    const checkFileLayoutRangeOverlap & overlapRes = 
        for_each(ranges.begin(), ranges.end(), checkFileLayoutRangeOverlap(ranges));
    if (overlapRes.getHasOverlap() ) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr("Error addFileWithLayoutRange() - overlap detected between ranges");
        return TSK_ERR;
    }

    //construct filename with parent obj id, start byte of first range, end byte of last range
    fileNameSs << "_" << parentObjId << "_" << ranges[0].byteStart;
    fileNameSs << "_" << (ranges[numRanges-1].byteStart + ranges[numRanges-1].byteLen);

    //insert into tsk files and tsk objects
    if (addLayoutFileInfo(parentObjId, fsObjId, dbFileType, fileNameSs.str().c_str(), size, objId) ) {
        return TSK_ERR;
    }

    //fill in fileObjId and insert ranges
    for (vector<TSK_DB_FILE_LAYOUT_RANGE>::iterator it = ranges.begin();
        it != ranges.end(); ++it) {
            TSK_DB_FILE_LAYOUT_RANGE & range = *it;
            range.fileObjId = objId;
            if (this->addFileLayoutRange(range) ) {
                return TSK_ERR;
            }
    }

    return TSK_OK;
}

/**
* Adds entry for to tsk_files for a layout file into the database.
* @param parObjId parent obj id in the database
* @param fsObjId fs obj id in the database, or 0 if parent it not fs (NULL)
* @param dbFileType type (unallocated, carved, unused)
* @param fileName file name for the layout file
* @param size Number of bytes in file
* @param objId layout file Id (output)
* @returns TSK_OK on success or TSK_ERR on error.
*/
TSK_RETVAL_ENUM TskDbPostgreSQL::addLayoutFileInfo(const int64_t parObjId, const int64_t fsObjId, const TSK_DB_FILES_TYPE_ENUM dbFileType, const char *fileName,
    const uint64_t size, int64_t & objId)
{
    char zSQL[2048];

    if (addObject(TSK_DB_OBJECT_TYPE_FILE, parObjId, objId))
        return TSK_ERR;

    //fsObjId can be NULL
    char *fsObjIdStrPtr = NULL;
    char fsObjIdStr[32];
    if (fsObjId != 0) {
        snprintf(fsObjIdStr, 32, "%"PRIu64, fsObjId);
        fsObjIdStrPtr = fsObjIdStr;
    }

    // escape strings for use within an SQL command
    char *name_sql = PQescapeLiteral(conn, fileName, strlen(fileName));
    char *fsObjIdStrPtr_sql = PQescapeLiteral(conn, fsObjIdStrPtr, strlen(fsObjIdStrPtr));

    snprintf(zSQL, 2048, "INSERT INTO tsk_files (has_layout, fs_obj_id, obj_id, type, attr_type, attr_id, name, meta_addr, meta_seq, dir_type, meta_type, dir_flags, meta_flags, size, crtime, ctime, atime, mtime, mode, gid, uid) "
        "VALUES ("
        "1, %s, %lld,"
        "%d,"
        "NULL,NULL,%s,"
        "NULL,NULL,"
        "%d,%d,%d,%d,"
        "%" PRIuOFF ","
        "NULL,NULL,NULL,NULL,NULL,NULL,NULL)",
        fsObjIdStrPtr_sql, objId,
        dbFileType,
        name_sql,
        TSK_FS_NAME_TYPE_REG, TSK_FS_META_TYPE_REG,
        TSK_FS_NAME_FLAG_UNALLOC, TSK_FS_META_FLAG_UNALLOC, size);

    if (attempt_exec(zSQL, "TskDbSqlite::addLayoutFileInfo: Error adding data to tsk_files table: %s\n")) {
        PQfreemem(name_sql);
        PQfreemem(fsObjIdStrPtr_sql);
        return TSK_ERR;
    }

    //cleanup
    PQfreemem(name_sql);
    PQfreemem(fsObjIdStrPtr_sql);

    return TSK_OK;
}


// ELTODO: delete this test code
void TskDbPostgreSQL::test()
{
    TSK_VS_INFO vsInfo;
    vsInfo.tag = 20;
    vsInfo.img_info = (TSK_IMG_INFO *)21;
    vsInfo.block_size = 22;
    vsInfo.vstype = TSK_VS_TYPE_BSD;        ///< Type of volume system / media management
    vsInfo.offset = 23;     ///< Byte offset where VS starts in disk image
    vsInfo.endian = TSK_BIG_ENDIAN; ///< Endian ordering of data
    vsInfo.part_list = (TSK_VS_PART_INFO *)24;    ///< Linked list of partitions
    vsInfo.part_count = 25;  ///< number of partitions 

    int64_t objId;
    const std::string timezone = "America/New York";
    const std::string md5 = "";
    int error = addImageInfo(1, 512, objId, timezone, 2097152, md5);

    int max = (unsigned int)-1;
    char largeNum[32] = "44294967296";
    int64_t largeNumInt = atoll(largeNum);
    __int64 largeNumInt2 = _atoi64(largeNum);
    const std::string timezone2 = "That's America/New York";
    const std::string md52 = "C:\\Temp";
    error = addImageInfo(1, 512, objId, timezone2, 2097152, md52);


    //    int64_t parObjId = 2;
    int64_t parObjId = 444294967296;

    error = addVsInfo(&vsInfo, parObjId, objId);
    TSK_DB_VS_INFO vsInfoRes;
    getVsInfo(1, vsInfoRes);

    TSK_DB_OBJECT objectInfo;
    TSK_RETVAL_ENUM ret = getObjectInfo(objId, objectInfo);

    // insert files
    addObject(TSK_DB_OBJECT_TYPE_VS, 2, objId);    
    char zSQL[2048];
    snprintf(zSQL, 2048, "INSERT INTO tsk_fs_info (obj_id, img_offset, fs_type, block_size, block_count, root_inum, first_inum, last_inum) VALUES (2,0,2,512,4096,2,2,65430)");
    if (attempt_exec(zSQL, "TskDbPostgreSQL::INSERT INTO tsk_fs_info\n")) {
        return;
    }

    //Ln 859: addObject() - parObjId=2, type=TSK_DB_OBJECT_TYPE_FILE. objId = 3;
    addObject(TSK_DB_OBJECT_TYPE_VS, 2, objId);
    snprintf(zSQL, 2048, "INSERT INTO tsk_files (fs_obj_id, obj_id, type, attr_type, attr_id, name, meta_addr, meta_seq, dir_type, meta_type, dir_flags, meta_flags, size, crtime, ctime, atime, mtime, mode, gid, uid, md5, known, parent_path) VALUES (2,3,0,1,0,'',2,0,3,2,1,5,16384,0,0,0,0,0,0,0,NULL,0,'/')");
    if (attempt_exec(zSQL, "TskDbPostgreSQL::INSERT INTO tsk_files\n")) {
        return;
    }

    //Ln 859: addObject() - parObjId=3, type=TSK_DB_OBJECT_TYPE_FILE. objId = 4;
    addObject(TSK_DB_OBJECT_TYPE_VS, 3, objId);
    snprintf(zSQL, 2048, "INSERT INTO tsk_files (fs_obj_id, obj_id, type, attr_type, attr_id, name, meta_addr, meta_seq, dir_type, meta_type, dir_flags, meta_flags, size, crtime, ctime, atime, mtime, mode, gid, uid, md5, known, parent_path) VALUES (2,4,0,1,0,'test.txt',4,0,5,1,1,1,6,1181684630,0,1181620800,1181684630,511,0,0,NULL,0,'/')");
    if (attempt_exec(zSQL, "TskDbPostgreSQL::INSERT INTO tsk_files\n")) {
        return;
    }
    //Ln 859: addObject() - parObjId=3, type=TSK_DB_OBJECT_TYPE_FILE. objId = 5;
    addObject(TSK_DB_OBJECT_TYPE_VS, 3, objId);
    snprintf(zSQL, 2048, "INSERT INTO tsk_files (fs_obj_id, obj_id, type, attr_type, attr_id, name, meta_addr, meta_seq, dir_type, meta_type, dir_flags, meta_flags, size, crtime, ctime, atime, mtime, mode, gid, uid, md5, known, parent_path) VALUES (2,5,0,1,0,'$MBR',65427,0,10,10,1,5,512,0,0,0,0,0,0,0,NULL,0,'/')");
    if (attempt_exec(zSQL, "TskDbPostgreSQL::INSERT INTO tsk_files\n")) {
        return;
    }

    for (int indx = 3; indx <=5; indx++) {
        // ELTODO: note that for PostgreSQL we have to do "obj_id =" whereas for SQLite query is "obj_id IS"...
        snprintf(zSQL, 1024, "SELECT fs_obj_id, obj_id, type, attr_type, attr_id, name, meta_addr, meta_seq, dir_type, meta_type, dir_flags, meta_flags, size, crtime, ctime, atime, mtime, mode, gid, uid, md5, known, parent_path FROM tsk_files WHERE obj_id = %d", indx);
        PGresult *res = PQexec(conn, zSQL);
        if (PQresultStatus(res) != PGRES_TUPLES_OK) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_AUTO_DB);
            char * str = PQerrorMessage(conn);
            tsk_error_set_errstr("TskDbPostgreSQL::getVsInfo: Error selecting object by objid: %s (result code %d)\n", PQerrorMessage(conn));
            PQclear(res);
            continue;
        }

        int numResults = PQntuples(res);
        int fs_obj_id = atoi(PQgetvalue(res, 0, 0));         
        int obj_id = atoi(PQgetvalue(res, 0, 1)); 
        int type  = atoi(PQgetvalue(res, 0, 2));      
        int attr_type = atoi(PQgetvalue(res, 0, 3));  
        int attr_id = atoi(PQgetvalue(res, 0, 4));  
        char* name = PQgetvalue(res, 0, 5); 
        int meta_addr = atoi(PQgetvalue(res, 0, 6)); 
        int meta_seq = atoi(PQgetvalue(res, 0, 7)); 
        int dir_type  = atoi(PQgetvalue(res, 0, 8)); 
        int meta_type = atoi(PQgetvalue(res, 0, 9)); 
        int dir_flags = atoi(PQgetvalue(res, 0, 10)); 
        int meta_flags = atoi(PQgetvalue(res, 0, 11));
        int size = atoi(PQgetvalue(res, 0, 12)); 
        int crtime = atoi(PQgetvalue(res, 0, 13));
        int ctime = atoi(PQgetvalue(res, 0, 14)); 
        int atime = atoi(PQgetvalue(res, 0, 15));         
        int mtime = atoi(PQgetvalue(res, 0, 16)); 
        int mode = atoi(PQgetvalue(res, 0, 17)); 
        int uid = atoi(PQgetvalue(res, 0, 18));      
        int gid = atoi(PQgetvalue(res, 0, 19)); 
        char* md5 = PQgetvalue(res, 0, 20); 
        int known = atoi(PQgetvalue(res, 0, 21)); 
        char* parent_path = PQgetvalue(res, 0, 22);

        //cleanup
        PQclear(res);    
    }

};


// NOT IMPLEMENTED:

int TskDbPostgreSQL::addVolumeInfo(const TSK_VS_PART_INFO * vs_part, int64_t parObjId,
    int64_t & objId){        return 0; }

int TskDbPostgreSQL::addFileLayoutRange(const TSK_DB_FILE_LAYOUT_RANGE & fileLayoutRange){return 0; }
int TskDbPostgreSQL::addFileLayoutRange(int64_t a_fileObjId, uint64_t a_byteStart, uint64_t a_byteLen, int a_sequence){return 0; }

bool TskDbPostgreSQL::isDbOpen() const {
    return true;}
int TskDbPostgreSQL::createSavepoint(const char *name){ 
    return 0; }
int TskDbPostgreSQL::revertSavepoint(const char *name){ 
    return 0; }
int TskDbPostgreSQL::releaseSavepoint(const char *name){ 
    return 1; }
bool TskDbPostgreSQL::inTransaction() { 
    return false;}

//query methods / getters
TSK_RETVAL_ENUM TskDbPostgreSQL::getFileLayouts(vector<TSK_DB_FILE_LAYOUT_RANGE> & fileLayouts) { return TSK_OK;}
TSK_RETVAL_ENUM TskDbPostgreSQL::getVsInfos(int64_t imgId, vector<TSK_DB_VS_INFO> & vsInfos) { return TSK_OK;}
TSK_RETVAL_ENUM TskDbPostgreSQL::getVsPartInfos(int64_t imgId, vector<TSK_DB_VS_PART_INFO> & vsPartInfos) { return TSK_OK;}
TSK_RETVAL_ENUM TskDbPostgreSQL::getFsRootDirObjectInfo(const int64_t fsObjId, TSK_DB_OBJECT & rootDirObjInfo) { return TSK_OK;}

#endif // TSK_WIN32
#endif // HAVE_POSTGRESQL