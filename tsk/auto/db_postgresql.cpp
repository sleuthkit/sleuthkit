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
* \file db_postgresql.cpp
* Contains code to perform operations against PostgreSQL database.
*/
#include "tsk_db.h"
#ifdef HAVE_LIBPQ_
#include "tsk_db_postgresql.h"
#include <string.h>
#include <sstream>
#include <algorithm>
#include "guid.h"

using std::stringstream;
using std::sort;
using std::for_each;

TskDbPostgreSQL::TskDbPostgreSQL(const TSK_TCHAR * a_dbFilePath, bool a_blkMapFlag)
    : TskDb(a_dbFilePath, a_blkMapFlag)
{
    conn = NULL;
	snprintf(m_dBName, MAX_CONN_INFO_FIELD_LENGTH - 1, "%" PRIttocTSK "", a_dbFilePath);
    m_blkMapFlag = a_blkMapFlag;

	strcpy(userName, "");
	strcpy(password, "");
	strcpy(hostNameOrIpAddr, "");
	strcpy(hostPort, "");

}

TskDbPostgreSQL::~TskDbPostgreSQL()
{
    if (conn) {
        PQfinish(conn);
        conn = NULL;
    }
}

TSK_RETVAL_ENUM TskDbPostgreSQL::setConnectionInfo(CaseDbConnectionInfo * info){

    if (info->getDbType() != CaseDbConnectionInfo::POSTGRESQL) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr("TskDbPostgreSQL::setConnectionInfo: Connection info is for wrong database type %d", info->getDbType());
        return TSK_ERR;
    }

    // verify input string sizes
    if (verifyConnectionInfoStringLengths(info->getUserName().size(), info->getPassword().size(), info->getHost().size(), info->getPort().size()) != TSK_OK) {
        return TSK_ERR;
    }

    strncpy(userName, info->getUserName().c_str(), sizeof(userName));
    strncpy(password, info->getPassword().c_str(), sizeof(password));
    strncpy(hostNameOrIpAddr, info->getHost().c_str(), sizeof(hostNameOrIpAddr));
    strncpy(hostPort, info->getPort().c_str(), sizeof(hostPort));

    return TSK_OK;
}

TSK_RETVAL_ENUM TskDbPostgreSQL::verifyConnectionInfoStringLengths(size_t userNameStrLen, size_t pwdStrLen, size_t hostNameStrLen, size_t portStrLen) {

    if (userNameStrLen >= MAX_CONN_INFO_FIELD_LENGTH - 1) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr("TskDbPostgreSQL::connectToDatabase: User name is too long. Length = %zd, Max length = %d", userNameStrLen, MAX_CONN_INFO_FIELD_LENGTH - 1);
        return TSK_ERR;
    }

    if (pwdStrLen >= MAX_CONN_INFO_FIELD_LENGTH - 1) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr("TskDbPostgreSQL::connectToDatabase: Password is too long. Length = %zd, Max length = %d", pwdStrLen, MAX_CONN_INFO_FIELD_LENGTH - 1);
        return TSK_ERR;
    }

    if (hostNameStrLen >= MAX_CONN_INFO_FIELD_LENGTH - 1) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr("TskDbPostgreSQL::connectToDatabase: Host name is too long. Length = %zd, Max length = %d", hostNameStrLen, MAX_CONN_INFO_FIELD_LENGTH - 1);
        return TSK_ERR;
    }

    if (portStrLen > MAX_CONN_PORT_FIELD_LENGTH) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr("TskDbPostgreSQL::connectToDatabase: Host port string is too long. Length = %zd, Max length = %d", portStrLen, MAX_CONN_PORT_FIELD_LENGTH);
        return TSK_ERR;
    }

    return TSK_OK;
}

PGconn* TskDbPostgreSQL::connectToDatabase(char *dbName) {

    // Make a connection to postgres database server
    char connectionString[1024];

    // verify input string sizes
    if (verifyConnectionInfoStringLengths(strlen(userName), strlen(password), strlen(hostNameOrIpAddr), strlen(hostPort)) != TSK_OK) {
        return NULL;
    }

    // escape strings for use within an SQL command. Usually use PQescapeLiteral but it requires connection to be already established.
    char userName_sql[MAX_CONN_INFO_FIELD_LENGTH];
    char password_sql[MAX_CONN_INFO_FIELD_LENGTH];
    char hostName_sql[MAX_CONN_INFO_FIELD_LENGTH];
    PQescapeString(&userName_sql[0], userName, strlen(userName));
    PQescapeString(&password_sql[0], password, strlen(password));
    PQescapeString(&hostName_sql[0], hostNameOrIpAddr, strlen(hostNameOrIpAddr));
    snprintf(connectionString, 1024, "user=%s password=%s dbname=%s host=%s port=%s", userName_sql, password_sql, dbName, hostName_sql, hostPort);	
    PGconn *dbConn = PQconnectdb(connectionString);

    // Check to see that the backend connection was successfully made
    if (verifyResultCode(PQstatus(dbConn), CONNECTION_OK, "TskDbPostgreSQL::connectToDatabase: Connection to PostgreSQL database failed, result code %d"))
    {
        PQfinish(dbConn);
        return NULL;
    }
    return dbConn;
}

TSK_RETVAL_ENUM TskDbPostgreSQL::createDatabase(){

    TSK_RETVAL_ENUM result = TSK_OK;

    // Connect to PostgreSQL server first
    char defaultPostgresDb[32] = "postgres";
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
    // you now need to always use double quotes when referring to it (e.dg when deleting database).
    char createDbString[1024];
    snprintf(createDbString, 1024, "CREATE DATABASE \"%s\" WITH ENCODING='UTF8';", m_dBName);    
    PGresult *res = PQexec(serverConn, createDbString);
    if (!res || PQresultStatus(res) != PGRES_COMMAND_OK) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        char * str = PQerrorMessage(serverConn);
        tsk_error_set_errstr("TskDbPostgreSQL::createDatabase: Database creation failed, %s", str);
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
    // close database connection if there is one open
    if (conn)
        close();

    if (createDbFlag) {
        // create new database first
        if (verifyResultCode(createDatabase(), TSK_OK, "TskDbPostgreSQL::open: Unable to create database, result code %d")){
            return -1;
        }
    }

    // connect to existing database
    conn = connectToDatabase(&m_dBName[0]);
    if (!conn){
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
       	tsk_error_set_errstr("TskDbPostgreSQL::open: Couldn't connect to database %s", m_dBName);
        return -1;
    }

    if (createDbFlag) {
        // initialize TSK tables
        if (initialize()) {
            tsk_error_set_errstr2("TskDbPostgreSQL::open: Couldn't initialize database %s", m_dBName);
            close();    // close connection to database
            return -1;
        }
    }

    return 0;
}

/*
* Close PostgreSQL database.
* Return 0 on success, 1 on failure
*/
int TskDbPostgreSQL::close()
{
    if (conn) {
        PQfinish(conn);
        conn = NULL;
    }
    return 0;
}


bool TskDbPostgreSQL::dbExists() {

    int numDb = 0;

    // Connect to PostgreSQL server first
    char defaultPostgresDb[32] = "postgres";
    PGconn *serverConn = connectToDatabase(&defaultPostgresDb[0]);
    if (!serverConn)
        return false;

    // Poll PostreSQL server for existing databases.
    char selectString[1024];
    snprintf(selectString, 1024, "SELECT datname FROM pg_catalog.pg_database WHERE datname = '%s';", m_dBName);
    
    PGresult *res = PQexec(serverConn, selectString);
    if (!res || PQresultStatus(res) != PGRES_TUPLES_OK)
    {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        char * str = PQerrorMessage(conn);
        tsk_error_set_errstr("TskDbPostgreSQL::dbExists: Existing database lookup failed, %s", str);
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
* Execute SQL command returning no data. Sets TSK error values on error.
* @returns 1 on error, 0 on success
*/
int TskDbPostgreSQL::attempt_exec(const char *sql, const char *errfmt)
{
    if (!conn) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr("Can't execute PostgreSQL query, not connected to database. Query: %s", sql);
        return 1;
    }

    PGresult *res = PQexec(conn, sql);

    if (!isQueryResultValid(res, sql)) {
        return 1;
    }

    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        char * str = PQerrorMessage(conn);
        tsk_error_set_errstr(errfmt, str);
        PQclear(res);
        return 1;
    }
    PQclear(res);
    return 0;
}


/**
* Validate string that was escaped by a call to PQescapeLiteral(). Sets TSK error values on error.
* @returns 1 if string is valid, 0 otherwise
*/
int TskDbPostgreSQL::isEscapedStringValid(const char *sql_str, const char *orig_str, const char *errfmt){

    if (sql_str == NULL){
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        char * str = PQerrorMessage(conn);
        tsk_error_set_errstr(errfmt, orig_str, str);
        return 0;
    }
    return 1;
}

/**
* Execute SQL statement and returns PostgreSQL result sets in ASCII format. Sets TSK error values on error.
* IMPORTANT: result set needs to be freed by calling PQclear(res) when no longer needed.
* @returns Result set on success, NULL on error
*/
PGresult* TskDbPostgreSQL::get_query_result_set(const char *sql, const char *errfmt)
{
    if (!conn){
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr("Can't execute PostgreSQL query, not connected to database. Query: %s", sql);
        return NULL;
    }

    PGresult *res = PQexec(conn, sql);
    if (!isQueryResultValid(res, sql)) {
        return NULL;
    }

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        char * str = PQerrorMessage(conn);
        tsk_error_set_errstr(errfmt, str);
        PQclear(res);
        return NULL;
    }
    return res;
}

/**
* Execute a statement and returns PostgreSQL result sets in binary format. Sets TSK error values on error.
* IMPORTANT: PostgreSQL returns binary representations in network byte order, which need to be converted to the local byte order.
* IMPORTANT: result set needs to be freed by calling PQclear(res) when no longer needed.
* @returns Result set on success, NULL on error
*/
PGresult* TskDbPostgreSQL::get_query_result_set_binary(const char *sql, const char *errfmt)
{
    if (!conn){
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr("Can't execute PostgreSQL query, not connected to database. Query: %s", sql);
        return NULL;
    }

    PGresult *res = PQexecParams(conn,
                       sql,
                       0,       /* no additional params, they are part sql string */
                       NULL,    /* let the backend deduce param type */
                       NULL,    /* no params */
                       NULL,    /* don't need param lengths since text */
                       NULL,    /* default to all text params */
                       1);      /* ask for binary results */

    if (!isQueryResultValid(res, sql)) {
        return NULL;
    }

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        char * str = PQerrorMessage(conn);
        tsk_error_set_errstr(errfmt, str);
        PQclear(res);
        return NULL;
    }
    return res;
}

/* Verifies that result code matches expected result code. Sets TSK error values if result codes do not match.
* @returns 0 if result codes match, 1 if they don't
*/
int TskDbPostgreSQL::verifyResultCode(int resultCode, int expectedResultCode, const char *errfmt)
{
    if (resultCode != expectedResultCode) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr(errfmt, resultCode);
        return 1;
    }
    return 0;
}

/* Verifies if PGresult is valid. Result set must contain at least one row. Number of returned fileds must match expected number of fields.
* Sets TSK error values if result is invalid.
* @returns 0 if result is valid, 1 if result is invalid	or empty
*/
int TskDbPostgreSQL::verifyNonEmptyResultSetSize(const char *sql, PGresult *res, int expectedNumFileds, const char *errfmt)
{
    if (!isQueryResultValid(res, sql)) {
        return 1;
    }

    // this query must produce at least one result
    if (PQntuples(res) < 1){
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr("SQL command returned empty result set: %s", sql);
        return 1;
    }

    if (PQnfields(res) != expectedNumFileds){
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr(errfmt, PQnfields(res), expectedNumFileds);
        return 1;
    }
    return 0;
}

/* Verifies if PGresult is valid. It's acceptable for result set to be empty. If result set is not empty, number of returned fileds must match expected number of fields.
* Sets TSK error values if result is invalid.
* @returns 0 if result is valid or empty, 1 if result is invalid
*/
int TskDbPostgreSQL::verifyResultSetSize(const char *sql, PGresult *res, int expectedNumFileds, const char *errfmt)
{
    // check if a valid result set was returned
    if (!isQueryResultValid(res, sql)) {
        return 1;
    }

    // it's ok for this query to produce no results
    if (PQntuples(res) == 0){
        return 0;
    }

    // If there are results, verify number of fields returned.
    if (PQnfields(res) != expectedNumFileds){
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr(errfmt, PQnfields(res), expectedNumFileds);
        PQclear(res);
        return 1;
    }

    return 0;
}


/* Verifies if PGresult is valid. Sets TSK error values if result is invalid.
* @returns true if result is valid, false if result is invalid
*/
bool TskDbPostgreSQL::isQueryResultValid(PGresult *res, const char *sql)
{
    if (!res) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr("SQL command returned a NULL result set pointer: %s", sql);
        return false;
    }
    return true;
}

/* Removes any existing non-UTF8 characters from string. Output string needs to be pre-allocated
* and it's max size is passed as input.
*/
void TskDbPostgreSQL::removeNonUtf8(char* newStr, int newStrMaxSize, const char* origStr)
{
    if (!newStr){
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr("TskDbPostgreSQL::removeNonUtf8: Output string has not been allocated");
        return;
    }
#undef min
    int strSize = std::min((int) strlen(origStr), newStrMaxSize);
    strncpy(newStr, origStr, strSize);
    newStr[strSize] = '\0';
    tsk_cleanupUTF8(newStr, '^');
}

/**
* Initialize the open DB: set PRAGMAs, create tables and indexes
* @returns 1 on error
*/
int TskDbPostgreSQL::initialize() {

    char foo[1024];
    if (attempt_exec("CREATE TABLE tsk_db_info (schema_ver INTEGER, tsk_ver INTEGER, schema_minor_ver INTEGER);","Error creating tsk_db_info table: %s\n")) {
        return 1;
    }

    snprintf(foo, 1024, "INSERT INTO tsk_db_info (schema_ver, tsk_ver, schema_minor_ver) VALUES (%d, %d,%d);", TSK_SCHEMA_VER, TSK_VERSION_NUM, TSK_SCHEMA_MINOR_VER);
    if (attempt_exec(foo, "Error adding data to tsk_db_info table: %s\n")) {
        return 1;
    }

    // ELTODO: change INTEGER (4 bytes) fields to SMALLINT (2 bytes) to use less memory for enum fields

	if (attempt_exec("CREATE TABLE tsk_objects (obj_id BIGSERIAL PRIMARY KEY, par_obj_id BIGINT, type INTEGER NOT NULL);", "Error creating tsk_objects table: %s\n")
		||
		attempt_exec
		("CREATE TABLE tsk_image_info (obj_id BIGSERIAL PRIMARY KEY, type INTEGER, ssize INTEGER, tzone TEXT, size BIGINT, md5 TEXT, display_name TEXT, FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id));",
			"Error creating tsk_image_info table: %s\n")
		||
		attempt_exec("CREATE TABLE tsk_image_names (obj_id BIGINT NOT NULL, name TEXT NOT NULL, sequence INTEGER NOT NULL, FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id));",
			"Error creating tsk_image_names table: %s\n")
		||
		attempt_exec
		("CREATE TABLE tsk_vs_info (obj_id BIGSERIAL PRIMARY KEY, vs_type INTEGER NOT NULL, img_offset BIGINT NOT NULL, block_size BIGINT NOT NULL, FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id));",
			"Error creating tsk_vs_info table: %s\n")
		||
		attempt_exec
		("CREATE TABLE data_source_info (obj_id INTEGER PRIMARY KEY, device_id TEXT NOT NULL, time_zone TEXT NOT NULL, FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id));",
			"Error creating data_source_info table: %s\n")
		||
		attempt_exec
		("CREATE TABLE tsk_fs_info (obj_id BIGSERIAL PRIMARY KEY, img_offset BIGINT NOT NULL, fs_type INTEGER NOT NULL, block_size BIGINT NOT NULL, block_count BIGINT NOT NULL, root_inum BIGINT NOT NULL, first_inum BIGINT NOT NULL, last_inum BIGINT NOT NULL, display_name TEXT, FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id));",
			"Error creating tsk_fs_info table: %s\n")
		||
		attempt_exec
		("CREATE TABLE tsk_files (obj_id BIGSERIAL PRIMARY KEY, fs_obj_id BIGINT, data_source_obj_id BIGINT NOT NULL, attr_type INTEGER, attr_id INTEGER, name TEXT NOT NULL, meta_addr BIGINT, meta_seq BIGINT, type INTEGER, has_layout INTEGER, has_path INTEGER, dir_type INTEGER, meta_type INTEGER, dir_flags INTEGER, meta_flags INTEGER, size BIGINT, ctime BIGINT, crtime BIGINT, atime BIGINT, mtime BIGINT, mode INTEGER, uid INTEGER, gid INTEGER, md5 TEXT, known INTEGER, parent_path TEXT, mime_type TEXT, extension TEXT, "
			"FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id), FOREIGN KEY(fs_obj_id) REFERENCES tsk_fs_info(obj_id), FOREIGN KEY(data_source_obj_id) REFERENCES data_source_info(obj_id));",
			"Error creating tsk_files table: %s\n")
		||
		attempt_exec
		("CREATE TABLE file_encoding_types (encoding_type INTEGER PRIMARY KEY, name TEXT NOT NULL);",
			"Error creating file_encoding_types table: %s\n")
		||
		attempt_exec("CREATE TABLE tsk_files_path (obj_id BIGSERIAL PRIMARY KEY, path TEXT NOT NULL, encoding_type INTEGER, FOREIGN KEY(encoding_type) references file_encoding_types(encoding_type), FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id))",
			"Error creating tsk_files_path table: %s\n")
		||
		attempt_exec("CREATE TABLE tsk_files_derived (obj_id BIGSERIAL PRIMARY KEY, derived_id BIGINT NOT NULL, rederive TEXT, FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id))", "Error creating tsk_files_derived table: %s\n")
		||
		attempt_exec("CREATE TABLE tsk_files_derived_method (derived_id BIGSERIAL PRIMARY KEY, tool_name TEXT NOT NULL, tool_version TEXT NOT NULL, other TEXT)", "Error creating tsk_files_derived_method table: %s\n")
		||
		attempt_exec("CREATE TABLE tag_names (tag_name_id BIGSERIAL PRIMARY KEY, display_name TEXT UNIQUE, description TEXT NOT NULL, color TEXT NOT NULL, knownStatus INTEGER NOT NULL)", "Error creating tag_names table: %s\n")
		||
		attempt_exec("CREATE TABLE content_tags (tag_id BIGSERIAL PRIMARY KEY, obj_id BIGINT NOT NULL, tag_name_id BIGINT NOT NULL, comment TEXT NOT NULL, begin_byte_offset BIGINT NOT NULL, end_byte_offset BIGINT NOT NULL, "
			"FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id), FOREIGN KEY(tag_name_id) REFERENCES tag_names(tag_name_id))",
			"Error creating content_tags table: %s\n")
		||
		attempt_exec("CREATE TABLE blackboard_artifact_types (artifact_type_id BIGSERIAL PRIMARY KEY, type_name TEXT NOT NULL, display_name TEXT)", "Error creating blackboard_artifact_types table: %s\n")
		||
		attempt_exec("CREATE TABLE blackboard_attribute_types (attribute_type_id BIGSERIAL PRIMARY KEY, type_name TEXT NOT NULL, display_name TEXT, value_type INTEGER NOT NULL)", "Error creating blackboard_attribute_types table: %s\n")
		||
		attempt_exec("CREATE TABLE review_statuses (review_status_id INTEGER PRIMARY KEY, "
			"review_status_name TEXT NOT NULL, "
			"display_name TEXT NOT NULL)",
			"Error creating review_statuses table: %s\n")
		||
		attempt_exec("CREATE TABLE blackboard_artifacts (artifact_id BIGSERIAL PRIMARY KEY, "
			"obj_id BIGINT NOT NULL, "
			"artifact_obj_id BIGINT NOT NULL, "
			"data_source_obj_id BIGINT NOT NULL, "
			"artifact_type_id BIGINT NOT NULL, "
			"review_status_id INTEGER NOT NULL, "
			"FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id), "
			"FOREIGN KEY(artifact_obj_id) REFERENCES tsk_objects(obj_id), "
			"FOREIGN KEY(data_source_obj_id) REFERENCES tsk_objects(obj_id), "
			"FOREIGN KEY(artifact_type_id) REFERENCES blackboard_artifact_types(artifact_type_id), "
			"FOREIGN KEY(review_status_id) REFERENCES review_statuses(review_status_id))",
			"Error creating blackboard_artifact table: %s\n")
		||
		attempt_exec("ALTER SEQUENCE blackboard_artifacts_artifact_id_seq minvalue -9223372036854775808 restart with -9223372036854775808", "Error setting starting value for artifact_id: %s\n")
		||
		attempt_exec("CREATE TABLE blackboard_artifact_tags (tag_id BIGSERIAL PRIMARY KEY, artifact_id BIGINT NOT NULL, tag_name_id BIGINT NOT NULL, comment TEXT NOT NULL, "
			"FOREIGN KEY(artifact_id) REFERENCES blackboard_artifacts(artifact_id), FOREIGN KEY(tag_name_id) REFERENCES tag_names(tag_name_id))",
			"Error creating blackboard_artifact_tags table: %s\n")
		||
		/* Binary representation of BYTEA is a bunch of bytes, which could
		* include embedded nulls so we have to pay attention to field length.
		* http://www.postgresql.org/docs/9.4/static/libpq-example.html
		*/
		attempt_exec
		("CREATE TABLE blackboard_attributes (artifact_id BIGINT NOT NULL, artifact_type_id BIGINT NOT NULL, source TEXT, context TEXT, attribute_type_id BIGINT NOT NULL, value_type INTEGER NOT NULL, "
			"value_byte BYTEA, value_text TEXT, value_int32 INTEGER, value_int64 BIGINT, value_double NUMERIC(20, 10), "
			"FOREIGN KEY(artifact_id) REFERENCES blackboard_artifacts(artifact_id), FOREIGN KEY(artifact_type_id) REFERENCES blackboard_artifact_types(artifact_type_id), FOREIGN KEY(attribute_type_id) REFERENCES blackboard_attribute_types(attribute_type_id))",
			"Error creating blackboard_attribute table: %s\n")
		||
		/* In PostgreSQL "desc" indicates "descending order" so I had to rename "desc TEXT" to "descr TEXT". Should I also make this change for SQLite?*/
		attempt_exec
		("CREATE TABLE tsk_vs_parts (obj_id BIGSERIAL PRIMARY KEY, addr BIGINT NOT NULL, start BIGINT NOT NULL, length BIGINT NOT NULL, descr TEXT, flags INTEGER NOT NULL, FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id));",
			"Error creating tsk_vol_info table: %s\n")
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
		("CREATE TABLE ingest_modules (ingest_module_id BIGSERIAL PRIMARY KEY, display_name TEXT NOT NULL, unique_name TEXT UNIQUE NOT NULL, type_id INTEGER NOT NULL, version TEXT NOT NULL, FOREIGN KEY(type_id) REFERENCES ingest_module_types(type_id));",
			"Error creating ingest_modules table: %s\n")
		||
		attempt_exec
		("CREATE TABLE ingest_jobs (ingest_job_id BIGSERIAL PRIMARY KEY, obj_id BIGINT NOT NULL, host_name TEXT NOT NULL, start_date_time BIGINT NOT NULL, end_date_time BIGINT NOT NULL, status_id INTEGER NOT NULL, settings_dir TEXT, FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id), FOREIGN KEY(status_id) REFERENCES ingest_job_status_types(type_id));",
			"Error creating ingest_jobs table: %s\n")
		||
		attempt_exec
		("CREATE TABLE ingest_job_modules (ingest_job_id INTEGER, ingest_module_id INTEGER, pipeline_position INTEGER, PRIMARY KEY(ingest_job_id, ingest_module_id), FOREIGN KEY(ingest_job_id) REFERENCES ingest_jobs(ingest_job_id), FOREIGN KEY(ingest_module_id) REFERENCES ingest_modules(ingest_module_id));",
			"Error creating ingest_job_modules table: %s\n")
		||
		attempt_exec
		("CREATE TABLE reports (obj_id BIGSERIAL PRIMARY KEY, path TEXT NOT NULL, crtime INTEGER NOT NULL, src_module_name TEXT NOT NULL, report_name TEXT NOT NULL, FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id));", "Error creating reports table: %s\n")
		||
		attempt_exec
		("CREATE TABLE account_types (account_type_id BIGSERIAL PRIMARY KEY, type_name TEXT UNIQUE NOT NULL, display_name TEXT NOT NULL)",
			"Error creating account_types table: %s\n")
		||
		attempt_exec
		("CREATE TABLE accounts (account_id BIGSERIAL PRIMARY KEY, account_type_id INTEGER NOT NULL, account_unique_identifier TEXT NOT NULL,  UNIQUE(account_type_id, account_unique_identifier) , FOREIGN KEY(account_type_id) REFERENCES account_types(account_type_id))",
		 "Error creating accounts table: %s\n")
		||
		attempt_exec
		("CREATE TABLE account_relationships  (relationship_id BIGSERIAL PRIMARY KEY, account1_id INTEGER NOT NULL, account2_id INTEGER NOT NULL, relationship_source_obj_id INTEGER NOT NULL, date_time BIGINT, relationship_type INTEGER NOT NULL, data_source_obj_id INTEGER NOT NULL, UNIQUE(account1_id, account2_id, relationship_source_obj_id), FOREIGN KEY(account1_id) REFERENCES accounts(account_id), FOREIGN KEY(account2_id) REFERENCES accounts(account_id), FOREIGN KEY(relationship_source_obj_id) REFERENCES tsk_objects(obj_id), FOREIGN KEY(data_source_obj_id) REFERENCES tsk_objects(obj_id))",
		 "Error creating relationships table: %s\n")
		||
		attempt_exec(
			"CREATE TABLE event_types ("
			" event_type_id BIGSERIAL PRIMARY KEY,"
			" display_name TEXT NOT NULL, "
			" super_type_id INTEGER REFERENCES event_types, "
			" artifact_based BOOLEAN )"
			, "Error creating event_types table: %s\n")
		||  
		attempt_exec(
			"insert into event_types(event_type_id, display_name, super_type_id, artifact_based) values( 0, 'Event Types', null, 0);"
			"insert into event_types(event_type_id, display_name, super_type_id, artifact_based) values(1, 'File System', 0, 0);"
			"insert into event_types(event_type_id, display_name, super_type_id, artifact_based) values(2, 'Web Activity', 0, 0);"
			"insert into event_types(event_type_id, display_name, super_type_id, artifact_based) values(3, 'Misc Types', 0, 0);"
			"insert into event_types(event_type_id, display_name, super_type_id, artifact_based) values(4, 'Modified', 1, 0);"
			"insert into event_types(event_type_id, display_name, super_type_id, artifact_based) values(5, 'Accessed', 1, 0);"
			"insert into event_types(event_type_id, display_name, super_type_id, artifact_based) values(6, 'Created', 1, 0);"
			"insert into event_types(event_type_id, display_name, super_type_id, artifact_based) values(7, 'Changed', 1, 0);"
			, "Error initializing event_types table rows: %s\n")
		||
		attempt_exec(
			"CREATE TABLE events ("
			" event_id BIGSERIAL PRIMARY KEY, "
			" datasource_id BIGINT REFERENCES data_source_info, "
			" file_id BIGINT REFERENCES tsk_files, "
			" artifact_id BIGINT REFERENCES blackboard_artifacts, "
			" time INTEGER, "
			" sub_type INTEGER REFERENCES event_types, "
			" base_type INTEGER REFERENCES event_types, "
			" full_description TEXT, "
			" med_description TEXT, "
			" short_description TEXT, "
			" known_state INTEGER, " //boolean 
			" hash_hit INTEGER, " //boolean 
			" tagged INTEGER )"
			, "Error creating events table: %s\n")||
		attempt_exec("CREATE TABLE db_info ( key TEXT,  value INTEGER, PRIMARY KEY (key))", //TODO: drop this table
			"Error creating db_info table: %s\n")
		){
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
int TskDbPostgreSQL::createIndexes() {
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
		attempt_exec("CREATE INDEX file_extension ON tsk_files(extension);",  //file extenssion
			"Error creating file_extension index on tsk_files: %s\n") ||
		attempt_exec("CREATE INDEX relationships_account1  ON account_relationships(account1_id);",
			"Error creating relationships_account1 index on account_relationships: %s\n") ||
		attempt_exec("CREATE INDEX relationships_account2  ON account_relationships(account2_id);",
			"Error creating relationships_account2 index on account_relationships: %s\n") ||
		attempt_exec("CREATE INDEX relationships_relationship_source_obj_id  ON account_relationships(relationship_source_obj_id);",
			"Error creating relationships_relationship_source_obj_id index on account_relationships: %s\n") ||
		attempt_exec("CREATE INDEX relationships_date_time  ON account_relationships(date_time);",
			"Error creating relationships_date_time index on account_relationships: %s\n") ||
		attempt_exec("CREATE INDEX relationships_relationship_type ON account_relationships(relationship_type);",
			"Error creating relationships_relationship_type index on account_relationships: %s\n") ||
		attempt_exec("CREATE INDEX relationships_data_source_obj_id  ON account_relationships(data_source_obj_id);",
			"Error creating relationships_data_source_obj_id index on account_relationships: %s\n")||
		//events indices
		attempt_exec("CREATE INDEX events_datasource_id  ON events(datasource_id);",
			"Error creating relationships_data_source_obj_id index on events: %s\n") ||
		attempt_exec("CREATE INDEX events_event_id_hash_hit  ON events(event_id, hash_hit);",
			"Error creating events_event_id_hash_hit index on events: %s\n") ||
		attempt_exec("CREATE INDEX events_event_id_tagged  ON events(event_id, tagged);",
			"Error creating events_event_id_tagged index on events: %s\n") ||
		attempt_exec("CREATE INDEX events_file_id  ON events(file_id);",
			"Error creating events_file_id index on events: %s\n") ||
		attempt_exec("CREATE INDEX events_artifact_id  ON events(artifact_id);",
			"Error creating events_artifact_id index on events: %s\n") ||
		attempt_exec("CREATE INDEX events_sub_type_short_description_time  ON events(sub_type, short_description, time);",
			"Error creating events_sub_type_short_description_time index on events: %s\n") ||
		attempt_exec("CREATE INDEX events_base_type_short_description_time  ON events(base_type, short_description, time);",
			"Error creating events_base_type_short_description_time index on events: %s\n") ||
		attempt_exec("CREATE INDEX events_time  ON events(time);",
			"Error creating events_time index on events: %s\n") ||
		attempt_exec("CREATE INDEX events_known_state  ON events(known_state);",
			"Error creating events_known_state index on events: %s\n");
}


/**
* @returns TSK_ERR on error, 0 on success
*/
uint8_t TskDbPostgreSQL::addObject(TSK_DB_OBJECT_TYPE_ENUM type, int64_t parObjId, int64_t & objId)
{
    char stmt[1024];
    int expectedNumFileds = 1;
    snprintf(stmt, 1024, "INSERT INTO tsk_objects (par_obj_id, type) VALUES (%" PRId64 ", %d) RETURNING obj_id", parObjId, type);

    PGresult *res = get_query_result_set(stmt, "TskDbPostgreSQL::addObj: Error adding object to row: %s (result code %d)\n");

    // check if a valid result set was returned
    if (verifyNonEmptyResultSetSize(stmt, res, expectedNumFileds, "TskDbPostgreSQL::addObj: Unexpected number of columns in result set: Expected %d, Received %d\n")) {
        return TSK_ERR;
    }

    // Returned value is objId
    objId = atoll(PQgetvalue(res, 0, 0));

    /* PostgreSQL returns binary results in network byte order, which need to be converted to the local byte order.
    int64_t *pInt64 = (int64_t*)PQgetvalue(res, 0, 0);
    objId = ntoh64(pInt64);*/

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

    snprintf(stmt, 1024, "INSERT INTO tsk_vs_info (obj_id, vs_type, img_offset, block_size) VALUES (%" PRId64 ", %d, %"
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
    int expectedNumFileds = 4;
    snprintf(stmt, 1024, "SELECT obj_id, vs_type, img_offset, block_size FROM tsk_vs_info WHERE obj_id = %" PRId64 "", objId);

    PGresult *res = get_query_result_set(stmt, "TskDbPostgreSQL::getVsInfo: Error selecting object by objid: %s (result code %d)\n");

    // check if a valid result set was returned
    if (verifyNonEmptyResultSetSize(stmt, res, expectedNumFileds, "TskDbPostgreSQL::getVsInfo: Unexpected number of columns in result set: Expected %d, Received %d\n")) {
        return TSK_ERR;
    }

    vsInfo.objId = atoll(PQgetvalue(res, 0, 0));
    vsInfo.vstype = (TSK_VS_TYPE_ENUM)atoi(PQgetvalue(res, 0, 1));
    vsInfo.offset = atoll(PQgetvalue(res, 0, 2));
    vsInfo.block_size = (unsigned int)atoll(PQgetvalue(res, 0, 3));

    //cleanup
    PQclear(res);

    return TSK_OK;
}

/**
* @deprecated
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
    return addImageInfo(type, size, objId, timezone, 0, "", "");
}

/**
 * Adds image details to the existing database tables.
 *
 * @param type Image type
 * @param ssize Size of device sector in bytes (or 0 for default)
 * @param objId The object id assigned to the image (out param)
 * @param timeZone The timezone the image is from
 * @param size The size of the image in bytes.
 * @param md5 MD5 hash of the image
 * @param deviceId An ASCII-printable identifier for the device associated with the data source that is intended to be unique across multiple cases (e.g., a UUID).
 * @returns 1 on error, 0 on success
 */
int TskDbPostgreSQL::addImageInfo(int type, TSK_OFF_T ssize, int64_t & objId, const string & timezone, TSK_OFF_T size, const string &md5, const string& deviceId)
{
    // Add the data source to the tsk_objects table.
    // We don't use addObject because we're passing in NULL as the parent
    char stmt[2048];
    int expectedNumFileds = 1;
    snprintf(stmt, 2048, "INSERT INTO tsk_objects (par_obj_id, type) VALUES (NULL, %d) RETURNING obj_id;", TSK_DB_OBJECT_TYPE_IMG);
    PGresult *res = get_query_result_set(stmt, "TskDbPostgreSQL::addObj: Error adding object to row: %s (result code %d)\n");
    if (verifyNonEmptyResultSetSize(stmt, res, expectedNumFileds, "TskDbPostgreSQL::addObj: Unexpected number of columns in result set: Expected %d, Received %d\n")) {
        return 1;
    }
    objId = atoll(PQgetvalue(res, 0, 0));

    // Add the data source to the tsk_image_info table.
    char timeZone_local[MAX_DB_STRING_LENGTH];
    removeNonUtf8(timeZone_local, MAX_DB_STRING_LENGTH - 1, timezone.c_str());
    char md5_local[MAX_DB_STRING_LENGTH];
    removeNonUtf8(md5_local, MAX_DB_STRING_LENGTH - 1, md5.c_str());
    char *timezone_sql = PQescapeLiteral(conn, timeZone_local, strlen(timeZone_local));
    char *md5_sql = PQescapeLiteral(conn, md5_local, strlen(md5_local));
    if (!isEscapedStringValid(timezone_sql, timeZone_local, "TskDbPostgreSQL::addImageInfo: Unable to escape time zone string: %s (Error: %s)\n")
        || !isEscapedStringValid(md5_sql, md5_local, "TskDbPostgreSQL::addImageInfo: Unable to escape md5 string: %s (Error: %s)\n")) {
        PQfreemem(timezone_sql);
        PQfreemem(md5_sql);
        return 1;
    }
    snprintf(stmt, 2048, "INSERT INTO tsk_image_info (obj_id, type, ssize, tzone, size, md5) VALUES (%" PRId64 ", %d, %" PRIuOFF ", %s, %" PRIuOFF ", %s);",
        objId, type, ssize, timezone_sql, size, md5_sql);
    int ret = attempt_exec(stmt, "Error adding data to tsk_image_info table: %s\n");
    PQfreemem(timezone_sql);
    PQfreemem(md5_sql);
    if (1 == ret) {
        return ret;
    }

    // Add the data source to the data_source_info table.
    // Add the data source to the data_source_info table.
    stringstream deviceIdStr;
#ifdef GUID_WINDOWS
    if (deviceId.empty()) {
        // Use a GUID as the default.
        GuidGenerator generator;
        Guid guid = generator.newGuid();
        deviceIdStr << guid;
    } else {
        deviceIdStr << deviceId;
    }
#else
    deviceIdStr << deviceId;
#endif
    char *deviceId_sql = PQescapeLiteral(conn, deviceId.c_str(), strlen(deviceIdStr.str().c_str()));
    if (!isEscapedStringValid(deviceId_sql, deviceId.c_str(), "TskDbPostgreSQL::addImageInfo: Unable to escape data source string: %s (Error: %s)\n")) {
        PQfreemem(deviceId_sql);
        return 1;
    }
    char *timeZone_sql = PQescapeLiteral(conn, timezone.c_str(), strlen(timezone.c_str()));
    if (!isEscapedStringValid(timeZone_sql, timezone.c_str(), "TskDbPostgreSQL::addImageInfo: Unable to escape data source string: %s (Error: %s)\n")) {
        PQfreemem(deviceId_sql);
        PQfreemem(timeZone_sql);
        return 1;
    }
    snprintf(stmt, 2048, "INSERT INTO data_source_info (obj_id, device_id, time_zone) VALUES (%" PRId64 ", %s, %s);",
        objId, deviceId_sql, timeZone_sql);
    ret = attempt_exec(stmt, "Error adding device id to data_source_info table: %s\n");
    PQfreemem(deviceId_sql);
    PQfreemem(timeZone_sql);
    return ret;
}

/**
* @returns 1 on error, 0 on success
*/
int TskDbPostgreSQL::addImageName(int64_t objId, char const *imgName, int sequence)
{
    char stmt[2048];

    // replace all non-UTF8 characters
    char imgName_local[MAX_DB_STRING_LENGTH];
    removeNonUtf8(imgName_local, MAX_DB_STRING_LENGTH - 1, imgName);

    char *imgName_sql = PQescapeLiteral(conn, imgName_local, strlen(imgName_local));
    if (!isEscapedStringValid(imgName_sql, imgName_local, "TskDbPostgreSQL::addImageName: Unable to escape image name string: %s\n")) {
        PQfreemem(imgName_sql);
        return 1;
    }

    snprintf(stmt, 2048, "INSERT INTO tsk_image_names (obj_id, name, sequence) VALUES (%" PRId64 ", %s, %d)", objId, imgName_sql, sequence);
    int ret = attempt_exec(stmt, "Error adding data to tsk_image_names table: %s\n");

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
        "%" PRId64 ",%" PRIuOFF ",%d,%u,%" PRIuDADDR ","
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
* @param path Path of parent folder
* @param md5 Binary value of MD5 (i.e. 16 bytes) or NULL
* @param known Status regarding if it was found in hash database or not
* @param fsObjId File system object of its file system
* @param objId ID that was assigned to it from the objects table
* @param dataSourceObjId The object Id of the data source
* @returns 1 on error and 0 on success
*/
int TskDbPostgreSQL::addFsFile(TSK_FS_FILE * fs_file,
    const TSK_FS_ATTR * fs_attr, const char *path,
    const unsigned char *const md5, const TSK_DB_FILES_KNOWN_ENUM known,
    int64_t fsObjId, int64_t & objId, int64_t dataSourceObjId)
{
    int64_t parObjId = 0;

    if (fs_file->name == NULL) {
        return 0;
    }

    // Find the object id for the parent folder.

    /* Root directory's parent should be the file system object.
     * Make sure it doesn't have a name, so that we don't pick up ".." entries */
    if ((fs_file->fs_info->root_inum == fs_file->name->meta_addr) &&
        ((fs_file->name->name == NULL) || (strlen(fs_file->name->name) == 0))) {
            parObjId = fsObjId;
    }
    else {
        parObjId = findParObjId(fs_file, path, fsObjId);
        if (parObjId == -1) {
            //error
            return 1;
        }
    }

    return addFile(fs_file, fs_attr, path, md5, known, fsObjId, parObjId, objId, dataSourceObjId);
}


int TskDbPostgreSQL::addMACTimeEvent(char*& zSQL, const int64_t data_source_obj_id, const int64_t obj_id, time_t time,
                                     const int64_t sub_type, const char* full_desc, const char* med_desc,
                                     const char* short_desc)
{
	if (time == 0)
	{
		//we skip any MAC time events with time == 0 since 0 is usually a bogus time and not helpfull 
		return 0;
	}

	//insert MAC time events
	if (0 > snprintf(zSQL, 2048 - 1,
	                 "INSERT INTO events ( datasource_id, file_id , artifact_id, time, sub_type, base_type, full_description, med_description, short_description, known_state, hash_hit, tagged) "
	                 // NON-NLS
	                 " VALUES ("
	                 "%" PRId64 "," // datasource_id
	                 "%" PRId64 "," // file_id
	                 "NULL," // fixed artifact_id
	                 "%" PRIu64 "," // time
					 "%" PRId64 "," // sub_type
	                 "1," // fixed base_type
	                 "%s," // full_description
	                 "%s," // med_description
	                 "%s," // short_description
	                 "0," // fixed known_state
	                 "0," // fixed hash_hit
	                 "0" // fixed tagged
	                 ")",
	                 data_source_obj_id,
	                 obj_id,
	                 (unsigned long long)time, // this one changes
	                 sub_type,
	                 full_desc,
	                 med_desc,
	                 short_desc))
	{
		return 1;
	}

	return attempt_exec(zSQL, "TskDbSqlite::addFile: Error adding event to events table: %s\n");
}

/**
* Add file data to the file table
* @param md5 binary value of MD5 (i.e. 16 bytes) or NULL
* @param dataSourceObjId The object Id of the data source
* Return 0 on success, 1 on error.
*/
int TskDbPostgreSQL::addFile(TSK_FS_FILE * fs_file, const TSK_FS_ATTR * fs_attr, const char *path,
    const unsigned char *const md5, const TSK_DB_FILES_KNOWN_ENUM known, int64_t fsObjId, int64_t parObjId, int64_t & objId,
    int64_t dataSourceObjId)
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
    size_t nlen = len + attr_nlen + 11; // Extra space for possible colon and '-slack'
    if ((name = (char *) tsk_malloc(nlen)) == NULL) {
        return 1;
    }

    strncpy(name, fs_file->name->name, nlen);

	char extension[24] = "";
	extractExtension(name, extension);

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

    // replace all non-UTF8 characters
    tsk_cleanupUTF8(name, '^');
    tsk_cleanupUTF8(escaped_path, '^');
	tsk_cleanupUTF8(extension, '^');

    // escape strings for use within an SQL command
    char *name_sql = PQescapeLiteral(conn, name, strlen(name));
    char *escaped_path_sql = PQescapeLiteral(conn, escaped_path, strlen(escaped_path));
	char *extension_sql = PQescapeLiteral(conn, extension, strlen(extension));
    if (!isEscapedStringValid(name_sql, name, "TskDbPostgreSQL::addFile: Unable to escape file name string: %s\n")
        || !isEscapedStringValid(escaped_path_sql, escaped_path, "TskDbPostgreSQL::addFile: Unable to escape path string: %s\n")
		|| !isEscapedStringValid(extension_sql, extension, "TskDbPostgreSQL::addFile: Unable to escape extension string: %s\n")
		) {
			free(name);
            free(escaped_path);
            PQfreemem(name_sql);
            PQfreemem(escaped_path_sql);
			PQfreemem(extension_sql);
            return 1;
    }

    char zSQL_fixed[2048];
    zSQL_fixed[2047] = '\0';
    char *zSQL_dynamic = NULL; // Only used if the query does not fit in the fixed length buffer
    char *zSQL = zSQL_fixed;
    size_t bufLen = 2048;

    // Check if the path may be too long. The rest of the query should take up far less than 500 bytes.
    if (strlen(name_sql) + strlen(escaped_path_sql) + 500 > bufLen) {
        // The query may be long to fit in the standard buffer, so create a larger one.
        // This should be a very rare case and allows us to not use malloc most of the time.
        // The same buffer will be used for the slack file entry.
        bufLen = strlen(escaped_path_sql) + strlen(name_sql) + 500;
        if ((zSQL_dynamic = (char *)tsk_malloc(bufLen)) == NULL) {
			free(name);
            free(escaped_path);
            PQfreemem(escaped_path_sql);
            PQfreemem(name_sql);
			PQfreemem(extension_sql);
            return 1;
        }
        zSQL_dynamic[bufLen - 1] = '\0';
        zSQL = zSQL_dynamic;
    }

    if (0 > snprintf(zSQL, bufLen - 1, "INSERT INTO tsk_files (fs_obj_id, obj_id, data_source_obj_id, type, attr_type, attr_id, name, meta_addr, meta_seq, dir_type, meta_type, dir_flags, meta_flags, size, crtime, ctime, atime, mtime, mode, gid, uid, md5, known, parent_path,extension) "
        "VALUES ("
        "%" PRId64 ",%" PRId64 ","
        "%" PRId64 ","
        "%d,"
        "%d,%d,%s,"
        "%" PRIuINUM ",%d,"
        "%d,%d,%d,%d,"
        "%" PRIuOFF ","
        "%llu,%llu,%llu,%llu,"
        "%d,%d,%d,%s,%d,"
        "%s,%s)",
        fsObjId, objId,
        dataSourceObjId,
        TSK_DB_FILES_TYPE_FS,
        type, idx, name_sql,
        fs_file->name->meta_addr, fs_file->name->meta_seq,
        fs_file->name->type, meta_type, fs_file->name->flags, meta_flags,
        size,
        (unsigned long long)crtime, (unsigned long long)ctime, (unsigned long long) atime, (unsigned long long) mtime,
        meta_mode, gid, uid, md5TextPtr, known,
        escaped_path_sql, extension_sql)) {

            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_AUTO_DB);
            tsk_error_set_errstr("Error inserting file with object ID for: %" PRId64 , objId);
            free(zSQL_dynamic);
            free(name);
            free(escaped_path);
            PQfreemem(name_sql);
            PQfreemem(escaped_path_sql);
			PQfreemem(extension_sql);
            return 1;
    }

    if (attempt_exec(zSQL, "TskDbPostgreSQL::addFile: Error adding data to tsk_files table: %s\n")) {
		    free(name);
        free(escaped_path);
        PQfreemem(name_sql);
        PQfreemem(escaped_path_sql);
		PQfreemem(extension_sql);
		free(zSQL_dynamic);
		return 1;
	}


	std::string escaped_path_str = std::string(escaped_path);
	const char* full_description = (escaped_path_str + name).c_str();
	const size_t firstslash = escaped_path_str.find('/', 1);
	const char* root_folder = (firstslash == string::npos)
		                          ? escaped_path
		                          : escaped_path_str.substr(0, firstslash+1).c_str();
	char* full_desc_sql = PQescapeLiteral(conn, full_description, strlen(full_description));
	char* med_desc_sql = PQescapeLiteral(conn, escaped_path, strlen(escaped_path));
	char* short_desc_sql = PQescapeLiteral(conn, root_folder, strlen(root_folder));
	if (addMACTimeEvent(zSQL, dataSourceObjId, objId, mtime, 4, full_desc_sql, med_desc_sql, short_desc_sql)
		|| addMACTimeEvent(zSQL, dataSourceObjId, objId, atime, 5, full_desc_sql, med_desc_sql, short_desc_sql)
		|| addMACTimeEvent(zSQL, dataSourceObjId, objId, crtime, 6, full_desc_sql, med_desc_sql, short_desc_sql)
		|| addMACTimeEvent(zSQL, dataSourceObjId, objId, ctime, 7, full_desc_sql, med_desc_sql, short_desc_sql))
	{
		free(escaped_path);
		PQfreemem(name_sql);
		PQfreemem(escaped_path_sql);
		PQfreemem(extension_sql);
		free(zSQL_dynamic);
		PQfreemem(full_desc_sql);
		PQfreemem(med_desc_sql);
		PQfreemem(short_desc_sql);
		return 1;
	}

	PQfreemem(full_desc_sql);
	PQfreemem(med_desc_sql);
	PQfreemem(short_desc_sql);


    //if dir, update parent id cache (do this before objId may be changed creating the slack file)
    if (TSK_FS_IS_DIR_META(meta_type)){
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
    if((fs_attr != NULL)
           && ((strlen(name) > 0) && (!TSK_FS_ISDOT(name)))
           && (! (fs_file->meta->flags & TSK_FS_META_FLAG_COMP))
           && (fs_attr->flags & TSK_FS_ATTR_NONRES)
           && (fs_attr->nrd.allocsize >  fs_attr->nrd.initsize)){
		strncat(name, "-slack", 6);
		PQfreemem(name_sql);
		name_sql = PQescapeLiteral(conn, name, strlen(name));
		if (strlen(extension) > 0) { //if there was an extension, add "-slack" and escape it again.
			strncat(extension, "-slack", 6);
			PQfreemem(extension_sql);
			extension_sql = PQescapeLiteral(conn, extension, strlen(extension));
		}


        TSK_OFF_T slackSize = fs_attr->nrd.allocsize - fs_attr->nrd.initsize;

        if (addObject(TSK_DB_OBJECT_TYPE_FILE, parObjId, objId)) {
			free(name);
            free(escaped_path);
			PQfreemem(name_sql);
			PQfreemem(escaped_path_sql);
			PQfreemem(extension_sql);
            return 1;
        }

        if (0 > snprintf(zSQL, bufLen - 1, "INSERT INTO tsk_files (fs_obj_id, obj_id, data_source_obj_id, type, attr_type, attr_id, name, meta_addr, meta_seq, dir_type, meta_type, dir_flags, meta_flags, size, crtime, ctime, atime, mtime, mode, gid, uid, md5, known, parent_path, extension) "
            "VALUES ("
            "%" PRId64 ",%" PRId64 ","
            "%" PRId64 ","
            "%d,"
            "%d,%d,%s,"
            "%" PRIuINUM ",%d,"
            "%d,%d,%d,%d,"
            "%" PRIuOFF ","
            "%llu,%llu,%llu,%llu,"
            "%d,%d,%d,NULL,%d,"
            "%s, %s)",
            fsObjId, objId,
            dataSourceObjId,
            TSK_DB_FILES_TYPE_SLACK,
            type, idx, name_sql,
            fs_file->name->meta_addr, fs_file->name->meta_seq,
            TSK_FS_NAME_TYPE_REG, TSK_FS_META_TYPE_REG, fs_file->name->flags, meta_flags,
            slackSize,
            (unsigned long long)crtime, (unsigned long long)ctime,(unsigned long long) atime,(unsigned long long) mtime,
            meta_mode, gid, uid, known,
            escaped_path_sql,extension_sql)) {

                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_AUTO_DB);
                tsk_error_set_errstr("Error inserting slack file with object ID for: %" PRId64, objId);
				free(name);
                free(escaped_path);
                PQfreemem(name_sql);
                PQfreemem(escaped_path_sql);
                PQfreemem(extension_sql);
                free(zSQL_dynamic);
                return 1;
        }

        if (attempt_exec(zSQL, "TskDbPostgreSQL::addFile: Error adding data to tsk_files table: %s\n")) {
            free(name);
            free(escaped_path);
            PQfreemem(name_sql);
            PQfreemem(escaped_path_sql);	
            PQfreemem(extension_sql);
            free(zSQL_dynamic);
            return 1;
        }
    }

    // cleanup
    free(name);
    free(escaped_path);
    free(zSQL_dynamic);
    PQfreemem(name_sql);
    PQfreemem(escaped_path_sql);
	PQfreemem(extension_sql);
    return 0;
}


/**
* Find parent object id of TSK_FS_FILE. Use local cache map, if not found, fall back to SQL
* @param fs_file file to find parent obj id for
* @param parentPath Path of parent folder that we want to match
* @param fsObjId fs id of this file
* @returns parent obj id ( > 0), -1 on error
*/
int64_t TskDbPostgreSQL::findParObjId(const TSK_FS_FILE * fs_file, const char *parentPath, const int64_t & fsObjId) {
    uint32_t seq;
    uint32_t path_hash = hash((const unsigned char *)parentPath);

    /* NTFS uses sequence, otherwise we hash the path. We do this to map to the
    * correct parent folder if there are two from the root dir that eventually point to
    * the same folder (one deleted and one allocated) or two hard links. */
    if (TSK_FS_TYPE_ISNTFS(fs_file->fs_info->ftype)) {
        seq = fs_file->name->par_seq;
    }
    else {
        seq = path_hash;
    }

    //get from cache by parent meta addr, if available
    map<TSK_INUM_T, map<uint32_t, map<uint32_t, int64_t> > > &fsMap = m_parentDirIdCache[fsObjId];
    if (fsMap.count(fs_file->name->par_addr) > 0) {
        map<uint32_t, map<uint32_t, int64_t> > &fileMap = fsMap[fs_file->name->par_addr];
        if (fileMap.count(seq) > 0) {
            map<uint32_t, int64_t> &pathMap = fileMap[seq];
            if (pathMap.count(path_hash) > 0) {
                return pathMap[path_hash];
            }
        }
        else {
            // printf("Miss: %d\n", fileMap.count(seq));
        }
    }

    // Need to break up 'path' in to the parent folder to match in 'parent_path' and the folder
    // name to match with the 'name' column in tsk_files table
    const char *parent_name = "";
    const char *parent_path = "";
    if (TskDb::getParentPathAndName(parentPath, &parent_path, &parent_name)){
        return -1;
    }

    // escape strings for use within an SQL command
    char *escaped_path_sql = PQescapeLiteral(conn, parent_path, strlen(parent_path));
    char *escaped_parent_name_sql = PQescapeLiteral(conn, parent_name, strlen(parent_name));
    if (!isEscapedStringValid(escaped_path_sql, parent_path, "TskDbPostgreSQL::findParObjId: Unable to escape path string: %s\n")
        || !isEscapedStringValid(escaped_parent_name_sql, parent_name, "TskDbPostgreSQL::findParObjId: Unable to escape path string: %s\n")) {
            PQfreemem(escaped_path_sql);
            PQfreemem(escaped_parent_name_sql);
            return -1;
    }

    // Find the parent file id in the database using the parent metadata address
    // @@@ This should use sequence number when the new database supports it
    char zSQL_fixed[1024];
    zSQL_fixed[1023] = '\0';
    char *zSQL_dynamic = NULL; // Only used if the query does not fit in the fixed length buffer
    char *zSQL = zSQL_fixed;
    size_t bufLen = 1024;

    // Check if the path may be too long
    if (strlen(escaped_parent_name_sql) + strlen(escaped_path_sql) + 200 > bufLen) {
        // The parent path was too long to fit in the standard buffer, so create a larger one.
        // This should be a very rare case and allows us to not use malloc most of the time.
        bufLen = strlen(escaped_path_sql) + strlen(escaped_parent_name_sql) + 200;
        if ((zSQL_dynamic = (char *)tsk_malloc(bufLen)) == NULL) {
            PQfreemem(escaped_path_sql);
            PQfreemem(escaped_parent_name_sql);
            return -1;
        }
        zSQL_dynamic[bufLen - 1] = '\0';
        zSQL = zSQL_dynamic;
    }

    int expectedNumFileds = 1;
    if (0 > snprintf(zSQL, bufLen - 1, "SELECT obj_id FROM tsk_files WHERE meta_addr = %" PRIu64 " AND fs_obj_id = %" PRId64 " AND parent_path = %s AND name = %s",
        fs_file->name->par_addr, fsObjId, escaped_path_sql, escaped_parent_name_sql)) {

            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_AUTO_DB);
            tsk_error_set_errstr("Error creating query for parent object ID for: %s", parentPath);
            free(zSQL_dynamic);
            PQfreemem(escaped_path_sql);
            PQfreemem(escaped_parent_name_sql);
            return -1;
    }
    PGresult* res = get_query_result_set(zSQL, "TskDbPostgreSQL::findParObjId: Error selecting file id by meta_addr: %s (result code %d)\n");

    // check if a valid result set was returned
    if (verifyNonEmptyResultSetSize(zSQL, res, expectedNumFileds, "TskDbPostgreSQL::findParObjId: Unexpected number of columns in result set: Expected %d, Received %d\n")) {
        free(zSQL_dynamic);
        return -1;
    }

    int64_t parObjId = atoll(PQgetvalue(res, 0, 0));
    free(zSQL_dynamic);
    PQclear(res);
    PQfreemem(escaped_path_sql);
    PQfreemem(escaped_parent_name_sql);
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
* Store info about a directory in a complex map structure as a cache for the
* files who are a child of this directory and want to know its object id.
*
* @param fsObjId fs id of this directory
* @param fs_file File for the directory to store
* @param path Full path (parent and this file) of the directory
* @param objId object id of the directory
*/
void TskDbPostgreSQL::storeObjId(const int64_t & fsObjId, const TSK_FS_FILE *fs_file, const char *path, const int64_t & objId) {
    // skip the . and .. entries
    if ((fs_file->name) && (fs_file->name->name) && (TSK_FS_ISDOT(fs_file->name->name))) {
        return;
    }

    uint32_t seq;
    uint32_t path_hash = hash((const unsigned char *)path);

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
        seq = path_hash;
    }

    map<TSK_INUM_T, map<uint32_t, map<uint32_t, int64_t> > > &fsMap = m_parentDirIdCache[fsObjId];
    if (fsMap.count(fs_file->name->meta_addr) == 0) {
        fsMap[fs_file->name->meta_addr][seq][path_hash] = objId;
    }
    else {
        map<uint32_t, map<uint32_t, int64_t> > &fileMap = fsMap[fs_file->name->meta_addr];
        if (fileMap.count(seq) == 0) {
            fileMap[seq][path_hash] = objId;
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

    char zSQL[1024];
    int expectedNumFileds = 8;
    snprintf(zSQL, 1024,"SELECT obj_id, img_offset, fs_type, block_size, block_count, root_inum, first_inum, last_inum FROM tsk_fs_info");
    PGresult* res = get_query_result_set(zSQL, "TskDbPostgreSQL::getFsInfos: Error selecting from tsk_fs_info: %s (result code %d)\n");

    if (verifyResultSetSize(zSQL, res, expectedNumFileds, "TskDbPostgreSQL::getFsInfos: Error selecting from tsk_fs_info: %s")) {
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
            tsk_error_set_errstr("Error finding parent for: %" PRIu64 , fsObjId);
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

    char zSQL[1024];
    int expectedNumFileds = 3;
    snprintf(zSQL, 1024, "SELECT obj_id, par_obj_id, type FROM tsk_objects WHERE obj_id = %" PRId64 "", objId);

    PGresult* res = get_query_result_set(zSQL, "TskDbPostgreSQL::getObjectInfo: Error selecting object by objid: %s (result code %d)\n");

    // check if a valid result set was returned
    if (verifyNonEmptyResultSetSize(zSQL, res, expectedNumFileds, "TskDbPostgreSQL::getObjectInfo: Unexpected number of columns in result set: Expected %d, Received %d\n")) {
        return TSK_ERR;
    }

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
* @param dataSourceObjId The object Id of the data source
* @returns TSK_ERR on error or TSK_OK on success
*/
TSK_RETVAL_ENUM TskDbPostgreSQL::addVirtualDir(const int64_t fsObjId, const int64_t parentDirId, const char * const name, int64_t & objId, int64_t dataSourceObjId) {
    char zSQL[2048];

    if (addObject(TSK_DB_OBJECT_TYPE_FILE, parentDirId, objId))
        return TSK_ERR;

    // replace all non-UTF8 characters
    char name_local[MAX_DB_STRING_LENGTH];
    removeNonUtf8(name_local, MAX_DB_STRING_LENGTH - 1, name);

    // escape strings for use within an SQL command
    char *name_sql = PQescapeLiteral(conn, name_local, strlen(name_local));
    if (!isEscapedStringValid(name_sql, name_local, "TskDbPostgreSQL::addVirtualDir: Unable to escape file name string: %s\n")) {
        PQfreemem(name_sql);
        return TSK_ERR;
    }
    snprintf(zSQL, 2048, "INSERT INTO tsk_files (attr_type, attr_id, has_layout, fs_obj_id, obj_id, data_source_obj_id, type, "
        "name, meta_addr, meta_seq, dir_type, meta_type, dir_flags, meta_flags, size, "
        "crtime, ctime, atime, mtime, mode, gid, uid, known, parent_path) "
        "VALUES ("
        "NULL, NULL,"
        "NULL,"
        "%" PRId64 ","
        "%" PRId64 ","
        "%" PRId64 ","
        "%d,"
        "%s,"
        "NULL,NULL,"
        "%d,%d,%d,%d,"
        "0,"
        "NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,'/')",
        fsObjId,
        objId,
        dataSourceObjId,
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
* @param dataSourceObjId The object Id of the data source
* @returns TSK_ERR on error or TSK_OK on success
*/
TSK_RETVAL_ENUM TskDbPostgreSQL::addUnallocFsBlockFilesParent(const int64_t fsObjId, int64_t & objId, int64_t dataSourceObjId) {

    const char * const unallocDirName = "$Unalloc";

    //get root dir
    TSK_DB_OBJECT rootDirObjInfo;
    if (getFsRootDirObjectInfo(fsObjId, rootDirObjInfo) == TSK_ERR) {
        return TSK_ERR;
    }

    return addVirtualDir(fsObjId, rootDirObjInfo.objId, unallocDirName, objId, dataSourceObjId);
}

//internal function object to check for range overlap
typedef struct _checkFileLayoutRangeOverlap{
    const vector<TSK_DB_FILE_LAYOUT_RANGE> & ranges;
    bool hasOverlap;

    explicit _checkFileLayoutRangeOverlap(const vector<TSK_DB_FILE_LAYOUT_RANGE> & ranges)
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
* @param dataSourceObjId The object ID for the data source
* @returns TSK_OK on success or TSK_ERR on error.
*/
TSK_RETVAL_ENUM TskDbPostgreSQL::addUnallocBlockFile(const int64_t parentObjId, const int64_t fsObjId, const uint64_t size, vector<TSK_DB_FILE_LAYOUT_RANGE> & ranges, int64_t & objId, int64_t dataSourceObjId) {
    return addFileWithLayoutRange(TSK_DB_FILES_TYPE_UNALLOC_BLOCKS, parentObjId, fsObjId, size, ranges, objId, dataSourceObjId);
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
TSK_RETVAL_ENUM TskDbPostgreSQL::addUnusedBlockFile(const int64_t parentObjId, const int64_t fsObjId, const uint64_t size, vector<TSK_DB_FILE_LAYOUT_RANGE> & ranges, int64_t & objId, int64_t dataSourceObjId) {
    return addFileWithLayoutRange(TSK_DB_FILES_TYPE_UNUSED_BLOCKS, parentObjId, fsObjId, size, ranges, objId, dataSourceObjId);
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
TSK_RETVAL_ENUM TskDbPostgreSQL::addCarvedFile(const int64_t parentObjId, const int64_t fsObjId, const uint64_t size, vector<TSK_DB_FILE_LAYOUT_RANGE> & ranges, int64_t & objId, int64_t dataSourceObjId) {
    return addFileWithLayoutRange(TSK_DB_FILES_TYPE_CARVED, parentObjId, fsObjId, size, ranges, objId, dataSourceObjId);
}

/**
* Internal helper method to add unalloc, unused and carved files with layout ranges to db
* Generates file_name and populates tsk_files, tsk_objects and tsk_file_layout tables
* @param dataSourceObjId The object Id of the data source
* @returns TSK_ERR on error or TSK_OK on success
*/
TSK_RETVAL_ENUM TskDbPostgreSQL::addFileWithLayoutRange(const TSK_DB_FILES_TYPE_ENUM dbFileType, const int64_t parentObjId, const int64_t fsObjId, const uint64_t size, vector<TSK_DB_FILE_LAYOUT_RANGE> & ranges, int64_t & objId, int64_t dataSourceObjId) {
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
    if (addLayoutFileInfo(parentObjId, fsObjId, dbFileType, fileNameSs.str().c_str(), size, objId, dataSourceObjId) ) {
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
* @param dataSourceObjId The object Id of the data source
* @returns TSK_OK on success or TSK_ERR on error.
*/
TSK_RETVAL_ENUM TskDbPostgreSQL::addLayoutFileInfo(const int64_t parObjId, const int64_t fsObjId, const TSK_DB_FILES_TYPE_ENUM dbFileType, const char *fileName, const uint64_t size, int64_t & objId, int64_t dataSourceObjId)
{
    char zSQL[2048];

    if (addObject(TSK_DB_OBJECT_TYPE_FILE, parObjId, objId))
        return TSK_ERR;

    //fsObjId can be NULL
    char nullStr[8] = "NULL";
    char *fsObjIdStrPtr = NULL;
    char fsObjIdStr[32];
    if (fsObjId != 0) {
        snprintf(fsObjIdStr, 32, "%" PRIu64 , fsObjId);
        fsObjIdStrPtr = fsObjIdStr;
    } else {
        fsObjIdStrPtr = &nullStr[0];
    }

    // replace all non-UTF8 characters
    char fileName_local[MAX_DB_STRING_LENGTH];
    removeNonUtf8(fileName_local, MAX_DB_STRING_LENGTH - 1, fileName);

    // escape strings for use within an SQL command
    char *name_sql = PQescapeLiteral(conn, fileName_local, strlen(fileName_local));
    if (!isEscapedStringValid(name_sql, fileName_local, "TskDbPostgreSQL::addLayoutFileInfo: Unable to escape file name string: %s\n")) {
        PQfreemem(name_sql);
        return TSK_ERR;
    }
    snprintf(zSQL, 2048, "INSERT INTO tsk_files (has_layout, fs_obj_id, obj_id, data_source_obj_id, type, attr_type, attr_id, name, meta_addr, meta_seq, dir_type, meta_type, dir_flags, meta_flags, size, crtime, ctime, atime, mtime, mode, gid, uid) "
        "VALUES ("
        "1, %s, %" PRId64 ","
        "%" PRId64 ","
        "%d,"
        "NULL,NULL,%s,"
        "NULL,NULL,"
        "%d,%d,%d,%d,"
        "%" PRIuOFF ","
        "NULL,NULL,NULL,NULL,NULL,NULL,NULL)",
        fsObjIdStrPtr, objId,
        dataSourceObjId,
        dbFileType,
        name_sql,
        TSK_FS_NAME_TYPE_REG, TSK_FS_META_TYPE_REG,
        TSK_FS_NAME_FLAG_UNALLOC, TSK_FS_META_FLAG_UNALLOC, size);

    if (attempt_exec(zSQL, "TskDbSqlite::addLayoutFileInfo: Error adding data to tsk_files table: %s\n")) {
        PQfreemem(name_sql);
        return TSK_ERR;
    }

    //cleanup
    PQfreemem(name_sql);

    return TSK_OK;
}

/**
* Adds the sector addresses of the volumes into the db.
* @returns 1 on error, 0 on success
*/
int TskDbPostgreSQL::addVolumeInfo(const TSK_VS_PART_INFO * vs_part,
    int64_t parObjId, int64_t & objId)
{
    char zSQL[1024];
    int ret;

    if (addObject(TSK_DB_OBJECT_TYPE_VOL, parObjId, objId))
        return 1;

    // replace all non-UTF8 characters
    tsk_cleanupUTF8(vs_part->desc, '^');

    // escape strings for use within an SQL command
    char *descr_sql = PQescapeLiteral(conn, vs_part->desc, strlen(vs_part->desc));
    if (!isEscapedStringValid(descr_sql, vs_part->desc, "TskDbPostgreSQL::addVolumeInfo: Unable to escape partition description string: %s\n")) {
        PQfreemem(descr_sql);
        return TSK_ERR;
    }

    snprintf(zSQL, 1024, "INSERT INTO tsk_vs_parts (obj_id, addr, start, length, descr, flags)"
        "VALUES (%" PRId64 ", %" PRIuPNUM ",%" PRIuOFF ",%" PRIuOFF ",%s,%d)",
        objId, (int) vs_part->addr, vs_part->start, vs_part->len,
        descr_sql, vs_part->flags);

    ret = attempt_exec(zSQL, "Error adding data to tsk_vs_parts table: %s\n");
    //cleanup
    PQfreemem(descr_sql);
    return ret;
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
int TskDbPostgreSQL::addFileLayoutRange(int64_t a_fileObjId, uint64_t a_byteStart, uint64_t a_byteLen, int a_sequence)
{
    char foo[1024];

    snprintf(foo, 1024, "INSERT INTO tsk_file_layout(obj_id, byte_start, byte_len, sequence) VALUES (%" PRId64 ", %" PRIu64 ", %" PRIu64 ", %d)",
        a_fileObjId, a_byteStart, a_byteLen, a_sequence);

    return attempt_exec(foo, "Error adding data to tsk_file_layout table: %s\n");
}

/**
* Add file layout info to the database.  This table stores the run information for each file so that we
* can map which parts of an image are used by what files.
* @param fileLayoutRange TSK_DB_FILE_LAYOUT_RANGE object storing a single file layout range entry
* @returns 1 on error
*/
int TskDbPostgreSQL::addFileLayoutRange(const TSK_DB_FILE_LAYOUT_RANGE & fileLayoutRange) {
    return addFileLayoutRange(fileLayoutRange.fileObjId, fileLayoutRange.byteStart, fileLayoutRange.byteLen, fileLayoutRange.sequence);
}


/**
* Query tsk_vs_part and return rows for every entry in tsk_vs_part table
* @param imgId the object id of the image to get vs parts for
* @param vsPartInfos (out) TSK_DB_VS_PART_INFO row representations to return
* @returns TSK_ERR on error, TSK_OK on success
*/
TSK_RETVAL_ENUM TskDbPostgreSQL::getVsPartInfos(int64_t imgId, vector<TSK_DB_VS_PART_INFO> & vsPartInfos) {

    char zSQL[512];
    int expectedNumFileds = 6;
    snprintf(zSQL, 512, "SELECT obj_id, addr, start, length, descr, flags FROM tsk_vs_parts");

    PGresult* res = get_query_result_set(zSQL, "TskDbPostgreSQL::getVsPartInfos: Error selecting from tsk_vs_parts: %s (result code %d)\n");

    // check if a valid result set was returned
    if (verifyResultSetSize(zSQL, res, expectedNumFileds, "TskDbPostgreSQL::getVsPartInfos: Error selecting from tsk_vs_parts: %s")) {
        return TSK_ERR;
    }

    //get rows
    TSK_DB_VS_PART_INFO rowData;
    for (int i = 0; i < PQntuples(res); i++) {

        int64_t vsPartObjId = atoll(PQgetvalue(res, i, 0));

        int64_t curImgId = 0;
        if (getParentImageId(vsPartObjId, curImgId) == TSK_ERR) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_AUTO_DB);
            tsk_error_set_errstr("Error finding parent for: %" PRIu64 , vsPartObjId);
            return TSK_ERR;
        }

        if (imgId != curImgId) {
            //ensure vs is (sub)child of the image requested, if not, skip it
            continue;
        }


        rowData.objId = vsPartObjId;
        rowData.addr = atoi(PQgetvalue(res, i, 1));
        rowData.start = atoll(PQgetvalue(res, i, 2));
        rowData.len = atoll(PQgetvalue(res, i, 3));
        char * text = PQgetvalue(res, i, 4);
        size_t textLen = PQgetlength(res, i, 4);
        const size_t copyChars = textLen < TSK_MAX_DB_VS_PART_INFO_DESC_LEN-1?textLen:TSK_MAX_DB_VS_PART_INFO_DESC_LEN-1;
        strncpy (rowData.desc,(char*)text,copyChars);
        rowData.desc[copyChars] = '\0';
        rowData.flags = (TSK_VS_PART_FLAG_ENUM)atoi(PQgetvalue(res, i, 5));
        //insert a copy of the rowData
        vsPartInfos.push_back(rowData);
    }

    //cleanup
    PQclear(res);

    return TSK_OK;
}

/**
* Query tsk_objects and tsk_files given file system id and return the root directory object
* @param fsObjId (int) file system id to query root dir object for
* @param rootDirObjInfo (out) TSK_DB_OBJECT root dir entry representation to return
* @returns TSK_ERR on error (or if not found), TSK_OK on success
*/
TSK_RETVAL_ENUM TskDbPostgreSQL::getFsRootDirObjectInfo(const int64_t fsObjId, TSK_DB_OBJECT & rootDirObjInfo) {

    char zSQL[1024];
    int expectedNumFileds = 3;
    snprintf(zSQL, 1024, "SELECT tsk_objects.obj_id,tsk_objects.par_obj_id,tsk_objects.type "
        "FROM tsk_objects,tsk_files WHERE tsk_objects.par_obj_id = %" PRId64 " AND tsk_files.obj_id = tsk_objects.obj_id AND tsk_files.name = ''",
        fsObjId);

    PGresult* res = get_query_result_set(zSQL, "TskDbPostgreSQL::getFsRootDirObjectInfo: Error selecting from tsk_objects,tsk_files: %s (result code %d)\n");

    // check if a valid result set was returned
    if (verifyNonEmptyResultSetSize(zSQL, res, expectedNumFileds, "TskDbPostgreSQL::getFsRootDirObjectInfo: Unexpected number of columns in result set: Expected %d, Received %d\n")) {
        return TSK_ERR;
    }

    rootDirObjInfo.objId = atoll(PQgetvalue(res, 0, 0));
    rootDirObjInfo.parObjId = atoll(PQgetvalue(res, 0, 1));
    rootDirObjInfo.type = (TSK_DB_OBJECT_TYPE_ENUM)atoi(PQgetvalue(res, 0, 2));

    //cleanup
    PQclear(res);

    return TSK_OK;
}

/**
* Query tsk_file_layout and return rows for every entry in tsk_file_layout table
* @param fileLayouts (out) TSK_DB_FILE_LAYOUT_RANGE row representations to return
* @returns TSK_ERR on error, TSK_OK on success
*/
TSK_RETVAL_ENUM TskDbPostgreSQL::getFileLayouts(vector<TSK_DB_FILE_LAYOUT_RANGE> & fileLayouts) {

    char zSQL[512];
    int expectedNumFileds = 4;
    snprintf(zSQL, 512, "SELECT obj_id, byte_start, byte_len, sequence FROM tsk_file_layout");

    PGresult* res = get_query_result_set(zSQL, "TskDbPostgreSQL::getFileLayouts: Error selecting from tsk_file_layout: %s (result code %d)\n");

    // check if a valid result set was returned
    if (verifyResultSetSize(zSQL, res, expectedNumFileds, "TskDbPostgreSQL::getFileLayouts: Error selecting from tsk_file_layout: %s")) {
        return TSK_ERR;
    }

    //get rows
    TSK_DB_FILE_LAYOUT_RANGE rowData;
    for (int i = 0; i < PQntuples(res); i++) {

        rowData.fileObjId = atoll(PQgetvalue(res, i, 0));
        rowData.byteStart = atoll(PQgetvalue(res, i, 1));
        rowData.byteLen = atoll(PQgetvalue(res, i, 2));
        rowData.sequence = atoi(PQgetvalue(res, i, 3));

        //insert a copy of the rowData
        fileLayouts.push_back(rowData);
    }

    //cleanup
    PQclear(res);

    return TSK_OK;
}


/**
* Query tsk_vs_info and return rows for every entry in tsk_vs_info table
* @param imgId the object id of the image to get volumesystems for
* @param vsInfos (out) TSK_DB_VS_INFO row representations to return
* @returns TSK_ERR on error, TSK_OK on success
*/
TSK_RETVAL_ENUM TskDbPostgreSQL::getVsInfos(int64_t imgId, vector<TSK_DB_VS_INFO> & vsInfos) {

    char zSQL[512];
    int expectedNumFileds = 4;
    snprintf(zSQL, 512, "SELECT obj_id, vs_type, img_offset, block_size FROM tsk_vs_info");

    PGresult* res = get_query_result_set(zSQL, "TskDbPostgreSQL::getVsInfos: Error selecting from tsk_vs_info: %s (result code %d)\n");

    // check if a valid result set was returned
    if (verifyResultSetSize(zSQL, res, expectedNumFileds, "TskDbPostgreSQL::getVsInfos: Error selecting from tsk_vs_info: %s")) {
        return TSK_ERR;
    }

    //get rows
    TSK_DB_VS_INFO rowData;
    for (int i = 0; i < PQntuples(res); i++) {

        int64_t vsObjId = atoll(PQgetvalue(res, i, 0));

        int64_t curImgId = 0;
        if (getParentImageId(vsObjId, curImgId) == TSK_ERR) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_AUTO_DB);
            tsk_error_set_errstr("Error finding parent for: %" PRIu64 , vsObjId);
            PQclear(res);
            return TSK_ERR;
        }

        if (imgId != curImgId ) {
            //ensure vs is (sub)child of the image requested, if not, skip it
            continue;
        }

        rowData.objId = vsObjId;
        rowData.vstype = (TSK_VS_TYPE_ENUM)atoi(PQgetvalue(res, i, 1));
        rowData.offset = atoll(PQgetvalue(res, i, 2));
        rowData.block_size = (unsigned int)atoi(PQgetvalue(res, i, 3));

        //insert a copy of the rowData
        vsInfos.push_back(rowData);
    }

    //cleanup
    PQclear(res);

    return TSK_OK;
}

/**
* Create a savepoint.  Call revertSavepoint() or releaseSavepoint()
* to revert or commit.
* @param name Name to call savepoint
* @returns 1 on error, 0 on success
*/
int TskDbPostgreSQL::createSavepoint(const char *name)
{
    char buff[1024];

    // In PostgreSQL savepoints can only be established when inside a transaction block.
    // NOTE: this will only work if we have 1 savepoint. If we use multiple savepoints, PostgreSQL will
    // not allow us to call "BEGIN" inside a transaction. We will need to keep track of whether we are
    // in transaction and only call "BEGIN" if we are not in transaction. Alternatively we can keep
    // calling "BEGIN" every time we create a savepoint and simply ignore the error if there is one.
    // Also see note inside TskDbPostgreSQL::releaseSavepoint().
    snprintf(buff, 1024, "BEGIN;");
    if (attempt_exec(buff, "Error starting transaction: %s\n")) {
        return 1;
    }

    snprintf(buff, 1024, "SAVEPOINT %s", name);

    return attempt_exec(buff, "Error setting savepoint: %s\n");
}

/**
* Rollback to specified savepoint and release
* @param name Name of savepoint
* @returns 1 on error, 0 on success
*/
int TskDbPostgreSQL::revertSavepoint(const char *name)
{
    char buff[1024];

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
int TskDbPostgreSQL::releaseSavepoint(const char *name)
{
    char buff[1024];

    snprintf(buff, 1024, "RELEASE SAVEPOINT %s", name);

    if (attempt_exec(buff, "Error releasing savepoint: %s\n")) {
        return 1;
    }

    // In PostgreSQL savepoints can only be used inside a transaction block.
    // NOTE: see note inside TskDbPostgreSQL::createSavepoint(). This will only work if we have 1 savepoint.
    // If we add more savepoints we will need to keep track of where we are in transaction and only call
    // "COMMIT" when releasing the outer most savepoint.
    snprintf(buff, 1024, "COMMIT;");

    return attempt_exec(buff, "Error committing transaction: %s\n");
}

/**
* Returns true if database is opened.
*/
bool TskDbPostgreSQL::isDbOpen()
{
    if (conn) {
        PGconn *serverConn = connectToDatabase(&m_dBName[0]);
        if (!serverConn) {
            return false;
        }
        PQfinish(serverConn);
        return true;
    }
    else {
        return false;
    }
}

/**
* Returns true if database is in transaction.
*/
bool TskDbPostgreSQL::inTransaction() {

    // In PostgreSQL nested BEGIN calls are not allowed. Therefore if we get an error when executing "BEGIN" query then we are inside a transaction.
    if (!conn)
        return false;

    char sql[32];
    snprintf(sql, 32, "BEGIN;");

    PGresult *res = PQexec(conn, sql);
    if (PQresultStatus(res) != PGRES_COMMAND_OK)
    {
        // PostgreSQL returned error, therefore we are inside a transaction block
        PQclear(res);
        return true;
    }

    // If we are here then we were not inside a transaction. Undo the "BEGIN".
    snprintf(sql, 32, "COMMIT;");
    res = PQexec(conn, sql);
    if (PQresultStatus(res) != PGRES_COMMAND_OK)
    {
        // how can this happen? and what to return in this scenario? I guess we are not in transaction since we couldn't "commit".
        PQclear(res);
        return false;
    }
    PQclear(res);
    return false;
}


/* ELTODO: These functions will be needed when functionality to get PostgreSQL queries in binary format is added.
// PostgreSQL returns binary results in network byte order so then need to be converted to local byte order.
int64_t ntoh64(int64_t *input)
{
    int64_t rval;
    uint8_t *data = (uint8_t *)&rval;

    data[0] = *input >> 56;
    data[1] = *input >> 48;
    data[2] = *input >> 40;
    data[3] = *input >> 32;
    data[4] = *input >> 24;
    data[5] = *input >> 16;
    data[6] = *input >> 8;
    data[7] = *input >> 0;

    return rval;
}


template <typename T>
static inline T
hton_any(T &input)
{
    T output(0);
    std::size_t size = sizeof(input) - 1;
    uint8_t *data = reinterpret_cast<uint8_t *>(&output);

    for (std::size_t i = 0; i < size; i++) {
        data[i] = input >> ((size - i) * 8);
    }

    return output;
}*/

#endif // HAVE_LIBPQ_

