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

    /* disable synchronous for loading the DB since we have no crash recovery anyway...
    if (attempt_exec("PRAGMA synchronous =  OFF;",
        "Error setting PRAGMA synchronous: %s\n")) {
            return 1;
    }*/

    /* allow to read while in transaction
    if (attempt_exec("PRAGMA read_uncommitted = True;",
        "Error setting PRAGMA read_uncommitted: %s\n")) {
            return 1;
    }*/

    // In PostgreSQL READ UNCOMMITTED is treated as READ COMMITTED.
    /*if (attempt_exec("SET TRANSACTION READ COMMITTED;",
        "Error setting transaction mode: %s\n")) {
            return 1;
    }*/

    /* Every PostgreSQL table and index is stored as an array of pages of a fixed size (usually 8 kB, although a different page size can be selected when compiling the server)
    if (attempt_exec("PRAGMA page_size = 4096;",
        "Error setting PRAGMA page_size: %s\n")) {
            return 1;
    }*/

    /* PostgreSQL has foreign keys enabled
    if (attempt_exec("PRAGMA foreign_keys = ON;",
        "Error setting PRAGMA foreign_keys: %s\n")) {
            return 1;
    }*/

    // increase the DB by 1MB at a time -- supposed to help performance when populating
    /*int chunkSize = 1024 * 1024;
    if (sqlite3_file_control(m_db, NULL, SQLITE_FCNTL_CHUNK_SIZE, &chunkSize) != SQLITE_OK) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr("TskDbSqlite::initialze: error setting chunk size %s", sqlite3_errmsg(m_db));
        return 1;
    }*/

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
        ("CREATE TABLE tsk_objects (obj_id SERIAL PRIMARY KEY, par_obj_id INTEGER, type INTEGER NOT NULL);",
        "Error creating tsk_objects table: %s\n")
        ||
        attempt_exec
        ("CREATE TABLE tsk_image_info (obj_id INTEGER PRIMARY KEY, type INTEGER, ssize INTEGER, tzone TEXT, size INTEGER, md5 TEXT, display_name TEXT, FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id));",
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
        ("CREATE TABLE tsk_fs_info (obj_id INTEGER PRIMARY KEY, img_offset INTEGER NOT NULL, fs_type INTEGER NOT NULL, block_size INTEGER NOT NULL, block_count INTEGER NOT NULL, root_inum INTEGER NOT NULL, first_inum INTEGER NOT NULL, last_inum INTEGER NOT NULL, display_name TEXT, FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id));",
        "Error creating tsk_fs_info table: %s\n")
        ||
        attempt_exec
        ("CREATE TABLE tsk_files (obj_id INTEGER PRIMARY KEY, fs_obj_id INTEGER, attr_type INTEGER, attr_id INTEGER, name TEXT NOT NULL, meta_addr INTEGER, meta_seq INTEGER, type INTEGER, has_layout INTEGER, has_path INTEGER, dir_type INTEGER, meta_type INTEGER, dir_flags INTEGER, meta_flags INTEGER, size INTEGER, ctime INTEGER, crtime INTEGER, atime INTEGER, mtime INTEGER, mode INTEGER, uid INTEGER, gid INTEGER, md5 TEXT, known INTEGER, parent_path TEXT, "
        "FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id), FOREIGN KEY(fs_obj_id) REFERENCES tsk_fs_info(obj_id));",
        "Error creating tsk_files table: %s\n")
        ||
        attempt_exec
        ("CREATE TABLE tsk_files_path (obj_id INTEGER PRIMARY KEY, path TEXT NOT NULL, FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id))",
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
        ("CREATE TABLE tag_names (tag_name_id INTEGER PRIMARY KEY, display_name TEXT UNIQUE, description TEXT NOT NULL, color TEXT NOT NULL)",
        "Error creating tag_names table: %s\n")
        ||
        attempt_exec
        ("CREATE TABLE content_tags (tag_id INTEGER PRIMARY KEY, obj_id INTEGER NOT NULL, tag_name_id INTEGER NOT NULL, comment TEXT NOT NULL, begin_byte_offset INTEGER NOT NULL, end_byte_offset INTEGER NOT NULL, "
        "FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id), FOREIGN KEY(tag_name_id) REFERENCES tag_names(tag_name_id))",
        "Error creating content_tags table: %s\n")
        ||
        attempt_exec
        ("CREATE TABLE blackboard_artifact_types (artifact_type_id INTEGER PRIMARY KEY, type_name TEXT NOT NULL, display_name TEXT)",
        "Error creating blackboard_artifact_types table: %s\n")
        ||
        attempt_exec
        ("CREATE TABLE blackboard_attribute_types (attribute_type_id INTEGER PRIMARY KEY, type_name TEXT NOT NULL, display_name TEXT)",
        "Error creating blackboard_attribute_types table: %s\n")
        ||
        attempt_exec
        ("CREATE TABLE blackboard_artifacts (artifact_id INTEGER PRIMARY KEY, obj_id INTEGER NOT NULL, artifact_type_id INTEGER NOT NULL, "
        "FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id), FOREIGN KEY(artifact_type_id) REFERENCES blackboard_artifact_types(artifact_type_id))",
        "Error creating blackboard_artifact table: %s\n")
        ||
        attempt_exec
        ("CREATE TABLE blackboard_artifact_tags (tag_id INTEGER PRIMARY KEY, artifact_id INTEGER NOT NULL, tag_name_id INTEGER NOT NULL, comment TEXT NOT NULL, "
        "FOREIGN KEY(artifact_id) REFERENCES blackboard_artifacts(artifact_id), FOREIGN KEY(tag_name_id) REFERENCES tag_names(tag_name_id))",
        "Error creating blackboard_artifact_tags table: %s\n")
        ||
        attempt_exec
        ("CREATE TABLE blackboard_attributes (artifact_id INTEGER NOT NULL, artifact_type_id INTEGER NOT NULL, source TEXT, context TEXT, attribute_type_id INTEGER NOT NULL, value_type INTEGER NOT NULL, "
        "value_byte BYTEA, value_text TEXT, value_int32 INTEGER, value_int64 INTEGER, value_double NUMERIC(20, 10), "
        "FOREIGN KEY(artifact_id) REFERENCES blackboard_artifacts(artifact_id), FOREIGN KEY(artifact_type_id) REFERENCES blackboard_artifact_types(artifact_type_id), FOREIGN KEY(attribute_type_id) REFERENCES blackboard_attribute_types(attribute_type_id))",
        "Error creating blackboard_attribute table: %s\n")
        ||
        /* In PostgreSQL "desc" indicates "descending order" so I had to rename "desc TEXT" to "descr TEXT" 
        ELTODO: make sure all insert queries have "descr". Should I also make this change for SQLite?*/
        attempt_exec
        ("CREATE TABLE tsk_vs_parts (obj_id INTEGER PRIMARY KEY, addr INTEGER NOT NULL, start INTEGER NOT NULL, length INTEGER NOT NULL, descr TEXT, flags INTEGER NOT NULL, FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id));",
        "Error creating tsk_vol_info table: %s\n")
        ||
        attempt_exec
        ("CREATE TABLE reports (report_id INTEGER PRIMARY KEY, path TEXT NOT NULL, crtime INTEGER NOT NULL, src_module_name TEXT NOT NULL, report_name TEXT NOT NULL)",
            "Error creating reports table: %s\n")) {
        return 1;
    }

    if (m_blkMapFlag) {
        if (attempt_exec
            ("CREATE TABLE tsk_file_layout (obj_id INTEGER NOT NULL, byte_start INTEGER NOT NULL, byte_len INTEGER NOT NULL, sequence INTEGER NOT NULL, FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id));",
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
* @returns 1 on error, 0 on success
*/
uint8_t
    TskDbPostgreSQL::addObject(TSK_DB_OBJECT_TYPE_ENUM type, int64_t parObjId,
    int64_t & objId)
{
    char stmt[1024];

//    snprintf(stmt, 1024, "INSERT INTO tsk_objects (obj_id, par_obj_id, type) VALUES (NULL, %d, %d)", 
//        parObjId, type);
    snprintf(stmt, 1024, "INSERT INTO tsk_objects (par_obj_id, type) VALUES (%d, %d)", 
        parObjId, type);

    if (attempt_exec(stmt, "TskDbSqlite::addObj: Error adding object to row: %s (result code %d)\n")) {
        return 1;
    }

    // ELTODO: use "RETURNING oid" in SQL command instead to get last insterted row id.
//    objId = sqlite3_last_insert_rowid(m_db);
    objId = 1;

    return 0;
}


/**
* @returns 1 on error, 0 on success
*/
int
    TskDbPostgreSQL::addVsInfo(const TSK_VS_INFO * vs_info, int64_t parObjId,
    int64_t & objId)
{
    char stmt[1024];

    if (addObject(TSK_DB_OBJECT_TYPE_VS, parObjId, objId))
        return 1;

    snprintf(stmt, 1024,
        "INSERT INTO tsk_vs_info (obj_id, vs_type, img_offset, block_size) VALUES (%lld, %d,%"
        PRIuOFF ",%d)", objId, vs_info->vstype, vs_info->offset,
        vs_info->block_size);

    return attempt_exec(stmt, "Error adding data to tsk_vs_info table: %s\n");
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

    int64_t parObjId = 41;
    int64_t objId;
    int error = addVsInfo(&vsInfo, parObjId, objId);
    int a = 9;
};


// NOT IMPLEMENTED:


    int TskDbPostgreSQL::addImageInfo(int type, int size, int64_t & objId, const string & timezone) {        return 0; }

    int TskDbPostgreSQL::addImageInfo(int type, int size, int64_t & objId, const string & timezone, TSK_OFF_T, const string &md5){        return 0; }
    int TskDbPostgreSQL::addImageName(int64_t objId, char const *imgName, int sequence){        return 0; }
    int TskDbPostgreSQL::addVolumeInfo(const TSK_VS_PART_INFO * vs_part, int64_t parObjId,
        int64_t & objId){        return 0; }
    int TskDbPostgreSQL::addFsInfo(const TSK_FS_INFO * fs_info, int64_t parObjId,
        int64_t & objId){        return 0; }
    int TskDbPostgreSQL::addFsFile(TSK_FS_FILE * fs_file, const TSK_FS_ATTR * fs_attr,
        const char *path, const unsigned char *const md5,
        const TSK_DB_FILES_KNOWN_ENUM known, int64_t fsObjId,
        int64_t & objId){        return 0; }

    TSK_RETVAL_ENUM TskDbPostgreSQL::addVirtualDir(const int64_t fsObjId, const int64_t parentDirId, const char * const name, int64_t & objId) { return TSK_OK;}
    TSK_RETVAL_ENUM TskDbPostgreSQL::addUnallocFsBlockFilesParent(const int64_t fsObjId, int64_t & objId) { return TSK_OK;}
    TSK_RETVAL_ENUM TskDbPostgreSQL::addUnallocBlockFile(const int64_t parentObjId, const int64_t fsObjId, const uint64_t size, 
        vector<TSK_DB_FILE_LAYOUT_RANGE> & ranges, int64_t & objId) { return TSK_OK;}
    TSK_RETVAL_ENUM TskDbPostgreSQL::addUnusedBlockFile(const int64_t parentObjId, const int64_t fsObjId, const uint64_t size, 
        vector<TSK_DB_FILE_LAYOUT_RANGE> & ranges, int64_t & objId) { return TSK_OK;}
    TSK_RETVAL_ENUM TskDbPostgreSQL::addCarvedFile(const int64_t parentObjId, const int64_t fsObjId, const uint64_t size, 
        vector<TSK_DB_FILE_LAYOUT_RANGE> & ranges, int64_t & objId) { return TSK_OK;}
    
    int TskDbPostgreSQL::addFileLayoutRange(const TSK_DB_FILE_LAYOUT_RANGE & fileLayoutRange){return 0; }
    int TskDbPostgreSQL::addFileLayoutRange(int64_t a_fileObjId, uint64_t a_byteStart, uint64_t a_byteLen, int a_sequence){return 0; }
    
    bool TskDbPostgreSQL::isDbOpen() const {return true;}
    int TskDbPostgreSQL::createSavepoint(const char *name){ return 0; }
    int TskDbPostgreSQL::revertSavepoint(const char *name){ return 0; }
    int TskDbPostgreSQL::releaseSavepoint(const char *name){ return 0; }
    bool TskDbPostgreSQL::inTransaction() { return true;}

    //query methods / getters
    TSK_RETVAL_ENUM TskDbPostgreSQL::getFileLayouts(vector<TSK_DB_FILE_LAYOUT_RANGE> & fileLayouts) { return TSK_OK;}
    TSK_RETVAL_ENUM TskDbPostgreSQL::getFsInfos(int64_t imgId, vector<TSK_DB_FS_INFO> & fsInfos) { return TSK_OK;}
    TSK_RETVAL_ENUM TskDbPostgreSQL::getVsInfos(int64_t imgId, vector<TSK_DB_VS_INFO> & vsInfos) { return TSK_OK;}
    TSK_RETVAL_ENUM TskDbPostgreSQL::getVsInfo(int64_t objId, TSK_DB_VS_INFO & vsInfo) { return TSK_OK;}
    TSK_RETVAL_ENUM TskDbPostgreSQL::getVsPartInfos(int64_t imgId, vector<TSK_DB_VS_PART_INFO> & vsPartInfos) { return TSK_OK;}
    TSK_RETVAL_ENUM TskDbPostgreSQL::getObjectInfo(int64_t objId, TSK_DB_OBJECT & objectInfo) { return TSK_OK;}
    TSK_RETVAL_ENUM TskDbPostgreSQL::getParentImageId (const int64_t objId, int64_t & imageId) { return TSK_OK;}
    TSK_RETVAL_ENUM TskDbPostgreSQL::getFsRootDirObjectInfo(const int64_t fsObjId, TSK_DB_OBJECT & rootDirObjInfo) { return TSK_OK;}

#endif // TSK_WIN32
#endif // HAVE_POSTGRESQL