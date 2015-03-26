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

//    const char *conninfo;
//    conninfo = "dbname = el_testdb";
//    PGconn *dbConn = PQconnectdb(conninfo);

    // Check to see that the backend connection was successfully made 
    if (PQstatus(dbConn) != CONNECTION_OK)
    {
        ConnStatusType connStatus = PQstatus(dbConn);
        printf("Connection to PostgreSQL database failed");
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

    // if need different encoding we can use this:
    // CREATE DATABASE dBname WITH ENCODING='UTF8';

    char createDbString[512];
    sprintf(createDbString, "CREATE DATABASE %S;", m_dBName);
	PGresult *res = PQexec(serverConn, createDbString);    
    if (PQresultStatus(res) != PGRES_COMMAND_OK)
    {
        printf("Database creation failed");
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

    // Poll PostreSQL server for existing databases. PostgreSQL database names are case sensitive   
    char selectString[512];
    sprintf(selectString, "select count(*) from pg_catalog.pg_database where datname = '%S';", m_dBName);

	PGresult *res = PQexec(serverConn, selectString);
    if (PQresultStatus(res) != PGRES_TUPLES_OK)
    {
        printf("Existing database lookup failed");
        numDb = 0;
    } else {
        // number of existing databases that matched name (if search is case sensitive then max is 1)
        numDb = atoi(PQgetvalue(res, 0, 0));
    }

    PQclear(res);
    PQfinish(serverConn);

    if (numDb > 0)
        return true;

    return false;
}



// NOT IMPLEMENTED:

    int TskDbPostgreSQL::initialize() { return 0;}
    int TskDbPostgreSQL::addImageInfo(int type, int size, int64_t & objId, const string & timezone) {        return 0; }

    int TskDbPostgreSQL::addImageInfo(int type, int size, int64_t & objId, const string & timezone, TSK_OFF_T, const string &md5){        return 0; }
    int TskDbPostgreSQL::addImageName(int64_t objId, char const *imgName, int sequence){        return 0; }
    int TskDbPostgreSQL::addVsInfo(const TSK_VS_INFO * vs_info, int64_t parObjId,
        int64_t & objId){        return 0; }
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