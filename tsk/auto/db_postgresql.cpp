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
{
    conn = NULL;
    wcsncpy(m_dbFilePath, a_dbFilePath, 1024);
}

TskDbPostgreSQL::~TskDbPostgreSQL()
{

}

int TskDbPostgreSQL::setLogInInfo(){

    strncpy(userName, "postgres___s", sizeof(userName));
    strncpy(password, "simple41", sizeof(password));
    strncpy(dbName, "testdb", sizeof(dbName));
    strncpy(hostIpAddr, "127.0.0.1", sizeof(hostIpAddr));
    strncpy(hostPort, "5432", sizeof(hostPort));

    return 0;
}

int TskDbPostgreSQL::open(bool flag)
{
    conn = NULL;

    // Make a connection to the database
    char connectionString[2048];
    sprintf(connectionString, "user=%s password=%s dbname=%s hostaddr=%s port=%s", userName, password, dbName, hostIpAddr, hostPort);
    conn = PQconnectdb(connectionString);

    // Check to see that the backend connection was successfully made 
    if (PQstatus(conn) != CONNECTION_OK)
    {
        printf("Connection to database failed");
        close();
        return -1;
    }

    printf("Connection to database - OK\n");

    return 0;
}

/*
* Close PostgreSQL database.
* Return 0 on success, 1 on failure
*/
int TskDbPostgreSQL::close()
{
    // EL: TODO need to surround this with try/catch. Otherwise if we close database second time an exception is thrown.
    PQfinish(conn);
    return 0;
}

#endif // TSK_WIN32
#endif // HAVE_POSTGRESQL