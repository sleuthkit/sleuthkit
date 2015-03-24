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

#include "tsk_db_postgresql.h"

/**
* Set the locations and logging object.  Must call
* open() before the object can be used.
*/
TskDbPostgreSQL::TskDbPostgreSQL(const char *a_dbFilePathUtf8, bool a_blkMapFlag)
{
    conn = NULL;
    strncpy(m_dbFilePathUtf8, a_dbFilePathUtf8, 1024);
}

#ifdef TSK_WIN32
//@@@@
TskDbPostgreSQL::TskDbPostgreSQL(const TSK_TCHAR * a_dbFilePath, bool a_blkMapFlag)
{
    conn = NULL;
    wcsncpy(m_dbFilePath, a_dbFilePath, 1024);
}
#endif

TskDbPostgreSQL::~TskDbPostgreSQL()
{

}

int TskDbPostgreSQL::open(bool flag)
{
    conn = NULL;

  // Make a connection to the database
  conn = PQconnectdb("user=postgres password=simple41 dbname=testdb hostaddr=127.0.0.1 port=5432");

  // Check to see that the backend connection was successfully made 
    if (PQstatus(conn) != CONNECTION_OK)
    {
        printf("Connection to database failed");
        close();
    }

  printf("Connection to database - OK\n");

    return 0;
}
/*
* Close the Sqlite database.
* Return 0 on success, 1 on failure
*/
int TskDbPostgreSQL::close()
{
    PQfinish(conn);
    getchar();
    exit(1);
    return 0;
}

