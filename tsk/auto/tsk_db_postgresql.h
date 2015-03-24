/*
 ** The Sleuth Kit 
 **
 ** Brian Carrier [carrier <at> sleuthkit [dot] org]
 ** Copyright (c) 2011-2012 Brian Carrier.  All Rights reserved
 **
 ** This software is distributed under the Common Public License 1.0
 **
 */

/**
 * \file tsk_db_postgresql.h
 * Contains the PostgreSQL code for maintaining the case-level database.
 * The class is an extension of TSK abstract database handling class. 
 */


#ifndef _TSK_DB_POSTGRESQL_H
#define _TSK_DB_POSTGRESQL_H

#include "tsk_db.h"

#ifdef TSK_WIN32

#include "libpq-fe.h"
#include <string.h>


#include <map>
using std::map;


/** \internal
 * C++ class that wraps the database internals. 
 */
class TskDbPostgreSQL {
  public:
#ifdef TSK_WIN32
//@@@@
    TskDbPostgreSQL(const TSK_TCHAR * a_dbFilePath, bool a_blkMapFlag);
#endif
     TskDbPostgreSQL(const char *a_dbFilePathUtf8, bool a_blkMapFlag);
    ~TskDbPostgreSQL();
    int open(bool);
    int close();

private:
    PGconn *conn;
    TSK_TCHAR m_dbFilePath[1024];
    char m_dbFilePathUtf8[1024];
};

#endif // _TSK_DB_POSTGRESQL_H

#endif // TSK_WIN32