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
* \file tsk_db.cpp
* Contains code related to abstract TSK database handling class. 
*/

#include "tsk_db.h"

/**
* Set the locations and logging object.  Must call
* open() before the object can be used.
*/
TskDb::TskDb(const char *a_dbFilePathUtf8, bool a_blkMapFlag)
{

}

#ifdef TSK_WIN32
//@@@@
TskDb::TskDb(const TSK_TCHAR * a_dbFilePath, bool a_blkMapFlag)
{

}
#endif

/**
* Store database connection info. NO-OP for single-user database. Multi-user database class
* needs to derive and implement this method.
*/
TSK_RETVAL_ENUM TskDb::setConnectionInfo(CaseDbConnectionInfo * info){
    return TSK_OK;
}

