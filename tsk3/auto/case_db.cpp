/*
** The Sleuth Kit
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2010-2011 Brian Carrier.  All Rights reserved
**
** This software is distributed under the Common Public License 1.0
**
*/

/**
* \file case_db.cpp
* Contains class definition for TskCaseDb class to handle creating/opening a case
* database and adding images to it.
*/

#include "tsk_case_db.h"
#include "tsk_auto_i.h"

TskCaseDb::TskCaseDb(TskDbSqlite * a_db)
{
    m_tag = TSK_CASE_DB_TAG;
    m_db = a_db;
}

TskCaseDb::~TskCaseDb()
{
    delete m_db;
};

/**
* Creates a new case with a new database and initializes its tables.
* Fails if there's already a file at the given path. Returns a pointer
* to a new TskCaseDb if successful, else NULL.
*
* @param path Full path to create new database at.
*/
TskCaseDb *
TskCaseDb::newDb(const TSK_TCHAR * const path)
{

    // Check if the database already exsists
    struct STAT_STR stat_buf;
    if (TSTAT(path, &stat_buf) == 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr("Database %" PRIttocTSK
            " already exists.  Must be deleted first.", path);
        return NULL;
    }

    TskDbSqlite *db = new TskDbSqlite(path, true);

    // Open the database.
    if (db->open())
        return NULL;

    if (db->initialize()) {
        delete db;
        return NULL;
    }

    return new TskCaseDb(db);
}

/**
* Opens a case from an existing database.
*
* @param path Full path to open database from.
*/
TskCaseDb *
TskCaseDb::openDb(const TSK_TCHAR * path)
{

    // Confirm that database already exsists
    struct STAT_STR stat_buf;
    if (TSTAT(path, &stat_buf) != 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr("Database %" PRIttocTSK
            " does not exist.  Must be created first.", path);
        return NULL;
    }

    TskDbSqlite *db = new TskDbSqlite(path, true);

    // Open the database.
    if (db->open())
        return NULL;

    return new TskCaseDb(db);
}

/**
* Add an image to the database.
*
* @param img An already opened image.
* @param blkMapFlag True if a block map should be created for the image.
*/
//uint8_t TskCaseDb::addImage(const TSK_IMG_INFO * image, bool blkMapFlag) {
//    TskAutoDb autoDb(m_db);
//    autoDb.createBlockMap(blkMapFlag);
//    if (autoDb.openImage(image)) return 1;
//    if (autoDb.addFilesInImgToDb()) return 1;
//    
//    return 0;
//}


/**
 * Prepares the process to add an image to the database
 *
 */
TskAutoDb *
TskCaseDb::initAddImage()
{
    return new TskAutoDb(m_db);
}

/**
* Add an image to the database.
*
* @param images Paths to the image splits to open.
*/
uint8_t
    TskCaseDb::addImage(int numImg, const TSK_TCHAR * const imagePaths[],
    TSK_IMG_TYPE_ENUM imgType, unsigned int sSize)
{

    TskAutoDb autoDb(m_db);
    return autoDb.runProcess(numImg, imagePaths, imgType, sSize);
}
