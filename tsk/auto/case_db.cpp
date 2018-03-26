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
* \file case_db.cpp
* Contains class definition for TskCaseDb class to handle creating/opening a case
* database and adding images to it.
*/

#include "tsk_case_db.h"
#include "tsk_auto_i.h"

TskCaseDb::TskCaseDb(TskDb * a_db)
{
    m_tag = TSK_CASE_DB_TAG;
    m_db = a_db;
    m_NSRLDb = NULL;
    m_knownBadDb = NULL;
}

TskCaseDb::~TskCaseDb()
{
    if (m_db != NULL) {
        delete m_db;
        m_db = NULL;
    }

    if (m_NSRLDb != NULL) {
        tsk_hdb_close(m_NSRLDb);
        m_NSRLDb = NULL;
    }

    if (m_knownBadDb != NULL) {
        tsk_hdb_close(m_knownBadDb);
        m_knownBadDb = NULL;
    }
    m_tag = 0;
}

/**
* Creates a new single-user case with a new database and initializes its tables.
* Fails if there's already a file at the given path.
*
* @param path Full path to create new database at.
* @returns Pointer to a new TskCaseDb object, NULL on error
*/
TskCaseDb *
TskCaseDb::newDb(const TSK_TCHAR * const path)
{
    TskDb *db = new TskDbSqlite(path, true);

    // Check if the database already exsists
    if (db->dbExists()) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr("Database %" PRIttocTSK
            " already exists.  Must be deleted first.", path);
        delete(db);
        return NULL;
    }

    // Open the database.
    if (db->open(true)) {
        delete(db);
        return NULL;
    }

    return new TskCaseDb(db);
}

/**
* Creates a new multi-user case with a new database and initializes its tables.
* Fails if multi-user database with requested name already exists.
*
* @param path Full path to create new database at.
* @returns Pointer to a new TskCaseDb object, NULL on error
*/
TskCaseDb *
TskCaseDb::newDb(const TSK_TCHAR * const path, CaseDbConnectionInfo * info)
{
#ifdef HAVE_LIBPQ_
    TskDb *db = new TskDbPostgreSQL(path, true);

    // Store connection info for the multi-user database
    if (db->setConnectionInfo(info) != TSK_OK) {
        delete(db);
        return NULL;
    }

    // Check if the database already exsists
    if (db->dbExists()) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr("Database %" PRIttocTSK
            " already exists.  Must be deleted first.", path);
        delete(db);
        return NULL;
    }

    // Open the database.
    if (db->open(true)) {
        delete(db);
        return NULL;
    }

    return new TskCaseDb(db);
#else
    return NULL;
#endif 
}

/**
* Opens a single-user case from an existing database.
*
* @param path Full path to open database from.
* @returns Pointer to a new TskCaseDb object, NULL on error
*/
TskCaseDb *
TskCaseDb::openDb(const TSK_TCHAR * path)
{
    TskDb *db = new TskDbSqlite(path, true);

    // Confirm that database already exsists
    if (!db->dbExists()) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr("Database %" PRIttocTSK
            " does not exist.  Must be created first.", path);
        delete(db);
        return NULL;
    }

    // Open the database.
    if (db->open(false)) {
        delete(db);
        return NULL;
    }

    return new TskCaseDb(db);
}

/**
* Opens a multi-user case from an existing database.
*
* @param path
* @param info CaseDbConnectionInfo object containing datbase connection info.
* @returns Pointer to a new TskCaseDb object, NULL on error
*/
TskCaseDb *
TskCaseDb::openDb(const TSK_TCHAR * path, CaseDbConnectionInfo * info)
{
#ifdef HAVE_LIBPQ_

    TskDb *db = new TskDbPostgreSQL(path, true);

    // Store connection info for the multi-user database
    if (db->setConnectionInfo(info) != TSK_OK) {
        delete(db);
        return NULL;
    }

    // Confirm that database already exsists
    if (!db->dbExists()) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr("Database %" PRIttocTSK
            " does not exist.  Must be created first.", path);
        delete(db);
        return NULL;
    }

    // Open the database.
    if (db->open(false)) {
        delete(db);
        return NULL;
    }

    return new TskCaseDb(db);
#else
    return NULL;
#endif // HAVE_POSTGRESQL && TSK_WIN32
}

/**
 * Prepares the process to add an image to the database. This method
 * allows the caller to specify options to be used during the ingest.
 * @returns TskAutDb object that can be used to add the image.
 */
TskAutoDb *
TskCaseDb::initAddImage()
{
    return new TskAutoDb(m_db, m_NSRLDb, m_knownBadDb);
}

/**
* Add an image to the database.  This method does not allow you
* to customize any of the settings for ingest (such as hash calculation,
* and block map population).  Use TskCaseDb::initAddImage() to set
* these values.
*
* @param numImg Number of images to add
* @param imagePaths Paths to the image splits to open.
* @param imgType TYpe of image format
* @param sSize Sector size of image
* @returns 1 on error and 0 on success
*/
uint8_t
    TskCaseDb::addImage(int numImg, const TSK_TCHAR * const imagePaths[],
    TSK_IMG_TYPE_ENUM imgType, unsigned int sSize)
{
    TskAutoDb autoDb(m_db, m_NSRLDb, m_knownBadDb);

    if (autoDb.startAddImage(numImg, imagePaths, imgType, sSize)) {
        autoDb.revertAddImage();
        return 1;
    }

    if (autoDb.commitAddImage()) {
        return 1;
    }

    return 0;
}

/*
 * Specify the NSRL index used for determining "known" files.
 * @param images Path to index.
 * @returns 1 on error and 0 on success
 */
uint8_t
TskCaseDb::setNSRLHashDb(TSK_TCHAR * const indexFile ) {
    if (m_NSRLDb != NULL) {
        tsk_hdb_close(m_NSRLDb);
        m_NSRLDb = NULL;
    }

    TSK_HDB_OPEN_ENUM flags = TSK_HDB_OPEN_IDXONLY;
    m_NSRLDb = tsk_hdb_open(indexFile, flags);
    return m_NSRLDb != NULL;
}

/*
 * Specify an index for determining "known bad" files.
 * @param images Path to index.
 * @returns 1 on error and 0 on success
 */
uint8_t
TskCaseDb::setKnownBadHashDb(TSK_TCHAR * const indexFile) {
    if (m_knownBadDb != NULL) {
        tsk_hdb_close(m_knownBadDb);
        m_knownBadDb = NULL;
    }

    TSK_HDB_OPEN_ENUM flags = TSK_HDB_OPEN_IDXONLY;
    m_knownBadDb = tsk_hdb_open(indexFile, flags);
    return m_knownBadDb != NULL;
}

/*
 * Clear set lookup databases.
 * @param images Path to index.
 */
void
TskCaseDb::clearLookupDatabases() {
    if (m_NSRLDb != NULL) {
        tsk_hdb_close(m_NSRLDb);
        m_NSRLDb = NULL;
    }

    if (m_knownBadDb != NULL) {
        tsk_hdb_close(m_knownBadDb);
        m_knownBadDb = NULL;
    }
}
