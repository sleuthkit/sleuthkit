/*
 *
 *  The Sleuth Kit
 *
 *  Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 *  Copyright (c) 2010-2011 Basis Technology Corporation. All Rights
 *  reserved.
 *
 *  This software is distributed under the Common Public License 1.0
 */

/**
 * \file TskImgDBPostgreSQL.cpp
 * A PostgreSQL based implementation of the framework data access layer.
 */
#include <stdio.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <Lmcons.h>
#include <assert.h>

#include "tsk/framework/services/TskDBBlackboard.h"
#include "TskImgDBPostgreSQL.h"
#include "tsk/framework/services/TskServices.h"
#include "tsk/framework/utilities/TskException.h"
#include "tsk/framework/utilities/TskUtilities.h"

#include "Poco/String.h"
#include "Poco/UnicodeConverter.h"
#include "Poco/NumberParser.h"
#include "Poco/Path.h"

/**
 *
 */
TskImgDBPostgreSQL::TskImgDBPostgreSQL(const std::string dbName) : m_dbName(dbName), m_dbConnection(NULL)
{
    m_artifactIDcounter = 1000;
    m_attributeIDcounter = 1000;
}

TskImgDBPostgreSQL::~TskImgDBPostgreSQL()
{
    close();
}

int TskImgDBPostgreSQL::close()
{
    if (m_dbConnection != NULL)
    {
        m_dbConnection->disconnect();
        delete m_dbConnection;
        m_dbConnection = NULL;
    }

    return 0;
}

bool TskImgDBPostgreSQL::initialized() const
{
    if (m_dbConnection == NULL)
    {
        LOGERROR(L"TskImgDBPostgreSQL::initialized - Database not initialized.\n");
        return false;
    }

    return true;
}

/** 
 * Open the DB and create the tables.
 * @returns 1 on error
 */
int TskImgDBPostgreSQL::initialize()
{

    // Open the database.
    if (open() != 0)
    {
        // Error message will have been logged by open()
        return 1;
    }

    try
    {
        pqxx::work W(*m_dbConnection);
        // ----- DB_INFO
        W.exec("CREATE TABLE db_info (name TEXT PRIMARY KEY, version TEXT)");
        // ----- IMAGE_INFO
        W.exec("CREATE TABLE image_info (type INTEGER, ssize INTEGER)");
        // ----- IMAGE_NAMES
        W.exec("CREATE TABLE image_names (seq SERIAL PRIMARY KEY, name TEXT)");
        // ----- VOL_INFO
        W.exec("CREATE TABLE vol_info (vol_id SERIAL PRIMARY KEY, sect_start BIGINT NOT NULL, sect_len BIGINT NOT NULL, description TEXT, flags INTEGER)");
        // ----- FS_INFO
        W.exec("CREATE TABLE fs_info (fs_id SERIAL PRIMARY KEY, img_byte_offset BIGINT, vol_id INTEGER NOT NULL, fs_type INTEGER, block_size INTEGER, block_count BIGINT, root_inum BIGINT, first_inum BIGINT, last_inum BIGINT)");
        // ----- FILES
        W.exec("CREATE TABLE files (file_id BIGSERIAL PRIMARY KEY, type_id INTEGER, name TEXT, par_file_id BIGINT, dir_type INTEGER, meta_type INTEGER, dir_flags INTEGER, meta_flags INTEGER, size BIGINT, ctime INTEGER, crtime INTEGER, atime INTEGER, mtime INTEGER, mode INTEGER, uid INTEGER, gid INTEGER, status INTEGER, full_path TEXT)");
        // ----- FS_FILES
        W.exec("CREATE TABLE fs_files (file_id BIGINT PRIMARY KEY, fs_id INTEGER, fs_file_id BIGINT, attr_type INTEGER, attr_id INTEGER)");
        // ----- FS_BLOCKS
        W.exec("CREATE TABLE fs_blocks (fs_id INTEGER NOT NULL, file_id BIGINT NOT NULL, seq INTEGER, blk_start BIGINT NOT NULL, blk_len BIGINT NOT NULL)");
        // ----- CARVED_FILES
        W.exec("CREATE TABLE carved_files (file_id BIGINT PRIMARY KEY, vol_id INTEGER)");
        // ----- CARVED_SECTORS
        W.exec("CREATE TABLE carved_sectors (file_id BIGINT, seq INTEGER, sect_start BIGINT, sect_len BIGINT)");
        // ----- DERIVED_FILES
        W.exec("CREATE TABLE derived_files (file_id BIGINT PRIMARY KEY, derivation_details TEXT)");
        // ----- ALLOC_UNALLOC_MAP
        W.exec("CREATE TABLE alloc_unalloc_map (vol_id INTEGER, unalloc_img_id INTEGER, unalloc_img_sect_start BIGINT, sect_len BIGINT, orig_img_sect_start BIGINT)");
        // ----- FILE_HASHES
        W.exec("CREATE TABLE file_hashes (file_id BIGINT PRIMARY KEY, md5 TEXT, sha1 TEXT, sha2_256 TEXT, sha2_512 TEXT, known INTEGER)");
        // ----- MODULES
        W.exec("CREATE TABLE modules (module_id SERIAL PRIMARY KEY, name TEXT UNIQUE NOT NULL, description TEXT)");
        // ----- MODULE_STATUS
        W.exec("CREATE TABLE module_status (file_id BIGINT, module_id SERIAL, status INTEGER, PRIMARY KEY (file_id, module_id))");
        // ----- UNALLOC_IMG_STATUS
        W.exec("CREATE TABLE unalloc_img_status (unalloc_img_id SERIAL PRIMARY KEY, status INTEGER)");
        // ----- UNUSED_SECTORS
        W.exec("CREATE TABLE unused_sectors (file_id BIGINT PRIMARY KEY, sect_start BIGINT, sect_len BIGINT, vol_id INTEGER)");
        // ----- BLACKBOARD_ARTIFACTS
        W.exec("CREATE TABLE blackboard_artifacts (artifact_id BIGSERIAL PRIMARY KEY, obj_id BIGINT NOT NULL, artifact_type_id INTEGER)");
        // ----- BLACKBOARD_ATTRIBUTES
        W.exec("CREATE TABLE blackboard_attributes (artifact_id BIGINT NOT NULL, source TEXT, context TEXT, attribute_type_id INTEGER NOT NULL, value_type INTEGER NOT NULL, "
        "value_byte BYTEA, value_text TEXT, value_int32 INTEGER, value_int64 BIGINT, value_double NUMERIC(20, 10), obj_id BIGINT NOT NULL)");
        // ----- BLACKBOARD_ARTIFACT_TYPES
        W.exec("CREATE TABLE blackboard_artifact_types (artifact_type_id INTEGER PRIMARY KEY, type_name TEXT, display_name TEXT)");
        // ----- BLACKBOARD_ATTRIBUTE_TYPES
        W.exec("CREATE TABLE blackboard_attribute_types (attribute_type_id INTEGER PRIMARY KEY, type_name TEXT, display_name TEXT)");
        // ----- INDEX ON ARTIFACT_ID OF BLACKBOARD_ATTRIBUTES
        W.exec("CREATE INDEX attrs_artifact_id ON blackboard_attributes(artifact_id)");        
        // ----- INDEX ON ATTRIBUTE_TYPE OF BLACKBOARD_ATTRIBUTES
        W.exec("CREATE INDEX attrs_attribute_type ON blackboard_attributes(attribute_type_id)");        
        // ----- INDEX ON OBJ_ID OF BLACKBOARD_ATTRIBUTES
        W.exec("CREATE INDEX attrs_obj_id ON blackboard_attributes(obj_id)");        
        
        W.exec("SET synchronous_commit TO OFF");

        W.commit();

        map<int, TskArtifactNames> artTypes = TskImgDB::getAllArtifactTypes();
        for(map<int, TskArtifactNames>::iterator it = artTypes.begin(); it != artTypes.end(); it++){
            addArtifactType(it->first, it->second.typeName, it->second.displayName);
        }
        map<int, TskAttributeNames> attrTypes = TskImgDB::getAllAttributeTypes();
        for(map<int, TskAttributeNames>::iterator it = attrTypes.begin(); it != attrTypes.end(); it++){
            addAttributeType(it->first, it->second.typeName, it->second.displayName);
        }

    }
    catch (std::exception& ex)
    {
        std::wstringstream errorMsg;
        errorMsg << L"TskImgDBPostgreSQL::initialize - Error creating database: " << ex.what() << std::endl;
        LOGERROR(errorMsg.str());
        return 1;
    }

    //if (initializePreparedStatements())
    //{
    //    // Error message will have been logged by initializePreparedStatements()
    //    return 1;
    //}

    addToolInfo("DbSchema", IMGDB_SCHEMA_VERSION);
    LOGINFO(L"ImgDB Created.");

    return 0;
}

/** 
 * Initialize prepared statements (server-side function-like objects) in the DB.
 * Assumes the DB is already created and open.
 * @returns 1 on error
 */
int TskImgDBPostgreSQL::initializePreparedStatements()
{
    try
    {
        pqxx::work W(*m_dbConnection);

        // Make prepared statement plans
        {
            std::stringstream stmt;
            stmt << "PREPARE addFsFileInfoPlan (int, int, text, bigint, int, int, int, int, bigint, int, int, int, int, int, int, int, text) AS "
                    << "INSERT INTO files (file_id, type_id, status, name, par_file_id, dir_type, meta_type, dir_flags, meta_flags, size, crtime, ctime, atime, mtime, mode, gid, uid, full_path) "
                    << "VALUES (DEFAULT, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17) "
                    << "RETURNING file_id";   
            W.exec(stmt.str());
        }
        {
            std::stringstream stmt;
            stmt << "PREPARE addCarvedFileInfoPlan (int, int, text, int, int, int, int, bigint, text) AS "
                    << "INSERT INTO files (file_id, type_id, status, name, par_file_id, dir_type, meta_type, dir_flags, meta_flags, size, crtime, ctime, atime, mtime, mode, gid, uid, full_path) "
                    << "VALUES (DEFAULT, $1, $2, $3, NULL, $4, $5, $6, $7, $8, 0, 0, 0, 0, NULL, NULL, NULL, $9) "
                    << "RETURNING file_id";   
            W.exec(stmt.str());
        }
        {
            std::stringstream stmt;
            stmt << "PREPARE addDerivedFileInfoPlan (int, int, text, bigint, int, int, bigint, int, int, int, int, text) AS "
                    << "INSERT INTO files (file_id, type_id, status, name, par_file_id, dir_type, meta_type, size, crtime, ctime, atime, mtime, full_path) "
                    << "VALUES (DEFAULT, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) "
                    << "RETURNING file_id";   
            W.exec(stmt.str());
        }

        W.commit();
    }
    catch (std::exception& ex)
    {
        std::wstringstream errorMsg;
        errorMsg << L"TskImgDBPostgreSQL::initializePreparedStatements - Error creating prepared statements: " << ex.what() << std::endl;
        LOGERROR(errorMsg.str());
        return 1;
    }
    return 0;
}

/*
 * Attempt to connect to an existing database. If connection attempt fails
 * a new database is created. This database must be initialized before it
 * is used.
 * Returns 1 if connection attempt fails.
 */
int TskImgDBPostgreSQL::open()
{
    // Get current user name. This will get used in connecting to the database.
    char name[UNLEN+1];
    DWORD size = UNLEN+1;

    GetUserNameA(name, &size);

    std::string db_host = GetSystemProperty(TskSystemProperties::DB_HOST);
    std::string db_port = GetSystemProperty(TskSystemProperties::DB_PORT);

    // Convert the hostname to an IPv4 address. We need to do this because if you attempt to establish a 
    // connection to a database server that exists on the same machine PostgreSQL will use the 'localhost'
    // rule from the pg_hba.conf file. Unfortunately, SSPI authentication doesn't work in that scenario.
    std::string db_host_ip;

    bool db_new = false;

    if (!TskUtilities::getHostIP(db_host, db_host_ip))
        return 1;

    try
    {
        // Construct the connection string to connect to the Postgres server.
        std::stringstream pgConnectionString;
        pgConnectionString << "host='" << db_host_ip << "' port='" << db_port
            << "' dbname='postgres' user='" << name << "'";

        pqxx::connection pgConnection(pgConnectionString.str());

        // Check whether the database exists
        pqxx::nontransaction nontrans(pgConnection);

        std::stringstream dbQuery;
        dbQuery << "select count(*) from pg_catalog.pg_database where datname = " << nontrans.quote(m_dbName);

        pqxx::result R = nontrans.exec(dbQuery);

        if (R.size() == 0 || R[0][0].as<int>() == 0) 
        {
            // There is no database. It needs to be created.
            std::stringstream createDatabase;
            createDatabase << "CREATE DATABASE \"" << m_dbName << "\" WITH OWNER=\"" << name << "\" ENCODING='UTF-8'";
            nontrans.exec(createDatabase);
            db_new = true;
        }

        std::stringstream dbConnectionString;
        dbConnectionString << "host='" << db_host_ip << "' port='" << db_port
            << "' dbname='" << Poco::replace(m_dbName, "'", "\\'") << "' user='" << name << "'";

        m_dbConnection = new pqxx::connection(dbConnectionString.str());
    }
    catch (std::exception& ex)
    {
        std::wstringstream errorMsg;
        errorMsg << L"TskDBPostgreSQL::open - Error connecting to the database: "
            << ex.what() << std::endl;
        LOGERROR(errorMsg.str());
        return 1;
    }

    if (!db_new)
    {
        if (initializePreparedStatements())
        {
            // Error message will have been logged by initializePreparedStatements()
            return 1;
        }
    }

    // We successfully connected to the database.
    LOGINFO(L"ImgDB Opened.");
    return 0;
}

pqxx::result TskImgDBPostgreSQL::executeStatement(const std::string& stmt) const
{
    pqxx::result R;

    try
    {
        // if select then do a read-only transaction
        std::string cmdstr("SELECT");
        if (stmt.compare(0, cmdstr.size(), cmdstr, 0, cmdstr.size()) == 0)
        {
            pqxx::read_transaction trans(*m_dbConnection);
            R = trans.exec(stmt);
        }
        else
        {
            pqxx::work W(*m_dbConnection);
            R = W.exec(stmt);
            W.commit();
        }
    }
    catch (const exception &e)
    {
        std::stringstream errorMsg;
        errorMsg << "TskDBPostgreSQL::executeStatement : " << e.what() << std::endl;
        throw TskException(errorMsg.str());
    }

    return R;
}

int TskImgDBPostgreSQL::addToolInfo(const char* name, const char* version)
{
    if (!initialized())
        return 1;

    stringstream stmt;

    stmt << "INSERT INTO db_info (name, version) VALUES ('" << name 
        << "', '" << version << "')";

    try
    {
        executeStatement(stmt.str());
        return 0;
    }
    catch (const exception &e)
    {
        std::wstringstream errorMsg;
        errorMsg << L"TskDBPostgreSQL::addToolInfo - Error adding data to db_info table: "
            << e.what() << std::endl;
        LOGERROR(errorMsg.str());

        return 1;
    }
}

int TskImgDBPostgreSQL::addImageInfo(int type, int size)
{
    if (!initialized())
        return 1;

    stringstream stmt;

    stmt << "INSERT INTO image_info (type, ssize) VALUES (" << type << ", " << size << ")";

    try
    {
        executeStatement(stmt.str());
        return 0;
    }
    catch (const exception &e)
    {
        std::wstringstream errorMsg;
        errorMsg << L"TskDBPostgreSQL::addImageInfo - Error adding data to image_info table: "
            << e.what() << std::endl;
        LOGERROR(errorMsg.str());

        return 1;
    }
}

int TskImgDBPostgreSQL::addImageName(char const * imgName)
{
    if (!initialized())
        return 1;

    stringstream stmt;

    stmt << "INSERT INTO image_names (seq, name) VALUES (DEFAULT, " 
        << m_dbConnection->quote(imgName) << ")";

    try
    {
        executeStatement(stmt.str());
        return 0;
    }
    catch (const exception &e)
    {
        std::wstringstream errorMsg;
        errorMsg << L"TskDBPostgreSQL::addImageName - Error adding data to image_names table: "
            << e.what() << std::endl;
        LOGERROR(errorMsg.str());

        return 1;
    }
}

/**
 * Adds the sector addresses of the volumes into the db.
 */
int TskImgDBPostgreSQL::addVolumeInfo(const TSK_VS_PART_INFO * vs_part)
{
    if (!initialized())
        return 1;

    stringstream stmt;

    stmt << "INSERT INTO vol_info (vol_id, sect_start, sect_len, description, flags) VALUES ("
        << (int)vs_part->addr << ", " << vs_part->start 
        << ", " << vs_part->len << ", '" << vs_part->desc 
        << "', " << vs_part->flags << ")";

    try
    {
        executeStatement(stmt.str());
    }
    catch (const TskException &e)
    {
        std::stringstream msg;
        msg << "TskImgDBPostgreSQL::addVolumeInfo : " << e.what();
        LOGERROR(msg.str());

        return 1;
    }

    return 0;
}

int TskImgDBPostgreSQL::addFsInfo(int volId, int fsId, const TSK_FS_INFO * fs_info)
{
    if (!initialized())
        return 1;

    stringstream stmt;

    stmt << "INSERT INTO fs_info (fs_id, img_byte_offset, vol_id, fs_type, block_size, block_count, root_inum, first_inum, last_inum) VALUES (" 
        << fsId << ", " << fs_info->offset << ", " << volId
        << ", " << (int)fs_info->ftype << ", " << fs_info->block_size << ", " << fs_info->block_count
        << ", " << fs_info->root_inum << ", " << fs_info->first_inum << ", " << fs_info->last_inum << ")";

    try
    {
        executeStatement(stmt.str());
    }
    catch (const TskException &e)
    {
        std::stringstream msg;
        msg << "TskImgDBPostgreSQL::addFsInfo : " << e.what();
        LOGERROR(msg.str());

        return 1;
    }

    return 0;
}


/**
 * Given a file system and fs_file_id, return the file_id.
 */
uint64_t TskImgDBPostgreSQL::getFileId(int a_fsId, uint64_t a_fsFileId) const
{
    if (!initialized())
        return 0;

    stringstream stmt;
    uint64_t fileId = 0;

    stmt << "SELECT file_id FROM fs_files WHERE fs_id=" 
        << a_fsId << " AND fs_file_id=" << a_fsFileId;

    try
    {
        pqxx::result R = executeStatement(stmt.str());

        // @@@ It's possible to have multiple file_ids for the same fs_file_id.
        // @@@ Which one should we use?
        if (R.size() > 0)
            fileId = R[0][0].as<uint64_t>();
    }
    catch (const TskException &e)
    {
        std::stringstream msg;
        msg << "TskDBPostgreSQL::getFileId : Error querying fs_files table: " << e.what();
        LOGERROR(msg.str());
    }
    return fileId;
}

/**
 * @returns the file record or -1 on error.
 */
int TskImgDBPostgreSQL::getFileRecord(const uint64_t fileId, TskFileRecord& fileRecord) const
{
    if (!initialized())
        return -1;

    stringstream stmt;

    stmt << "SELECT f.file_id, f.type_id, f.name, f.par_file_id, f.dir_type, f.meta_type, f.dir_flags, "
        << "f.meta_flags, f.size, f.ctime, f.crtime, f.atime, f.mtime, f.mode, f.uid, f.gid, f.status, f.full_path, "
        << "fh.md5, fh.sha1, fh.sha2_256, fh.sha2_512 "
        << "FROM files f LEFT OUTER JOIN file_hashes fh ON f.file_id = fh.file_id WHERE f.file_id=" << fileId;

    try
    {
        pqxx::read_transaction W(*m_dbConnection);
        pqxx::result R = W.exec(stmt);

        if (R.size() == 1)
        {
            R[0][0].to(fileRecord.fileId);
            R[0][1].to((int &)fileRecord.typeId);
            R[0][2].to(fileRecord.name);
            R[0][3].to(fileRecord.parentFileId);
            R[0][4].to((int &)fileRecord.dirType);
            R[0][5].to((int &)fileRecord.metaType);
            R[0][6].to((int &)fileRecord.dirFlags);
            R[0][7].to((int &)fileRecord.metaFlags);
            R[0][8].to(fileRecord.size);
            R[0][9].to(fileRecord.ctime);
            R[0][10].to(fileRecord.crtime);
            R[0][11].to(fileRecord.atime);
            R[0][12].to(fileRecord.mtime);
            R[0][13].to((int &)fileRecord.mode);
            R[0][14].to(fileRecord.uid);
            R[0][15].to(fileRecord.gid);
            R[0][16].to((int &)fileRecord.status);
            R[0][17].to(fileRecord.fullPath);
            R[0][18].to(fileRecord.md5);
            R[0][19].to(fileRecord.sha1);
            R[0][20].to(fileRecord.sha2_256);
            R[0][21].to(fileRecord.sha2_512);            
        }
        else if (R.size() == 0)
        {
            std::wstringstream msg;
            msg << L"TskImgDBPostgreSQL::getFileRecord - No record found for file id: " << fileId;
            LOGERROR(msg.str());
            return -1;
        }
    }
    catch (const exception &e)
    {
        std::wstringstream msg;
        msg << L"TskImgDBPostgreSQL::getFileRecord - Error querying files table: "
            << e.what();
        LOGERROR(msg.str());
        return -1;
    }

    return 0;
}

int TskImgDBPostgreSQL::addFsFileInfo(int fileSystemID, const TSK_FS_FILE *fileSystemFile, const char *fileName, int fileSystemAttrType, int fileSystemAttrID, uint64_t &fileID, const char *filePath)
{
    const std::string msgPrefix = "TskImgDBPostgreSQL::addFsFileInfo : ";
    fileID = 0;

    if (!initialized())
    {
        return -1;
    }

    // Construct the full path of the file within the image.
    std::string fullpath(filePath);
    fullpath.append(fileName);

    // Check whether the file name contains a single quote. If so, replace it with a double single quote.
    std::string fileNameAsString(fileName);
    size_t found;
    found = fileNameAsString.find("'");
    if (found != std::string::npos) //Replace it and replace all its subsequent occurrences.
    {
        fileNameAsString.replace(found,1,"''");

        while ((found=fileNameAsString.find("'",found+2)) != std::string::npos)// found+2 because we want to move past the newly inserted single quote.
        {
            fileNameAsString.replace(found,1,"''");
        }
    }

    // Now remove all the control characters from the file name.
    for (int codePoint=1; codePoint < 32; codePoint++)
    {
        char codePointAsHex[10];
        codePointAsHex[0] = codePoint;
        codePointAsHex[1] = '\0';
        std::string stringToRemove(codePointAsHex);

        found = fileNameAsString.find(stringToRemove);
        if (found != std::string::npos) //Replace it and replace all its subsequent occurrences.
        {
            fileNameAsString.replace(found,1,"");

            while ((found=fileNameAsString.find(stringToRemove,found+1)) != std::string::npos)// found+1 because the control characters are just 1 character.
            {
                fileNameAsString.replace(found,1,"");
            }
        }
    }

    fileName = fileNameAsString.c_str();

    uint64_t parFileId = findParObjId(fileSystemFile, fileSystemID);

    // Get the file size.
    TSK_OFF_T size = 0; 
    const TSK_FS_ATTR *fileSystemAttribute = tsk_fs_file_attr_get_id(const_cast<TSK_FS_FILE*>(fileSystemFile), fileSystemAttrID); 
    if (fileSystemAttribute)
    {
        size = fileSystemAttribute->size;
    }

    // Get the file metadata, if it's available.
    int mtime = 0;
    int crtime = 0;
    int ctime = 0;
    int atime = 0;
    int meta_type = 0;
    int meta_flags = 0;
    int meta_mode = 0;
    int gid = 0;
    int uid = 0;
    if (fileSystemFile->meta) 
    {
        mtime = static_cast<int>(fileSystemFile->meta->mtime);
        atime = static_cast<int>(fileSystemFile->meta->atime);
        ctime = static_cast<int>(fileSystemFile->meta->ctime);
        crtime = static_cast<int>(fileSystemFile->meta->crtime);
        meta_type = fileSystemFile->meta->type;
        meta_flags = fileSystemFile->meta->flags;
        meta_mode = fileSystemFile->meta->mode;
        gid = fileSystemFile->meta->gid;
        uid = fileSystemFile->meta->uid;
    }

    // Insert into the files table.
    std::stringstream stmt;

    try
    {
        // We don't provide file_id to the prepared function because it uses DEFAULT for that.
        stmt << "INSERT INTO files (file_id, type_id, status, name, par_file_id, dir_type, meta_type, dir_flags, meta_flags, size, crtime, ctime, atime, mtime, mode, gid, uid, full_path) VALUES ("
            << "DEFAULT, " << IMGDB_FILES_TYPE_FS << ", " << IMGDB_FILES_STATUS_READY_FOR_ANALYSIS << ", " << m_dbConnection->quote(fileName) << ", "
            << parFileId << ", " << fileSystemFile->name->type << ", " << meta_type << ", "
            << fileSystemFile->name->flags << ", " << meta_flags << ", " << size << ", " << crtime << ", " << ctime << ", " << atime << ", "
            << mtime << ", " << meta_mode << ", " << gid << ", " << uid << ", " << m_dbConnection->quote(fullpath) << ")"
            << " RETURNING file_id";

        // Commenting out to see if the addition of prepared statements is
        // the cause of the frequent PostgreSQL server crashes we've seen
        // recently.

        //stmt << "EXECUTE addFsFileInfoPlan ("
        //    << IMGDB_FILES_TYPE_FS << ", "
        //    << IMGDB_FILES_STATUS_READY_FOR_ANALYSIS << ", "
        //    << m_dbConnection->quote(fileName) << ", "
        //    << parFileId << ", "
        //    << fileSystemFile->name->type << ", "
        //    << meta_type << ", "
        //    << fileSystemFile->name->flags << ", "
        //    << meta_flags << ", "
        //    << size << ", "
        //    << crtime << ", "
        //    << ctime << ", "
        //    << atime << ", "
        //    << mtime << ", "
        //    << meta_mode << ", "
        //    << gid << ", "
        //    << uid
        //    << ", " << m_dbConnection->quote(fullpath) << ")";

        result R = executeStatement(stmt.str());
        
        // get the file_id from the last insert
        fileID = 0;
        if (R.size() == 1)
        {
            fileID = R[0][0].as<uint64_t>();
        }
        else if (R.size() > 1)
        {
            std::ostringstream msg;
            msg << msgPrefix << "Unexpected number of records (" << R.size() << ") returned from files table INSERT";
            LOGERROR(msg.str());
        }
    }
    catch (const exception &e)
    {
        std::ostringstream errorMsg;
        errorMsg << msgPrefix << "Error adding data to files table: " << e.what();
        LOGERROR(errorMsg.str());

        return -1;
    }

    // Insert into the fs_files table.
    try
    {
        stmt.str("");
        stmt << "INSERT INTO fs_files (file_id, fs_id, fs_file_id, attr_type, attr_id) VALUES ("
            << fileID << ", " << fileSystemID << ", " << fileSystemFile->name->meta_addr << ", " << fileSystemAttrType << ", " << fileSystemAttrID << ")";
        executeStatement(stmt.str());
    }
    catch (const exception &e)
    {
        std::stringstream errorMsg;
        errorMsg << msgPrefix << "Error adding data to fs_files table: " << e.what();
        LOGERROR(errorMsg.str());

        return -1;
    }

    //if dir, update parent id cache
    if (meta_type == TSK_FS_META_TYPE_DIR) {
        storeParObjId(fileSystemID, fileSystemFile, fileID);
    }

    return 0;
}

/**
 * Add block info to the database.  This table stores the run information for each file so that we
 * can map which blocks are used by what files.
 * @param a_fsId Id that the file is located in
 * @param a_fileId ID of the file
 * @param a_sequence The sequence number of this run in the file (0 for the first run, 1 for the second run, etc.)
 * @param a_blk_addr Block address (the address that the file system uses -- NOT the physical sector addr)
 * @param a_len The number of blocks in the run
 * @returns 1 on error
 */
int TskImgDBPostgreSQL::addFsBlockInfo(int a_fsId, uint64_t a_fileId, int a_sequence, uint64_t a_blk_addr, uint64_t a_len)
{
    if (!initialized())
        return 1;

    stringstream stmt;

    stmt << "INSERT INTO fs_blocks (fs_id, file_id, seq, blk_start, blk_len) VALUES ("
        << a_fsId << ", " << a_fileId << ", " << a_sequence << ", " << a_blk_addr << ", " << a_len << ")";

    try
    {
        executeStatement(stmt.str());
    }
    catch (const exception &e)
    {
        std::stringstream errorMsg;
        errorMsg << "TskDBPostgreSQL::addFsBlockInfo : Error adding data to fs_blocks table: "
            << e.what();
        LOGERROR(errorMsg.str());

        return 1;
    }

    return 0;
}


int TskImgDBPostgreSQL::addAllocUnallocMapInfo(int a_volID, int unallocImgID, 
                                               uint64_t unallocImgStart, uint64_t length, uint64_t origImgStart)
{
    if (!initialized())
        return 1;

    stringstream stmt;

    stmt << "INSERT INTO alloc_unalloc_map (vol_id, unalloc_img_id, unalloc_img_sect_start, sect_len, orig_img_sect_start) VALUES ("
        << a_volID << ", " << unallocImgID << ", " << unallocImgStart << ", " << length << ", " << origImgStart << ")";

    try
    {
        executeStatement(stmt.str());
        return 0;
    }
    catch (const exception &e)
    {
        std::wstringstream errorMsg;
        errorMsg << L"TskDBPostgreSQL::addAllocUnallocMapInfo - Error adding data to alloc_unalloc_map table: "
            << e.what();
        LOGERROR(errorMsg.str());

        return 1;
    }
}

/**
 * Get information on all of the free sectors in an image.
 *
 * @return Info on unallocated runs (or NULL on error).  Caller must free this when done.
 */
SectorRuns * TskImgDBPostgreSQL::getFreeSectors() const
{
    if (!initialized())
        return NULL;

    SectorRuns * sr = new SectorRuns();

    LOGINFO(L"TskImgDBPostgreSQL::getFreeSectors - Identifying Unallocated Sectors");

    std::stringstream stmt;
    std::wstringstream msg;

    /********** FIND the unallocated volumes *************/
    stmt << "SELECT vol_id, sect_start, sect_len, flags FROM vol_info";
    try
    {
        pqxx::read_transaction readTrans(*m_dbConnection);
        pqxx::result R = readTrans.exec(stmt);

        for (int rownum=0; rownum < R.size(); ++rownum)
        {
            const result::tuple row = R[rownum];

            int flags = row[3].as<int>();

            int vol_id = row[0].as<int>();
            int64_t start = row[1].as<int64_t>();
            int64_t len = row[2].as<int64_t>();

            // add the unallocated volumes
            if (flags & TSK_VS_PART_FLAG_UNALLOC) {
                sr->addRun(start, len, vol_id);
            }

            // add the allocated volumes that don't have a known file system
            else
            {
                stmt.str("");
                stmt << "SELECT fs_id FROM fs_info WHERE vol_id = " << vol_id;
                pqxx::result R1 = readTrans.exec(stmt);

                if (R1.size() == 0)
                {
                    sr->addRun(start, len, vol_id);
                }
            }
        } // end of 'for' statement
    }
    catch (const exception &e)
    {
        std::wstringstream errorMsg;
        errorMsg << L"TskImgDBPostgreSQL::getFreeSectors - Error querying vol_info table: "
            << e.what();
        LOGERROR(errorMsg.str());

        return NULL;
    }

    /*************** Find the unallocated blocks in each file system *************/
    // @@@ Need to make more dynamic
    int blk_size[32];
    memset(blk_size, 0, sizeof(blk_size));
    uint64_t blk_count[32];
    memset(blk_count, 0, sizeof(blk_count));
    int vol_id[32];
    uint64_t img_offset[32];

    // get basic info on each file system
    stmt.str("");
    stmt << "SELECT fs_id, vol_id, img_byte_offset, block_size, block_count FROM fs_info";
    try
    {
        pqxx::read_transaction readTrans(*m_dbConnection);
        pqxx::result R = readTrans.exec(stmt);

        LOGINFO(L"TskImgDBPostgreSQL::getFreeSectors - START LOOP: Find the unallocated blocks in each file system.");
        for (int rownum=0; rownum < R.size(); ++rownum)
        {
            const result::tuple row = R[rownum];

            int fs_id = row[0].as<int>();
            if (fs_id > 32)
            {
                std::wstringstream errorMsg;
                errorMsg << L"TskImgDBPostgreSQL::getFreeSectors - fs_id in fs_info is bigger than 32: " << fs_id;
                LOGERROR(errorMsg.str());
                break;
            }

            vol_id[fs_id] = row[1].as<int>();
            img_offset[fs_id] = row[2].as<uint64_t>() / 512;
            blk_size[fs_id] = row[3].as<int>() / 512;
            blk_count[fs_id] = row[4].as<uint64_t>(); 

            // Debug Info
            msg.str(L"");
            msg << L"TskImgDBPostgreSQL::getFreeSectors - fs_id=" << fs_id << " vol_id=" << vol_id[fs_id] << " img_offset=" << img_offset[fs_id] << " blk_size=" << blk_size[fs_id] <<
                " blk_count=" << blk_count[fs_id];
            LOGINFO(msg.str().c_str());
        }
        LOGINFO(L"TskImgDBPostgreSQL::getFreeSectors - DONE: Find the unallocated blocks in each file system.");
    }// end of 'try' block
    catch (const exception &e)
    {
        std::wstringstream errorMsg;
        errorMsg << L"TskImgDBPostgreSQL::getFreeSectors - Error querying fs_info table: "
            << e.what();
        LOGERROR(errorMsg.str());

        return NULL;
    }

    // see what blocks have been used and add them to a list
    TSK_LIST *seen[32];
    memset(seen, 0, 32*sizeof(TSK_LIST *));

    stmt.str("");
    stmt << "SELECT fs_id, file_id, blk_start, blk_len FROM fs_blocks";
    try
    {
        pqxx::read_transaction readTrans(*m_dbConnection);
        pqxx::result blocksResult = readTrans.exec(stmt);

        LOGINFO(L"TskImgDBPostgreSQL::getFreeSectors - START LOOP: see what blocks have been used and add them to a list.");
        for (int rownum=0; rownum < blocksResult.size(); ++rownum)
        {
            const result::tuple row = blocksResult[rownum];

            int fs_id = row[0].as<int>();
            if (fs_id > 32)
            {
                std::wstringstream errorMsg;
                errorMsg << L"TskImgDBPostgreSQL::getFreeSectors - fs_id in fs_info is bigger than 32: " << fs_id;
                LOGERROR(errorMsg.str());
                break;
            }
            uint64_t file_id = row[1].as<uint64_t>();
            int64_t addr = row[2].as<int64_t>();
            int64_t len = row[3].as<int64_t>();

            // We only want to consider the runs for files that we allocated.
            int flags = 0;
            stmt.str("");
            stmt << "SELECT meta_flags from files WHERE file_id=" << file_id;
            pqxx::result flagsResult = readTrans.exec(stmt);

            // @@@ It is possible for fs_blocks entries to have a file_id = 0
            // @@@ An example is "pointer" blocks in ext file systems that
            // @@@ contain the addresses of where the file content is stored.
            // @@@ We should tag these blocks with the actual file_id instead of 0
            // @@@ and use another mechanism to identify them as non-content blocks.
            if (file_id != 0 && flagsResult.size() == 0)
            {
                std::wstringstream errorMsg;
                errorMsg << L"TskImgDBPostgreSQL::getFreeSectors - error finding flags for file " << file_id;
                LOGERROR(errorMsg.str());
                continue;
            }
            else if (flagsResult.size() > 0)
            {
                flags = flagsResult[0][0].as<int>();
            }

            if (flags & TSK_FS_META_FLAG_UNALLOC)
                continue;

            // @@@ We can probably find a more efficient storage method than this...
            int error = 0;
            for (int64_t i = 0; i < len; i++) {
                if (tsk_list_add(&seen[fs_id], addr+i)) {
                    std::wstringstream errorMsg;
                    errorMsg << L"TskImgDBPostgreSQL::getFreeSectors - Error adding seen block address to list";
                    LOGERROR(errorMsg.str());

                    error = 1;
                    break;
                }
            }
            if (error)
                break;
        } // end of 'for' block
        LOGINFO(L"TskImgDBPostgreSQL::getFreeSectors - DONE: see what blocks have been used and add them to a list.");
    } // end of 'try' block
    catch (const exception &e)
    {
        std::wstringstream errorMsg;
        errorMsg << L"TskImgDBPostgreSQL::getFreeSectors - Error querying fs_block table: "
            << e.what();
        LOGERROR(errorMsg.str());

        return NULL;
    }

    // cycle through each file system to find the unused blocks
    LOGINFO(L"TskImgDBPostgreSQL::getFreeSectors - START LOOP: cycle through each file system to find the unused blocks.");
    for (int f = 0; f < 32; f++) {
        if (blk_count[f] == 0)
            continue;

        uint64_t st = 0;
        int len = 0;
        // we previously adjusted blk_size and img_offset to be in sectors

        msg.str(L"");
        msg << L"blk_count[" << f << "]=" << blk_count[f];
        LOGINFO(msg.str().c_str());

        for (uint64_t a = 0; a < blk_count[f]; a++) {
            // see if this addr was used in a file
            if (tsk_list_find(seen[f], a) == 0) {
                // we already have a run being defined
                if (len) {
                    // same run, so add on to it
                    if (st + len == a) {
                        len++;
                    }
                    // different run, make a new one
                    else {
                        sr->addRun(img_offset[f]+st*blk_size[f], len*blk_size[f], vol_id[f]);
                        st = a;
                        len = 1;
                    }
                }
                // start a new run
                else {
                    st = a;
                    len = 1;
                }
            }
        }
        // add the final run
        if (len) {
            sr->addRun(img_offset[f]+st*blk_size[f], len*blk_size[f], vol_id[f]);
        }
        tsk_list_free(seen[f]);
        seen[f] = NULL;
    }
    LOGINFO(L"TskImgDBPostgreSQL::getFreeSectors - DONE: cycle through each file system to find the unused blocks.");

    return sr;
}

std::string TskImgDBPostgreSQL::getImageBaseName() const
{
    // There may be multiple file paths if the image is a split image. Oreder by sequence number to extract the file name from the first path.
    pqxx::read_transaction trans(*m_dbConnection);
    pqxx::result resultSet = trans.exec("SELECT name FROM image_names ORDER BY seq;");
    if (resultSet.begin() != resultSet.end())
    {
        Poco::Path imagePath((resultSet.begin())[0].c_str()); 
        return imagePath.getFileName();
    }
    else
    {
        return "";
    }
}

std::vector<std::wstring> TskImgDBPostgreSQL::getImageNamesW() const
{
    std::vector<std::wstring> imgList;

    if (!initialized())
        return imgList;

    stringstream stmt;

    stmt << "SELECT name FROM image_names ORDER BY seq";

    try
    {
        pqxx::read_transaction trans(*m_dbConnection);
        pqxx::result R = trans.exec(stmt);

        for (pqxx::result::const_iterator i = R.begin(); i != R.end(); ++i)
        {
            std::wstring imgName;
            Poco::UnicodeConverter::toUTF16(i[0].c_str(), imgName);

            imgList.push_back(imgName);
        }
    }
    catch (const exception &e)
    {
        std::wstringstream errorMsg;
        errorMsg << L"TskImgDBPostgreSQL::getImageNames - Error getting image names : "
            << e.what();
        LOGERROR(errorMsg.str());
    }

    if (imgList.empty()) 
    {
        LOGERROR(L"No images found in TskImgDBPostgres");
    }

    return imgList;
}

std::vector<std::string> TskImgDBPostgreSQL::getImageNames() const
{
    std::vector<std::string> imgList;

    if (!initialized())
        return imgList;

    stringstream stmt;

    stmt << "SELECT name FROM image_names ORDER BY seq";

    try
    {
        pqxx::read_transaction trans(*m_dbConnection);
        pqxx::result R = trans.exec(stmt);

        for (pqxx::result::const_iterator i = R.begin(); i != R.end(); ++i)
        {
            imgList.push_back(i[0].c_str());
        }
    }
    catch (const exception &e)
    {
        std::stringstream errorMsg;
        errorMsg << "TskImgDBPostgreSQL::getImageNames - Error getting image names : "
            << e.what();
        LOGERROR(errorMsg.str());
    }

    if (imgList.empty()) 
    {
        LOGERROR("No images found in TskImgDBPostgres");
    }

    return imgList;
}

/**
 * @param a_fileId  File id to get information about
 * @param a_fsOffset Byte offset of start of file system that the file is located in
 * @param a_fsFileId File system-specific id of the file
 * @param a_attrType Type of attribute for this file
 * @param a_attrId The ID of the attribute for this file
 * @returns 0 on success, -1 on error
 */
int TskImgDBPostgreSQL::getFileUniqueIdentifiers(uint64_t a_fileId, uint64_t &a_fsOffset, uint64_t &a_fsFileId, int &a_attrType, int &a_attrId) const
{
    if (!initialized())
        return -1;

    stringstream stmt;

    stmt << "SELECT fs_file_id, attr_type, attr_id, fs_info.img_byte_offset "
        "FROM fs_files, fs_info WHERE file_id=" << a_fileId
        << " AND fs_info.fs_id = fs_files.fs_id";

    try
    {
        pqxx::read_transaction trans(*m_dbConnection);
        pqxx::result R = trans.exec(stmt);

        if (R.size() == 1)
        {
            R[0][0].to(a_fsFileId);
            R[0][1].to(a_attrType);
            R[0][2].to(a_attrId);
            R[0][3].to(a_fsOffset);
        }
        else
        {
            std::wstringstream errorMsg;
            errorMsg << L"TskImgDBPostgreSQL::getFileUniqueIdentifiers - Not a file system file : "
                << a_fileId;
            LOGERROR(errorMsg.str());

            return -1;
        }
    }
    catch (const exception &e)
    {
        std::wstringstream errorMsg;
        errorMsg << L"TskImgDBPostgreSQL::getFileUniqueIdentifiers - Error getting file identifiers: "
            << e.what();
        LOGERROR(errorMsg.str());

        return -1;
    }

    return 0;
}

/**
 * Get number of volumes in image.
 * @return Number of volumes in image or -1 on error
 */
int TskImgDBPostgreSQL::getNumVolumes() const
{
    if (!initialized())
        return -1;

    int count = 0;

    try
    {
        pqxx::read_transaction trans(*m_dbConnection);
        pqxx::result R = trans.exec("SELECT count(*) from vol_info");

        if (R.size() == 1)
        {
            R[0][0].to(count);
        }
        else
        {
            std::wstringstream errorMsg;
            errorMsg << L"TskImgDBPostgreSQL::getNumVolumes - Unexpected number of rows returned."
                << R.size();
            LOGERROR(errorMsg.str());

            return -1;
        }
    }
    catch (const exception &e)
    {
        std::wstringstream errorMsg;
        errorMsg << L"TskImgDBPostgreSQL::getNumVolumes - Error getting number of volumes: "
            << e.what();
        LOGERROR(errorMsg.str());

        return -1;
    }

    return count;
}

/**
 * Get number of files in image.
 * @return Number of files in image or -1 on error
 */
int TskImgDBPostgreSQL::getNumFiles() const
{
    if (!initialized())
        return -1;

    std::string condition("");
    int count = getFileCount(condition);

    return count;
}

/**
 * @returns the session_id or -1 on error.
 */
int TskImgDBPostgreSQL::getSessionID() const
{
    if (!initialized())
        return -1;

    int sessionId;
    stringstream stmt;

    stmt << "SELECT version FROM db_info WHERE name = 'SID'";

    try
    {
        pqxx::read_transaction trans(*m_dbConnection);
        pqxx::result R = trans.exec(stmt);

        if (R.size() == 1)
        {
            R[0][0].to(sessionId);
        }
        else
        {
            std::wstringstream errorMsg;
            errorMsg << L"TskImgDBPostgreSQL::getSessionID - Unexpected number of rows returned."
                << R.size();
            LOGERROR(errorMsg.str());

            return -1;
        }
    }
    catch (const exception &e)
    {
        std::wstringstream errorMsg;
        errorMsg << L"TskImgDBPostgreSQL::getSessionID - Error getting session id: "
            << e.what();
        LOGERROR(errorMsg.str());

        return -1;
    }

    return sessionId;
}

/**
 * begin is a no-op since all PostgreSQL statements are run in the
 * context of a transaction.
 */
int TskImgDBPostgreSQL::begin()
{
    return 0;
}

/**
 * commit is a no-op since all PostgreSQL statements are run in the
 * context of a transaction.
 */
int TskImgDBPostgreSQL::commit()
{
    return 0;
}


UnallocRun * TskImgDBPostgreSQL::getUnallocRun(int a_unalloc_img_id, int a_file_offset) const
{
    if (!initialized())
        return NULL;

    stringstream stmt;

    stmt << "SELECT vol_id, unalloc_img_sect_start, sect_len, orig_img_sect_start FROM "
        "alloc_unalloc_map WHERE unalloc_img_id = " << a_unalloc_img_id 
        << " AND unalloc_img_sect_start <= " << a_file_offset << " ORDER BY unalloc_img_sect_start DESC";

    try
    {
        pqxx::read_transaction trans(*m_dbConnection);
        pqxx::result R = trans.exec(stmt);

        if (R.size() > 0)
        {
            int vol_id; R[0][0].to(vol_id);
            int unalloc_img_sect_start; R[0][1].to(unalloc_img_sect_start);
            int sect_len; R[0][2].to(sect_len);
            int orig_img_sect_start; R[0][3].to(orig_img_sect_start);

            return new UnallocRun(vol_id, a_unalloc_img_id, unalloc_img_sect_start, sect_len, orig_img_sect_start);
        }
        else
        {
            LOGERROR(L"TskImgDBPostgreSQL::getUnallocRun - No records returned.\n");
            return new UnallocRun(-1, -1, -1, -1, -1);
        }
    }
    catch (const exception &e)
    {
        std::wstringstream errorMsg;
        errorMsg << L"TskImgDBPostgreSQL::getUnallocRun - Error fetching data from alloc_unalloc_map table: "
            << e.what();
        LOGERROR(errorMsg.str());

        return new UnallocRun(-1, -1, -1, -1, -1);
    }
}

/**
 * Adds information about a carved file into the database.  This includes the sector layout
 * information. 
 * 
 * @param size Number of bytes in file
 * @param runStarts Array with starting sector (relative to start of image) for each run in file.
 * @param runLengths Array with number of sectors in each run 
 * @param numRuns Number of entries in previous arrays
 * @param fileId Carved file Id (output)
 * @returns 0 on success or -1 on error.
 */
int TskImgDBPostgreSQL::addCarvedFileInfo(int vol_id, const char *name, uint64_t size, 
                                          uint64_t *runStarts, uint64_t *runLengths, int numRuns, uint64_t & fileId)
{
    if (!initialized())
        return -1;

    std::string utf8Name(name);

    fileId = 0;

    stringstream stmt;

    // Commenting out to see if the addition of prepared statements is
    // the cause of the frequent PostgreSQL server crashes we've seen
    // recently.

    //stmt << "EXECUTE addCarvedFileInfoPlan ("
    //    << IMGDB_FILES_TYPE_CARVED << ", "
    //    << IMGDB_FILES_STATUS_CREATED << ", "
    //    << m_dbConnection->quote(utf8Name) << ", "
    //    << TSK_FS_NAME_TYPE_REG << ", "
    //    << TSK_FS_META_TYPE_REG << ", "
    //    << TSK_FS_NAME_FLAG_UNALLOC << ", "
    //    << TSK_FS_META_FLAG_UNALLOC << ", "
    //    << size << ","
    //    << m_dbConnection->quote(utf8Name) << ")";

    stmt << "INSERT INTO files (file_id, type_id, name, par_file_id, dir_type, meta_type,"
        "dir_flags, meta_flags, size, ctime, crtime, atime, mtime, mode, uid, gid, status, full_path) "
        "VALUES (DEFAULT, " << IMGDB_FILES_TYPE_CARVED << ", " << m_dbConnection->quote(utf8Name)
        << ", NULL, " <<  TSK_FS_NAME_TYPE_REG << ", " <<  TSK_FS_META_TYPE_REG << ", "
        << TSK_FS_NAME_FLAG_UNALLOC << ", " << TSK_FS_META_FLAG_UNALLOC << ", "
        << size << ", 0, 0, 0, 0, NULL, NULL, NULL, " << IMGDB_FILES_STATUS_CREATED << "," << m_dbConnection->quote(utf8Name) << ")"
        << " RETURNING file_id";

    try
    {
        pqxx::work W(*m_dbConnection);
        pqxx::result R = W.exec(stmt);

        // get the file_id from the last insert
        fileId = R[0][0].as<uint64_t>();

        stmt.str("");

        // insert into the carved_files_table
        stmt << "INSERT INTO carved_files (file_id, vol_id) VALUES ("
            << fileId << ", " << vol_id << ")";

        R = W.exec(stmt);

        // insert into carved_sectors table
        for (int i = 0; i < numRuns; i++)
        {
            stmt.str("");
            stmt << "INSERT INTO carved_sectors (file_id, seq, sect_start, sect_len) VALUES ("
                << fileId << ", " << i << ", " << runStarts[i] << ", " << runLengths[i] << ")";

            R = W.exec(stmt);
        }

        W.commit();
    }
    catch (exception& ex)
    {
        std::wstringstream errorMsg;
        errorMsg << L"TskImgDBPostgreSQL::addCarvedFileInfo - Error adding data to carved_files table: "
            << ex.what();
        LOGERROR(errorMsg.str());

        return -1;
    }

    return 0;
}

/**
 * Adds information about derived files to the database.  Derived files typically come
 * from archives and may be compressed.
 * 
 * @param name The name of the file.
 * @param parentId The id of the file from which this file is derived.
 * @param size The size of the file.
 * @param details This is a string that may contain extra details related
 * to the particular type of mechanism that was used to derive this file, 
 * e.g. files derived from zip archives may have extra information about the
 * compressed size of the file.
 * @param ctime Time file system file entry was changed.
 * @param crtime Time the file was created.
 * @param atime Last access time.
 * @param mtime Last modified time.
 * @param fileId Return the file_id value.
 *
 * @returns 0 on success or -1 on error.
 */
int TskImgDBPostgreSQL::addDerivedFileInfo(const std::string& name, const uint64_t parentId, 
                                           const bool isDirectory, const uint64_t size,
                                           const std::string& details,
                                           const int ctime, const int crtime, const int atime, const int mtime,
                                           uint64_t &fileId, std::string path)
{
    if (!initialized())
        return -1;

    fileId = 0;

    // Ensure that strings are valid UTF-8
    std::vector<char> cleanName(name.begin(), name.end());
    cleanName.push_back('\0');
    TskUtilities::cleanUTF8(&cleanName[0]);

    std::vector<char> cleanDetails(details.begin(), details.end());
    cleanDetails.push_back('\0');
    TskUtilities::cleanUTF8(&cleanDetails[0]);

    std::vector<char> cleanPath(path.begin(), path.end());
    cleanPath.push_back('\0');
    TskUtilities::cleanUTF8(&cleanPath[0]);

    TSK_FS_NAME_TYPE_ENUM dirType = isDirectory ? TSK_FS_NAME_TYPE_DIR : TSK_FS_NAME_TYPE_REG;
    TSK_FS_META_TYPE_ENUM metaType = isDirectory ? TSK_FS_META_TYPE_DIR : TSK_FS_META_TYPE_REG;

    std::stringstream stmt;

    // Commenting out to see if the addition of prepared statements is
    // the cause of the frequent PostgreSQL server crashes we've seen
    // recently.

    //stmt << "EXECUTE addDerivedFileInfoPlan ("
    //    << IMGDB_FILES_TYPE_DERIVED << ", "
    //    << IMGDB_FILES_STATUS_CREATED << ", "
    //    << m_dbConnection->quote(&cleanName[0]) << ", " 
    //    << parentId << ", "
    //    << dirType << ", "
    //    << metaType << ", "
    //    << size << ", "
    //    << crtime << ", "
    //    << ctime << ", "
    //    << atime << ", "
    //    << mtime << ", "
    //    << m_dbConnection->quote(&cleanPath[0]) << ")";

    stmt << "INSERT INTO files (file_id, type_id, name, par_file_id, dir_type, meta_type, size, ctime, crtime, atime, mtime, status, full_path) "
        "VALUES (DEFAULT, " << IMGDB_FILES_TYPE_DERIVED << ", " << m_dbConnection->quote(&cleanName[0]) << ", " << parentId << ", " << dirType << ", " << metaType << ", " << size
        << ", " << ctime << ", " << crtime << ", " << atime << ", " << mtime << ", " << IMGDB_FILES_STATUS_CREATED << ", " << m_dbConnection->quote(&cleanPath[0]) << ")"
        << " RETURNING file_id";

    try
    {
        pqxx::work W(*m_dbConnection);
        pqxx::result R = W.exec(stmt);

        // get the file_id from the last insert
        fileId = R[0][0].as<uint64_t>();

        stmt.str("");

        // insert into the derived_files table
        stmt << "INSERT INTO derived_files (file_id, derivation_details) VALUES ("
            << fileId << ", " << m_dbConnection->quote(&cleanDetails[0]) << ")";

        R = W.exec(stmt);
        W.commit();
    }
    catch (exception& ex)
    {
        std::wstringstream errorMsg;
        errorMsg << L"TskImgDBPostgreSQL::addDerivedFileInfo - Error adding derived file data: "
            << ex.what();
        LOGERROR(errorMsg.str());

        return -1;
    }

    return 0;
}

/**
 * Fills outBuffer with file IDs that match the name fileName.
 * Returns the number of file IDs written into outBuffer or -1 on error.
 */
int TskImgDBPostgreSQL::getFileIds(char *a_fileName, uint64_t *a_outBuffer, int a_buffSize) const
{
    if (!initialized())
        return -1;

    int outIdx = 0;
    stringstream stmt;

    stmt << "SELECT file_id FROM files WHERE name LIKE "
        << m_dbConnection->quote(a_fileName);

    try
    {
        pqxx::read_transaction trans(*m_dbConnection);
        pqxx::result R = trans.exec(stmt);

        if (R.size() > a_buffSize)
        {
            std::wstringstream errorMsg;
            errorMsg << L"TskImgDBPostgreSQL::getFileIds - Number of file ids returned ("
                << R.size() << ") is greated than buffer capacity (" << a_buffSize << ")";
            LOGERROR(errorMsg.str());
            return -1;
        }

        for (pqxx::result::const_iterator i = R.begin(); i != R.end(); ++i)
        {
            i[0].to(a_outBuffer[outIdx++]);
        }
    }
    catch (const exception &e)
    {
        std::wstringstream errorMsg;
        errorMsg << L"TskImgDBPostgreSQL::getFileIds - Error getting file ids : "
            << e.what();
        LOGERROR(errorMsg.str());

        return -1;
    }

    return outIdx;
}

/**
 * Given the last file ID ready for analysis, find the largest file ID ready of analysis (in maxFileId)
 * Returns 0 on success or -1 on error.
 */
int TskImgDBPostgreSQL::getMaxFileIdReadyForAnalysis(uint64_t a_lastFileId, uint64_t & maxFileId) const
{
    if (!initialized())
        return -1;

    maxFileId = 0;
    stringstream stmt;

    stmt << "SELECT max(file_id) FROM files WHERE status = " << TskImgDB::IMGDB_FILES_STATUS_READY_FOR_ANALYSIS
        << " AND file_id >= " << a_lastFileId;

    try
    {
        pqxx::read_transaction trans(*m_dbConnection);
        pqxx::result R = trans.exec(stmt);

        if (R.size() == 1)
        {
            R[0][0].to(maxFileId);
        }
        else
        {
            std::wstringstream errorMsg;
            errorMsg << L"TskImgDBPostgreSQL::getMaxFileIdReadyForAnalysis - Unexpected number of rows returned."
                << R.size();
            LOGERROR(errorMsg.str());
            return -1;
        }
    }
    catch (const exception &e)
    {
        std::wstringstream errorMsg;
        errorMsg << L"TskImgDBPostgreSQL::getMaxFileIdReadyForAnalysis - Error retrieving maximum file id: "
            << e.what();
        LOGERROR(errorMsg.str());

        return -1;
    }

    return 0;
}

/*
 * Return the minimum file id with status = READY_FOR_ANALYSIS in minFileId.
 * Return 0 on success, -1 if failed.
 */
int TskImgDBPostgreSQL::getMinFileIdReadyForAnalysis(uint64_t & minFileId) const
{
    if (!initialized())
        return -1;

    minFileId = 0;
    stringstream stmt;

    stmt << "SELECT min(file_id) FROM files WHERE status = " << TskImgDB::IMGDB_FILES_STATUS_READY_FOR_ANALYSIS;

    try
    {
        pqxx::read_transaction trans(*m_dbConnection);
        pqxx::result R = trans.exec(stmt);

        if (R.size() == 1)
        {
            R[0][0].to(minFileId);
        }
        else
        {
            std::wstringstream errorMsg;
            errorMsg << L"TskImgDBPostgreSQL::getMinFileIdReadyForAnalysis - Unexpected number of rows returned."
                << R.size();
            LOGERROR(errorMsg.str());
            return -1;
        }
    }
    catch (const exception &e)
    {
        std::wstringstream errorMsg;
        errorMsg << L"TskImgDBPostgreSQL::getMinFileIdReadyForAnalysis - Error retrieving minimum file id: "
            << e.what();
        LOGERROR(errorMsg.str());

        return -1;
    }

    return 0;
}

SectorRuns * TskImgDBPostgreSQL::getFileSectors(uint64_t a_fileId) const 
{
    if (!initialized())
        return NULL;

    SectorRuns * sr = new SectorRuns();
    int srCount = 0;

    stringstream stmt;

    stmt << "SELECT fs_blocks.blk_start, fs_blocks.blk_len, "
        "fs_info.block_size, fs_info.img_byte_offset, fs_info.vol_id "
        "FROM files "
        "JOIN fs_files ON files.file_id = fs_files.file_id "
        "JOIN fs_blocks ON files.file_id = fs_blocks.file_id "
        "JOIN fs_info ON fs_blocks.fs_id = fs_info.fs_id "
        "WHERE files.file_id = " << a_fileId << " ORDER BY fs_blocks.seq;";

    try
    {
        pqxx::read_transaction trans(*m_dbConnection);
        pqxx::result R = trans.exec(stmt);

        for (pqxx::result::const_iterator i = R.begin(); i!= R.end(); ++i)
        {
            uint64_t blkStart; i[0].to(blkStart);
            uint64_t blkLength; i[1].to(blkLength);
            int blkSize; i[2].to(blkSize);
            uint64_t imgByteOffset; i[3].to(imgByteOffset);
            int volId; i[4].to(volId);

            uint64_t start = (imgByteOffset + blkStart * blkSize) / 512;
            uint64_t len = (blkLength * blkSize) / 512;

            sr->addRun(start, len, volId);
            srCount++;
        }
    }
    catch (const exception &e)
    {
        std::wstringstream errorMsg;
        errorMsg << L"TskImgDBPostgreSQL::getFileSectors - Error finding block data for file_id= " << a_fileId
            << e.what() << std::endl;
        LOGERROR(errorMsg.str());

        return NULL;
    }

    return sr;
}

/**
 * update the status field in the database for a given file.
 * @param a_file_id File to update.
 * @param a_status Status flag to update to.
 * @returns 1 on error.
 */
int TskImgDBPostgreSQL::updateFileStatus(uint64_t a_file_id, TskImgDB::FILE_STATUS a_status)
{
    if (!initialized())
        return 1;

    stringstream stmt;

    stmt << "UPDATE files SET status = " << a_status << " WHERE file_id = " << a_file_id;

    try
    {
        work W(*m_dbConnection);
        result R = W.exec(stmt);
        W.commit();
    }
    catch (const exception &e)
    {
        std::wstringstream errorMsg;
        errorMsg << L"TskImgDBPostgreSQL::updateFileStatus - Error updating file status: "
            << e.what();
        LOGERROR(errorMsg.str());

        return 1;
    }

    return 0;
}

/**
 * update the known status field in the database for a given file.
 * @param a_file_id File to update.
 * @param a_status Status flag to update to.
 * @returns 1 on error.
 */
int TskImgDBPostgreSQL::updateKnownStatus(uint64_t a_file_id, TskImgDB::KNOWN_STATUS a_status)
{
    if (!initialized())
        return 1;

    stringstream stmt;

    stmt << "SELECT known FROM file_hashes WHERE file_id = " << a_file_id;

    try
    {
        int status;
        pqxx::read_transaction trans(*m_dbConnection);
        pqxx::result R = trans.exec(stmt);
        pqxx::result::const_iterator i = R.begin(); 
        if(R.size() != 0)
            i[0].to(status);
        else
            status = TskImgDB::IMGDB_FILES_UNKNOWN;
        trans.commit();

        if((status == TskImgDB::IMGDB_FILES_UNKNOWN) ||
           (a_status == TskImgDB::IMGDB_FILES_KNOWN_BAD) ||
           (status == TskImgDB::IMGDB_FILES_KNOWN && a_status == TskImgDB::IMGDB_FILES_KNOWN_GOOD)){
            stmt.str("");
            stmt << "UPDATE file_hashes SET known = " << a_status << " WHERE file_id = " << a_file_id;

            work W(*m_dbConnection);
            R = W.exec(stmt);
            W.commit();
        }
    }
    catch (const exception &e)
    {
        std::wstringstream errorMsg;
        errorMsg << L"TskImgDBPostgreSQL::updateKnownStatus - Error updating file status: "
            << e.what();
        LOGERROR(errorMsg.str());

        return 1;
    }

    return 0;
}

bool TskImgDBPostgreSQL::dbExist() const
{
    bool rc = false;

    // Get current user name. This will get used in connecting to the database.
    char name[UNLEN+1];
    DWORD size = UNLEN+1;

    GetUserNameA(name, &size);

    std::string db_host = GetSystemProperty(TskSystemProperties::DB_HOST);
    std::string db_port = GetSystemProperty(TskSystemProperties::DB_PORT);
    std::string db_host_ip;
    if (!TskUtilities::getHostIP(db_host, db_host_ip))
        return false;

    try
    {
        // Construct the connection string to connect to the Postgres server.
        std::stringstream pgConnectionString;
        pgConnectionString << "host='" << db_host_ip << "' port='" << db_port
            << "' dbname='postgres' user='" << name << "'";

        pqxx::connection pgConnection(pgConnectionString.str());

        // Check whether the database exists
        pqxx::nontransaction nontrans(pgConnection);

        std::stringstream dbQuery;
        dbQuery << "select count(*) from pg_catalog.pg_database where datname = " << nontrans.quote(m_dbName);

        pqxx::result R = nontrans.exec(dbQuery);

        if (R.size() == 0 || R[0][0].as<int>() == 0) 
        {
            // There is no database.
            ;
        } else {
            rc = true;
        }
    }
    catch (const exception &e)
    {
        std::wstringstream errorMsg;
        errorMsg << L"TskDBPostgreSQL::dbExist - Error pg_database where datname= " << m_dbName.c_str() << " Error: "
            << e.what();
        LOGERROR(errorMsg.str());
    }
    return rc;
}

void TskImgDBPostgreSQL::getCarvedFileInfo(const std::string& stmt,
                                           std::map<uint64_t, std::string>& results) const
{
    try
    {
        pqxx::read_transaction trans(*m_dbConnection);
        pqxx::result R = trans.exec(stmt);
        uint64_t file_id;
        std::string cfileName;
        std::string fileName;
        for (pqxx::result::const_iterator i = R.begin(); i != R.end(); ++i)
        {
            i[0].to(file_id);
            i[1].to(fileName);
            i[2].to(cfileName);

            // Grab the extension and append it to the cfile name
            std::string::size_type pos = fileName.rfind('.');
            if (pos != std::string::npos)
                cfileName.append(fileName.substr(pos));

            results[file_id] = cfileName;
        }
    }
    catch (const exception &e)
    {
        std::wstringstream msg;
        msg << L"TskImgDBPostgreSQL::getCarvedFileInfo - Error getting carved file details : "
            << e.what();
        LOGERROR(msg.str());
    }
}

std::map<uint64_t, std::string> TskImgDBPostgreSQL::getUniqueCarvedFiles(HASH_TYPE hashType) const
{
    std::map<uint64_t, std::string> results;

    if (!initialized())
        return results;

    string hash;
    switch (hashType) {
    case TskImgDB::MD5:
        hash = "md5";
        break;
    case TskImgDB::SHA1:
        hash = "sha1";
        break;
    case TskImgDB::SHA2_256:
        hash = "sha2_256";
        break;
    case TskImgDB::SHA2_512:
        hash = "sha2_512";
        break;
    default:
        std::wstringstream msg;
        msg << L"TskImgDBPostgreSQL::getUniqueCarvedFiles - Unsupported hashType : " << hashType;
        LOGERROR(msg.str());
        return results;
    }

    std::stringstream stmt;

    // If hashes have not been calculated return all carved files.
    stmt << "select count(*) from file_hashes";

    try
    {
        pqxx::read_transaction trans(*m_dbConnection);
        pqxx::result R = trans.exec(stmt);
        uint64_t counter = 0;
        if (R.size() == 1)
            counter = R[0][0].as<uint64_t>();
        if (counter == 0) 
        {
            std::wstringstream msg;
            msg << L"TskImgDBPostgreSQL::getUniqueCarvedFiles - file_hashes table is empty";
            LOGWARN(msg.str());

            trans.commit();

            stmt.str("");
            stmt << "select c.file_id, f.name, 'cfile_' || c.vol_id || '_' || cs.sect_start || '_' "
                << "|| c.file_id from files f, carved_files c, carved_sectors cs "
                << "where c.file_id = cs.file_id and cs.seq = 0 and f.file_id = c.file_id order by c.file_id";
            getCarvedFileInfo(stmt.str(), results);
            return results;
        }
    }
    catch (const exception &e)
    {
        std::wstringstream msg;
        msg << L"TskImgDBPostgreSQL::getUniqueCarvedFileIds - Error getting file_hashes count : "
            << e.what();
        LOGERROR(msg.str());
    }

    stmt.str("");
    // Get the set of files for which the hash has been calculated.
    stmt << "select c.file_id, f.name, 'cfile_' || c.vol_id || '_' || cs.sect_start || '_' "
        << "|| c.file_id from files f, carved_files c, carved_sectors cs "
        << "where c.file_id = cs.file_id and cs.seq = 0 and f.file_id = c.file_id and c.file_id in "
        << "(select min(file_id) from file_hashes where " << hash << " != '' group by " << hash << " ) order by c.file_id";

    getCarvedFileInfo(stmt.str(), results);

    // Next get the set of files for which the hash has *not* been calculated.
    stmt.str("");
    stmt << "select c.file_id, f.name, 'cfile_' || c.vol_id || '_' || cs.sect_start || '_' "
        << "|| c.file_id from files f, carved_files c, carved_sectors cs "
        << "where c.file_id = cs.file_id and cs.seq = 0 and f.file_id = c.file_id and c.file_id in "
        << "(select file_id from file_hashes where " << hash << " = '') order by c.file_id";

    getCarvedFileInfo(stmt.str(), results);

    // Finally, add file info for all of the carved files for which there are no hashes of any sort.
        // All of these files must be included because without hashes there is no way to determine uniqueness.
    stmt.clear();
    stmt.str("");
    stmt << "SELECT c.file_id, f.name, 'cfile_' || c.vol_id || '_' || cs.sect_start || '_' || c.file_id "
         << "FROM files f, carved_files c, carved_sectors cs "
         << "WHERE c.file_id = cs.file_id AND cs.seq = 0 AND f.file_id = c.file_id AND c.file_id NOT IN "
         << "(SELECT fh.file_id FROM file_hashes fh) ORDER BY c.file_id";
    getCarvedFileInfo(stmt.str(), results);

    return results;
}

void TskImgDBPostgreSQL::getCarvedFileInfo(const std::string &stmtToExecute, bool getHash, std::vector<TskCarvedFileInfo> &carvedFileInfos) const
{
    TskCarvedFileInfo info;
    std::string fileName;
    pqxx::read_transaction trans(*m_dbConnection);
    pqxx::result result = trans.exec(stmtToExecute);
    for (pqxx::result::const_iterator row = result.begin(); row != result.end(); ++row)
    {
        row[0].to(info.fileID);
        row[1].to(fileName);
        row[2].to(info.cFileName);
        if (getHash)
        {
            row[3].to(info.hash);
        }

        // Append the extension from the original file name to the constructed "cfile" name.
        std::string::size_type pos = fileName.rfind('.');
        if (pos != std::string::npos)
        {
            info.cFileName.append(fileName.substr(pos));
        }

        carvedFileInfos.push_back(info);
    }
}

std::vector<TskCarvedFileInfo> TskImgDBPostgreSQL::getUniqueCarvedFilesInfo(HASH_TYPE hashType) const
{
    const std::string msgPrefix = "TskImgDBPostgreSQL::getUniqueCarvedFilesInfo : "; 

    if (!initialized())
    {
        std::ostringstream msg;
        msg << msgPrefix << "no database connection";
        throw TskException(msg.str());
    }

    // Map the hash type to a file_hashes table column name.
    string hash;
    switch (hashType) 
    {
    case TskImgDB::MD5:
        hash = "md5";
        break;
    case TskImgDB::SHA1:
        hash = "sha1";
        break;
    case TskImgDB::SHA2_256:
        hash = "sha2_256";
        break;
    case TskImgDB::SHA2_512:
        hash = "sha2_512";
        break;
    default:
        std::ostringstream msg;
        msg << msgPrefix << "unsupported hash type :" << hashType;
        throw TskException(msg.str());
    }

    try
    {
        std::vector<TskCarvedFileInfo> carvedFileInfos;

        // Do a quick check to see if any hashes have been calculated.
        std::ostringstream stmt;
        stmt << "SELECT COUNT(*) FROM file_hashes;";
        pqxx::read_transaction trans(*m_dbConnection);
        pqxx::result result = trans.exec(stmt.str());
        uint64_t counter = 0;
        if (result.size() == 1)
        {
            counter = result[0][0].as<uint64_t>();
        }
        trans.commit();

        if (counter != 0)
        {
            // At least one type of hash has been calculated (presumably for all files, but this is not guaranteed). 
            // First, add file info for the set of unique files among the carved files for which the specified type of hash is available.
            stmt.clear();
            stmt.str("");
            stmt << "SELECT c.file_id, f.name, 'cfile_' || c.vol_id || '_' || cs.sect_start || '_' || c.file_id, fh." << hash << " "
                 << "FROM files f, carved_files c, carved_sectors cs, file_hashes fh "
                 << "WHERE c.file_id = cs.file_id AND cs.seq = 0 AND f.file_id = c.file_id AND c.file_id = fh.file_id AND c.file_id IN "
                 << "(SELECT MIN(file_id) FROM file_hashes WHERE " << hash << " != '' GROUP BY " << hash << ") ORDER BY c.file_id";
            getCarvedFileInfo(stmt.str(), true, carvedFileInfos);

             // Next, add file info for all of the carved files for which the specified hash is not available.
             // All of these files must be included because without the specified hash there is no acceptable way to determine uniqueness.
            stmt.clear();
            stmt.str("");
            stmt << "SELECT c.file_id, f.name, 'cfile_' || c.vol_id || '_' || cs.sect_start || '_' || c.file_id "
                 << "FROM files f, carved_files c, carved_sectors cs "
                 << "WHERE c.file_id = cs.file_id AND cs.seq = 0 AND f.file_id = c.file_id AND c.file_id IN "
                 << "(SELECT file_id FROM file_hashes WHERE " << hash << " = '') ORDER BY c.file_id";
            getCarvedFileInfo(stmt.str(), false, carvedFileInfos);

            // Finally, add file info for all of the carved files for which there are no hashes of any sort.
             // All of these files must be included because without hashes there is no way to determine uniqueness.
            stmt.clear();
            stmt.str("");
            stmt << "SELECT c.file_id, f.name, 'cfile_' || c.vol_id || '_' || cs.sect_start || '_' || c.file_id "
                 << "FROM files f, carved_files c, carved_sectors cs "
                 << "WHERE c.file_id = cs.file_id AND cs.seq = 0 AND f.file_id = c.file_id AND c.file_id NOT IN "
                 << "(SELECT fh.file_id FROM file_hashes fh) ORDER BY c.file_id";
            getCarvedFileInfo(stmt.str(), false, carvedFileInfos);
        }
        else
        {
            // No hashes have been calculated.
            // Return carved file info all of the carved files because without hashes there is no way to determine uniqueness.
            stmt.clear();
            stmt.str("");
            stmt << "SELECT c.file_id, f.name, 'cfile_' || c.vol_id || '_' || cs.sect_start || '_' || c.file_id "
                 << "FROM files f, carved_files c, carved_sectors cs "
                 << "WHERE c.file_id = cs.file_id AND cs.seq = 0 AND f.file_id = c.file_id ORDER BY c.file_id";
            getCarvedFileInfo(stmt.str(), false, carvedFileInfos);

            std::ostringstream msg;
            msg << msgPrefix << "no hashes available, returning all carved files";
            LOGWARN(msg.str());
        }

        return carvedFileInfos;
    }
    catch (std::exception &ex)
    {
        std::stringstream msg;
        msg << msgPrefix << "std::exception: " << ex.what();
        throw TskException(msg.str());
    }
    catch (...)
    {
        throw TskException(msgPrefix + "unrecognized exception");
    }
}

std::vector<uint64_t> TskImgDBPostgreSQL::getCarvedFileIds() const
{
    return getFileIdsWorker("carved_files");
}

std::vector<uint64_t> TskImgDBPostgreSQL::getUniqueFileIds(HASH_TYPE hashType) const
{
    std::vector<uint64_t> results;

    if (!initialized())
        return results;

    string hash;
    switch (hashType) {
    case TskImgDB::MD5:
        hash = "md5";
        break;
    case TskImgDB::SHA1:
        hash = "sha1";
        break;
    case TskImgDB::SHA2_256:
        hash = "sha2_256";
        break;
    case TskImgDB::SHA2_512:
        hash = "sha2_512";
        break;
    default:
        std::wstringstream errorMsg;
        errorMsg << L"TskImgDBPostgreSQL::getUniqueFileIds - Unsupported hashType : " << hashType;
        LOGERROR(errorMsg.str());
        return results;
    }

    stringstream stmt;

    stmt << "SELECT min(file_id) FROM file_hashes WHERE " << hash << " != '' group by " << hash ;

    try
    {
        pqxx::read_transaction trans(*m_dbConnection);
        pqxx::result R = trans.exec(stmt);
        uint64_t file_id;
        for (pqxx::result::const_iterator i = R.begin(); i != R.end(); ++i)
        {
            i[0].to(file_id);
            results.push_back(file_id);
        }
    }
    catch (const exception &e)
    {
        std::wstringstream errorMsg;
        errorMsg << L"TskImgDBPostgreSQL::getUniqueFileIds - Error getting file ids : "
            << e.what();
        LOGERROR(errorMsg.str());
    }

    // Get all carved_files with empty hash, if hash was not generated.
    stmt << "SELECT file_id FROM file_hashes WHERE " << hash << " = '' ";
    try
    {
        pqxx::read_transaction trans(*m_dbConnection);
        pqxx::result R = trans.exec(stmt);
        uint64_t file_id;
        uint64_t counter = 0;
        for (pqxx::result::const_iterator i = R.begin(); i != R.end(); ++i)
        {
            i[1].to(file_id);
            results.push_back(file_id);
            counter++;
        }
        if (counter) {
            // There are some files without hash, generate a warning.
            std::wstringstream errorMsg;
            errorMsg << L"TskImgDBPostgreSQL::getUniqueFileIds - Including " << counter << L" files with no hash value.";
            LOGWARN(errorMsg.str());
        }
    }
    catch (const exception &e)
    {
        std::wstringstream errorMsg;
        errorMsg << L"TskImgDBPostgreSQL::getUniqueFileIds - Error getting file ids : "
            << e.what();
        LOGERROR(errorMsg.str());
    }
    return results;
}

/**
 * Get the list of file ids that match the given criteria.
 * The given string will be appended to "select files.file_id from files".
 *
 * @param condition Must be a valid SQL string defining the selection criteria.
 * @returns The collection of file ids matching the selection criteria. Throws
 * TskException if database not initialized.
 */
std::vector<uint64_t> TskImgDBPostgreSQL::getFileIds(const std::string& condition) const 
{
    if (!initialized())
        throw TskException("Database not initialized.");

    std::vector<uint64_t> results;
    
    std::string stmt("SELECT files.file_id from files");

    constructStmt(stmt, condition);

    try
    {
        pqxx::read_transaction trans(*m_dbConnection);
        pqxx::result R = trans.exec(stmt);
        uint64_t file_id;
        for (pqxx::result::const_iterator i = R.begin(); i != R.end(); ++i)
        {
            i[0].to(file_id);
            results.push_back(file_id);
        }
    }
    catch (const exception &e)
    {
        std::wstringstream errorMsg;
        errorMsg << L"TskImgDBPostgreSQL::getFileIds - Error getting file ids : "
            << e.what();
        LOGERROR(errorMsg.str());
    }

    return results;
}

/**
 * Get the list of file records that match the given criteria.
 * The given string will be appended to "select .... from files".
 *
 * @param condition Must be a valid SQL string defining the selection criteria.
 * @returns The collection of file records matching the selection criteria. Throws
 * TskException if database not initialized.
 */
const std::vector<TskFileRecord> TskImgDBPostgreSQL::getFileRecords(const std::string& condition) const 
{
    if (!initialized())
        throw TskException("Database not initialized.");

    std::vector<TskFileRecord> results;
    
    std::stringstream stmtstrm;
    stmtstrm << "SELECT f.file_id, f.type_id, f.name, f.par_file_id, f.dir_type, f.meta_type, f.dir_flags, "
        << "f.meta_flags, f.size, f.ctime, f.crtime, f.atime, f.mtime, f.mode, f.uid, f.gid, f.status, f.full_path, "
        << "fh.md5, fh.sha1, fh.sha2_256, fh.sha2_512 "
        << "FROM files f LEFT OUTER JOIN file_hashes fh ON f.file_id = fh.file_id ";

    std::string stmt = stmtstrm.str();

    constructStmt(stmt, condition);

    try
    {
        pqxx::read_transaction trans(*m_dbConnection);
        pqxx::result R = trans.exec(stmt);
        for (pqxx::result::const_iterator i = R.begin(); i != R.end(); ++i)
        {
            TskFileRecord fileRecord;
            
            i[0].to(fileRecord.fileId);
            i[1].to((int &)fileRecord.typeId);
            i[2].to(fileRecord.name);
            i[3].to(fileRecord.parentFileId);
            i[4].to((int &)fileRecord.dirType);
            i[5].to((int &)fileRecord.metaType);
            i[6].to((int &)fileRecord.dirFlags);
            i[7].to((int &)fileRecord.metaFlags);
            i[8].to(fileRecord.size);
            i[9].to(fileRecord.ctime);
            i[10].to(fileRecord.crtime);
            i[11].to(fileRecord.atime);
            i[12].to(fileRecord.mtime);
            i[13].to((int &)fileRecord.mode);
            i[14].to(fileRecord.uid);
            i[15].to(fileRecord.gid);
            i[16].to((int &)fileRecord.status);
            i[17].to(fileRecord.fullPath);
            i[18].to(fileRecord.md5);
            i[19].to(fileRecord.sha1);
            i[20].to(fileRecord.sha2_256);
            i[21].to(fileRecord.sha2_512);   
            results.push_back(fileRecord);
        }
    }
    catch (const exception &e)
    {
        std::wstringstream errorMsg;
        errorMsg << L"TskImgDBPostgreSQL::getFileRecords - Error getting file records: "
            << e.what();
        LOGERROR(errorMsg.str());
    }

    return results;
}

/**
 * Get the number of files that match the given criteria.
 * The given string will be appended to "select files.file_id from files".
 *
 * @param condition Must be a valid SQL string defining the selection criteria.
 * @returns The number of files matching the selection criteria. 
 */
int TskImgDBPostgreSQL::getFileCount(const std::string& condition) const 
{
    if (!initialized())
        throw TskException("Database not initialized.");

    int result = 0;
    std::string stmt("SELECT count(files.file_id) from files");

    constructStmt(stmt, condition);

    try
    {
        pqxx::read_transaction trans(*m_dbConnection);
        pqxx::result R = trans.exec(stmt);

        if (R.size() == 1)
        {
            R[0][0].to(result);
        }
        else
        {
            std::wstringstream msg;
            msg << L"TskImgDBPostgreSQL::getFileCount - Unexpected number of rows returned."
                << R.size();
            LOGERROR(msg.str());

            return -1;
        }
    }
    catch (const exception &e)
    {
        std::wstringstream msg;
        msg << L"TskImgDBPostgreSQL::getFileCount - Error getting file count : "
            << e.what();
        LOGERROR(msg.str());
        return -1;
    }

    return result;
}



void TskImgDBPostgreSQL::constructStmt(std::string& stmt, std::string condition) const
{
    if (!condition.empty())
    {
        // Remove leading whitespace from condition
        std::string trimmedCond = Poco::trimLeft(condition);

        std::string whereClause("WHERE");
        std::string joinClause("JOIN");
        std::string leftClause("LEFT");
        std::string orderClause("ORDER");

        // If the condition doesn't start with a WHERE clause and it doesn't
        // start with a comma it is presumably extending the FROM clause with
        // one or more table names. In this case we need to add the comma to
        // the statement.
        if (Poco::icompare(trimmedCond, 0, whereClause.length(), whereClause) != 0 
            && Poco::icompare(trimmedCond, 0, joinClause.length(), joinClause) != 0
            && Poco::icompare(trimmedCond, 0, leftClause.length(), leftClause) != 0
            && Poco::icompare(trimmedCond, 0, orderClause.length(), orderClause) != 0
            && trimmedCond[0] != ',')
        {
            stmt.append(",");
        }
    }

    stmt.append(" ");
    stmt.append(condition);
}

std::vector<uint64_t> TskImgDBPostgreSQL::getFileIds() const
{
    return getFileIdsWorker("files");
}

std::vector<uint64_t> TskImgDBPostgreSQL::getFileIdsWorker(std::string tableName, const std::string condition) const
{
    std::vector<uint64_t> results;

    if (!initialized())
        return results;

    stringstream stmt;
    stmt << "SELECT file_id FROM " << tableName;
    if (condition.compare("") != 0)
        stmt << " WHERE " << condition;
    stmt << " ORDER BY file_id";

    try
    {
        pqxx::read_transaction trans(*m_dbConnection);
        pqxx::result R = trans.exec(stmt);
        uint64_t file_id;
        for (pqxx::result::const_iterator i = R.begin(); i != R.end(); ++i)
        {
            i[0].to(file_id);
            results.push_back(file_id);
        }
    }
    catch (const exception &e)
    {
        std::wstringstream errorMsg;
        std::wstring wTableName;
        Poco::UnicodeConverter::toUTF16(tableName, wTableName);
        errorMsg << L"TskImgDBPostgreSQL::getFileIdsWorker - Error getting file ids from " << wTableName << " : "
            << e.what();
        LOGERROR(errorMsg.str());
    }

    return results;
}

// Set file hash for hashType for a_file_id
// Return 1 on failure, 0 on success.
int TskImgDBPostgreSQL::setHash(const uint64_t a_file_id, const TskImgDB::HASH_TYPE hashType, const std::string& hash) const
{
    if (!initialized())
        return 1;

    string hashTypeStr;
    switch (hashType) {
    case TskImgDB::MD5:
        hashTypeStr = "md5";
        break;
    case TskImgDB::SHA1:
        hashTypeStr = "sha1";
        break;
    case TskImgDB::SHA2_256:
        hashTypeStr = "sha2_256";
        break;
    case TskImgDB::SHA2_512:
        hashTypeStr = "sha2_512";
        break;
    default:
        std::wstringstream errorMsg;
        errorMsg << L"TskImgDBPostgreSQL::setHash - Unsupported hashType : " << hashType;
        LOGERROR(errorMsg.str());
        return 1;
    }

    stringstream stmt;
    bool found = false;
    std::string md5, sha1, sha2_256, sha2_512;
    int known = IMGDB_FILES_UNKNOWN;
    std::stringstream stream;

    stmt << "SELECT md5, sha1, sha2_256, sha2_512, known from file_hashes WHERE file_id = " << a_file_id;
    try 
    {
        pqxx::read_transaction W(*m_dbConnection);
        result R = W.exec(stmt);
        if (R.size() == 1) {
            R[0][0].to(md5);
            R[0][1].to(sha1);
            R[0][2].to(sha2_256);
            R[0][3].to(sha2_512);
            R[0][4].to(known);
            found = true;
        }
    }
    catch (const exception&)
    {
        ; // ok to fail if file_id don't exist
    }

    if (found) {
        // delete existing record
        stmt.str("");
        stmt << "DELETE FROM file_hashes WHERE file_id=" << a_file_id;
        try
        {
            pqxx::work W(*m_dbConnection);
            pqxx::result R = W.exec(stmt);
            W.commit();
        }
        catch (const exception &e)
        {
            std::wstringstream errorMsg;
            errorMsg << L"TskImgDBPostgreSQL::setHash - DELETE " << hashType << L" failed: " << e.what();
            LOGERROR(errorMsg.str());
            return 1;
        }

    }
    // insert new record
    stmt.str("");
    stmt << "INSERT INTO file_hashes (file_id, md5, sha1, sha2_256, sha2_512, known) VALUES (" << a_file_id;
    switch (hashType) {
    case TskImgDB::MD5:
        stmt << ", '" << hash << "'";
        stmt << ", '" << sha1 << "'";
        stmt << ", '" << sha2_256 << "'";
        stmt << ", '" << sha2_512 << "'";
        stream << known;
        stmt << ", " << stream.str();
        break;
    case TskImgDB::SHA1:
        stmt << ", '" << md5 << "'";
        stmt << ", '" << hash << "'";
        stmt << ", '" << sha2_256 << "'";
        stmt << ", '" << sha2_512 << "'";
        stream << known;
        stmt << ", " << stream.str();
        break;
    case TskImgDB::SHA2_256:
        stmt << ", '" << md5 << "'";
        stmt << ", '" << sha1 << "'";
        stmt << ", '" << hash << "'";
        stmt << ", '" << sha2_512 << "'";
        stream << known;
        stmt << ", " << stream.str();
        break;
    case TskImgDB::SHA2_512:
        stmt << ", '" << md5 << "'";
        stmt << ", '" << sha1 << "'";
        stmt << ", '" << sha2_256 << "'";
        stmt << ", '" << hash << "'";
        stream << known;
        stmt << ", " << stream.str();
        break;
    }
    stmt << ")";

    try
    {
        work W(*m_dbConnection);
        result R = W.exec(stmt);
        W.commit();
    }
    catch (const exception &e)
    {
        std::wstringstream errorMsg;
        errorMsg << L"TskDBPostgreSQL::setHash - INSERT failed: "
            << e.what();
        LOGERROR(errorMsg.str());
        return 1;
    }
    return 0;
}

std::string TskImgDBPostgreSQL::getCfileName(uint64_t a_file_id) const
{
    std::string cfileName;

    if (!initialized())
        return cfileName;

    stringstream stmt;

    stmt << "select 'cfile_' || c.vol_id || '_' || cs.sect_start || '_' || f.file_id"
        " from files f, carved_files c, carved_sectors cs where f.file_id = c.file_id and c.file_id = cs.file_id and cs.seq = 0"
        " and f.file_id = " << a_file_id;
    try
    {
        pqxx::read_transaction trans(*m_dbConnection);
        pqxx::result R = trans.exec(stmt);
        for (pqxx::result::const_iterator i = R.begin(); i != R.end(); ++i)
        {
            cfileName = (char *)i[0].c_str();
        }
    }
    catch (const exception &e)
    {
        std::wstringstream errorMsg;
        errorMsg << L"TskImgDBPostgreSQL::getCfileName - Error getting CFileName for file id " << a_file_id << " : "
            << e.what();
        LOGERROR(errorMsg.str());
    }

    stmt.str("");
    stmt << "select f.name "
        " from files f, carved_files c, carved_sectors cs where f.file_id = c.file_id and c.file_id = cs.file_id and cs.seq = 0"
        " and f.file_id = " << a_file_id;
    std::string name;
    try
    {
        pqxx::read_transaction trans(*m_dbConnection);
        pqxx::result R = trans.exec(stmt);
        for (pqxx::result::const_iterator i = R.begin(); i != R.end(); ++i)
        {
            name = (char *)i[0].c_str();
            int pos = name.rfind('.');
            if (pos != string::npos)
                cfileName += name.substr(pos);
        }
    }
    catch (const exception &e)
    {
        std::wstringstream errorMsg;
        errorMsg << L"TskImgDBPostgreSQL::getCfileName - Error getting CFileName for file id " << a_file_id << " : "
            << e.what();
        LOGERROR(errorMsg.str());
    }

    return cfileName;
}

/**
 * Return the ImageInfo
 * @param type Image Type (output)
 * @param sectorSize Image sector size (output)
 * @returns 0 on success or -1 on error.
 */
int TskImgDBPostgreSQL::getImageInfo(int & type, int & sectorSize) const
{
    int result = -1;

    if (!initialized())
        return result;

    try
    {
        pqxx::read_transaction trans(*m_dbConnection);
        pqxx::result R = trans.exec("SELECT type, ssize from image_info");

        if (R.size() == 1)
        {
            R[0][0].to(type);
            R[0][1].to(sectorSize);
            result = 0;
        }
        else
        {
            std::wstringstream errorMsg;
            errorMsg << L"TskImgDBPostgreSQL::getImageInfo - Unexpected number of rows returned."
                << R.size();
            LOGERROR(errorMsg.str());
        }
    }
    catch (const exception &e)
    {
        std::wstringstream errorMsg;
        errorMsg << L"TskImgDBPostgreSQL::getImageInfo - Error getting image_info: "
            << e.what();
        LOGERROR(errorMsg.str());
    }
    return result;
}

/**
 * Return a list of TskVolumeInfoRecord
 * @param volumeInfoList A list of TskVolumeInfoRecord (output)
 * @returns 0 on success or -1 on error.
 */
int TskImgDBPostgreSQL::getVolumeInfo(std::list<TskVolumeInfoRecord> & volumeInfoList) const
{
    int rc = -1;

    if (!initialized())
        return rc;

    try
    {
        pqxx::read_transaction trans(*m_dbConnection);
        pqxx::result R = trans.exec("SELECT vol_id, sect_start, sect_len, description, flags FROM vol_info");

        for (result::size_type rownum=0; rownum < R.size(); ++rownum) {
            const result::tuple row = R[rownum];
            TskVolumeInfoRecord vol_info;
            vol_info.vol_id = row[0].as<int>();
            vol_info.sect_start = row[1].as<uint64_t>();
            vol_info.sect_len = row[2].as<uint64_t>();
            vol_info.description.assign(row[3].as<const char *>());
            vol_info.flags = (TSK_VS_PART_FLAG_ENUM)row[4].as<int>();
            volumeInfoList.push_back(vol_info);
        }
        rc = 0;
    }
    catch (const exception &e)
    {
        std::wstringstream errorMsg;
        errorMsg << L"TskImgDBPostgreSQL::getVolumeInfo - Error getting vol_info: "
            << e.what();
        LOGERROR(errorMsg.str());
    }
    return rc;
}

/**
 * Return a list of TskFsInfoRecord
 * @param fsInfoList A list of TskFsInfoRecord (output)
 * @returns 0 on success or -1 on error.
 */
int TskImgDBPostgreSQL::getFsInfo(std::list<TskFsInfoRecord> & fsInfoList) const
{
    int rc = -1;

    if (!initialized())
        return rc;

    try
    {
        pqxx::read_transaction trans(*m_dbConnection);
        pqxx::result R = trans.exec("SELECT fs_id, img_byte_offset, vol_id, fs_type, block_size, block_count, root_inum, first_inum, last_inum FROM fs_info");

        for (result::size_type rownum=0; rownum < R.size(); ++rownum) {
            const result::tuple row = R[rownum];
            TskFsInfoRecord fs_info;
            fs_info.fs_id = row[0].as<int>();
            fs_info.img_byte_offset = row[1].as<uint64_t>();
            fs_info.vol_id = row[2].as<int>();
            fs_info.fs_type = (TSK_FS_TYPE_ENUM)row[3].as<int>();
            fs_info.block_size = row[4].as<int>();
            fs_info.block_count = row[5].as<uint64_t>();
            fs_info.root_inum = row[6].as<uint64_t>();
            fs_info.first_inum = row[7].as<uint64_t>();
            fs_info.last_inum =  row[8].as<uint64_t>();
            fsInfoList.push_back(fs_info);
        }
        rc = 0;
    }
    catch (const exception &e)
    {
        std::wstringstream errorMsg;
        errorMsg << L"TskImgDBPostgreSQL::getFsInfo - Error getting fs_info: "
            << e.what();
        LOGERROR(errorMsg.str());
    }
    return rc;
}

typedef std::map<std::string, int> FileTypeMap_t;

static std::string getFileType(const char *name)
{
    std::string filename = name;
    int pos = filename.rfind('.');
    if (pos != std::string::npos) {
        std::string suffix = filename.substr(pos);
        std::string result;
        for (size_t i=0; i < suffix.size(); i++) {
            result += (char)tolower(suffix[i]);
        }
        return result;
    }
    else
        return std::string("");
}

/**
 * Return a list of TskFileTypeRecord for all files.
 * @param fileTypeInfoList A list of TskFileTypeRecord (output)
 * @returns 0 on success or -1 on error.
 */
int TskImgDBPostgreSQL::getFileInfoSummary(std::list<TskFileTypeRecord> &fileTypeInfoList) const
{
    std::stringstream stmt;
    stmt << "SELECT name FROM files WHERE dir_type = " << TSK_FS_NAME_TYPE_REG;

    return getFileTypeRecords(stmt.str(), fileTypeInfoList);
}

/**
 * Return a list of TskFileTypeRecord for fileType
 * @param fileType FILE_TYPE to report
 * @param fileTypeInfoList A list of TskFileTypeRecord (output)
 * @returns 0 on success or -1 on error.
 */
int TskImgDBPostgreSQL::getFileInfoSummary(FILE_TYPES fileType, std::list<TskFileTypeRecord> & fileTypeInfoList) const
{
    std::stringstream stmt;
    stmt << "SELECT name FROM files WHERE type_id = " << fileType << " AND dir_type = " << TSK_FS_NAME_TYPE_REG;

    return getFileTypeRecords(stmt.str(), fileTypeInfoList);
}

/**
 * Return a list of TskFileTypeRecords matching the given SQL statement.
 * @param stmt The SQL statement used to match file records.
 * @param fileTypeInfoList A list of TskFileTypeRecord (output)
 * @returns 0 on success of -1 on error.
 */
int TskImgDBPostgreSQL::getFileTypeRecords(std::string& stmt, std::list<TskFileTypeRecord>& fileTypeInfoList) const
{
    int rc = -1;

    if (!initialized())
        return rc;

    std::list<TskFileTypeRecord> list;

    try {
        pqxx::read_transaction trans(*m_dbConnection);
        pqxx::result R = trans.exec(stmt.c_str());
        FileTypeMap_t fileTypeMap;

        for (result::size_type rownum=0; rownum < R.size(); ++rownum) {
            const result::tuple row = R[rownum];
            const char* name = row[0].as<const char *>();
            std::string type = getFileType(name);
            FileTypeMap_t::iterator iter = fileTypeMap.find(type);
            if (iter != fileTypeMap.end()) {
                // increment file counter
                int count = iter->second;
                fileTypeMap[type] = ++count;
            } else {
                // add a new file type
                fileTypeMap.insert(pair<std::string, int>(type, 1));
            }
        }
        for (FileTypeMap_t::const_iterator iter=fileTypeMap.begin(); iter != fileTypeMap.end(); iter++) {
            TskFileTypeRecord info;
            info.suffix.assign((*iter).first.c_str());
            info.count = (*iter).second;
            info.description.assign("File Type Description");
            fileTypeInfoList.push_back(info);
        }
        rc = 0;
    }
    catch (const exception &e)
    {
        std::wstringstream errorMsg;
        errorMsg << L"TskImgDBPostgreSQL::getFileTypeRecords - Error retrieving file type records: "
            << e.what();
        LOGERROR(errorMsg.str());
    }
    return rc;
}

/**
 *
 */
int TskImgDBPostgreSQL::getModuleId(const std::string& name, int & moduleId) const
{
    stringstream stmt;

    stmt << "SELECT module_id FROM modules WHERE name = " << m_dbConnection->quote(name);

    try 
    {
        pqxx::read_transaction trans(*m_dbConnection);
        result R = trans.exec(stmt);

        if (R.size() == 1)
        {
            R[0][0].to(moduleId);
        }
    }
    catch(exception& e)
    {
        std::stringstream errorMsg;
        errorMsg << "TskDBPostgreSQL::getModuleId - Error querying modules table: "
            << e.what();
        LOGERROR(errorMsg.str());
        return -1;
    }

    return 0;
}

/**
 * Insert the Module record, if module name does not already exist in modules table.
 * Returns Module Id associated with the Module record.
 * @param name Module name
 * @param description Module description
 * @param moduleId Module Id (output)
 * @returns 0 on success, -1 on error.
 */
int TskImgDBPostgreSQL::addModule(const std::string& name, const std::string& description, int & moduleId)
{
    if (!initialized())
        return 0;

    moduleId = 0;

    if (getModuleId(name, moduleId) == 0 && moduleId > 0)
        return 0;

    try 
    {
        stringstream stmt;

        work W(*m_dbConnection);
        stmt << "INSERT INTO modules (module_id, name, description) VALUES (DEFAULT, " << m_dbConnection->quote(name) << ", " << m_dbConnection->quote(description) << ")"
             << " RETURNING module_id";

        pqxx::result R = W.exec(stmt);

        // Get the newly assigned module id
        R[0][0].to(moduleId);
        W.commit();
    }
    catch (pqxx::unique_violation&)
    {
        // The module may have been added between our initial call
        // to getModuleId() and the subsequent INSERT attempt.
        getModuleId(name, moduleId);
    }
    catch (const exception &e)
    {
        std::stringstream errorMsg;
        errorMsg << "TskDBPostgreSQL::addModule - Error inserting into modules table: "
            << e.what();
        LOGERROR(errorMsg.str());
        return -1;
    }

    return 0;
}

/**
 * Insert the module status record.
 * @param file_id file_id
 * @param module_id module_id
 * @param status Status of module
 * @returns 0 on success, -1 on error.
 */
int TskImgDBPostgreSQL::setModuleStatus(uint64_t file_id, int module_id, int status)
{
    int rc = -1;

    if (!initialized())
        return rc;

    stringstream stmt;
    stmt << "INSERT INTO module_status (file_id, module_id, status) VALUES (" << 
        file_id << ", " <<
        module_id << ", " <<
        status << ")";
    try
    {
        work W(*m_dbConnection);
        result R = W.exec(stmt);
        W.commit();
        rc = 0;
    }
    catch (const exception &e)
    {
        std::wstringstream errorMsg;
        errorMsg << L"TskDBPostgreSQL::setModuleStatus - Error adding data to module_status table: "
            << e.what();
        LOGERROR(errorMsg.str());
    }
    return rc;
}

/**
 * Get a list of TskModuleStatus.
 * @param moduleStatusList A list of TskModuleStatus (output)
 * @returns 0 on success, -1 on error.
 */
int TskImgDBPostgreSQL::getModuleInfo(std::vector<TskModuleInfo> & moduleInfoList) const
{
    int rc = -1;

    if (!initialized())
        return rc;

    stringstream stmt;
    stmt << "SELECT module_id, name, description FROM modules"
         << " ORDER BY module_id";
    try
    {
        pqxx::read_transaction trans(*m_dbConnection);
        pqxx::result R = trans.exec(stmt);
        TskModuleInfo moduleInfo;
        for (pqxx::result::const_iterator i = R.begin(); i != R.end(); ++i)
        {
            i[0].to(moduleInfo.module_id);
            moduleInfo.module_name.assign(i[1].c_str());
            moduleInfo.module_description.assign(i[2].c_str());
            moduleInfoList.push_back(moduleInfo);
        }
        rc = 0;
    }
    catch (const exception &e)
    {
        std::wstringstream errorMsg;
        errorMsg << L"TskImgDBPostgreSQL::getModuleErrors - Error getting module_status: "
            << e.what();
        LOGERROR(errorMsg.str());
    }
    return rc;
}

/**
 * Get a list of TskModuleStatus.
 * @param moduleStatusList A list of TskModuleStatus (output)
 * @returns 0 on success, -1 on error.
 */
int TskImgDBPostgreSQL::getModuleErrors(std::vector<TskModuleStatus> & moduleStatusList) const
{
    int rc = -1;

    if (!initialized())
        return rc;

    stringstream stmt;
    stmt << "SELECT f.file_id, m.name, ms.status FROM module_status ms, files f, modules m"
         << " WHERE ms.status != 0 AND ms.file_id = f.file_id AND m.module_id = ms.module_id"
         << " ORDER BY f.file_id";
    try
    {
        pqxx::read_transaction trans(*m_dbConnection);
        pqxx::result R = trans.exec(stmt);
        TskModuleStatus moduleStatus;
        for (pqxx::result::const_iterator i = R.begin(); i != R.end(); ++i)
        {
            i[0].to(moduleStatus.file_id);
            moduleStatus.module_name.assign(i[1].c_str());
            i[2].to(moduleStatus.status);
            moduleStatusList.push_back(moduleStatus);
        }
        rc = 0;
    }
    catch (const exception &e)
    {
        std::wstringstream errorMsg;
        errorMsg << L"TskImgDBPostgreSQL::getModuleErrors - Error getting module_status: "
            << e.what();
        LOGERROR(errorMsg.str());
    }
    // Find report module errors. These have file_id = 0.
    stmt.str("");
    stmt << "SELECT 0, m.name, ms.status FROM module_status ms, modules m"
         << " WHERE ms.status != 0 AND ms.file_id = 0 AND m.module_id = ms.module_id";
    try
    {
        pqxx::read_transaction trans(*m_dbConnection);
        pqxx::result R = trans.exec(stmt);
        TskModuleStatus moduleStatus;
        for (pqxx::result::const_iterator i = R.begin(); i != R.end(); ++i)
        {
            i[0].to(moduleStatus.file_id);
            moduleStatus.module_name.assign(i[1].c_str());
            i[2].to(moduleStatus.status);
            moduleStatusList.push_back(moduleStatus);
        }
        rc = 0;
    }
    catch (const exception &e)
    {
        std::wstringstream errorMsg;
        errorMsg << L"TskImgDBPostgreSQL::getModuleErrors - Error getting module_status: "
            << e.what();
        LOGERROR(errorMsg.str());
    }
    return rc;
}

/*
 * Return a file name associated with a file_id, prefer Cfilename, otherwise name in the files table.
 * @param file_id file id
 * @returns file name as std::string
 */
std::string TskImgDBPostgreSQL::getFileName(uint64_t file_id) const
{
    std::string name;

    if (!initialized())
        return name;

    name = getCfileName(file_id);
    if (name == "") {
        TskFileRecord fileRecord;
        if (getFileRecord(file_id, fileRecord) == 0)
            name = fileRecord.name;
    }
    return name;
}

/**
 * Return the known status of the file with the given id
 * @param fileId id of the file to get the status of
 * @returns KNOWN_STATUS
 */
TskImgDB::KNOWN_STATUS TskImgDBPostgreSQL::getKnownStatus(const uint64_t fileId) const
{
     int retval = -1;

    if (!initialized())
        return (TskImgDB::KNOWN_STATUS)retval;

    stringstream stmt;
    stmt << "SELECT known FROM file_hashes WHERE file_id = " << fileId;

    try
    {
        pqxx::read_transaction trans(*m_dbConnection);
        pqxx::result R = trans.exec(stmt);
        pqxx::result::const_iterator i = R.begin(); 
        if(i != R.end()){
            i[0].to(retval);
        }
    }
    catch (const exception &e)
    {
        std::wstringstream errorMsg;
        std::wstring wTableName;
        errorMsg << L"TskImgDBPostgreSQL::getFileIdsWorker - Error getting known status : "
            << e.what() << std::endl;
        LOGERROR(errorMsg.str());
    }

    return (TskImgDB::KNOWN_STATUS)retval;
}

/**
 * Add a new row to the unalloc_img_status table, returning the unalloc_img_id.
 * @param unallocImgId unalloc_img_id (output)
 * @returns -1 on error, 0 on success.
 */
int TskImgDBPostgreSQL::addUnallocImg(int & unallocImgId)
{
    int rc = -1;

    if (!initialized())
        return rc;

    std::stringstream stmt;
    stmt << "INSERT INTO unalloc_img_status (unalloc_img_id, status) VALUES (DEFAULT, " << TskImgDB::IMGDB_UNALLOC_IMG_STATUS_CREATED << ")"
         << " RETURNING unalloc_img_id";
         
    try
    {
        pqxx::work W(*m_dbConnection);
        pqxx::result R = W.exec(stmt);

        // get the unalloc_img_id from the last insert
        unallocImgId = R[0][0].as<int>();
        W.commit();
        rc = 0;
    }
    catch (const exception& ex)
    {
        std::wstringstream errorMsg;
        errorMsg << L"TskImgDBPostgreSQL::addUnallocImg - Error adding unalloc_img_status table: "
            << ex.what();
        LOGERROR(errorMsg.str());
    }

    return rc;
}

/**
 * Set the status in the unalloc_img_status table given the unalloc_img_id.
 * @param unallocImgId unalloc_img_id
 * @param status status of unalloc_img_id
 * @returns -1 on error, 0 on success.
 */
int TskImgDBPostgreSQL::setUnallocImgStatus(int unallocImgId, TskImgDB::UNALLOC_IMG_STATUS status)
{
    int rc = -1;

    if (!initialized())
        return rc;

    std::stringstream stmt;
    stmt << "UPDATE unalloc_img_status SET status = " << status << " WHERE unalloc_img_id = " << unallocImgId;
    try
    {
        pqxx::work W(*m_dbConnection);
        pqxx::result R = W.exec(stmt);
        W.commit();
        rc = 0;
    }
    catch (const exception& ex)
    {
        std::wstringstream errorMsg;
        errorMsg << L"TskImgDBPostgreSQL::setUnallocImgStatus - Error updating unalloc_img_status table: "
            << ex.what() << std::endl;
        LOGERROR(errorMsg.str());
    }

    return rc;
}

/**
 * Get the status of the unalloc_img_status table given the unalloc_img_id.
 * Can throws TskException.
 * @param unallocImgId unalloc_img_id
 * @returns TskImgDB::UNALLOC_IMG_STATUS
 */
TskImgDB::UNALLOC_IMG_STATUS TskImgDBPostgreSQL::getUnallocImgStatus(int unallocImgId) const
{
    if (!initialized())
        throw TskException("Database not initialized.");

    int status;

    stringstream stmt;
    stmt << "SELECT status FROM unalloc_img_status WHERE unalloc_img_id = " << unallocImgId;
    try {
        pqxx::read_transaction trans(*m_dbConnection);
        pqxx::result R = trans.exec(stmt.str().c_str());
        if (R.size() == 1) {
            R[0][0].to(status);
        } else {
            throw TskException("No unalloc_img_status.");
        }
    }
    catch (const exception &e)
    {
        std::wstringstream errorMsg;
        errorMsg << L"TskImgDBPostgreSQL::getUnallocImgStatus - Error getting unalloc_img_status: "
            << e.what() << std::endl;
        LOGERROR(errorMsg.str());
    }
    return (TskImgDB::UNALLOC_IMG_STATUS)status;
}

/**
 * Get all the unalloc_img_status table.
 * @param unallocImgStatusList A vector of TskUnallocImgStatusRecord (output)
 * @returns -1 on error, 0 on success.
 */
int TskImgDBPostgreSQL::getAllUnallocImgStatus(std::vector<TskUnallocImgStatusRecord> & unallocImgStatusList) const
{
    int rc = -1;
    unallocImgStatusList.clear();

    if (!initialized())
        return rc;

    stringstream stmt;
    stmt << "SELECT unalloc_img_id, status FROM unalloc_img_status";

    try
    {
        pqxx::read_transaction W(*m_dbConnection);
        pqxx::result R = W.exec(stmt.str().c_str());

        for (pqxx::result::const_iterator i = R.begin(); i != R.end(); ++i)
        {
            TskUnallocImgStatusRecord record;

            i[0].to(record.unallocImgId);
            i[1].to((int &)record.status);
            unallocImgStatusList.push_back(record);
        }
        rc = 0;
    }
    catch (const exception &e)
    {
        std::wstringstream msg;
        msg << L"TskDBPostgreSQL::getAllBlackboardRows - Error querying blackboard table: "
            << e.what() << std::endl;
        LOGERROR(msg.str());
    }
    return rc;
}

/**
 * Find and add all the unused sectors (unallocated and uncarved bytes) in the given unallocImgId
 * @param unallocImgId The unalloc image id.
 * @param unusedSectorsList A vector of TskUnusedSectorsRecord
 * @returns -1 on error, 0 on success.
 */
int TskImgDBPostgreSQL::addUnusedSectors(int unallocImgId, std::vector<TskUnusedSectorsRecord> & unusedSectorsList)
{
    assert(unallocImgId > 0);

    if (!initialized())
        return -1;

    std::stringstream stmt;
    stmt << "SELECT vol_id, unalloc_img_sect_start, sect_len, orig_img_sect_start FROM alloc_unalloc_map "
        "WHERE unalloc_img_id = " << unallocImgId << " ORDER BY orig_img_sect_start ASC";

    try {
        pqxx::read_transaction W(*m_dbConnection);
        pqxx::result R = W.exec(stmt.str());

        vector<TskAllocUnallocMapRecord> allocUnallocMapList;

        for (pqxx::result::const_iterator i = R.begin(); i != R.end(); ++i)
        {
            TskAllocUnallocMapRecord record;
            i[0].to(record.vol_id);
            record.unalloc_img_id = unallocImgId;
            i[1].to(record.unalloc_img_sect_start);
            i[2].to(record.sect_len);
            i[3].to(record.orig_img_sect_start);
            allocUnallocMapList.push_back(record);
        }

        W.commit();

        for (std::vector<TskAllocUnallocMapRecord>::const_iterator it = allocUnallocMapList.begin();
             it != allocUnallocMapList.end(); it++)
        {
            // Sector position tracks our position through the unallocated map record.
            uint64_t sectPos = it->orig_img_sect_start;

            uint64_t endSect = it->orig_img_sect_start + it->sect_len;

            // Retrieve all carved_sector records in range for this section of unallocated space.
            stmt.str("");
            stmt << "SELECT cs.sect_start, cs.sect_len FROM carved_files cf, carved_sectors cs"
                << " WHERE cf.file_id = cs.file_id AND cs.sect_start >= " << it->orig_img_sect_start
                << " AND cs.sect_start < " << endSect << " ORDER BY cs.sect_start ASC";

            pqxx::read_transaction trans(*m_dbConnection);

            R = trans.exec(stmt.str());
            trans.commit();

            for (pqxx::result::const_iterator i = R.begin(); i != R.end(); i++)
            {
                uint64_t cfileSectStart;
                uint64_t cfileSectLen;

                i[0].to(cfileSectStart);
                i[1].to(cfileSectLen);

                if (cfileSectStart > sectPos)
                {
                    // We have a block of unused sectors between this position in the unallocated map
                    // and the start of the carved file.
                    addUnusedSector(sectPos, cfileSectStart, it->vol_id, unusedSectorsList);
                }

                sectPos = cfileSectStart + cfileSectLen;
            }

            // Handle case where there is slack at the end of the unalloc range
            if (sectPos < endSect)
                addUnusedSector(sectPos, endSect, it->vol_id, unusedSectorsList);
        }
    }
    catch (const exception &e)
    {
        std::wstringstream msg;
        msg << L"TskDBPostgreSQL::addUnusedSectors - Error adding unused sectors : "
            << e.what() << std::endl;
        LOGERROR(msg.str());
    }

    return 0;
}

/**
 * Add one unused sector to the database, add it to the files and unused_sectors tables.
 * @param sectStart Unused sector start.
 * @param sectEnd Unused sector end.
 * @param volId Volume Id of the unused sector.
 * @param unusedSectorsList A vector of TskUnusedSectorsRecord (output)
 * @returns -1 on error, 0 on success.
 */
int TskImgDBPostgreSQL::addUnusedSector(uint64_t sectStart, uint64_t sectEnd, int volId, std::vector<TskUnusedSectorsRecord> & unusedSectorsList)
{
    assert(sectEnd > sectStart);
    int rc = -1;
    if (!initialized())
        return rc;

    char *ufilename = "ufile";
    std::stringstream stmt;

    std::string maxUnused = GetSystemProperty("MAX_UNUSED_FILE_SIZE_BYTES");
    const uint64_t maxUnusedFileSizeBytes = maxUnused.empty() ? (50 * 1024 * 1024) : Poco::NumberParser::parse64(maxUnused);

    uint64_t maxUnusedSectorSize = maxUnusedFileSizeBytes / 512;
    uint64_t sectorIndex = 0;
    uint64_t sectorCount = (sectEnd - sectStart) / maxUnusedSectorSize;

    while (sectorIndex <= sectorCount) {
        uint64_t thisSectStart = sectStart + (sectorIndex * maxUnusedSectorSize);
        uint64_t thisSectEnd = thisSectStart + std::min(maxUnusedSectorSize, sectEnd - thisSectStart);

        stmt.str("");
        stmt << "INSERT INTO files (file_id, type_id, name, par_file_id, dir_type, meta_type,"
            "dir_flags, meta_flags, size, ctime, crtime, atime, mtime, mode, uid, gid, status, full_path) "
            "VALUES (DEFAULT, " << IMGDB_FILES_TYPE_UNUSED << ", " << m_dbConnection->quote(ufilename)
            << ", NULL, " <<  TSK_FS_NAME_TYPE_REG << ", " <<  TSK_FS_META_TYPE_REG << ", "
            << TSK_FS_NAME_FLAG_UNALLOC << ", " << TSK_FS_META_FLAG_UNALLOC << ", "
            << (thisSectEnd - thisSectStart) * 512 << ", NULL, NULL, NULL, NULL, NULL, NULL, NULL, " << IMGDB_FILES_STATUS_READY_FOR_ANALYSIS << "," << m_dbConnection->quote(ufilename) << ")"
            << " RETURNING file_id";

        try
        {
            pqxx::work W(*m_dbConnection);
            pqxx::result R = W.exec(stmt.str().c_str());

            TskUnusedSectorsRecord record;

            // get the file_id from the last insert
            record.fileId = R[0][0].as<uint64_t>();
            record.sectStart = thisSectStart;
            record.sectLen = thisSectEnd - thisSectStart;

            std::stringstream name;
            name << "ufile_" << thisSectStart << "_" << thisSectEnd << "_" << record.fileId;
            stmt.str("");
            stmt << "UPDATE files SET name = " << m_dbConnection->quote(name.str().c_str()) << ", full_path = " 
                << m_dbConnection->quote(name.str().c_str()) << " WHERE file_id = " << record.fileId;
            R = W.exec(stmt.str().c_str());

            stmt.str("");
            stmt << "INSERT INTO unused_sectors (file_id, sect_start, sect_len, vol_id) VALUES (" 
                 << record.fileId << ", " << record.sectStart << ", " << record.sectLen << ", " << volId << ")";
            R = W.exec(stmt.str().c_str());

            W.commit();
            unusedSectorsList.push_back(record);
            rc = 0;
        } 
        catch (const exception& ex)
        {
            std::wstringstream errorMsg;
            errorMsg << L"TskImgDBPostgreSQL::addUnusedSector - Error insert into files table: "
                << ex.what() << std::endl;
            LOGERROR(errorMsg.str());
            rc = -1;
            break;
        }
        sectorIndex++;
    } // while
    return rc;
}

/**
 * Get unused sector record given a file id.
 * @param fileId File id of the unused sector.
 * @param unusedSectorsRecord TskUnusedSectorsRecord (output)
 * @returns -1 on error, 0 on success.
 */
int TskImgDBPostgreSQL::getUnusedSector(uint64_t fileId, TskUnusedSectorsRecord & unusedSectorsRecord) const
{
    int rc = -1;
    if (!initialized())
        return rc;

    std::stringstream stmt;
    stmt << "SELECT sect_start, sect_len FROM unused_sectors WHERE file_id = " << fileId;

    try {
        pqxx::read_transaction W(*m_dbConnection);
        pqxx::result R = W.exec(stmt.str().c_str());
        if (R.size() == 1) {
            unusedSectorsRecord.fileId = fileId;
            unusedSectorsRecord.sectStart = R[0][0].as<uint64_t>();
            unusedSectorsRecord.sectLen = R[0][1].as<uint64_t>();
            rc = 0;
        } else {
            std::wstringstream msg;
            msg << L"TskDBPostgreSQL::getUnusedSector - Error querying unused_sectors table for file_id "
                << fileId << ", result size = " << R.size() << std::endl;
            LOGERROR(msg.str());
        }
    } 
    catch (const exception &e)
    {
        std::wstringstream msg;
        msg << L"TskDBPostgreSQL::getUnusedSector - Error querying unused_sectors table: "
            << e.what() << std::endl;
        LOGERROR(msg.str());
    }
    return rc;
}

///BLACKBOARD FUNCTIONS
/**
 * Add the given blackboard attribute to the database
 * @param attr input attribute. should be fully populated
 */
void TskImgDBPostgreSQL::addBlackboardAttribute(TskBlackboardAttribute attr){
    if (!m_dbConnection)
        throw TskException("No database.");

    artifact_t artifactId = 0;
    std::stringstream str;

    str << "INSERT INTO blackboard_attributes (artifact_id, source, context, attribute_type_id, value_type, "
        "value_byte, value_text, value_int32, value_int64, value_double, obj_id) VALUES (";
        str << attr.getArtifactID() << ", ";
    str << m_dbConnection->quote(attr.getModuleName()) << ", ";
    str << m_dbConnection->quote(attr.getContext()) << ", ";
    str << attr.getAttributeTypeID() << ", ";
    str << attr.getValueType() << ", ";
    std::string escStr;
    int a_size;
    unsigned char *pBuf;
    switch (attr.getValueType()) {
        case TSK_BYTE:
            a_size = attr.getValueBytes().size();
            pBuf = new unsigned char[a_size];
            
            for (int i = 0; i < a_size; i++) {
                pBuf[i] = attr.getValueBytes()[i];
            }

            escStr = m_dbConnection->esc_raw(pBuf, a_size);
            delete pBuf;
            str << " '" << escStr.c_str() << "', '', 0, 0, 0.0";
            break;
        case TSK_STRING:
            a_size = attr.getValueString().size();
            pBuf = new unsigned char[a_size];
            
            for (int i = 0; i < a_size; i++) {
                pBuf[i] = attr.getValueString()[i];
            }
            str << " '', " << m_dbConnection->quote(attr.getValueString()) << ", 0, 0, 0.0";
            break;
        case TSK_INTEGER:
            str << " '', '', " << attr.getValueInt() << ",     0, 0.0";
            break;
        case TSK_LONG:
            str << " '', '', 0, " << attr.getValueLong() << ",     0.0";
            break;
        case TSK_DOUBLE:
            str << " '', '', 0, 0, " << setprecision(20) << attr.getValueDouble();
            break;
    };
    str << ", " << attr.getObjectID() << ")";

    try
    {
        pqxx::work W(*m_dbConnection);
        pqxx::result R = W.exec(str);
  
        W.commit();

    } catch (const exception &e) {
        std::wstringstream msg;
        msg << L"TskDBPostgreSQL::addBlackboardAttribute - Error adding data to blackboard table: "
            << e.what() << std::endl;
        LOGERROR(msg.str());
        throw TskException("TskDBPostgreSQL::addBlackboardInfo - Insert failed");
    }
}

/**
 * Get the display name for the given artifact type id
 * @param artifactTypeID artifact type id
 * @returns display name
 */
string TskImgDBPostgreSQL::getArtifactTypeDisplayName(int artifactTypeID){
    if (!m_dbConnection)
        throw TskException("No database.");

    std::stringstream str;
    std::string displayName = "";

    str << "SELECT display_name FROM blackboard_artifact_types WHERE artifact_type_id = " << artifactTypeID;

    try{
        pqxx::work W(*m_dbConnection);
        pqxx::result R = W.exec(str);
        
        if(R.size() > 0)
            displayName = R[0][0].as<string>();
        
        W.commit();
        return displayName;

    }catch(const exception &e) {
        std::wstringstream msg;
        msg << L"TskDBPostgreSQL::getArtifactTypeDisplayName:"
            << e.what() << std::endl;
        LOGERROR(msg.str());
        throw TskException("TskDBPostgreSQL::getArtifactTypeDisplayName - No artifact type with that ID");
    }
}

/**
 * Get the artifact type id for the given artifact type string
 * @param artifactTypeString display name
 * @returns artifact type id
 */
int TskImgDBPostgreSQL::getArtifactTypeID(string artifactTypeString){
    if (!m_dbConnection)
        throw TskException("No database.");

    std::stringstream str;
    int typeID;

    str << "SELECT artifact_type_id FROM blackboard_artifact_types WHERE type_name = " << artifactTypeString;

    try{
        pqxx::work W(*m_dbConnection);
        pqxx::result R = W.exec(str);
        
        if(R.size() > 0)
            typeID = R[0][0].as<int>();
        
        W.commit();
        return typeID;
    }catch(const exception &e) {
        std::wstringstream msg;
        msg << L"TskDBPostgreSQL::getArtifactTypeID:"
            << e.what() << std::endl;
        LOGERROR(msg.str());
        throw TskException("TskDBPostgreSQL::getArtifactTypeID - No artifact type with that name");
    }
}

/**
 * Get the artifact type name for the given artifact type id
 * @param artifactTypeID id
 * @returns artifact type name
 */
string TskImgDBPostgreSQL::getArtifactTypeName(int artifactTypeID){
    if (!m_dbConnection)
        throw TskException("No database.");

    std::stringstream str;
    std::string typeName = "";

    str << "SELECT type_name FROM blackboard_artifact_types WHERE artifact_type_id = " << artifactTypeID;

    try{
        pqxx::work W(*m_dbConnection);
        pqxx::result R = W.exec(str);
        
        if(R.size() > 0)
            typeName = R[0][0].as<string>();
        W.commit();
        return typeName;
    }
    catch(const exception &e) {
        std::wstringstream msg;
        msg << L"TskDBPostgreSQL::getArtifactTypeName:"
            << e.what() << std::endl;
        LOGERROR(msg.str());
        throw TskException("TskDBPostgreSQL::getArtifactTypeName - No artifact type with that id");
    }
}

/**
 * Get the display name for the given attribute type id
 * @param attributeTypeID attribute type id
 * @returns display name
 */
string TskImgDBPostgreSQL::getAttributeTypeDisplayName(int attributeTypeID){
    if (!m_dbConnection)
        throw TskException("No database.");

    std::stringstream str;
    std::string displayName = "";

    str << "SELECT display_name FROM blackboard_attribute_types WHERE attribute_type_id = " << attributeTypeID;

    try{
        pqxx::work W(*m_dbConnection);
        pqxx::result R = W.exec(str);
        
        if(R.size() > 0)
            displayName = R[0][0].as<string>();
        W.commit();
        return displayName;
    }
    catch(const exception &e) {
        std::wstringstream msg;
        msg << L"TskDBPostgreSQL::getAttributeTypeDisplayName:"
            << e.what() << std::endl;
        LOGERROR(msg.str());
        throw TskException("TskDBPostgreSQL::getAttributeTypeDisplayName - No attribute type with that id");
    }
}

/**
 * Get the attribute type id for the given artifact type string
 * @param attributeTypeString display name
 * @returns attribute type id
 */
int TskImgDBPostgreSQL::getAttributeTypeID(string attributeTypeString){
    if (!m_dbConnection)
        throw TskException("No database.");

    std::stringstream str;
    int typeID;

    str << "SELECT attribute_type_id FROM blackboard_attribute_types WHERE type_name = " << attributeTypeString;

    try{
        pqxx::work W(*m_dbConnection);
        pqxx::result R = W.exec(str);
        
        if(R.size() > 0)
            typeID = R[0][0].as<int>();
        W.commit();
        return typeID;
    }
    catch(const exception &e) {
        std::wstringstream msg;
        msg << L"TskDBPostgreSQL::getAttributeTypeID:"
            << e.what() << std::endl;
        LOGERROR(msg.str());
        throw TskException("TskDBPostgreSQL::getAttributeTypeID - No attribute type with that name");
    }
}


/**
 * Get the attribute type name for the given artifact type id
 * @param attributeTypeID id
 * @returns attribute type name
 */
string TskImgDBPostgreSQL::getAttributeTypeName(int attributeTypeID){
    if (!m_dbConnection)
        throw TskException("No database.");

    std::stringstream str;
    std::string typeName = "";

    str << "SELECT type_name FROM blackboard_attribute_types WHERE attribute_type_id = " << attributeTypeID;

    try{
        pqxx::work W(*m_dbConnection);
        pqxx::result R = W.exec(str);
        
        if(R.size() > 0)
            typeName = R[0][0].as<string>();
        W.commit();
        return typeName;
    }
    catch(const exception &e) {
        std::wstringstream msg;
        msg << L"TskDBPostgreSQL::getAttributeTypeName:"
            << e.what() << std::endl;
        LOGERROR(msg.str());
        throw TskException("TskDBPostgreSQL::getAttributeTypeName - No attribute type with that id");
    }
}

/**
 * Get all artifacts with that match the given where clause 
 * @param whereClause where clause to use for matching
 * @returns vector of matching artifacts
 */
vector<TskBlackboardArtifact> TskImgDBPostgreSQL::getMatchingArtifacts(string whereClause){
    if (!m_dbConnection)
        throw TskException("No database.");
    
    vector<TskBlackboardArtifact> artifacts;
    std::string stmt("SELECT blackboard_artifacts.artifact_id, blackboard_artifacts.obj_id, blackboard_artifacts.artifact_type_id FROM blackboard_artifacts");

    constructStmt(stmt, whereClause);

    try
    {
        pqxx::work W(*m_dbConnection);
        pqxx::result R = W.exec(stmt);
        W.commit();

        for (pqxx::result::const_iterator i = R.begin(); i != R.end(); ++i) 
        {
            int artifactTypeID = i[2].as<int>();
            
            artifacts.push_back(TskImgDB::createArtifact(i[0].as<uint64_t>(), i[1].as<uint64_t>(), artifactTypeID));
        }
        
        return artifacts;
    } catch(const exception &e) {
        std::wstringstream msg;
        msg << L"TskDBPostgreSQL::getMatchingArtifacts:"
            << e.what() << std::endl;
        LOGERROR(msg.str());
        throw TskException("TskDBPostgreSQL::getMatchingArtifacts");
    }
    return artifacts;
}

/**
 * Get all attributes with that match the given where clause 
 * @param whereClause where clause to use for matching
 * @returns vector of matching attributes
 */
vector<TskBlackboardAttribute> TskImgDBPostgreSQL::getMatchingAttributes(string whereClause){
    if (!m_dbConnection)
        throw TskException("No database.");
    
    vector<TskBlackboardAttribute> attributes;
    std::string stmt("SELECT blackboard_attributes.artifact_id, blackboard_attributes.source, blackboard_attributes.context, blackboard_attributes.attribute_type_id, blackboard_attributes.value_type, blackboard_attributes.value_byte, blackboard_attributes.value_text, blackboard_attributes.value_int32, blackboard_attributes.value_int64, blackboard_attributes.value_double, blackboard_attributes.obj_id FROM blackboard_attributes ");

    constructStmt(stmt, whereClause);

    try
    {
        pqxx::work W(*m_dbConnection);
        pqxx::result R = W.exec(stmt);

        for (pqxx::result::const_iterator i = R.begin(); i != R.end(); ++i) 
        {
            pqxx::binarystring binStr(i[6]);
            int a_size = binStr.size();
            vector<unsigned char> bytes;
            bytes.reserve(a_size);
            for (int j = 0; j < a_size; j++)
                bytes.push_back((unsigned char)binStr[j]);
            
            attributes.push_back(TskImgDB::createAttribute(i[0].as<uint64_t>(), i[3].as<int>(), i[10].as<uint64_t>(), 
                i[1].as<string>(), i[2].as<string>(), (TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE) i[4].as<int>(), i[7].as<int>(), 
                i[8].as<uint64_t>(), i[9].as<double>(), i[6].as<string>(), bytes));
        }
        W.commit();
    } catch(const exception &e) {
        std::wstringstream msg;
        msg << L"TskDBPostgreSQL::getMatchingAttributes:"
            << e.what() << std::endl;
        LOGERROR(msg.str());
        throw TskException("TskDBPostgreSQL::getMatchingAttributes");
    }
    return attributes;
}

/**
 * Create a new blackboard artifact with the given type id and file id
 * @param artifactTypeID artifact type id
 * @param file_id associated file id
 * @returns the new artifact
 */
TskBlackboardArtifact TskImgDBPostgreSQL::createBlackboardArtifact(uint64_t file_id, int artifactTypeID){
    if (!m_dbConnection)
        throw TskException("No database.");

    uint64_t artifactId = 0;
    std::stringstream str;

    str << "INSERT INTO blackboard_artifacts (artifact_id, obj_id, artifact_type_id) VALUES (DEFAULT, " 
        << file_id << ", " << artifactTypeID << ")"
        << "RETURNING artifact_id";

    try {
        pqxx::work W(*m_dbConnection);
        pqxx::result R = W.exec(str);
        
        if (R.size() == 1)
        {
            R[0][0].to(artifactId);
        }
        else
        {
            std::stringstream errorMsg;
            errorMsg << "TskImgDBPostgreSQL::createBlackboardArtifact - Unexpected number of rows returned."
                << R.size();
            throw TskException(errorMsg.str());
        }
        W.commit();
    } catch(const exception &e) {
        std::wstringstream msg;
        msg << L"TskDBPostgreSQL::newBlackboardArtifact:"
            << e.what() << std::endl;
        LOGERROR(msg.str());
        throw TskException("TskDBPostgreSQL::newBlackboardArtifact");
    }

    return TskImgDB::createArtifact(artifactId, file_id, artifactTypeID);
}

/**
 * Add a new artifact type with the given name, display name and id 
 * @param artifactTypeName type name
 * @param displayName display name
 * @param typeID type id
 */
void TskImgDBPostgreSQL::addArtifactType(int typeID, string artifactTypeName, string displayName){
    if (!m_dbConnection)
        throw TskException("No database.");

    std::stringstream str;

    str << "SELECT * FROM blackboard_artifact_types WHERE type_name = '" << artifactTypeName << "'";

    try{
        pqxx::work W(*m_dbConnection);
        pqxx::result R = W.exec(str);
        if(R.size() == 0){
            str.str("");
            str << "INSERT INTO blackboard_artifact_types (artifact_type_id, type_name, display_name) VALUES (" << typeID << " , '" << artifactTypeName << "', '" << displayName << "')";
            pqxx::result R = W.exec(str);

        }
        else{
            throw TskException("TskImgDBPostgreSQL::addArtifactType - Artifact type with that name already exists");
        }
        W.commit();
    } catch(const exception &e) {
        std::wstringstream msg;
        msg << L"TskDBPostgreSQL::addArtifactType:"
            << e.what() << std::endl;
        LOGERROR(msg.str());
        throw TskException("TskDBPostgreSQL::addArtifactType");
    }
}

/**
 * Add a new attribute type with the given name, display name and id 
 * @param attributeTypeName type name
 * @param displayName display name
 * @param typeID type id
 */
void TskImgDBPostgreSQL::addAttributeType(int typeID, string attributeTypeName, string displayName){
    if (!m_dbConnection)
        throw TskException("No database.");

    std::stringstream str;

    str << "SELECT * FROM blackboard_attribute_types WHERE type_name = '" << attributeTypeName << "'";

    try{
        pqxx::work W(*m_dbConnection);
        pqxx::result R = W.exec(str);
        if(R.size() == 0){
            str.str("");
            str << "INSERT INTO blackboard_attribute_types (attribute_type_id, type_name, display_name) VALUES (" << typeID << " , '" << attributeTypeName << "', '" << displayName << "')";
            pqxx::result R = W.exec(str);

        }
        else{
            throw TskException("TskImgDBPostgreSQL::addArtifactType - Artifact type with that name already exists");
        }
        W.commit();
    } catch(const exception &e) {
        std::wstringstream msg;
        msg << L"TskDBPostgreSQL::addAttributeType:"
            << e.what() << std::endl;
        LOGERROR(msg.str());
        throw TskException("TskDBPostgreSQL::addAttributeType");
    }
}

/**
 * Get all artifacts with the given type id, type name, and file id
 * @param artifactTypeID type id
 * @param artifactTypeName type name
 * @param file_id file id
 */
vector<TskBlackboardArtifact> TskImgDBPostgreSQL::getArtifactsHelper(uint64_t file_id, int artifactTypeID, string artifactTypeName){
    if (!m_dbConnection)
        throw TskException("No database.");
    
    int result = 0;
    vector<TskBlackboardArtifact> artifacts;
    std::stringstream stmt;
    stmt << "SELECT artifact_id, obj_id, artifact_type_id FROM blackboard_artifacts WHERE obj_id = " << file_id << " AND artifact_type_id = " << artifactTypeID;

    try 
    {

        string displayName = getArtifactTypeDisplayName(artifactTypeID);
        pqxx::work W(*m_dbConnection);
        pqxx::result R = W.exec(stmt);

        for (pqxx::result::const_iterator i = R.begin(); i != R.end(); ++i) 
        {
            int artifactTypeID = i[2].as<int>();
            
            artifacts.push_back(TskImgDB::createArtifact(i[0].as<uint64_t>(), file_id, artifactTypeID));
        }
        W.commit();
    } catch(const exception &e) {
        std::wstringstream msg;
        msg << L"TskDBPostgreSQL::getArtifactsHelper:"
            << e.what() << std::endl;
        LOGERROR(msg.str());
        throw TskException("TskDBPostgreSQL::getArtifactsHelper");
    }
    return artifacts;
}
vector<int> TskImgDBPostgreSQL::findAttributeTypes(int artifactTypeId){
    if (!m_dbConnection)
        throw TskException("No database.");
    
    int result = 0;
    vector<int> attributeTypes;
    std::stringstream stmt;
    stmt << "SELECT DISTINCT(attribute_type_id) FROM blackboard_attributes JOIN blackboard_artifacts ON blackboard_attributes.artifact_id = blackboard_artifacts.artifact_id WHERE artifact_type_id = " << artifactTypeId;

    try 
    {
        pqxx::work W(*m_dbConnection);
        pqxx::result R = W.exec(stmt);

        for (pqxx::result::const_iterator i = R.begin(); i != R.end(); ++i) 
        {
            int artifactTypeID = i[0].as<int>();
            
            attributeTypes.push_back(artifactTypeID);
        }
        W.commit();
    } catch(const exception &e) {
        std::wstringstream msg;
        msg << L"TskDBPostgreSQL::findAttributeTypes:"
            << e.what() << std::endl;
        LOGERROR(msg.str());
        throw TskException("TskDBPostgreSQL::findAttributeTypes");
    }
    return attributeTypes;
}

std::string TskImgDBPostgreSQL::quote(const std::string str) const
{
    return m_dbConnection->quote(str);
}
