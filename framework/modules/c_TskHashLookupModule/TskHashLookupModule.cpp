/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2011-2012 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

/** \file TskHashLookupModule.cpp
 * Contains an implementation of a hash look up file analysis module that uses one or more
 * TSK hash database indexes to check a given file's MD5 hash against known bad file and 
 * known file hash sets. Hash set hits are posted to the blackboard and the module can be 
 * configured to issue a pipeline stop request if there is a hit.
 */

// System includes
#include <string>
#include <vector>
#include <sstream>

// Framework includes
#include "tsk/framework/utilities/TskModuleDev.h"

// Poco includes
#include "Poco/StringTokenizer.h"

namespace
{
    const char *MODULE_NAME = "TskHashLookup";
    const char *MODULE_DESCRIPTION = "Looks up a file's MD5 hash value in one or more hash databases that have been indexed using the Sleuth Kit's hfind tool";
    const char *MODULE_VERSION = "1.0.0";

    static bool issueStopRequestsOnHits = false;
    static TSK_HDB_INFO* knownHashDBInfo = NULL;
    static std::vector<TSK_HDB_INFO*> knownBadHashDBInfos;
}



/**
 * Helper function to open the index file for a TSK-indexed hash database.
 *
 * @param hashDatabasePath The path to a TSK-indexed hash database file.
 * @param option           The option argument associated with the file, 
 *                         for logging purposes.
 * @return                 A TSK_HDB_INFO pointer if the index file is 
 *                         successfully opened, NULL otherwise.
 */
static TSK_HDB_INFO* openHashDatabaseIndexFile(const std::string& hashDatabasePath, const std::string& option)
{
    // Was the hash database path specified?
    if (hashDatabasePath.empty()) {
        std::wstringstream msg;
        msg << L"TskHashLookupModule::initialize - missing hash database path for " << option.c_str() << L" option.";
        LOGERROR(msg.str());
        return NULL;
    }

    // Get a hash database info record for the hash database.
    std::vector<TSK_TCHAR> hashDbPath(hashDatabasePath.length() + 1);
    std::copy(hashDatabasePath.begin(), hashDatabasePath.end(), hashDbPath.begin());
    hashDbPath[hashDatabasePath.length()] = '\0';
    TSK_HDB_INFO* hashDBInfo = tsk_hdb_open(&hashDbPath[0], TSK_HDB_OPEN_IDXONLY);

    if (!hashDBInfo) {
        std::wstringstream msg;
        msg << L"TskHashLookupModule::initialize - failed to hash database info record for '" << hashDatabasePath.c_str() << L"'";
        LOGERROR(msg.str());
        return NULL;
    }

    // Is there an MD5 index?
    if (!tsk_hdb_hasindex(hashDBInfo, TSK_HDB_HTYPE_MD5_ID)) {
        std::wstringstream msg;
        msg << L"TskHashLookupModule::initialize - failed to find MD5 index for '" << hashDatabasePath.c_str() << L"'";
        LOGERROR(msg.str());
        return NULL;
    }

    return hashDBInfo;
}

extern "C" 
{
    /**
     * Module identification function. 
     *
     * @return The name of the module.
     */
    TSK_MODULE_EXPORT const char *name()
    {
        return MODULE_NAME;
    }

    /**
     * Module identification function. 
     *
     * @return A description of the module.
     */
    TSK_MODULE_EXPORT const char *description()
    {
        return MODULE_DESCRIPTION;
    }

    /**
     * Module identification function. 
     *
     * @return The version of the module.
     */
    TSK_MODULE_EXPORT const char *version()
    {
        return MODULE_VERSION;
    }

    /**
     * Module initialization function. 
     *
     * @param args A semicolon delimited list of arguments:
     *      -k <path> The path of a TSK-indexed hash database for a known files
     *                hash set.
     *      -b <path> The path of a TSK-indexed hash database for a known bad 
     *                files hash set. Multiple known bad hash sets may be 
     *                specified.
     *      -s        A flag directing the module to issue a pipeline stop 
     *                request if a hash set hit occurs.
     * @return TskModule::OK if initialization succeeded, otherwise TskModule::FAIL.
     */
    TskModule::Status TSK_MODULE_EXPORT initialize(const char* arguments)
    {
        std::string args(arguments);

        // At least one hash database path must be provided.
        if (args.empty()) {
            LOGERROR(L"TskHashLookupModule::initialize - passed empty argument string.");
            return TskModule::FAIL;
        }

        // Parse and process the arguments.
        Poco::StringTokenizer tokenizer(args, ";");
        std::vector<std::string> argsVector(tokenizer.begin(), tokenizer.end());
        for (std::vector<std::string>::const_iterator it = argsVector.begin(); it < argsVector.end(); ++it) {
            if ((*it).find("-s") == 0) {
                issueStopRequestsOnHits = true;
            }
            else if ((*it).find("-k") == 0) {
                // Only one known files hash set may be specified.
                if (knownHashDBInfo) {
                    LOGERROR(L"TskHashLookupModule::initialize - multiple known hash databases specified, only one is allowed.");
                    return TskModule::FAIL;
                }

                knownHashDBInfo = openHashDatabaseIndexFile((*it).substr(3), "-k");
                if (!knownHashDBInfo)
                    return TskModule::FAIL;
            }
            else if ((*it).find("-b") == 0) {
                // Any number of known bad files hash sets may be specified.
                TSK_HDB_INFO* hashDBInfo = openHashDatabaseIndexFile((*it).substr(3), "-b");
                if (hashDBInfo)
                    knownBadHashDBInfos.push_back(hashDBInfo);
                else
                    return TskModule::FAIL;
            }
            else {
                LOGERROR(L"TskHashLookupModule::initialize - unrecognized option in argument string.");
                return TskModule::FAIL;
            }
        }

        // At least one hash database file path must be provided.
        if (!knownHashDBInfo && knownBadHashDBInfos.empty()) {
            LOGERROR(L"TskHashLookupModule::initialize - no hash database paths specified in argument string.");
            return TskModule::FAIL;
        }

        return TskModule::OK;
    }

    /**
     * Module execution function. Receives a pointer to a file the module is to
     * process. The file is represented by a TskFile interface which is queried
     * to get the MD5 hash of the file. The hash is then used do a lookup in
     * the hash database. If the lookup succeeds, a request to terminate 
     * processing of the file is issued.
     *
     * @param pFile File for which the hash database lookup is to be performed.
     * @returns     TskModule::FAIL if an error occurs, otherwise TskModule::OK 
     *              or TskModule::STOP. TskModule::STOP is returned if the look 
     *              up succeeds and the module is configured to request a 
     *              pipeline stop when a hash set hit occurs.
     */
    TskModule::Status TSK_MODULE_EXPORT run(TskFile * pFile)
    {
        // Received a file to analyze?
        if (pFile == NULL) {
            LOGERROR(L"TskHashLookupModule::run passed NULL file pointer.");
            return TskModule::FAIL;
        }

        // Need at least one hash database index file to run.
        if (!knownHashDBInfo && knownBadHashDBInfos.empty()) {
            LOGERROR(L"TskHashLookupModule::run - no hash database index files to search.");
            return TskModule::FAIL;
        }

        // Check for hash set hits.
        TskBlackboard &blackBoard = TskServices::Instance().getBlackboard();
        TskImgDB& imageDB = TskServices::Instance().getImgDB();
        bool hashSetHit = false;
        try {
            std::string md5 = pFile->getHash(TskImgDB::MD5); 

            // Check for known bad files hash set hits. If a hit occurs, mark the file as IMGDB_FILES_KNOWN_BAD
            // and post the hit to the blackboard.
            for (std::vector<TSK_HDB_INFO*>::iterator it = knownBadHashDBInfos.begin(); it < knownBadHashDBInfos.end(); ++it) {
                if (tsk_hdb_lookup_str(*it, md5.c_str(), TSK_HDB_FLAG_QUICK, NULL, NULL)) {
                    if (!hashSetHit) {
                        imageDB.updateKnownStatus(pFile->getId(), TskImgDB::IMGDB_FILES_KNOWN_BAD);
                        hashSetHit = true;
                    }
                    TskBlackboardArtifact artifact = blackBoard.createArtifact(pFile->getId(), TSK_HASHSET_HIT);
                    TskBlackboardAttribute attribute(TSK_SET_NAME, "TskHashLookupModule", "", (*it)->db_name);
                    artifact.addAttribute(attribute);
                }
            }

            // If there were no known bad file hits, check for a known file hash set hit. if a hit occurs, 
            // mark the file as IMGDB_FILES_KNOWN and post the hit to the blackboard.
            if (knownHashDBInfo && !hashSetHit && tsk_hdb_lookup_str(knownHashDBInfo, md5.c_str(), TSK_HDB_FLAG_QUICK, NULL, NULL)) {
                imageDB.updateKnownStatus(pFile->getId(), TskImgDB::IMGDB_FILES_KNOWN);
                hashSetHit = true;
                TskBlackboardArtifact artifact = blackBoard.createArtifact(pFile->getId(), TSK_HASHSET_HIT);
                TskBlackboardAttribute attribute(TSK_SET_NAME, "TskHashLookupModule", "", knownHashDBInfo->db_name);
                artifact.addAttribute(attribute);
            }
        }
        catch (TskException& ex) {
            std::wstringstream msg;
            msg << L"TskHashLookupModule::run - error on lookup for file id " << pFile->getId() << L": " << ex.what();
            LOGERROR(msg.str());
            return TskModule::FAIL;
        }

        return hashSetHit && issueStopRequestsOnHits ? TskModule::STOP : TskModule::OK;
    }

    /**
     * Module cleanup function that closes the hash database index files.
     *
     * @returns TskModule::OK 
     */
    TskModule::Status TSK_MODULE_EXPORT finalize() 
    {
        if (knownHashDBInfo != NULL)
            tsk_hdb_close(knownHashDBInfo); // Closes the index file and frees the memory for the TSK_HDB_INFO struct. 

        for (std::vector<TSK_HDB_INFO*>::iterator it = knownBadHashDBInfos.begin(); it < knownBadHashDBInfos.end(); ++it)
            tsk_hdb_close(*it); // Closes the index file and frees the memory for the TSK_HDB_INFO struct.

        return TskModule::OK;
    }
}
