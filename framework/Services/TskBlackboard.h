/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2011 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

/**
 * \file TskBlackboard.h
 * Interface for class that will implement the black board.  The black board
 * is used to store data from analysis modules.  The data is available to
 * later modules in the pipeline and in the final reporting phase.
 */

#ifndef _TSK_BLACKBOARD_H
#define _TSK_BLACKBOARD_H

#include <string>
#include <vector>
#include "Utilities/TskException.h"
#include "framework_i.h"
#include "Services/TskImgDB.h"

using namespace std;

/**
 * An interface for setting and retrieving name/value pairs to the blackboard.
 * The blackboard is used to store data for use by later modules in the pipeline.
 * Can be registered with and retrieved from TskServices.
 */
class TSK_FRAMEWORK_API TskBlackboard
{
public:

    // BLACKBOARD ATTRIBUTE
    static const string TSK_DATETIME; 
    static const string TSK_GEO;      
    static const string TSK_USERNAME; 
    static const string TSK_PASSWORD; 
    static const string TSK_NAME_PERSON;
    static const string TSK_DEVICE_MODEL; 
    static const string TSK_DEVICE_MAKE;
    static const string TSK_DEVICE_ID;
    static const string TSK_KEYWORD;
    static const string TSK_EMAIL;
    static const string TSK_URL;
    static const string TSK_DOMAIN;
    static const string TSK_HASH_MD5;
    static const string TSK_HASH_SHA1;
    static const string TSK_HASH_SHA2_256;
    static const string TSK_HASH_SHA2_512;
    static const string TSK_TEXT;
    static const string TSK_TEXT_FILE;
    static const string TSK_TEXT_LANGUAGE;
    static const string TSK_ENTROPY;
    static const string TSK_PROGRAM_NAME;
    static const string TSK_HASHSET_NAME;
    static const string TSK_NAME;
    static const string TSK_VALUE;
    static const string TSK_FLAG;
    static const string TSK_PATH;
    static const string TSK_KEYWORD_REGEXP;
    static const string TSK_KEYWORD_PREVIEW;
    static const string TSK_KEYWORD_SET;

#if 0
    /**
     * Standard artifact types.
     * Refer to http://wiki.sleuthkit.org/index.php?title=Artifact_Examples
     * for the attributes that should be used with each artifact.
     */
    enum ARTIFACT_TYPE {
        /**
         * General artifact that most attributes should be stored in,
         * unless there is a better fit. */
        TSK_GEN_INFO = "TSK_GEN_INFO",
        TSK_WEB_BOOKMARK = "TSK_WEB_BOOKMARK", ///< Web browser bookmark
        TSK_WEB_COOKIE = "TSK_WEB_COOKIE", ///< web browser cookie
        TSK_WEB_HISTORY = "TSK_WEB_HISTORY", ///< web browser history
        TSK_WEB_DOWNLOAD = "TSK_WEB_DOWNLOAD", ///< web browser download
        TSK_RECENT_OBJ = "TSK_RECENT_OBJ", ///< Recently accessed object (recent doc, MRU, etc.)
        TSK_TRACKPOINT = "TSK_TRACKPOINT", ///< GPS Trackpoint from log
        TSK_INSTALLED_PROG = "TSK_INSTALLED_PROG", ///< Installed program
        TSK_KEYWORD_HIT = "TSK_KEYWORD_HIT" ///< Keyword hit
    };
#endif


    // TEXT
    virtual artifact_t set(const uint64_t fileId, const string & attribute, const string & value, const string & source = "", const string & context = "") = 0;
    virtual void set(const artifact_t artifactId, const uint64_t fileId, const string & attribute, const string & value, const string & source = "", const string & context = "") = 0;
    virtual vector<string> getString(const uint64_t fileId, const string & attribute) const = 0;

    // int32
    virtual artifact_t set(const uint64_t fileId, const string & attribute, int32_t value, const string & source = "", const string & context = "") = 0;
    virtual void set(const artifact_t artifactId, const uint64_t fileId, const string & attribute, int32_t value, const string & source = "", const string & context = "") = 0;
    virtual vector<int32_t> getInt32(const uint64_t fileId, const string & attribute) const = 0;

    // int64
    virtual artifact_t set(const uint64_t fileId, const string & attribute, int64_t value, const string & source = "", const string & context = "") = 0;
    virtual void set(const artifact_t artifactId, const uint64_t fileId, const string & attribute, int64_t value, const string & source = "", const string & context = "") = 0;
    virtual vector<int64_t> getInt64(const uint64_t fileId, const string & attribute) const = 0;

    // double
    virtual artifact_t set(const uint64_t fileId, const string & attribute, double value, const string & source = "", const string & context = "") = 0;
    virtual void set(const artifact_t artifactId, const uint64_t fileId, const string & attribute, double value, const string & source = "", const string & context = "") = 0;
    virtual vector<double> getDouble(const uint64_t fileId, const string & attribute) const = 0;

    // byte
    virtual artifact_t set(const uint64_t fileId, const string & attribute, const vector<unsigned char> & value, const string & source = "", const string & context = "") = 0;
    virtual void set(const artifact_t artifactId, const uint64_t fileId, const string & attribute, const vector<unsigned char> & value, const string & source = "", const string & context = "") = 0;
    virtual vector<vector<unsigned char>> getByte(const uint64_t fileId, const string & attribute) const = 0;
    
    virtual void getBlackboardRows(uint64_t fileId, vector<TskBlackboardRecord> & bbRecords) const = 0;

protected:
    /// Default Constructor
    TskBlackboard() {};

    /// Copy Constructor
    TskBlackboard(TskBlackboard const&) {};

    /// Destructor
    virtual ~TskBlackboard() {};
};



#endif
