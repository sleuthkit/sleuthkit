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
 * Contains the interface for the TskBlackboard class.
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
 */
class TSK_FRAMEWORK_API TskBlackboard
{
public:

    // BLACKBOARD ATTRIBUTE
    static const string TSK_DATETIME; // INT32: GMT based Unix time, defines number of secords elapsed since UTC Jan 1, 1970.
    static const string TSK_GEO;      // STRING: TBD
    static const string TSK_USERNAME; // STRING: TBD
    static const string TSK_PASSWORD; // STRING: TBD
    static const string TSK_NAME;     // STRING: TBD
    static const string TSK_DEVICE_MODEL; // STRING: TBD
    static const string TSK_DEVICE_MAKE;  // STRING: TBD
    static const string TSK_DEVICE_ID;// STRING: TBD
    static const string TSK_RECENTLYUSED; // STRING: TBD
    static const string TSK_KEYWORD;  // STRING: One keyword per artifact
    static const string TSK_EMAIL;    // STRING: One email per artifact
    static const string TSK_URL;      // STRING: URL, should starts with http:// or ftp:// etc.
    static const string TSK_URL_HISTORY; // STRING: One URL per artifact
    static const string TSK_DOMAIN;   // STRING: DNS Domain name, e.g. basis.com
    static const string TSK_HASH_MD5; // STRING: MD5 hash
    static const string TSK_HASH_SHA1;     // STRING: SHA1 hash
    static const string TSK_HASH_SHA2_256; // STRING: SHA2 256 bit hash
    static const string TSK_HASH_SHA2_512; // STRING: SHA2 512 bit hash
    static const string TSK_TEXT;      // STRING: TEXT
    static const string TSK_TEXT_LANGUGE;  // STRING: Language of Text, should use ISO 639-3 langage code
    static const string TSK_ENTROPY;   // DOUBLE: Entropy value of file
    static const string TSK_PROGRAM_NAME;   // STRING: name of a program
    static const string TSK_HASHSET_NAME; //STRING: name of a hashset

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
