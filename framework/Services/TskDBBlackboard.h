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
 * \file TskDBBlackboard.h
 * Contains the definition for the TskDBBlackboard class.
 */

#ifndef _TSK_DB_BLACKBOARD_H
#define _TSK_DB_BLACKBOARD_H

#include <string>
#include "Utilities/TskException.h"
#include "Services/TskBlackboard.h"
#include "Services/TskImgDB.h"
#include "Services/TskServices.h"

/**
 * An implementation of TskBlackboard that stores the name / value pairs
 * in the TskImgDB. 
 */
class TSK_FRAMEWORK_API TskDBBlackboard : public TskBlackboard
{
public:
    // Singleton access
    static TskDBBlackboard& instance();

    // TEXT
    virtual artifact_t set(const uint64_t fileId, const string & attribute, const string & value, const string & source = "", const string & context = "");
    virtual void set(const artifact_t artifactId, const uint64_t fileId, const string & attribute, const string & value, const string & source = "", const string & context = "");
    virtual vector<string> getString(const uint64_t fileId, const string & attribute) const;

    // int32
    virtual artifact_t set(const uint64_t fileId, const string & attribute, int32_t value, const string & source = "", const string & context = "");
    virtual void set(const artifact_t artifactId, const uint64_t fileId, const string & attribute, int32_t value, const string & source = "", const string & context = "");
    virtual vector<int32_t> getInt32(const uint64_t fileId, const string & attribute) const;

    // int64
    virtual artifact_t set(const uint64_t fileId, const string & attribute, int64_t value, const string & source = "", const string & context = "");
    virtual void set(const artifact_t artifactId, const uint64_t fileId, const string & attribute, int64_t value, const string & source = "", const string & context = "");
    virtual vector<int64_t> getInt64(const uint64_t fileId, const string & attribute) const;

    // double
    virtual artifact_t set(const uint64_t fileId, const string & attribute, double value, const string & source = "", const string & context = "");
    virtual void set(const artifact_t artifactId, const uint64_t fileId, const string & attribute, double value, const string & source = "", const string & context = "");
    virtual vector<double> getDouble(const uint64_t fileId, const string & attribute) const;

    // byte
    virtual artifact_t set(const uint64_t fileId, const string & attribute, const vector<unsigned char> & value, const string & source = "", const string & context = "");
    virtual void set(const artifact_t artifactId, const uint64_t fileId, const string & attribute, const vector<unsigned char> & value, const string & source = "", const string & context = "");
    virtual vector<vector<unsigned char>> getByte(const uint64_t fileId, const string & attribute) const;
	virtual void getBlackboardRows(uint64_t fileId, vector<TskBlackboardRecord> & bbRecords) const;

protected:
    // Default Constructor
    TskDBBlackboard() { m_pImgDB = &(TskServices::Instance().getImgDB()); };

    // Copy Constructor
    TskDBBlackboard(TskDBBlackboard const&) {};

    // Assignment operator
    TskDBBlackboard& operator=(TskDBBlackboard const&) { return *m_pInstance; };

    // Destructor
    virtual ~TskDBBlackboard() {};

    // Our one and only instance
    static TskDBBlackboard * m_pInstance;

    TskImgDB * m_pImgDB;
};

#endif
