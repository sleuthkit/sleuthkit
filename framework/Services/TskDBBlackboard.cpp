/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2011 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

#include <string>
#include <sstream>

#include "TskDBBlackboard.h"
#include "Services/TskImgDB.h"
#include "Services/TskServices.h"

TskDBBlackboard * TskDBBlackboard::m_pInstance = NULL;

#define IMGDB() (TskServices::Instance().getImgDB())

TskDBBlackboard& TskDBBlackboard::instance()
{
    if (!m_pInstance)
    {
        m_pInstance = new TskDBBlackboard();
    }
    return *m_pInstance;
}

// TEXT
artifact_t TskDBBlackboard::set(const uint64_t fileId, const string & attribute, const string & value, const string & source, const string & context)
{
    TskBlackboardRecord blackboardRecord(0, fileId, attribute, source, context);
    
    blackboardRecord.valueType = TskImgDB::BB_VALUE_TYPE_STRING;
    blackboardRecord.valueString = value;

    return IMGDB().addBlackboardInfo(blackboardRecord);
}

void TskDBBlackboard::set(const artifact_t artifactId, uint64_t fileId, const string & attribute, const string & value, const string & source, const string & context)
{
    TskBlackboardRecord blackboardRecord(artifactId, fileId, attribute, source, context);
    
    blackboardRecord.valueType = TskImgDB::BB_VALUE_TYPE_STRING;
    blackboardRecord.valueString = value;

    IMGDB().addBlackboardInfo(blackboardRecord);
}

vector<string> TskDBBlackboard::getString(const uint64_t fileId, const string & attribute) const
{
    vector<string> strings;
    IMGDB().getBlackboard(fileId, attribute.c_str(), strings);
    return strings;
}

// int32
artifact_t TskDBBlackboard::set(const uint64_t fileId, const string & attribute, int32_t value, const string & source, const string & context)
{
    TskBlackboardRecord blackboardRecord(0, fileId, attribute, source, context);
    
    blackboardRecord.valueType = TskImgDB::BB_VALUE_TYPE_INT32;
    blackboardRecord.valueInt32 = value;

    return IMGDB().addBlackboardInfo(blackboardRecord);
}

void TskDBBlackboard::set(const artifact_t artifactId, const uint64_t fileId, const string & attribute, int32_t value, const string & source, const string & context)
{
    TskBlackboardRecord blackboardRecord(artifactId, fileId, attribute, source, context);
    
    blackboardRecord.valueType = TskImgDB::BB_VALUE_TYPE_INT32;
    blackboardRecord.valueInt32 = value;

    IMGDB().addBlackboardInfo(blackboardRecord);
}

vector<int32_t> TskDBBlackboard::getInt32(const uint64_t fileId, const string & attribute) const
{
    vector<int32_t> results;
    IMGDB().getBlackboard(fileId, attribute.c_str(), results);
    return results;
}

// int64
artifact_t TskDBBlackboard::set(const uint64_t fileId, const string & attribute, int64_t value, const string & source, const string & context)
{
    TskBlackboardRecord blackboardRecord(0, fileId, attribute, source, context);
    
    blackboardRecord.valueType = TskImgDB::BB_VALUE_TYPE_INT64;
    blackboardRecord.valueInt64 = value;

    return IMGDB().addBlackboardInfo(blackboardRecord);
}

void TskDBBlackboard::set(const artifact_t artifactId, const uint64_t fileId, const string & attribute, int64_t value, const string & source, const string & context)
{
    TskBlackboardRecord blackboardRecord(artifactId, fileId, attribute, source, context);
    
    blackboardRecord.valueType = TskImgDB::BB_VALUE_TYPE_INT64;
    blackboardRecord.valueInt64 = value;

    IMGDB().addBlackboardInfo(blackboardRecord);
}

vector<int64_t> TskDBBlackboard::getInt64(const uint64_t fileId, const string & attribute) const
{
    vector<int64_t> results;
    IMGDB().getBlackboard(fileId, attribute.c_str(), results);
    return results;
}

// double
artifact_t TskDBBlackboard::set(const uint64_t fileId, const string & attribute, double value, const string & source, const string & context)
{
    TskBlackboardRecord blackboardRecord(0, fileId, attribute, source, context);
    
    blackboardRecord.valueType = TskImgDB::BB_VALUE_TYPE_DOUBLE;
    blackboardRecord.valueDouble = value;

    return IMGDB().addBlackboardInfo(blackboardRecord);
}

void TskDBBlackboard::set(const artifact_t artifactId, const uint64_t fileId, const string & attribute, double value, const string & source, const string & context)
{
    TskBlackboardRecord blackboardRecord(artifactId, fileId, attribute, source, context);
    
    blackboardRecord.valueType = TskImgDB::BB_VALUE_TYPE_DOUBLE;
    blackboardRecord.valueDouble = value;

    IMGDB().addBlackboardInfo(blackboardRecord);
}

vector<double> TskDBBlackboard::getDouble(const uint64_t fileId, const string & attribute) const
{
    vector<double> results;
    IMGDB().getBlackboard(fileId, attribute.c_str(), results);
    return results;
}

// byte
artifact_t TskDBBlackboard::set(uint64_t fileId, const string & attribute, const vector<unsigned char> & value, const string & source, const string & context)
{
    TskBlackboardRecord blackboardRecord(0, fileId, attribute, source, context);
    
    blackboardRecord.valueType = TskImgDB::BB_VALUE_TYPE_BYTE;
    blackboardRecord.valueByte = value;

    return IMGDB().addBlackboardInfo(blackboardRecord);
}

void TskDBBlackboard::set(artifact_t artifactId, uint64_t fileId, const string & attribute, const vector<unsigned char> & value, const string & source, const string & context)
{
    TskBlackboardRecord blackboardRecord(artifactId, fileId, attribute, source, context);
    
    blackboardRecord.valueType = TskImgDB::BB_VALUE_TYPE_BYTE;
    blackboardRecord.valueByte = value;

    IMGDB().addBlackboardInfo(blackboardRecord);
}

vector<vector<unsigned char>> TskDBBlackboard::getByte(uint64_t fileId, const string & attribute) const
{
    vector<vector<unsigned char>> results;
    IMGDB().getBlackboard(fileId, attribute.c_str(), results);
    return results;
}

void TskDBBlackboard::getBlackboardRows(uint64_t fileId, vector<TskBlackboardRecord> & bbRecords) const
{
    IMGDB().getAllBlackboardRows(fileId, bbRecords);
}
