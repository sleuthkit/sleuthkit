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
 * \file TskImgDB.cpp
 * Some common defines used by the framework data model.
 */

#include "TskImgDB.h"

/// Default constructor
TskImgDB::TskImgDB()
{
}

/// Destructor
TskImgDB::~TskImgDB()
{
}

//// Convenience functions

// return the valueString field, if valueType is BB_VALUE_TYPE_STRING, otherwise raise exception
string TskImgDB::toString(const TskBlackboardRecord & rec) const
{
    if (rec.valueType == BB_VALUE_TYPE_STRING)
        return rec.valueString;
    else
        throw("Invalid Blackboard record: valueType not STRING");
    return "";
}

// return the valueInt32 field, if valueType is BB_VALUE_TYPE_INT32, otherwise raise exception
int32_t TskImgDB::toInt32(const TskBlackboardRecord & rec) const
{
    if (rec.valueType == BB_VALUE_TYPE_INT32)
        return rec.valueInt32;
    else
        throw("Invalid Blackboard record: valueType not INT32");
}

// return the valueInt64 field, if valueType is BB_VALUE_TYPE_INT64, otherwise raise exception
int64_t TskImgDB::toInt64(const TskBlackboardRecord & rec) const
{
    if (rec.valueType == BB_VALUE_TYPE_INT64)
        return rec.valueInt64;
    else
        throw("Invalid Blackboard record: valueType not INT64");
}

// return the valueDouble field, if valueType is BB_VALUE_TYPE_DOUBLE, otherwise raise exception
double TskImgDB::toDouble(const TskBlackboardRecord & rec) const
{
    if (rec.valueType == BB_VALUE_TYPE_DOUBLE)
        return rec.valueDouble;
    else
        throw("Invalid Blackboard record: valueType not Double");
}
