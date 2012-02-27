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
 * \file TskBlackboardAttribute.h
 * Contains the definition for the TskBlackboardAttribute class.
 */

#ifndef _TSK_BLACKBOARD_ATTR_H
#define _TSK_BLACKBOARD_ATTR_H

#include <string>
#include <vector>
#include "framework_i.h"

using namespace std;

/**
 * Value type enum, should always correspond to the stored value in an 
 * attribute
 */
typedef enum TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE {
    TSK_STRING = 0,	   ///< string
    TSK_INTEGER,   ///< int
    TSK_LONG,			///< long
    TSK_DOUBLE,	  ///< double
    TSK_BYTE,
};	  ///< byte

/**
 * Built in attribute types 
 */
typedef enum ATTRIBUTE_TYPE {
    TSK_URL = 1,
    TSK_DATETIME,
    TSK_NAME,
    TSK_PROG_NAME,
    TSK_WEB_BOOKMARK,
    TSK_VALUE,
    TSK_FLAG,
    TSK_PATH,
    TSK_GEO,
    TSK_KEYWORD,
    TSK_KEYWORD_REGEXP,
    TSK_KEYWORD_PREVIEW,
    TSK_KEYWORD_SET,
    TSK_USERNAME,
    TSK_DOMAIN,
    TSK_PASSWORD,
    TSK_NAME_PERSON,
    TSK_DEVICE_MODEL,
    TSK_DEVICE_MAKE,
    TSK_DEVICE_ID,
    TSK_EMAIL,
    TSK_HASH_HD5,
    TSK_HASH_SHA1,
    TSK_HASH_SHA2_256,
    TSK_HASH_SHA2_512,
    TSK_TEXT,
    TSK_TEXT_FILE,
    TSK_TEXT_LANGUAGE ,
    TSK_ENTROPY,
    TSK_HASHSET_NAME,
    TSK_INTERESTING_FILE,
};

class TskBlackboardArtifact;
class TskBlackboard;

/**
 * Class that represents a blackboard attribute object.
 */
class TSK_FRAMEWORK_API TskBlackboardAttribute 
{
public:
	static string getTypeName(ATTRIBUTE_TYPE type);
	static string getDisplayName(ATTRIBUTE_TYPE type);
	TskBlackboardAttribute(int attributeTypeID, string moduleName, string context, int valueInt);
	TskBlackboardAttribute(int attributeTypeID, string moduleName, string context, uint64_t valueLong);
	TskBlackboardAttribute(int attributeTypeID, string moduleName, string context, double valueDouble);
	TskBlackboardAttribute(int attributeTypeID, string moduleName, string context, string valueString);
	TskBlackboardAttribute(int attributeTypeID, string moduleName, string context, vector<unsigned char> valueBytes);
    TskBlackboardAttribute(TskBlackboard * blackboard, uint64_t artifactID, int attributeTypeID, string moduleName, string context,
		TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE valueType, int valueInt, uint64_t valueLong, double valueDouble, 
		string valueString, vector<unsigned char> valueBytes);
    ~TskBlackboardAttribute();
    virtual uint64_t getArtifactID();
	virtual int getAttributeTypeID();
	virtual TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE getValueType();
	virtual int getValueInt();
	virtual uint64_t getValueLong();
    virtual double getValueDouble();
    virtual string getValueString();
    virtual vector<unsigned char> getValueBytes();
    virtual string getModuleName();
    virtual string getContext();
    virtual TskBlackboardArtifact getParentArtifact();
    virtual void setArtifactID(uint64_t artifactID);
    virtual void setBlackboard(TskBlackboard * blackboard);
protected:

private:
    TskBlackboardAttribute();
    uint64_t m_artifactID;
	int m_attributeTypeID;
	string m_moduleName;
	string m_context;
	TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE m_valueType;
	int m_valueInt;
	uint64_t m_valueLong;
	double m_valueDouble;
	string m_valueString;
	vector<unsigned char> m_valueBytes;
    TskBlackboard * m_blackboard;
};

#endif