/*
* The Sleuth Kit
*
* Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
* Copyright (c) 2010-2012 Basis Technology Corporation. All Rights
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
#include <map>
#include "tsk/framework/framework_i.h"

using namespace std;

/**
* Value type enum, should always correspond to the stored value in an 
* attribute
*/
enum TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE {
    TSK_STRING = 0,	   ///< string
    TSK_INTEGER,   ///< int
    TSK_LONG,			///< long
    TSK_DOUBLE,	  ///< double
    TSK_BYTE,
};	  ///< byte


class TskBlackboardArtifact;
class TskBlackboard;

/**
* Class that represents a blackboard attribute object.
*/
class TSK_FRAMEWORK_API TskBlackboardAttribute 
{
public:


    /**
    * Constructor for an attribute storing an int 
    * @param attributeTypeID attribute type id 
    * @param moduleName module that created this attribute 
    * @param context additional context 
    * @param valueInt integer value
    */	
    TskBlackboardAttribute(const int attributeTypeID, const string& moduleName, const string& context, const int valueInt);
    /**
    * Constructor for an attribute storing a 64 bit integer 
    * @param attributeTypeID attribute type id 
    * @param moduleName module that created this attribute 
    * @param context additional context 
    * @param valueLong 64 bit integer value
    */	
    TskBlackboardAttribute(const int attributeTypeID, const string& moduleName, const string& context, const uint64_t valueLong);
    /**
    * Constructor for an attribute storing a double 
    * @param attributeTypeID attribute type id 
    * @param moduleName module that created this attribute 
    * @param context additional context 
    * @param valueDouble double value
    */	
    TskBlackboardAttribute(const int attributeTypeID, const string& moduleName, const string& context, const double valueDouble);
    /**
    * Constructor for an attribute storing a string
    * @param attributeTypeID attribute type id 
    * @param moduleName module that created this attribute 
    * @param context additional context 
    * @param valueString string value
    */	
    TskBlackboardAttribute(const int attributeTypeID, const string& moduleName, const string& context, const string& valueString);
    /**
    * Constructor for an attribute storing a byte array
    * @param attributeTypeID attribute type id 
    * @param moduleName module that created this attribute 
    * @param context additional context 
    * @param valueBytes byte array value
    */
    TskBlackboardAttribute(const int attributeTypeID, const string& moduleName, const string& context, const vector<unsigned char>& valueBytes);
    /*
    * destructor
    */
    ~TskBlackboardAttribute();

    /**
    * Get artifact id for the parent of this attribute
    * @returns artifact id
    */	
    uint64_t getArtifactID() const;
    /**
    * Get attribute type id for this attribute
    * @returns attribute type id
    */	
    int getAttributeTypeID() const;
    /**
    * Get typeof value this attribute stores
    * @returns value type
    */	
    TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE getValueType() const;
    /**
    * Get value int (if the attribute stores an int)
    * @returns value int
    */	
    int getValueInt() const;
    /**
    * Get value long (if the attribute stores a long0
    * @returns value long
    */	
    uint64_t getValueLong() const;
    /**
    * Get value double (if the attribute stores a double)
    * @returns value double
    */	
    double getValueDouble() const;
    /**
    * Get value string (if this attribute stores a string)
    * @returns value string
    */	
    string getValueString() const;
    /**
    * Get value bytes (if this attribute stores bytes)
    * @returns value bytes
    */	
    vector<unsigned char> getValueBytes() const;
    /**
    * Get nameof the module that created this attribute
    * @returns module name
    */
    string getModuleName() const;
    /**
    * Get context for this attribute
    * @returns context
    */
    string getContext() const;
    /**
    * Get object id this attribute is associated with
    * @returns object id
    */
    uint64_t getObjectID() const;

    /**
    * Get parent artifact for this attribute
    * @returns parent artifact
    */	
    TskBlackboardArtifact getParentArtifact() const; 

    friend class TskImgDB;
    friend class TskDBBlackboard;
    friend class TskBlackboardArtifact;
    friend class TskFile;

protected:
    void setArtifactID(uint64_t artifactID);
    void setObjectID(uint64_t objectID);

    TskBlackboardAttribute(const uint64_t artifactID, const int attributeTypeID, const uint64_t objectID, const string& moduleName, const string& context,
        const TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE valueType, const int valueInt, const uint64_t valueLong, const double valueDouble, 
        const string& valueString, const vector<unsigned char>& valueBytes);
private:
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
    uint64_t m_objectID;
};

#endif
