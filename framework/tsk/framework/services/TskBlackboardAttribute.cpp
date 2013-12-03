/*
* The Sleuth Kit
*
* Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
* Copyright (c) 2010-2012 Basis Technology Corporation. All Rights
* reserved.
*
* This software is distributed under the Common Public License 1.0
*/

#include <string>
#include <vector>
#include "tsk/framework/framework_i.h"
#include "TskBlackboardAttribute.h"
#include "TskBlackboardArtifact.h"
#include "TskBlackboard.h"
#include "tsk/framework/utilities/TskException.h"
#include "TskServices.h"

/**
* Default destructor
*/	
TskBlackboardAttribute::~TskBlackboardAttribute(){
}

/**
* Constructor 
* @param attributeTypeID attribute type id 
* @param moduleName module that created this attribute 
* @param context additional context 
* @param valueInt integer value
*/	
TskBlackboardAttribute::TskBlackboardAttribute(const int attributeTypeID, const string& moduleName, const string& context, const int valueInt): 
    m_artifactID(),
    m_attributeTypeID(attributeTypeID),
    m_moduleName(moduleName),
    m_context(context),
    m_valueType(TSK_INTEGER),
    m_valueInt(valueInt),   
    m_valueLong(),
    m_valueDouble(),
    m_valueString(),
    m_valueBytes(),
    m_objectID(){}

/**
* Constructor 
* @param attributeTypeID attribute type id 
* @param moduleName module that created this attribute 
* @param context additional context 
* @param valueLong 64 bit integer value
*/	
TskBlackboardAttribute::TskBlackboardAttribute(const int attributeTypeID, const string& moduleName, const string& context, const uint64_t valueLong): 
    m_artifactID(),
    m_attributeTypeID(attributeTypeID),
    m_moduleName(moduleName),
    m_context(context),
    m_valueType(TSK_LONG),
    m_valueInt(),
    m_valueLong(valueLong),   
    m_valueDouble(),
    m_valueString(),
    m_valueBytes(),
    m_objectID(){}

/**
* Constructor 
* @param attributeTypeID attribute type id 
* @param moduleName module that created this attribute 
* @param context additional context 
* @param valueDouble double value
*/	
TskBlackboardAttribute::TskBlackboardAttribute(const int attributeTypeID, const string& moduleName, const string& context, const double valueDouble): 
    m_artifactID(),
    m_attributeTypeID(attributeTypeID),
    m_moduleName(moduleName),
    m_context(context),
    m_valueType(TSK_DOUBLE),
    m_valueInt(),
    m_valueLong(),   
    m_valueDouble(valueDouble),
    m_valueString(),
    m_valueBytes(),
    m_objectID(){}

/**
* Constructor 
* @param attributeTypeID attribute type id 
* @param moduleName module that created this attribute 
* @param context additional context 
* @param valueString string value
*/	
TskBlackboardAttribute::TskBlackboardAttribute(const int attributeTypeID, const string& moduleName, const string& context, const string& valueString): 
    m_artifactID(),
    m_attributeTypeID(attributeTypeID),
    m_moduleName(moduleName),
    m_context(context),
    m_valueType(TSK_STRING),
    m_valueInt(),
    m_valueLong(),   
    m_valueDouble(),
    m_valueString(valueString),
    m_valueBytes(),
    m_objectID(){}

/**
* Constructor 
* @param attributeTypeID attribute type id 
* @param moduleName module that created this attribute 
* @param context additional context 
* @param valueBytes byte array value
*/	
TskBlackboardAttribute::TskBlackboardAttribute(const int attributeTypeID, const string& moduleName, const string& context, const vector<unsigned char>& valueBytes): 
    m_artifactID(),
    m_attributeTypeID(attributeTypeID),
    m_moduleName(moduleName),
    m_context(context),
    m_valueType(TSK_BYTE),
    m_valueInt(),
    m_valueLong(),   
    m_valueDouble(),
    m_valueString(),
    m_valueBytes(valueBytes),
    m_objectID(){}

/**
* Constructor 
* @param artifactID if of the artifact this is associated with
* @param attributeTypeID attribute type id 
* @param moduleName module that created this attribute 
* @param context additional context 
* @param valueType Type of value being set (only the corresponding value from the next parameters will be used)
* @param valueInt integer value
* @param valueLong 64 bit integer value
* @param valueDouble double value
* @param valueString string value
* @param valueBytes byte array value
* @param objectID object the attribute is associated with
*/	
TskBlackboardAttribute::TskBlackboardAttribute(const uint64_t artifactID, const int attributeTypeID, const uint64_t objectID, const string& moduleName, const string& context,
                                               const TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE valueType, const int valueInt, const uint64_t valueLong, const double valueDouble, 
                                               const string& valueString, const vector<unsigned char>& valueBytes):
m_artifactID(artifactID), 
m_attributeTypeID(attributeTypeID),
m_moduleName(moduleName),
m_context(context),
m_valueType(valueType),
m_valueInt(valueInt),
m_valueLong(valueLong),
m_valueDouble(valueDouble),
m_valueString(valueString),
m_valueBytes(valueBytes),
m_objectID(objectID){}

/**
* Get artifact id
* @returns artifact id
*/	
uint64_t TskBlackboardAttribute::getArtifactID()const{
    return m_artifactID;
}

/**
* Get attribute type id
* @returns attribute type id
*/	
int TskBlackboardAttribute::getAttributeTypeID()const{
    return m_attributeTypeID;
}

/**
* Get value type
* @returns value type
*/	
TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE TskBlackboardAttribute::getValueType()const {
    return m_valueType;
}

/**
* Get value int
* @returns value int
*/	
int TskBlackboardAttribute::getValueInt()const{
    return m_valueInt;
}

/**
* Get value long
* @returns value long
*/	
uint64_t TskBlackboardAttribute::getValueLong()const{
    return m_valueLong;
}

/**
* Get value double
* @returns value double
*/	
double TskBlackboardAttribute::getValueDouble()const{
    return m_valueDouble;
}

/**
* Get value string
* @returns value string
*/	
string TskBlackboardAttribute::getValueString()const{
    return m_valueString;
}

/**
* Get value bytes
* @returns value bytes
*/	
vector<unsigned char> TskBlackboardAttribute::getValueBytes()const{
    return m_valueBytes;
}

/**
* Get module name
* @returns module name
*/	
string TskBlackboardAttribute::getModuleName()const{
    return m_moduleName;
}

/**
* Get context
* @returns context
*/	
string TskBlackboardAttribute::getContext()const{
    return m_context;
}

/**
* Get parent artifact
* @returns parent artifact
*/	
TskBlackboardArtifact TskBlackboardAttribute::getParentArtifact()const{
    return TskServices::Instance().getBlackboard().getBlackboardArtifact(m_artifactID);
}

/**
* Get object id
* @returns object id
*/
uint64_t TskBlackboardAttribute::getObjectID()const{
    return m_objectID;
}

/**
* Set object id
* @param objectID object id
*/
void TskBlackboardAttribute::setObjectID(uint64_t objectID){
    m_objectID = objectID;
}

/**
* Set artifact id
* @param artifactID artifact id
*/
void TskBlackboardAttribute::setArtifactID(uint64_t artifactID){
    m_artifactID = artifactID;
}
