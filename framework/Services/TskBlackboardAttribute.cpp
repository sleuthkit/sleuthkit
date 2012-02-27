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
#include <vector>
#include "framework_i.h"
#include "TskBlackboardAttribute.h"
#include "TskBlackboardArtifact.h"
#include "TskBlackboard.h"
#include "Utilities/TskException.h"

/**
 * Default destructor
 */	
TskBlackboardAttribute::~TskBlackboardAttribute(){
}

/**
 * Get the type name for the given attribute type
 * @param type built in attribute type
 * @returns type name
 */	
string TskBlackboardAttribute::getTypeName(ATTRIBUTE_TYPE type){
    switch(type){
        case TSK_URL:
            return "TSK_URL";
            break;
        case TSK_DATETIME:
            return "TSK_DATETIME";
            break;
        case TSK_NAME:
            return "TSK_NAME";
            break;

        case  TSK_PROG_NAME:
            return "TSK_PROG_NAME";
            break;

        case TSK_WEB_BOOKMARK:
            return "TSK_WEB_BOOKMARK";
            break;

        case TSK_VALUE:
            return "TSK_VALUE";
            break;

        case TSK_FLAG:
            return "TSK_FLAG";
            break;

        case TSK_PATH:
            return "TSK_PATH";
            break;

        case TSK_GEO:
            return "TSK_GEO";
            break;

        case TSK_KEYWORD:
            return "TSK_KEYWORD";
            break;

        case TSK_KEYWORD_REGEXP:
            return "TSK_KEYWORD_REGEXP";
            break;

        case TSK_KEYWORD_PREVIEW:
            return "TSK_KEYWORD_PREVIEW";
            break;

        case TSK_KEYWORD_SET:
            return "TSK_KEYWORD_SET";
            break;

        case TSK_USERNAME:
            return "TSK_USERNAME";
            break;

        case TSK_DOMAIN:
            return "TSK_DOMAIN";
            break;

        case TSK_PASSWORD:
            return "TSK_PASSWORD";
            break;

        case TSK_NAME_PERSON:
            return "TSK_NAME_PERSON";
            break;

        case TSK_DEVICE_MODEL:
            return "TSK_DEVICE_MODEL";
            break;

        case TSK_DEVICE_MAKE:
            return "TSK_DEVICE_MAKE";
            break;

        case TSK_DEVICE_ID:
            return "TSK_DEVICE_ID";
            break;

        case TSK_EMAIL:
            return "TSK_EMAIL";
            break;

        case TSK_HASH_HD5:
            return "TSK_HASH_HD5";
            break;

        case TSK_HASH_SHA1:
            return "TSK_HASH_SHA1";
            break;

        case TSK_HASH_SHA2_256:
            return "TSK_HASH_SHA2_256";
            break;

        case TSK_HASH_SHA2_512:
            return "TSK_HASH_SHA2_512";
            break;

        case TSK_TEXT:
            return "TSK_TEXT";
            break;

        case TSK_TEXT_FILE:
            return "TSK_TEXT_FILE";
            break;

        case TSK_TEXT_LANGUAGE:
            return "TSK_TEXT_LANGUAGE";
            break;

        case TSK_ENTROPY:
            return "TSK_ENTROPY";
            break;

        case TSK_HASHSET_NAME:
            return "TSK_HASHSET_NAME";
            break;
        case TSK_INTERESTING_FILE:
            return "TSK_INTERESTING_FILE";
            break;
        default:
            throw TskException("No Enum with that value"); 
    }

}

/**
 * Get the display name for the given attribute type
 * @param type built in attribute type
 * @returns display name
 */	
string TskBlackboardAttribute::getDisplayName(ATTRIBUTE_TYPE type){
    switch(type){
        case TSK_URL:
            return "URL";
            break;
        case TSK_DATETIME:
            return "Datetime";
            break;
        case TSK_NAME:
            return "Name";
            break;

        case  TSK_PROG_NAME:
            return "Program Name";
            break;

        case TSK_WEB_BOOKMARK:
            return "Web Bookmark";
            break;

        case TSK_VALUE:
            return "Value";
            break;

        case TSK_FLAG:
            return "Flag";
            break;

        case TSK_PATH:
            return "Path";
            break;

        case TSK_GEO:
            return "Geo";
            break;

        case TSK_KEYWORD:
            return "Keyword";
            break;

        case TSK_KEYWORD_REGEXP:
            return "Keyword Regular Expression";
            break;

        case TSK_KEYWORD_PREVIEW:
            return "Keyword Preview";
            break;

        case TSK_KEYWORD_SET:
            return "Keyword Set";
            break;

        case TSK_USERNAME:
            return "Username";
            break;

        case TSK_DOMAIN:
            return "Domain";
            break;

        case TSK_PASSWORD:
            return "Password";
            break;

        case TSK_NAME_PERSON:
            return "Person Name";
            break;

        case TSK_DEVICE_MODEL:
            return "Device Model";
            break;

        case TSK_DEVICE_MAKE:
            return "Device Make";
            break;

        case TSK_DEVICE_ID:
            return "Device ID";
            break;

        case TSK_EMAIL:
            return "Email";
            break;

        case TSK_HASH_HD5:
            return "MD5 Hash";
            break;

        case TSK_HASH_SHA1:
            return "SHA1 Hash";
            break;

        case TSK_HASH_SHA2_256:
            return "SHA2-256 Hash";
            break;

        case TSK_HASH_SHA2_512:
            return "SHA2-512 Hash";
            break;

        case TSK_TEXT:
            return "Text";
            break;

        case TSK_TEXT_FILE:
            return "Text File";
            break;

        case TSK_TEXT_LANGUAGE:
            return "Text Language";
            break;

        case TSK_ENTROPY:
            return "Entropy";
            break;

        case TSK_HASHSET_NAME:
            return "Hashset Name";
            break;

        case TSK_INTERESTING_FILE:
            return "Interesting File";
            break;
        default:
            throw TskException("No Enum with that value"); 
     
    }
}

/**
 * Construct 
 * @param attributeTypeID attribute type id 
 * @param moduleName module that created this attribute 
 * @param context additional context 
 * @param valueInt integer value
 */	
TskBlackboardAttribute::TskBlackboardAttribute(int attributeTypeID, string moduleName, string context, int valueInt){
    m_attributeTypeID = attributeTypeID;
    m_moduleName = moduleName;
    m_context = context;
    m_valueInt = valueInt;   
    m_valueType = TSK_INTEGER;
}

/**
 * Construct 
 * @param attributeTypeID attribute type id 
 * @param moduleName module that created this attribute 
 * @param context additional context 
 * @param valueLong 64 bit integer value
 */	
TskBlackboardAttribute::TskBlackboardAttribute(int attributeTypeID, string moduleName, string context, uint64_t valueLong){
    m_attributeTypeID = attributeTypeID;
    m_moduleName = moduleName;
    m_context = context;
    m_valueLong = valueLong;   
    m_valueType = TSK_LONG;
}

/**
 * Construct 
 * @param attributeTypeID attribute type id 
 * @param moduleName module that created this attribute 
 * @param context additional context 
 * @param valueDouble double value
 */	
TskBlackboardAttribute::TskBlackboardAttribute(int attributeTypeID, string moduleName, string context, double valueDouble){
    m_attributeTypeID = attributeTypeID;
    m_moduleName = moduleName;
    m_context = context;
    m_valueDouble = valueDouble;   
    m_valueType = TSK_DOUBLE;
}

/**
 * Construct 
 * @param attributeTypeID attribute type id 
 * @param moduleName module that created this attribute 
 * @param context additional context 
 * @param valueString string value
 */	
TskBlackboardAttribute::TskBlackboardAttribute(int attributeTypeID, string moduleName, string context, string valueString){
    m_attributeTypeID = attributeTypeID;
    m_moduleName = moduleName;
    m_context = context;
    m_valueString = valueString;   
    m_valueType = TSK_STRING;
}

/**
 * Construct 
 * @param blackboard the blackboard storing this
 * @param artifactID if of the artifact this is associated with
 * @param attributeTypeID attribute type id 
 * @param moduleName module that created this attribute 
 * @param context additional context 
 * @param valueInt integer value
 * @param valueLong 64 bit integer value
 * @param valueDouble double value
 * @param valueString string value
 * @param valueBytes byte array value
 */	
TskBlackboardAttribute::TskBlackboardAttribute(TskBlackboard * blackboard, uint64_t artifactID, int attributeTypeID, string moduleName, string context,
                               TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE valueType, int valueInt, uint64_t valueLong, double valueDouble, 
                               string valueString, vector<unsigned char> valueBytes){
    m_artifactID = artifactID; 
    m_attributeTypeID = attributeTypeID;
    m_moduleName = moduleName;
    m_context = context;
    m_valueType = valueType;
    m_valueInt = valueInt;
    m_valueLong = valueLong;
    m_valueDouble = valueDouble;
    m_valueString = valueString;
    m_valueBytes = valueBytes;
    m_blackboard = blackboard;
}

/**
 * Construct 
 * @param attributeTypeID attribute type id 
 * @param moduleName module that created this attribute 
 * @param context additional context 
 * @param valueBytes byte array value
 */	
TskBlackboardAttribute::TskBlackboardAttribute(int attributeTypeID, string moduleName, string context, vector<unsigned char> valueBytes){
    m_attributeTypeID = attributeTypeID;
    m_moduleName = moduleName;
    m_context = context;
    m_valueBytes = valueBytes;   
    m_valueType = TSK_BYTE;
}

/**
 * Get artifact id
 * @returns artifact id
 */	
uint64_t TskBlackboardAttribute::getArtifactID(){
    return m_artifactID;
}

/**
 * Get attribute type id
 * @returns attribute type id
 */	
int TskBlackboardAttribute::getAttributeTypeID(){
    return m_attributeTypeID;
}

/**
 * Get value type
 * @returns value type
 */	
TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE TskBlackboardAttribute::getValueType() {
    return m_valueType;
}

/**
 * Get value int
 * @returns value int
 */	
int TskBlackboardAttribute::getValueInt(){
    return m_valueInt;
}

/**
 * Get value long
 * @returns value long
 */	
uint64_t TskBlackboardAttribute::getValueLong(){
    return m_valueLong;
}

/**
 * Get value double
 * @returns value double
 */	
double TskBlackboardAttribute::getValueDouble(){
    return m_valueDouble;
}

/**
 * Get value string
 * @returns value string
 */	
string TskBlackboardAttribute::getValueString(){
    return m_valueString;
}

/**
 * Get value bytes
 * @returns value bytes
 */	
vector<unsigned char> TskBlackboardAttribute::getValueBytes(){
    return m_valueBytes;
}

/**
 * Get module name
 * @returns module name
 */	
string TskBlackboardAttribute::getModuleName(){
    return m_moduleName;
}

/**
 * Get context
 * @returns context
 */	
string TskBlackboardAttribute::getContext(){
    return m_context;
}

/**
 * Get parent artifact
 * @returns parent artifact
 */	
TskBlackboardArtifact TskBlackboardAttribute::getParentArtifact(){
    return m_blackboard->getBlackboardArtifact(m_artifactID);
}

/**
 * Set artifact id
 * @param artifactID artifact id
 */
void TskBlackboardAttribute::setArtifactID(uint64_t artifactID){
    m_artifactID = artifactID;
}

/**
 * Set blackboard
 * @param blackboard blackboard
 */
void TskBlackboardAttribute::setBlackboard(TskBlackboard * blackboard){
    m_blackboard = blackboard;
}


