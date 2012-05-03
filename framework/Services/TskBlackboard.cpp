/*
* The Sleuth Kit
*
* Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
* Copyright (c) 2010-2011 Basis Technology Corporation. All Rights
* reserved.
*
* This software is distributed under the Common Public License 1.0
*/

#include "TskBlackboard.h"

map<int, TskArtifactNames> initializeArtifactTypeMap(){
    map<int, TskArtifactNames> retval;
    retval.insert(pair<int, TskArtifactNames>(TSK_ART_GEN_INFO, TskArtifactNames("TSK_ART_GEN_INFO", "General Info")));
    retval.insert(pair<int, TskArtifactNames>(TSK_ART_WEB_BOOKMARK, TskArtifactNames("TSK_ART_WEB_BOOKMARK", "Date Time")));
    retval.insert(pair<int, TskArtifactNames>(TSK_ART_WEB_COOKIE, TskArtifactNames("TSK_ART_WEB_COOKIE", "Web Cookie")));
    retval.insert(pair<int, TskArtifactNames>(TSK_ART_WEB_HISTORY, TskArtifactNames("TSK_ART_WEB_HISTORY", "History")));
    retval.insert(pair<int, TskArtifactNames>(TSK_ART_WEB_DOWNLOAD, TskArtifactNames("TSK_ART_WEB_DOWNLOAD", "Download")));
    retval.insert(pair<int, TskArtifactNames>(TSK_ART_RECENT_OBJECT, TskArtifactNames("TSK_ART_RECENT_OBJECT", "Recent History Object")));
    retval.insert(pair<int, TskArtifactNames>(TSK_ART_TRACKPOINT, TskArtifactNames("TSK_ART_TRACKPOINT", "Trackpoint")));
    retval.insert(pair<int, TskArtifactNames>(TSK_ART_INSTALLED_PROG, TskArtifactNames("TSK_ART_INSTALLED_PROG", "Installed Program")));
    retval.insert(pair<int, TskArtifactNames>(TSK_ART_KEYWORD_HIT, TskArtifactNames("TSK_ART_KEYWORD_HIT", "Keyword Hit")));
    retval.insert(pair<int, TskArtifactNames>(TSK_ART_DEVICE_ATTACHED, TskArtifactNames("TSK_ART_DEVICE_ATTACHED", "Device Attached")));
    return retval;
}

map<int, TskAttributeNames> initializeAttributeTypeMap(){
    map<int, TskAttributeNames> retval;
    retval.insert(pair<int, TskAttributeNames>(TSK_URL, TskAttributeNames("TSK_URL", "URL")));
    retval.insert(pair<int, TskAttributeNames>(TSK_DATETIME, TskAttributeNames("TSK_DATETIME", "Datetime")));
    retval.insert(pair<int, TskAttributeNames>(TSK_NAME, TskAttributeNames("TSK_NAME", "Name")));
    retval.insert(pair<int, TskAttributeNames>(TSK_PROG_NAME, TskAttributeNames("TSK_PROG_NAME", "Program Name")));
    retval.insert(pair<int, TskAttributeNames>(TSK_WEB_BOOKMARK, TskAttributeNames("TSK_WEB_BOOKMARK", "Web Bookmark")));
    retval.insert(pair<int, TskAttributeNames>(TSK_VALUE, TskAttributeNames("TSK_VALUE", "Value")));
    retval.insert(pair<int, TskAttributeNames>(TSK_FLAG, TskAttributeNames("TSK_FLAG", "Flag")));
    retval.insert(pair<int, TskAttributeNames>(TSK_PATH, TskAttributeNames("TSK_PATH", "Path")));
    retval.insert(pair<int, TskAttributeNames>(TSK_GEO, TskAttributeNames("TSK_GEO", "Geo")));
    retval.insert(pair<int, TskAttributeNames>(TSK_KEYWORD, TskAttributeNames("TSK_KEYWORD", "Keyword")));
    retval.insert(pair<int, TskAttributeNames>(TSK_KEYWORD_REGEXP, TskAttributeNames("TSK_KEYWORD_REGEXP", "Keyword Regular Expression")));
    retval.insert(pair<int, TskAttributeNames>(TSK_KEYWORD_PREVIEW, TskAttributeNames("TSK_KEYWORD_PREVIEW", "Keyword Preview")));
    retval.insert(pair<int, TskAttributeNames>(TSK_KEYWORD_SET, TskAttributeNames("TSK_KEYWORD_SET", "Keyword Set")));
    retval.insert(pair<int, TskAttributeNames>(TSK_USERNAME, TskAttributeNames("TSK_USERNAME", "Username")));
    retval.insert(pair<int, TskAttributeNames>(TSK_DOMAIN, TskAttributeNames("TSK_DOMAIN", "Domain")));
    retval.insert(pair<int, TskAttributeNames>(TSK_PASSWORD, TskAttributeNames("TSK_PASSWORD", "Password")));
    retval.insert(pair<int, TskAttributeNames>(TSK_NAME_PERSON, TskAttributeNames("TSK_NAME_PERSON", "Person Name")));
    retval.insert(pair<int, TskAttributeNames>(TSK_DEVICE_MODEL, TskAttributeNames("TSK_DEVICE_MODEL", "Device Model")));
    retval.insert(pair<int, TskAttributeNames>(TSK_DEVICE_MAKE, TskAttributeNames("TSK_DEVICE_MAKE", "Device Make")));
    retval.insert(pair<int, TskAttributeNames>(TSK_DEVICE_ID, TskAttributeNames("TSK_DEVICE_ID", "Device ID")));
    retval.insert(pair<int, TskAttributeNames>(TSK_EMAIL, TskAttributeNames("TSK_EMAIL", "Email")));
    retval.insert(pair<int, TskAttributeNames>(TSK_HASH_HD5, TskAttributeNames("TSK_HASH_HD5", "MD5 Hash")));
    retval.insert(pair<int, TskAttributeNames>(TSK_HASH_SHA1, TskAttributeNames("TSK_HASH_SHA1", "SHA1 Hash")));
    retval.insert(pair<int, TskAttributeNames>(TSK_HASH_SHA2_256, TskAttributeNames("TSK_HASH_SHA2_256", "SHA2-256 Hash")));
    retval.insert(pair<int, TskAttributeNames>(TSK_HASH_SHA2_512, TskAttributeNames("TSK_HASH_SHA2_512", "SHA2-512 Hash")));
    retval.insert(pair<int, TskAttributeNames>(TSK_TEXT, TskAttributeNames("TSK_TEXT", "Text")));
    retval.insert(pair<int, TskAttributeNames>(TSK_TEXT_FILE, TskAttributeNames("TSK_TEXT_FILE", "Text File")));
    retval.insert(pair<int, TskAttributeNames>(TSK_TEXT_LANGUAGE, TskAttributeNames("TSK_TEXT_LANGUAGE", "Text Language")));
    retval.insert(pair<int, TskAttributeNames>(TSK_ENTROPY, TskAttributeNames("TSK_ENTROPY", "Entropy")));
    retval.insert(pair<int, TskAttributeNames>(TSK_HASHSET_NAME, TskAttributeNames("TSK_HASHSET_NAME", "Hashset Name")));
    retval.insert(pair<int, TskAttributeNames>(TSK_INTERESTING_FILE, TskAttributeNames("TSK_INTERESTING_FILE", "Interesting File")));
    retval.insert(pair<int, TskAttributeNames>(TSK_REFERRER, TskAttributeNames("TSK_REFERRER", "Referrer URL")));
    retval.insert(pair<int, TskAttributeNames>(TSK_LAST_ACCESSED, TskAttributeNames("TSK_LAST_ACCESSED", "Last Time Accessed")));  // @@@ Review this instead of using DATETIME
    retval.insert(pair<int, TskAttributeNames>(TSK_IP_ADDRESS, TskAttributeNames("TSK_IP_ADDRESS", "IP Address")));
    retval.insert(pair<int, TskAttributeNames>(TSK_PHONE_NUMBER, TskAttributeNames("TSK_PHONE_NUMBER", "Phone Number")));
    retval.insert(pair<int, TskAttributeNames>(TSK_PATH_ID, TskAttributeNames("TSK_PATH_ID", "Id of Path")));

    return retval;
}

/** \internal
* The table used to store names and display names for built in artifacts
*/

map<int, TskArtifactNames> artifact_type_table= initializeArtifactTypeMap();
map<int, TskAttributeNames> attribute_type_table= initializeAttributeTypeMap();

int m_artifactIDcounter = 1000;
int m_attributeIDcounter = 1000;

string TskBlackboard::attrTypeIDToTypeDisplayName(const int attributeTypeID){
    map<int, TskAttributeNames>::iterator it = attribute_type_table.find(attributeTypeID);
    if(it == attribute_type_table.end())
        throw TskException("No attribute type with that id");
    else
        return it->second.displayName;
}
int TskBlackboard::attrTypeNameToTypeID(const string& attributeTypeString){
    map<int, TskAttributeNames>::iterator it = attribute_type_table.begin();
    for(it; it != attribute_type_table.end(); it++){
        if(attributeTypeString.compare(it->second.typeName) == 0)
            return it->first;
    }
    throw TskException("No attribute type with that name");
}

string TskBlackboard::attrTypeIDToTypeName(const int attributeTypeID){
    map<int, TskAttributeNames>::iterator it = attribute_type_table.find(attributeTypeID);
    if(it == attribute_type_table.end())
        throw TskException("No attribute type with that id");
    else
        return it->second.typeName;
}

int TskBlackboard::addAttributeType(const string& attributeTypeName, const string& displayName){
    map<int, TskAttributeNames>::iterator it = attribute_type_table.begin();
    for(it; it != attribute_type_table.end(); it++){
        if(attributeTypeName.compare(it->second.typeName) == 0)
            throw TskException("Attribute type with that name already exists");
    }
    attribute_type_table.insert(pair<int, TskAttributeNames>(m_attributeIDcounter, TskAttributeNames(attributeTypeName, displayName)));
    return m_attributeIDcounter++;
}

string TskBlackboard::artTypeIDToDisplayName(const int artifactTypeID){
    map<int, TskArtifactNames>::iterator it = artifact_type_table.find(artifactTypeID);
    if(it == artifact_type_table.end())
        throw TskException("No artifact type with that id");
    else
        return it->second.displayName;
}

int TskBlackboard::artTypeNameToTypeID(const string& artifactTypeString){
    map<int, TskArtifactNames>::iterator it = artifact_type_table.begin();
    for(it; it != artifact_type_table.end(); it++){
        if(artifactTypeString.compare(it->second.typeName) == 0)
            return it->first;
    }
    throw TskException("No attribute type with that name");
}

string TskBlackboard::artTypeIDToTypeName(const int artifactTypeID){
    map<int, TskArtifactNames>::iterator it = artifact_type_table.find(artifactTypeID);
    if(it == artifact_type_table.end())
        throw TskException("No attribute type with that id");
    else
        return it->second.typeName;
}

int TskBlackboard::addArtifactType(const string& artifactTypeName, const string& displayName){
    map<int, TskArtifactNames>::iterator it = artifact_type_table.begin();
    for(it; it != artifact_type_table.end(); it++){
        if(artifactTypeName.compare(it->second.typeName) == 0)
            throw TskException("Attribute type with that name already exists");
    }
    artifact_type_table.insert(pair<int, TskArtifactNames>(m_artifactIDcounter, TskArtifactNames(artifactTypeName, displayName)));
    return m_artifactIDcounter++;
}

map<int, TskArtifactNames> TskBlackboard::getAllArtifactTypes(){
    return artifact_type_table;
}
map<int, TskAttributeNames> TskBlackboard::getAllAttributeTypes(){
    return attribute_type_table;
}