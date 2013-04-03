/*
* The Sleuth Kit
*
* Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
* Copyright (c) 2010-2012 Basis Technology Corporation. All Rights
* reserved.
*
* This software is distributed under the Common Public License 1.0
*/

#include "TskBlackboard.h"

map<int, TskArtifactNames> initializeArtifactTypeMap(){
    map<int, TskArtifactNames> retval;
    retval.insert(pair<int, TskArtifactNames>(TSK_GEN_INFO, TskArtifactNames("TSK_GEN_INFO", "General Info")));
    retval.insert(pair<int, TskArtifactNames>(TSK_WEB_BOOKMARK, TskArtifactNames("TSK_WEB_BOOKMARK", "Web Bookmark")));
    retval.insert(pair<int, TskArtifactNames>(TSK_WEB_COOKIE, TskArtifactNames("TSK_WEB_COOKIE", "Web Cookie")));
    retval.insert(pair<int, TskArtifactNames>(TSK_WEB_HISTORY, TskArtifactNames("TSK_WEB_HISTORY", "History")));
    retval.insert(pair<int, TskArtifactNames>(TSK_WEB_DOWNLOAD, TskArtifactNames("TSK_WEB_DOWNLOAD", "Download")));
    retval.insert(pair<int, TskArtifactNames>(TSK_RECENT_OBJECT, TskArtifactNames("TSK_RECENT_OBJECT", "Recent History Object")));
    retval.insert(pair<int, TskArtifactNames>(TSK_TRACKPOINT, TskArtifactNames("TSK_TRACKPOINT", "Trackpoint")));
    retval.insert(pair<int, TskArtifactNames>(TSK_INSTALLED_PROG, TskArtifactNames("TSK_INSTALLED_PROG", "Installed Program")));
    retval.insert(pair<int, TskArtifactNames>(TSK_KEYWORD_HIT, TskArtifactNames("TSK_KEYWORD_HIT", "Keyword Hit")));
    retval.insert(pair<int, TskArtifactNames>(TSK_HASHSET_HIT, TskArtifactNames("TSK_HASHSET_HIT", "Hashset Hit")));
    retval.insert(pair<int, TskArtifactNames>(TSK_DEVICE_ATTACHED, TskArtifactNames("TSK_DEVICE_ATTACHED", "Device Attached")));
    retval.insert(pair<int, TskArtifactNames>(TSK_INTERESTING_FILE_HIT, TskArtifactNames("TSK_INTERESTING_FILE_HIT", "Interesting File")));
    retval.insert(pair<int, TskArtifactNames>(TSK_EMAIL_MSG, TskArtifactNames("TSK_EMAIL_MSG", "E-Mail Message")));
    retval.insert(pair<int, TskArtifactNames>(TSK_EXTRACTED_TEXT, TskArtifactNames("TSK_EXTRACTED_TEXT", "Extracted Text")));
    retval.insert(pair<int, TskArtifactNames>(TSK_WEB_SEARCH_QUERY, TskArtifactNames("TSK_WEB_SEARCH_QUERY", "Web Search Engine Query")));
    retval.insert(pair<int, TskArtifactNames>(TSK_METADATA_EXIF, TskArtifactNames("TSK_METADATA_EXIF", "EXIF Metadata")));
    retval.insert(pair<int, TskArtifactNames>(TSK_TAG_FILE, TskArtifactNames("TSK_TAG_FILE", "File Tag")));
    retval.insert(pair<int, TskArtifactNames>(TSK_TAG_ARTIFACT, TskArtifactNames("TSK_TAG_ARTIFACT", "Result Tag")));
    retval.insert(pair<int, TskArtifactNames>(TSK_OS_INFO, TskArtifactNames("TSK_OS_INFO", "Operating System Information")));
    retval.insert(pair<int, TskArtifactNames>(TSK_OS_ACCOUNT, TskArtifactNames("TSK_OS_ACCOUNT", "Operating System User Account")));
    retval.insert(pair<int, TskArtifactNames>(TSK_SERVICE_ACCOUNT, TskArtifactNames("TSK_SERVICE_ACCOUNT", "Network Service User Account")));

    return retval;
}

map<int, TskAttributeNames> initializeAttributeTypeMap(){
    map<int, TskAttributeNames> retval;
    retval.insert(pair<int, TskAttributeNames>(TSK_URL, TskAttributeNames("TSK_URL", "URL")));
    retval.insert(pair<int, TskAttributeNames>(TSK_DATETIME, TskAttributeNames("TSK_DATETIME", "Datetime")));
    retval.insert(pair<int, TskAttributeNames>(TSK_NAME, TskAttributeNames("TSK_NAME", "Name")));
    retval.insert(pair<int, TskAttributeNames>(TSK_PROG_NAME, TskAttributeNames("TSK_PROG_NAME", "Program Name")));
    retval.insert(pair<int, TskAttributeNames>(TSK_VALUE, TskAttributeNames("TSK_VALUE", "Value")));
    retval.insert(pair<int, TskAttributeNames>(TSK_FLAG, TskAttributeNames("TSK_FLAG", "Flag")));
    retval.insert(pair<int, TskAttributeNames>(TSK_PATH, TskAttributeNames("TSK_PATH", "Path")));
    retval.insert(pair<int, TskAttributeNames>(TSK_KEYWORD, TskAttributeNames("TSK_KEYWORD", "Keyword")));
    retval.insert(pair<int, TskAttributeNames>(TSK_KEYWORD_REGEXP, TskAttributeNames("TSK_KEYWORD_REGEXP", "Keyword Regular Expression")));
    retval.insert(pair<int, TskAttributeNames>(TSK_KEYWORD_PREVIEW, TskAttributeNames("TSK_KEYWORD_PREVIEW", "Keyword Preview")));
    retval.insert(pair<int, TskAttributeNames>(TSK_KEYWORD_SET, TskAttributeNames("TSK_KEYWORD_SET", "Keyword Set")));
    retval.insert(pair<int, TskAttributeNames>(TSK_USER_NAME, TskAttributeNames("TSK_USER_NAME", "Username")));
    retval.insert(pair<int, TskAttributeNames>(TSK_DOMAIN, TskAttributeNames("TSK_DOMAIN", "Domain")));
    retval.insert(pair<int, TskAttributeNames>(TSK_PASSWORD, TskAttributeNames("TSK_PASSWORD", "Password")));
    retval.insert(pair<int, TskAttributeNames>(TSK_NAME_PERSON, TskAttributeNames("TSK_NAME_PERSON", "Person Name")));
    retval.insert(pair<int, TskAttributeNames>(TSK_DEVICE_MODEL, TskAttributeNames("TSK_DEVICE_MODEL", "Device Model")));
    retval.insert(pair<int, TskAttributeNames>(TSK_DEVICE_MAKE, TskAttributeNames("TSK_DEVICE_MAKE", "Device Make")));
    retval.insert(pair<int, TskAttributeNames>(TSK_DEVICE_ID, TskAttributeNames("TSK_DEVICE_ID", "Device ID")));
    retval.insert(pair<int, TskAttributeNames>(TSK_EMAIL, TskAttributeNames("TSK_EMAIL", "Email")));
    retval.insert(pair<int, TskAttributeNames>(TSK_HASH_MD5, TskAttributeNames("TSK_HASH_MD5", "MD5 Hash")));
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
    retval.insert(pair<int, TskAttributeNames>(TSK_DATETIME_ACCESSED, TskAttributeNames("TSK_DATETIME_ACCESSED", "Date Accessed"))); 
    retval.insert(pair<int, TskAttributeNames>(TSK_IP_ADDRESS, TskAttributeNames("TSK_IP_ADDRESS", "IP Address")));
    retval.insert(pair<int, TskAttributeNames>(TSK_PHONE_NUMBER, TskAttributeNames("TSK_PHONE_NUMBER", "Phone Number")));
    retval.insert(pair<int, TskAttributeNames>(TSK_PATH_ID, TskAttributeNames("TSK_PATH_ID", "Id of Path")));
    retval.insert(pair<int, TskAttributeNames>(TSK_SET_NAME, TskAttributeNames("TSK_SET_NAME", "Set Name")));
    retval.insert(pair<int, TskAttributeNames>(TSK_ENCRYPTION_DETECTED, TskAttributeNames("TSK_ENCRYPTION_DETECTED", "File Encryption Detected")));
    retval.insert(pair<int, TskAttributeNames>(TSK_MALWARE_DETECTED, TskAttributeNames("TSK_MALWARE_DETECTED", "Malware Detected")));
    retval.insert(pair<int, TskAttributeNames>(TSK_STEG_DETECTED, TskAttributeNames("TSK_STEG_DETECTED", "Steganography Detected")));
    retval.insert(pair<int, TskAttributeNames>(TSK_EMAIL_TO, TskAttributeNames("TSK_EMAIL_TO", "E-Mail To")));
    retval.insert(pair<int, TskAttributeNames>(TSK_EMAIL_CC, TskAttributeNames("TSK_EMAIL_CC", "E-Mail CC")));
    retval.insert(pair<int, TskAttributeNames>(TSK_EMAIL_BCC, TskAttributeNames("TSK_EMAIL_BCC", "E-Mail BCC")));
    retval.insert(pair<int, TskAttributeNames>(TSK_EMAIL_FROM, TskAttributeNames("TSK_EMAIL_FROM", "E-Mail From")));
    retval.insert(pair<int, TskAttributeNames>(TSK_EMAIL_CONTENT_PLAIN, TskAttributeNames("TSK_EMAIL_CONTENT_PLAIN", "Content (Plain Text)")));
    retval.insert(pair<int, TskAttributeNames>(TSK_EMAIL_CONTENT_HTML, TskAttributeNames("TSK_EMAIL_CONTENT_HTML", "Content (HTML)")));
    retval.insert(pair<int, TskAttributeNames>(TSK_EMAIL_CONTENT_RTF, TskAttributeNames("TSK_EMAIL_CONTENT_RTF", "Content (RTF)")));
    retval.insert(pair<int, TskAttributeNames>(TSK_MSG_ID, TskAttributeNames("TSK_MSG_ID", "Message ID")));
    retval.insert(pair<int, TskAttributeNames>(TSK_MSG_REPLY_ID, TskAttributeNames("TSK_MSG_REPLY_ID", "Message Reply ID")));
    retval.insert(pair<int, TskAttributeNames>(TSK_DATETIME_RCVD, TskAttributeNames("TSK_DATETIME_RCVD", "Date Received")));
    retval.insert(pair<int, TskAttributeNames>(TSK_DATETIME_SENT, TskAttributeNames("TSK_DATETIME_SENT", "Date Sent")));
    retval.insert(pair<int, TskAttributeNames>(TSK_SUBJECT, TskAttributeNames("TSK_SUBJECT", "Subject")));
    retval.insert(pair<int, TskAttributeNames>(TSK_GEO_LATITUDE, TskAttributeNames("TSK_GEO_LATITUDE", "Latitude")));
    retval.insert(pair<int, TskAttributeNames>(TSK_GEO_LONGITUDE, TskAttributeNames("TSK_GEO_LONGITUDE", "Longitude")));
    retval.insert(pair<int, TskAttributeNames>(TSK_GEO_VELOCITY, TskAttributeNames("TSK_GEO_VELOCITY", "Velocity")));
    retval.insert(pair<int, TskAttributeNames>(TSK_GEO_ALTITUDE, TskAttributeNames("TSK_GEO_ALTITUDE", "Altitude")));
    retval.insert(pair<int, TskAttributeNames>(TSK_GEO_BEARING, TskAttributeNames("TSK_GEO_BEARING", "Bearing")));
    retval.insert(pair<int, TskAttributeNames>(TSK_GEO_HPRECISION, TskAttributeNames("TSK_GEO_HPRECISION", "Horizontal Precision")));
    retval.insert(pair<int, TskAttributeNames>(TSK_GEO_VPRECISION, TskAttributeNames("TSK_GEO_VPRECISION", "Vertical Precision")));
    retval.insert(pair<int, TskAttributeNames>(TSK_GEO_MAPDATUM, TskAttributeNames("TSK_GEO_MAPDATUM", "Map Datum")));
    retval.insert(pair<int, TskAttributeNames>(TSK_FILE_TYPE_SIG, TskAttributeNames("TSK_FILE_TYPE_SIG", "File Type (by signature)")));
    retval.insert(pair<int, TskAttributeNames>(TSK_FILE_TYPE_EXT, TskAttributeNames("TSK_FILE_TYPE_EXT", "File Type (by extension)")));
    retval.insert(pair<int, TskAttributeNames>(TSK_TAGGED_ARTIFACT, TskAttributeNames("TSK_TAGGED_ARTIFACT", "Tagged Result")));
    retval.insert(pair<int, TskAttributeNames>(TSK_TAG_NAME, TskAttributeNames("TSK_TAG_NAME", "Tag Name")));
    retval.insert(pair<int, TskAttributeNames>(TSK_COMMENT, TskAttributeNames("TSK_COMMENT", "Comment")));
    retval.insert(pair<int, TskAttributeNames>(TSK_URL_DECODED, TskAttributeNames("TSK_URL_DECODED", "Decoded URL")));
    retval.insert(pair<int, TskAttributeNames>(TSK_DATETIME_CREATED, TskAttributeNames("TSK_DATETIME_CREATED", "Date Created")));
    retval.insert(pair<int, TskAttributeNames>(TSK_DATETIME_MODIFIED, TskAttributeNames("TSK_DATETIME_MODIFIED", "Date Modified")));
    retval.insert(pair<int, TskAttributeNames>(TSK_PROCESSOR_ARCHITECTURE, TskAttributeNames("TSK_PROCESSOR_ARCHITECTURE", "Processor Architecture")));
    retval.insert(pair<int, TskAttributeNames>(TSK_VERSION, TskAttributeNames("TSK_VERSION", "Version")));
    retval.insert(pair<int, TskAttributeNames>(TSK_USER_ID, TskAttributeNames("TSK_USER_ID", "User ID")));

    return retval;
}

/** \internal
* The table used to store names and display names for built in artifacts
*/

static map<int, TskArtifactNames> artifact_type_table= initializeArtifactTypeMap();
static map<int, TskAttributeNames> attribute_type_table= initializeAttributeTypeMap();

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
    map<int, TskAttributeNames>::iterator it;
    for(it = attribute_type_table.begin(); it != attribute_type_table.end(); it++){
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
