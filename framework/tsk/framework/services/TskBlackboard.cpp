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
    retval.insert(pair<int, TskArtifactNames>(TSK_WEB_BOOKMARK, TskArtifactNames("TSK_WEB_BOOKMARK", "Web Bookmarks")));
    retval.insert(pair<int, TskArtifactNames>(TSK_WEB_COOKIE, TskArtifactNames("TSK_WEB_COOKIE", "Web Cookies")));
    retval.insert(pair<int, TskArtifactNames>(TSK_WEB_HISTORY, TskArtifactNames("TSK_WEB_HISTORY", "Web History")));
    retval.insert(pair<int, TskArtifactNames>(TSK_WEB_DOWNLOAD, TskArtifactNames("TSK_WEB_DOWNLOAD", "Web Downloads")));
    retval.insert(pair<int, TskArtifactNames>(TSK_RECENT_OBJECT, TskArtifactNames("TSK_RECENT_OBJECT", "Recent History Object")));
    retval.insert(pair<int, TskArtifactNames>(TSK_GPS_TRACKPOINT, TskArtifactNames("TSK_GPS_TRACKPOINT", "GPS Trackpoints")));
    retval.insert(pair<int, TskArtifactNames>(TSK_INSTALLED_PROG, TskArtifactNames("TSK_INSTALLED_PROG", "Installed Programs")));
    retval.insert(pair<int, TskArtifactNames>(TSK_KEYWORD_HIT, TskArtifactNames("TSK_KEYWORD_HIT", "Keyword Hits")));
    retval.insert(pair<int, TskArtifactNames>(TSK_HASHSET_HIT, TskArtifactNames("TSK_HASHSET_HIT", "Hashset Hits")));
    retval.insert(pair<int, TskArtifactNames>(TSK_DEVICE_ATTACHED, TskArtifactNames("TSK_DEVICE_ATTACHED", "Devices Attached")));
    retval.insert(pair<int, TskArtifactNames>(TSK_INTERESTING_FILE_HIT, TskArtifactNames("TSK_INTERESTING_FILE_HIT", "Interesting Files")));
    retval.insert(pair<int, TskArtifactNames>(TSK_EMAIL_MSG, TskArtifactNames("TSK_EMAIL_MSG", "E-Mail Messages")));
    retval.insert(pair<int, TskArtifactNames>(TSK_EXTRACTED_TEXT, TskArtifactNames("TSK_EXTRACTED_TEXT", "Extracted Text")));
    retval.insert(pair<int, TskArtifactNames>(TSK_WEB_SEARCH_QUERY, TskArtifactNames("TSK_WEB_SEARCH_QUERY", "Web Search")));
    retval.insert(pair<int, TskArtifactNames>(TSK_METADATA_EXIF, TskArtifactNames("TSK_METADATA_EXIF", "EXIF Metadata")));
    retval.insert(pair<int, TskArtifactNames>(TSK_TAG_FILE, TskArtifactNames("TSK_TAG_FILE", "Tagged Files")));
    retval.insert(pair<int, TskArtifactNames>(TSK_TAG_ARTIFACT, TskArtifactNames("TSK_TAG_ARTIFACT", "Tagged Results")));
    retval.insert(pair<int, TskArtifactNames>(TSK_OS_INFO, TskArtifactNames("TSK_OS_INFO", "Operating System Information")));
    retval.insert(pair<int, TskArtifactNames>(TSK_OS_ACCOUNT, TskArtifactNames("TSK_OS_ACCOUNT", "Operating System User Account")));
    retval.insert(pair<int, TskArtifactNames>(TSK_SERVICE_ACCOUNT, TskArtifactNames("TSK_SERVICE_ACCOUNT", "Accounts")));
    retval.insert(pair<int, TskArtifactNames>(TSK_TOOL_OUTPUT, TskArtifactNames("TSK_TOOL_OUTPUT", "Raw Tool Output")));
    retval.insert(pair<int, TskArtifactNames>(TSK_CONTACT, TskArtifactNames("TSK_CONTACT", "Contacts")));
    retval.insert(pair<int, TskArtifactNames>(TSK_MESSAGE, TskArtifactNames("TSK_MESSAGE", "Messages")));
    retval.insert(pair<int, TskArtifactNames>(TSK_CALLLOG, TskArtifactNames("TSK_CALLLOG", "Call Logs")));
    retval.insert(pair<int, TskArtifactNames>(TSK_CALENDAR_ENTRY, TskArtifactNames("TSK_CALENDAR_ENTRY", "Calendar Entries")));
    retval.insert(pair<int, TskArtifactNames>(TSK_SPEED_DIAL_ENTRY, TskArtifactNames("TSK_SPEED_DIAL_ENTRY", "Speed Dial Entries")));
    retval.insert(pair<int, TskArtifactNames>(TSK_BLUETOOTH_PAIRING, TskArtifactNames("TSK_BLUETOOTH_PAIRING", "Bluetooth Pairings")));
    retval.insert(pair<int, TskArtifactNames>(TSK_GPS_BOOKMARK, TskArtifactNames("TSK_GPS_BOOKMARK", "GPS Bookmarks")));
    retval.insert(pair<int, TskArtifactNames>(TSK_GPS_LAST_KNOWN_LOCATION, TskArtifactNames("TSK_GPS_LAST_KNOWN_LOCATION", "GPS Last Known Location")));
    retval.insert(pair<int, TskArtifactNames>(TSK_GPS_SEARCH, TskArtifactNames("TSK_GPS_SEARCH", "GPS Searches")));
    retval.insert(pair<int, TskArtifactNames>(TSK_PROG_RUN, TskArtifactNames("TSK_PROG_RUN", "Run Programs")));
    retval.insert(pair<int, TskArtifactNames>(TSK_ENCRYPTION_DETECTED, TskArtifactNames("TSK_ENCRYPTION_DETECTED", "Encryption Detected")));
    retval.insert(pair<int, TskArtifactNames>(TSK_EXT_MISMATCH_DETECTED, TskArtifactNames("TSK_EXT_MISMATCH_DETECTED", "Extension Mismatch Detected")));
    retval.insert(pair<int, TskArtifactNames>(TSK_INTERESTING_ARTIFACT_HIT, TskArtifactNames("TSK_INTERESTING_ARTIFACT_HIT", "Interesting Results")));
    retval.insert(pair<int, TskArtifactNames>(TSK_GPS_ROUTE, TskArtifactNames("TSK_GPS_ROUTE", "GPS Route")));
    retval.insert(pair<int, TskArtifactNames>(TSK_REMOTE_DRIVE, TskArtifactNames("TSK_REMOTE_DRIVE", "Remote Drive")));
	retval.insert(pair<int, TskArtifactNames>(TSK_FACE_DETECTED, TskArtifactNames("TSK_FACE_DETECTED", "Face Detected")));

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
//    retval.insert(pair<int, TskAttributeNames>(TSK_ENCRYPTION_DETECTED, TskAttributeNames("TSK_ENCRYPTION_DETECTED", "File Encryption Detected")));
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
    retval.insert(pair<int, TskAttributeNames>(TSK_DESCRIPTION, TskAttributeNames("TSK_DESCRIPTION", "Description")));
    retval.insert(pair<int, TskAttributeNames>(TSK_MESSAGE_TYPE, TskAttributeNames("TSK_MESSAGE_TYPE",  "Message Type")));
    retval.insert(pair<int, TskAttributeNames>(TSK_PHONE_NUMBER_HOME, TskAttributeNames("TSK_PHONE_NUMBER_HOME",  "Phone Number (Home)")));
    retval.insert(pair<int, TskAttributeNames>(TSK_PHONE_NUMBER_OFFICE, TskAttributeNames("TSK_PHONE_NUMBER_OFFICE",  "Phone Number (Office)")));
    retval.insert(pair<int, TskAttributeNames>(TSK_PHONE_NUMBER_MOBILE, TskAttributeNames("TSK_PHONE_NUMBER_MOBILE",  "Phone Number (Mobile)")));
    retval.insert(pair<int, TskAttributeNames>(TSK_PHONE_NUMBER_FROM, TskAttributeNames("TSK_PHONE_NUMBER_FROM",  "From Phone Number")));
    retval.insert(pair<int, TskAttributeNames>(TSK_PHONE_NUMBER_TO, TskAttributeNames("TSK_PHONE_NUMBER_TO",  "To Phone Number")));
    retval.insert(pair<int, TskAttributeNames>(TSK_DIRECTION, TskAttributeNames("TSK_DIRECTION",  "Direction")));
    retval.insert(pair<int, TskAttributeNames>(TSK_EMAIL_HOME, TskAttributeNames("TSK_EMAIL_HOME",  "Email (Home)")));
    retval.insert(pair<int, TskAttributeNames>(TSK_EMAIL_OFFICE, TskAttributeNames("TSK_EMAIL_OFFICE", "Email (Office)")));
    retval.insert(pair<int, TskAttributeNames>(TSK_DATETIME_START, TskAttributeNames("TSK_DATETIME_START",  "Start Date/Time")));
    retval.insert(pair<int, TskAttributeNames>(TSK_DATETIME_END, TskAttributeNames("TSK_DATETIME_END",  "End Date/Time")));
    retval.insert(pair<int, TskAttributeNames>(TSK_CALENDAR_ENTRY_TYPE, TskAttributeNames("TSK_CALENDAR_ENTRY_TYPE", "Calendar Entry Type")));
    retval.insert(pair<int, TskAttributeNames>(TSK_LOCATION, TskAttributeNames("TSK_LOCATION", "Location")));
    retval.insert(pair<int, TskAttributeNames>(TSK_SHORTCUT, TskAttributeNames("TSK_SHORTCUT",  "Short Cut")));
    retval.insert(pair<int, TskAttributeNames>(TSK_DEVICE_NAME, TskAttributeNames("TSK_DEVICE_NAME", "Device Name")));
    retval.insert(pair<int, TskAttributeNames>(TSK_CATEGORY, TskAttributeNames("TSK_CATEGORY",  "Category")));
    retval.insert(pair<int, TskAttributeNames>(TSK_EMAIL_REPLYTO, TskAttributeNames("TSK_EMAIL_REPLYTO", "ReplyTo Address")));
    retval.insert(pair<int, TskAttributeNames>(TSK_SERVER_NAME, TskAttributeNames("TSK_SERVER_NAME", "Server Name")));
    retval.insert(pair<int, TskAttributeNames>(TSK_COUNT, TskAttributeNames("TSK_COUNT",  "Count")));
    retval.insert(pair<int, TskAttributeNames>(TSK_MIN_COUNT, TskAttributeNames("TSK_MIN_COUNT",  "Minimum Count")));
    retval.insert(pair<int, TskAttributeNames>(TSK_PATH_SOURCE, TskAttributeNames("TSK_PATH_SOURCE",  "Path Source")));
    retval.insert(pair<int, TskAttributeNames>(TSK_PERMISSIONS, TskAttributeNames("TSK_PERMISSIONS",  "Permissions")));
    retval.insert(pair<int, TskAttributeNames>(TSK_ASSOCIATED_ARTIFACT, TskAttributeNames("TSK_ASSOCIATED_ARTIFACT", "Associated Artifact")));
    retval.insert(pair<int, TskAttributeNames>(TSK_ISDELETED, TskAttributeNames("TSK_ISDELETED", "Is Deleted")));
    retval.insert(pair<int, TskAttributeNames>(TSK_GEO_LATITUDE_START, TskAttributeNames("TSK_GEO_LATITUDE_START", "Starting Latitude")));
    retval.insert(pair<int, TskAttributeNames>(TSK_GEO_LATITUDE_END, TskAttributeNames("TSK_GEO_LATITUDE_END", "Ending Latitude")));
    retval.insert(pair<int, TskAttributeNames>(TSK_GEO_LONGITUDE_START, TskAttributeNames("TSK_GEO_LONGITUDE_START", "Starting Longitude")));
    retval.insert(pair<int, TskAttributeNames>(TSK_GEO_LONGITUDE_END, TskAttributeNames("TSK_GEO_LONGITUDE_END", "Ending Longitude")));
    retval.insert(pair<int, TskAttributeNames>(TSK_READ_STATUS, TskAttributeNames("TSK_READ_STATUS",  "Read")));
    retval.insert(pair<int, TskAttributeNames>(TSK_LOCAL_PATH, TskAttributeNames("TSK_LOCAL_PATH",  "Local Path")));
    retval.insert(pair<int, TskAttributeNames>(TSK_REMOTE_PATH, TskAttributeNames("TSK_REMOTE_PATH",  "Remote Path")));
    retval.insert(pair<int, TskAttributeNames>(TSK_TEMP_DIR, TskAttributeNames("TSK_TEMP_DIR",  "Temporary Files Directory")));
    retval.insert(pair<int, TskAttributeNames>(TSK_PRODUCT_ID, TskAttributeNames("TSK_PRODUCT_ID",  "Product ID")));
    retval.insert(pair<int, TskAttributeNames>(TSK_OWNER, TskAttributeNames("TSK_OWNER",  "Owner")));
    retval.insert(pair<int, TskAttributeNames>(TSK_ORGANIZATION, TskAttributeNames("TSK_ORGANIZATION",  "Organization")));

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
