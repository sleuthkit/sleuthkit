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
 * \file TskBlackboard.h
 * Interface for class that will implement the black board.  The black board
 * is used to store data from analysis modules.  The data is available to
 * later modules in the pipeline and in the final reporting phase.
 */

#ifndef _TSK_BLACKBOARD_H
#define _TSK_BLACKBOARD_H

#include <string>
#include <vector>
#include "tsk/framework/utilities/TskException.h"
#include "tsk/framework/framework_i.h"
#include "tsk/framework/services/TskImgDB.h"
#include "TskBlackboardArtifact.h"
#include "TskBlackboardAttribute.h"

using namespace std;

/**
 * Built in artifact types.
 * Refer to http://wiki.sleuthkit.org/index.php?title=Artifact_Examples
 * for details on which attributes should be used for each artifact.
 *
 * Refer to http://wiki.sleuthkit.org/index.php?title=Adding_Artifacts_and_Attributes
 * for checklist of steps to add new artifacts and attributes.
 */

/* Note that the below comments are the only documentation 
 * for the standard types.  Please ensure that all types are
 * documented. 
 * 
 * The numbers are explicitly added to make it easier to verify
 * that the Java and C++ code is in sync.
 *
 * It is very important that this list be kept up to date and 
 * in sync with the Java code.  Do not add anything here unless
 * you also add it there.  
 * See bindings/java/src/org/sleuthkit/datamodel/BlackboardArtifact.java */
enum TSK_ARTIFACT_TYPE {
    TSK_GEN_INFO = 1,///< The general info artifact, if information doesn't need its own artifact it should go here
    TSK_WEB_BOOKMARK = 2,///< A web bookmark. 
    TSK_WEB_COOKIE = 3,///< A web cookie. 
    TSK_WEB_HISTORY = 4,///< A web history enrty. 
    TSK_WEB_DOWNLOAD = 5,///< A web download. 
    TSK_RECENT_OBJECT = 6,///< A recently used object (MRU, recent document, etc.).
    TSK_GPS_TRACKPOINT = 7,///< A trackpoint from a GPS log.
    TSK_INSTALLED_PROG = 8,///< An installed program. 
    TSK_KEYWORD_HIT = 9,///< A keyword hit. 
    TSK_HASHSET_HIT = 10, ///< A hit within a known bad / notable hashset / hash database. 
    TSK_DEVICE_ATTACHED = 11, ///< An event for a device being attached to the host computer
    TSK_INTERESTING_FILE_HIT = 12, ///< A file that was flagged because it matched some search criteria for being interesting (i.e. because of its name, extension, etc.)
    TSK_EMAIL_MSG = 13, ///< An e-mail message that was extracted from a file.
    TSK_EXTRACTED_TEXT = 14, ///< Text that was extracted from a file.
    TSK_WEB_SEARCH_QUERY = 15, ///< Web search engine query extracted from web history.
    TSK_METADATA_EXIF = 16, ///< EXIF Metadata
    TSK_TAG_FILE = 17, ///< File tags.
    TSK_TAG_ARTIFACT = 18, ///< Result tags.
    TSK_OS_INFO = 19, ///< Information pertaining to an operating system.
    TSK_OS_ACCOUNT = 20, ///< An operating system user account.
    TSK_SERVICE_ACCOUNT = 21, ///< A network service user account.
    TSK_TOOL_OUTPUT = 22,  ///< Output from an external tool or module (raw text)
	TSK_CONTACT = 23, ///< A Contact extracted from a phone, or from an Addressbook/Email/Messaging Application
	TSK_MESSAGE = 24, ///< An SMS/MMS message extracted from phone, or from another messaging application, like IM
	TSK_CALLLOG = 25, ///< A Phone call log extracted from a phones or softphone application
	TSK_CALENDAR_ENTRY = 26, ///< A Calendar entry from a phone, PIM or a Calendar application.
	TSK_SPEED_DIAL_ENTRY = 27,  ///< A speed dial entry from a phone 
	TSK_BLUETOOTH_PAIRING = 28,  ///< A bluetooth pairing entry
	TSK_GPS_BOOKMARK = 29, ///< GPS Bookmarks
	TSK_GPS_LAST_KNOWN_LOCATION = 30, ///< GPS Last known location
	TSK_GPS_SEARCH = 31,	///< GPS Searches
	TSK_PROG_RUN = 32, ///< Application run information
    TSK_ENCRYPTION_DETECTED = 33, ///< Encrypted File
    TSK_EXT_MISMATCH_DETECTED = 34, ///< Extension Mismatch
    TSK_INTERESTING_ARTIFACT_HIT = 35,	///< Any artifact interesting enough that it should be called out in the UI.
	TSK_GPS_ROUTE = 36,	///< Route based on GPS coordinates
	TSK_REMOTE_DRIVE = 37, ///< Network drive
	TSK_FACE_DETECTED = 38, ///< Face detected
    
    /* SEE ABOVE:
    * - KEEP JAVA CODE IN SYNC 
    * - UPDATE map in TskBlackboard.cpp
	* - UPDATE Autopsy report module to display the new data
	*     Core/src/org/sleuthkit/autopsy/report/ReportGenerator.java
    * - Update Wiki to reflect the attributes that should be part of the artifact. 
    */
};

/**
 * Built in attribute types 
 */
/* The numbers are explicitly added to make it easier to verify
 * that the Java and C++ code is in sync.
 *
 * It is very important that this list be kept up to date and 
 * in sync with the Java code.  Do not add anything here unless
 * you also add it there.  
 * See bindings/java/src/org/sleuthkit/datamodel/BlackboardAttribute.java 
 */
enum TSK_ATTRIBUTE_TYPE {
    TSK_URL = 1,///< String of a URL, should start with http:// or ftp:// etc.  You should also make a TskBlackoard::TSK_DOMAIN entry for the base domain name. 
    TSK_DATETIME = 2,///< INT32: GMT based Unix time, defines number of secords elapsed since UTC Jan 1, 1970.
    TSK_NAME = 3,///< STRING: The name associated with an artifact
    TSK_PROG_NAME = 4,///< String of name of a program that was installed on the system
    TSK_VALUE = 6,///< Some value associated with an artifact
    TSK_FLAG = 7,///< Some flag associated with an artifact
    TSK_PATH = 8,///< A filesystem path.  Should be fully qualified. Should set TSK_PATH_ID as well when this is set. TODO: Need to define this value more for cases with multiple images and multiple file systems per image. 
    TSK_KEYWORD = 10,///< STRING: Keyword that was found in this file. 
    TSK_KEYWORD_REGEXP = 11,///< STRING: A regular expression string
    TSK_KEYWORD_PREVIEW = 12,///< STRING: A text preview
    TSK_KEYWORD_SET = 13,///< STRING: A keyword set -- Deprecated in favor of TSK_SET_NAME
    TSK_USER_NAME = 14,///< String of a user name.  Use TskBlackboard::TSK_DOMAIN to store the domain that the username is from (if it is known). 
    TSK_DOMAIN = 15,///< String of a DNS Domain name, e.g. sleuthkit.org  use TskBlackboad::TSK_URL for a full URL.
    TSK_PASSWORD = 16,///< String of a password that was found.  Use TskBlackboard::TSK_USER_NAME and TskBlackboard::TSK_DOMAIN to link the password to a given user and site. 
    TSK_NAME_PERSON = 17,///< String of a person name
    TSK_DEVICE_MODEL = 18,///< String of manufacturer name of device that was connected (or somehow related to) the data being analyzed
    TSK_DEVICE_MAKE = 19,///< String of make of a device that was connected (or somehow related to) the data being analyzed
    TSK_DEVICE_ID = 20,///< String of ID/serial number of a device that was connected (or somehow related to) the data being analyzed
    TSK_EMAIL = 21,///< String of e-mail address in the form of user@host.com (note that there are also more specific TSK_EMAIL_TO and TSK_EMAIL_FROM attributes if you know the use of the address)
    TSK_HASH_MD5 = 22,///< STRING: MD5 hash
    TSK_HASH_SHA1 = 23,///< STRING: SHA1 hash
    TSK_HASH_SHA2_256 = 24,///< STRING: SHA2 256 bit hash
    TSK_HASH_SHA2_512 = 25,///< STRING: SHA2 512 bit hash
    TSK_TEXT = 26,///< String of text extracted from a file (should be part of TSK_EXTRACTED_TEXT artifact).
    TSK_TEXT_FILE = 27,///< String of path to file containing text. May be absolute or relative. If relative, will be evaluated relative to OUT_DIR setting. Should be part of TSK_EXTRACTED_TEXT artifact)
    TSK_TEXT_LANGUAGE = 28,///< String of the detected language in ISO 639-3 language code of TskBlackboard::TSK_TEXT data in the same artifact (TSK_EXTRACTED_TEXT, for example).
    TSK_ENTROPY = 29,///< DOUBLE: Entropy value of file
    TSK_HASHSET_NAME = 30,///< String of the name or file name of the hashset -- Deprecated in favor of TSK_SET_NAME
    TSK_INTERESTING_FILE = 31,///< An interesting file hit, potentially file id, name, or path -- Deprecated, use TSK_INTERESTING_FILE_HIT artifact instead.
    TSK_REFERRER = 32,///< String of referrer URL
    TSK_DATETIME_ACCESSED = 33,///<datetime last time accessed
    TSK_IP_ADDRESS = 34,///<String of IP Address
    TSK_PHONE_NUMBER = 35,///<String of phone number
    TSK_PATH_ID = 36,///< Object ID from database that a TSK_PATH attribute corresponds to.  Set to -1 if path is for a file that is not in database (i.e. deleted). 
    TSK_SET_NAME = 37,///< STRING: The name of a set that was used to find this artifact (to be used for hash hits, keyword hits, interesting files, etc.)
    //TSK_ENCRYPTION_DETECTED = 38,///< \deprecated STRING: The type of encryption that is believed to have been used on the file.
    TSK_MALWARE_DETECTED = 39,///< STRING: The name of the malware that was detected in this file.
    TSK_STEG_DETECTED = 40,///< STRING: The name of the steganography technique that was detected in this file.
    TSK_EMAIL_TO = 41, ///< String of an e-mail address that a message is being sent to directly (not cc:).
    TSK_EMAIL_CC = 42, ///< String of an e-mail address that a message is being sent to as a cc:.
    TSK_EMAIL_BCC = 43, ///< String of an e-mail address that a message is being sent to as a bcc:.
    TSK_EMAIL_FROM = 44, ///< String of an e-mail address that a message is being sent from.
    TSK_EMAIL_CONTENT_PLAIN = 45, ///< String of e-mail message body in plain text
    TSK_EMAIL_CONTENT_HTML = 46, ///< STring of e-mail message body in HTML
    TSK_EMAIL_CONTENT_RTF = 47, ///< STring of e-mail message body in RTF
    TSK_MSG_ID = 48, ///< String of a message ID (such as one of an e-mail message)
    TSK_MSG_REPLY_ID = 49, ///< String of a message ID that a given message is in response to (such as one of an e-mail message) 
    TSK_DATETIME_RCVD = 50, ///< Time in Unix epoch that something was received.
    TSK_DATETIME_SENT = 51, ///< Time in Unix epoch that something was sent.
    TSK_SUBJECT = 52, ///< String of a subject (such as one of an e-mail message)
    TSK_TITLE = 53, ///< String of a title (such as a webpage or other document)
    TSK_GEO_LATITUDE = 54, ///< Floating point of latitude coordinate.  Should be in WGS84. Positive North, Negative South. 
    TSK_GEO_LONGITUDE = 55, ///< Floating point of longitude coordinate.  Should be in WGS84.  Positive East, Negative West.
    TSK_GEO_VELOCITY = 56, ///< Floating point of velocity in geo coordinate in meters per second.
    TSK_GEO_ALTITUDE = 57, ///< Floating point of altitude in geo coordinate in meters.
    TSK_GEO_BEARING = 58, ///< Floating point of bearing in geo coordinate in true degrees.
    TSK_GEO_HPRECISION = 59, ///< Floating point of horizontal precision in geo coordinate in meters.
    TSK_GEO_VPRECISION = 60, ///< Floating point of vertical precision in geo coordinate in meters.
    TSK_GEO_MAPDATUM = 61, ///< String of map datum used for coordinates if not WGS84.
    TSK_FILE_TYPE_SIG = 62, ///< String of file type based on signature detection in file content.
    TSK_FILE_TYPE_EXT = 63, ///< String of file type based on file name extension.
    TSK_TAGGED_ARTIFACT = 64, ///< Tagged artifact (associated result).
    TSK_TAG_NAME = 65, ///< The tag name.  Can contain slashes "/" to represent tag hierarchy.
    TSK_COMMENT = 66, ///< Comment string.
    TSK_URL_DECODED = 67, ///< Decoded URL.
    TSK_DATETIME_CREATED = 68,///< Time in Unix epoch that something was created
    TSK_DATETIME_MODIFIED = 69,///< Time in Unix epoch that something was modified
    TSK_PROCESSOR_ARCHITECTURE = 70,///< String of processor architecture.  Naming convention from http://en.wikipedia.org/wiki/Comparison_of_CPU_architectures.  So far, we've used x86, x86-64, and IA64.
    TSK_VERSION = 71,///< String for a software version 
    TSK_USER_ID = 72,///< User IDfor a user account, e.g., a Windows SID or Linux UID.
    TSK_DESCRIPTION = 73, ///< String for a description associated with an artifact.
	TSK_MESSAGE_TYPE =74, ///< SMS or MMS or IM ...
	TSK_PHONE_NUMBER_HOME = 75, ///< Phone number (Home)
	TSK_PHONE_NUMBER_OFFICE = 76, ///< Phone number (Office)
	TSK_PHONE_NUMBER_MOBILE = 77, ///< Phone Number (Mobile)
	TSK_PHONE_NUMBER_FROM = 78, ///<  Source Phone Number, originating a call or message
	TSK_PHONE_NUMBER_TO = 79, /// < Destination Phone Number, receiving a call or message
	TSK_DIRECTION = 80,  ///< Msg/Call direction: incoming, outgoing
	TSK_EMAIL_HOME = 81, ///< Email (Home)"),
	TSK_EMAIL_OFFICE = 82, ///< Email (Office)
	TSK_DATETIME_START = 83, ///< start time of an event - call log, Calendar entry
	TSK_DATETIME_END = 84, ///< end time of an event - call log, Calendar entry
	TSK_CALENDAR_ENTRY_TYPE = 85, ///< calendar entry type: meeting, task, 
	TSK_LOCATION = 86, 	// Location string associated with an event - Conf Room Name, Address ....
	TSK_SHORTCUT = 87, ///< Short Cut string - short code or dial string for Speed dial, a URL short cut - e.g. bitly string, Windows Desktop Short cut name etc.
	TSK_DEVICE_NAME = 88, ///< device name - a user assigned (usually) device name - such as "Joe's computer", "bob_win8", "BT Headset"
	TSK_CATEGORY = 89, 	///< category/type, possible value set varies by the artifact
	TSK_EMAIL_REPLYTO = 90, ///< ReplyTo address
	TSK_SERVER_NAME = 91, 	///< server name
	TSK_COUNT = 92, ///< Count related to the artifact
	TSK_MIN_COUNT = 93, ///<  Minimum number/count
	TSK_PATH_SOURCE = 94, ///< Path to a source file related to the artifact
	TSK_PERMISSIONS = 95, ///< Permissions
	TSK_ASSOCIATED_ARTIFACT = 96, ///< Artifact ID of a related artifact
    TSK_ISDELETED = 97, ///< the artifact is recovered from deleted content
    TSK_GEO_LATITUDE_START= 98, ///< Starting location lattitude
    TSK_GEO_LATITUDE_END= 99, ///< Ending location lattitude
    TSK_GEO_LONGITUDE_START= 100, ///< Starting location longitude
    TSK_GEO_LONGITUDE_END = 101, ///< Ending Location longitude
    TSK_READ_STATUS = 102, ///< Message read status: 1 if read, 0 if unread
    TSK_LOCAL_PATH = 103, ///< Local path to a network share
    TSK_REMOTE_PATH = 104, ///< Remote path of the network share
    TSK_TEMP_DIR = 105, ///< Path to the default temp directory
    TSK_PRODUCT_ID = 106, ///< ID string
    TSK_OWNER = 107, ///< Registered owner for software
    TSK_ORGANIZATION = 108, ///< Registered organization for software

    /* SEE ABOVE: 
    * - KEEP JAVA CODE IN SYNC 
    * - UPDATE map in TskBlackBoard.cpp too */
};

/**
 * Class used to store the pair of type and display names of attributes.
 */
class TskAttributeNames{
public:
    string typeName;
    string displayName;
    TskAttributeNames(string name, string display):
    typeName(name),
        displayName(display){}
};

/**
 * Class used to store the pair of type and display names of artifacts.
 */
class TskArtifactNames{
public:
    string typeName;
    string displayName;
    TskArtifactNames(string name, string display):
    typeName(name),
        displayName(display){}
};

/**
 * An interface for setting and retrieving name/value pairs to the blackboard.
 * The blackboard is used to store data for use by later modules in the pipeline.
 * Can be registered with and retrieved from TskServices.
 */
class TSK_FRAMEWORK_API TskBlackboard
{
public:

    /**
    * Get the artifact with the given id
    * @param artifactID id
    * @returns the artifact throws an error if no artifact matches that id.
    */
    virtual TskBlackboardArtifact getBlackboardArtifact(const long artifactID) = 0;

    /**
    * Get all artifacts that match the given condition
    * @param condition condition (implementation specific) to use for matching
    * @returns vector of matching artifacts can return an empty vector if there are no matches
    * @throws error if a bad condition string is supplied
    */
    virtual vector<TskBlackboardArtifact> getMatchingArtifacts(const string& condition)const = 0;
    /**
    * Get all artifacts with the given type name and file id
    * @param file_id associated file id
    * @param artifactTypeName type name
    * @returns vector of matching artifacts can return an empty vector if there are no matches
    */
    virtual vector<TskBlackboardArtifact> getArtifacts(const uint64_t file_id, const string& artifactTypeName)const = 0;
    /**
    * Get all artifacts with the given type id and file id
    * @param file_id associated file id
    * @param artifactTypeID type id
    * @returns vector of matching artifacts can return an empty vector if there are no matches
    */
    virtual vector<TskBlackboardArtifact> getArtifacts(const uint64_t file_id, int artifactTypeID)const = 0;
    /**
    * Get all artifacts with the given type and file id
    * @param file_id associated file id
    * @param artifactType name
    * @returns vector of matching artifacts can return an empty vector if there are no matches
    */
    virtual vector<TskBlackboardArtifact> getArtifacts(const uint64_t file_id, TSK_ARTIFACT_TYPE artifactType)const = 0;
    /**
    * Get all artifacts with the given type
    * @param artifactType type
    * @returns vector of matching artifacts can return an empty vector if there are no matches
    */
    virtual vector<TskBlackboardArtifact> getArtifacts(const TSK_ARTIFACT_TYPE artifactType)const = 0;

    /**
    * Get all attributes that match the given condition 
    * @param condition (implementation specific) to use for matching
    * @returns vector of matching attributes can return an empty vector if there are no matches
    * @throws error if a bad condition string is supplied
    */
    virtual vector<TskBlackboardAttribute> getMatchingAttributes(const string& condition)const = 0;   

    /**
    * Get all attributes with the given type name and file id
    * @param file_id associated file id
    * @param attributeTypeName type name
    * @returns vector of matching attributes can return an empty vector if there are no matches
    */
    virtual vector<TskBlackboardAttribute> getAttributes(const uint64_t file_id, const string& attributeTypeName)const = 0;

    /**
    * Get all attributes with the given type and file id
    * @param file_id associated file id
    * @param attributeTypeID Type of attribute to return
    * @returns vector of matching attributes can return an empty vector if there are no matches
    */
    virtual vector<TskBlackboardAttribute> getAttributes(const uint64_t file_id, int attributeTypeID)const = 0;

    /** Get all attributes with the given type and file id
    * @param file_id associated file id
    * @param attributeType name
    * @returns vector of matching attributes can return an empty vector if there are no matches
    */
    virtual vector<TskBlackboardAttribute> getAttributes(const uint64_t file_id, TSK_ATTRIBUTE_TYPE attributeType)const = 0;
    /**
    * Get all attributes with the given type
    * @param attributeType type
    * @returns vector of matching attributes can return an empty vector if there are no matches
    */
    virtual vector<TskBlackboardAttribute> getAttributes(const TSK_ATTRIBUTE_TYPE attributeType)const = 0;


    /**
    * Create a new blackboard artifact with the given type id and file id
    * @param artifactTypeID artifact type id 
    * @param file_id associated file id 
    * @returns the new artifact
    * @throws error if the artifact type does not exist
    */
    virtual TskBlackboardArtifact createArtifact(const uint64_t file_id, const int artifactTypeID) = 0;

    /**
    * Create a new blackboard artifact with the given type and file id
    * @param file_id associated file id
    * @param artifactType artifact type 
    * @returns the new artifact
    * @throws error if the artifact type does not exist
    */
    virtual TskBlackboardArtifact createArtifact(const uint64_t file_id, const TSK_ARTIFACT_TYPE artifactType) = 0;

    /**
    * Add a new artifact type with the given name and file id
    * @param file_id associated file id
    * @param artifactTypeName System name of artifact type 
    * @returns the new artifact
    * @throws error if the artifact type does not exist
    */
    virtual TskBlackboardArtifact createArtifact(const uint64_t file_id, const string& artifactTypeName) = 0;

    /**
    * Add a new attribute to the general info artifact for the given file
    * @param file_id file id for the file to add the attribute to
    * @param attr and attribute populated with values. this attribute will have
    * its artifact_id and obj_id set by this method.
    * @throws error if no file with the given id exists or if a bad attribute is passed in.
    */
    virtual void createGenInfoAttribute(const uint64_t file_id, TskBlackboardAttribute& attr) = 0;

    /**
    * Search the entire blackboard for all attribute types associated with any
    * artifact of the given type.
    * @param artifactTypeId artifact type to search
    * @returns a vector of attribute ids can return an empty vector if no types are found
    */
    virtual vector<int> findAttributeTypes(int artifactTypeId) = 0;

    /**
    * Convert attribute type id to display name
    * @param attributeTypeID attribute type id
    * @returns display name
    * @throws error if no type exists for that id
    */
    static string attrTypeIDToTypeDisplayName(const int attributeTypeID);
    /**
    * Convert attribute type name to id
    * @param attributeTypeString attribute type name
    * @returns attribute type id
    * @throws error if no type exists with that name
    */
    static int attrTypeNameToTypeID(const string& attributeTypeString);
    /**
    * Convert attribute type id to name
    * @param attributeTypeID id
    * @returns attribute type name
    * @throws error if no type exists with that name
    */
    static string attrTypeIDToTypeName(const int attributeTypeID);

    /**
    * Add a new attribute type with the given name and display name
    * @param attributeTypeName name for the new attribute type. should be unique
    * @param displayName name to display for this type. need not be unique
    * @returns the new attribute type id generated for the type.
    * @throws error if a type with that name already exists
    */
    static int addAttributeType(const string& attributeTypeName, const string& displayName);

    /**
    * Convert artifact type id to display name
    * @param artifactTypeID artifact type id
    * @returns display name
    * @throws error if no type exists with that id
    */
    static string artTypeIDToDisplayName(const int artifactTypeID);
    /**
    * Convert artifact type name to id
    * @param artifactTypeString artifact type name
    * @returns artifact type id
    * @throws error if no type exists with that name
    */
    static int artTypeNameToTypeID(const string& artifactTypeString);
    /**
    * Convert artifact type id to name
    * @param artifactTypeID id
    * @returns artifact type name
    * @throws error if no type exists with that id
    */
    static string artTypeIDToTypeName(const int artifactTypeID);

    /**
    * Add a new artifact type with the given name and display name
    * @param artifactTypeName name for the new attribute type. should be unique
    * @param displayName name to display for this type. need not be unique
    * @returns the new artifact type id generated for the type.
    * @throws error if a type with that name already exists
    */
    static int addArtifactType(const string& artifactTypeName, const string& displayName);

    friend class TskBlackboardArtifact;
    friend class TskImgDB;

protected:
    static map<int, TskArtifactNames> getAllArtifactTypes();
    static map<int, TskAttributeNames> getAllAttributeTypes();
    virtual void addBlackboardAttribute(TskBlackboardAttribute& attr) = 0;
    /// Default Constructor
    TskBlackboard() {};

    /// Copy Constructor
    TskBlackboard(TskBlackboard const&) {};

    /// Destructor
    virtual ~TskBlackboard() {};

private:

};


#endif
