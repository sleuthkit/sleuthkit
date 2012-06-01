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
#include "Utilities/TskException.h"
#include "framework_i.h"
#include "Services/TskImgDB.h"
#include "TskBlackboardArtifact.h"
#include "TskBlackboardAttribute.h"

using namespace std;

/**
 * Built in artifact types.
 * Refer to http://wiki.sleuthkit.org/index.php?title=Artifact_Examples
 * for details on which attributes should be used for each artifact.
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
typedef enum TSK_ARTIFACT_TYPE {
		TSK_GEN_INFO = 1,///< The general info artifact, if information doesn't need its own artifact it should go here
		TSK_WEB_BOOKMARK = 2,///< A web bookmark. 
		TSK_WEB_COOKIE = 3,///< A web cookie. 
		TSK_WEB_HISTORY = 4,///< A web history enrty. 
		TSK_WEB_DOWNLOAD = 5,///< A web download. 
		TSK_RECENT_OBJECT = 6,///< A recently used object (MRU, recent document, etc.).
		TSK_TRACKPOINT = 7,///< A trackpoint from a GPS log.
		TSK_INSTALLED_PROG = 8,///< An installed program. 
		TSK_KEYWORD_HIT = 9,///< A keyword hit. 
        TSK_HASHSET_HIT = 10, ///< A hit within a known bad / notable hashset / hash database. 
        TSK_DEVICE_ATTACHED = 11, ///< An event for a device being attached to the host computer
        TSK_INTERESTING_FILE_HIT = 12, ///< A file that was flagged because it matched some search criteria for being interesting (i.e. because of its name, extension, etc.)
    /* SEE ABOVE:
     * - KEEP JAVA CODE IN SYNC 
     * - UPDATE map in TskBlackboard.cpp
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
typedef enum TSK_ATTRIBUTE_TYPE {
    TSK_URL = 1,///< String of a URL, should start with http:// or ftp:// etc.  You should also make a TskBlackoard::TSK_DOMAIN entry for the base domain name. 
    TSK_DATETIME = 2,///< INT32: GMT based Unix time, defines number of secords elapsed since UTC Jan 1, 1970.
    TSK_NAME = 3,///< STRING: The name associated with an artifact
    TSK_PROG_NAME = 4,///< String of name of a program that was installed on the system
    TSK_VALUE = 6,///< Some value associated with an artifact
    TSK_FLAG = 7,///< Some flag associated with an artifact
    TSK_PATH = 8,///< A filesystem path.  Should be fully qualified. Should set TSK_PATH_ID as well when this is set. TODO: Need to define this value more for cases with multiple images and multiple file systems per image. 
    TSK_GEO = 9,///< STRING: TBD
    TSK_KEYWORD = 10,///< STRING: Keyword that was found in this file. 
    TSK_KEYWORD_REGEXP = 11,///< STRING: A regular expression string
    TSK_KEYWORD_PREVIEW = 12,///< STRING: A text preview
    TSK_KEYWORD_SET = 13,///< STRING: A keyword set 
    TSK_USERNAME = 14,///< String of a user name.  Use TskBlackboard::TSK_DOMAIN to store the domain that the username is from (if it is known). 
    TSK_DOMAIN = 15,///< String of a DNS Domain name, e.g. sleuthkit.org  use TskBlackboad::TSK_URL for a full URL.
    TSK_PASSWORD = 16,///< String of a password that was found.  Use TskBlackboard::TSK_USERNAME and TskBlackboard::TSK_DOMAIN to link the password to a given user and site. 
    TSK_NAME_PERSON = 17,///< String of a person name
    TSK_DEVICE_MODEL = 18,///< String of manufacturer name of device that was connected (or somehow related to) the data being analyzed
    TSK_DEVICE_MAKE = 19,///< String of make of a device that was connected (or somehow related to) the data being analyzed
    TSK_DEVICE_ID = 20,///< String of ID/serial number of a device that was connected (or somehow related to) the data being analyzed
    TSK_EMAIL = 21,///< String of e-mail address in the form of user@host.com
    TSK_HASH_HD5 = 22,///< STRING: MD5 hash
    TSK_HASH_SHA1 = 23,///< STRING: SHA1 hash
    TSK_HASH_SHA2_256 = 24,///< STRING: SHA2 256 bit hash
    TSK_HASH_SHA2_512 = 25,///< STRING: SHA2 512 bit hash
    TSK_TEXT = 26,///< String of text extracted from a file.
    TSK_TEXT_FILE = 27,///< String of path to file containing text. May be absolute or relative. If relative, will be evaluated relative to OUT_DIR setting.
    TSK_TEXT_LANGUAGE = 28,///< String of the detected language in ISO 639-3 language code of TskBlackboard::TSK_TEXT data.
    TSK_ENTROPY = 29,///< DOUBLE: Entropy value of file
    TSK_HASHSET_NAME = 30,///< String of the name or file name of the hashset 
    TSK_INTERESTING_FILE = 31,///< An interesting file hit, potentially file id, name, or path
    TSK_REFERRER = 32,///< String of referrer URL
    TSK_LAST_ACCESSED = 33,///<last time access, review this instead of DATETIME
    TSK_IP_ADDRESS = 34,///<String of IP Address
    TSK_PHONE_NUMBER = 35,///<String of phone number
    TSK_PATH_ID = 36,///< Object ID from database that a TSK_PATH attribute corresponds to.  Set to -1 if path is for a file that is not in database (i.e. deleted). 
    TSK_SET_NAME = 37,///< STRING: The name of a set that was used to find this artifact (to be used for hash hits, keyword hits, interesting files, etc.)
    TSK_ENCRYPTION_DETECTED = 38,///< STRING: The type of encryption that is believed to have been used on the file.
    TSK_MALWARE_DETECTED = 39,///< STRING: The name of the malware that was detected in this file.
    TSK_STEG_DETECTED = 40,///< STRING: The name of the steganography technique that was detected in this file.
    /* SEE ABOVE: 
     * - KEEP JAVA CODE IN SYNC 
     * - UPDATE map in TskBlackBoard.cpp too */
};

/*
 * class to store attibute type names in the id to name map
 */
class TskAttributeNames{
public:
    string typeName;
    string displayName;
    TskAttributeNames(string name, string display):
    typeName(name),
        displayName(display){}
};

/*
 * class to store artifact type names in the id to name map
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
