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

/* Note that the below comments are the only documentation for the standard types.
 * Please ensure that all types are documented. 
 */

/**
 * Built in artifact types 
 */
typedef enum TSK_ARTIFACT_TYPE {
		TSK_ART_GEN_INFO = 1,///< The general info artifact, if information doesn't need its own artifact it should go here
		TSK_ART_WEB_BOOKMARK,///< A web bookmark. Each bookmark should have its own artifact and should expand its information using attributes
		TSK_ART_WEB_COOKIE,///< A web cookie. Each cookie should have its own artifact and should expand its information using attributes
		TSK_ART_WEB_HISTORY,///< A web history enrty. Each history enrty should have its own artifact and should expand its information using attributes
		TSK_ART_WEB_DOWNLOAD,///< A web download. Each download enrty should have its own artifact and should expand its information using attributes
		TSK_ART_RECENT_OBJECT,///< A recently used object record. Each record should have its own artifact and should expand its information using attributes
		TSK_ART_TRACKPOINT,///< A trackpoint. Each trackpoint should have its own artifact and should expand its information using attributes
		TSK_ART_INSTALLED_PROG,///< An installed program. Each program should have its own artifact and should expand its information using attributes
		TSK_ART_KEYWORD_HIT///< A keyword hit. Each hit should have its own artifact and should expand its information using attributes
    };

/**
 * Built in attribute types 
 */
typedef enum TSK_ATTRIBUTE_TYPE {
    TSK_URL = 1,///< String of a URL, should start with http:// or ftp:// etc.  You should also make a TskBlackoard::TSK_DOMAIN entry for the base domain name. 
    TSK_DATETIME,///< INT32: GMT based Unix time, defines number of secords elapsed since UTC Jan 1, 1970.
    TSK_NAME,///< STRING: The name associated with an artifact
    TSK_PROG_NAME,///< String of name of a program that was installed on the system
    TSK_WEB_BOOKMARK,///< STRING: Browser bookmark information
    TSK_VALUE,///< Some value associated with an artifact
    TSK_FLAG,///< Some flag associated with an artifact
    TSK_PATH,///< A filesystem path. There is no required formatting style
    TSK_GEO,///< STRING: TBD
    TSK_KEYWORD,///< STRING: Keyword that was found in this file. 
    TSK_KEYWORD_REGEXP,///< STRING: A regular expression string
    TSK_KEYWORD_PREVIEW,///< STRING: A text preview
    TSK_KEYWORD_SET,///< STRING: A keyword set 
    TSK_USERNAME,///< String of a user name.  Use TskBlackboard::TSK_DOMAIN to store the domain that the username is from (if it is known). 
    TSK_DOMAIN,///< String of a DNS Domain name, e.g. sleuthkit.org  use TskBlackboad::TSK_URL for a full URL.
    TSK_PASSWORD,///< String of a password that was found.  Use TskBlackboard::TSK_USERNAME and TskBlackboard::TSK_DOMAIN to link the password to a given user and site. 
    TSK_NAME_PERSON,///< String of a person name
    TSK_DEVICE_MODEL,///< String of manufacturer name of device that was connected (or somehow related to) the data being analyzed
    TSK_DEVICE_MAKE,///< String of make of a device that was connected (or somehow related to) the data being analyzed
    TSK_DEVICE_ID,///< String of ID of a device that was connected (or somehow related to) the data being analyzed
    TSK_EMAIL,///< String of e-mail address in the form of user@host.com
    TSK_HASH_HD5,///< STRING: MD5 hash
    TSK_HASH_SHA1,///< STRING: SHA1 hash
    TSK_HASH_SHA2_256,///< STRING: SHA2 256 bit hash
    TSK_HASH_SHA2_512,///< STRING: SHA2 512 bit hash
    TSK_TEXT,///< String of text extracted from a file.
    TSK_TEXT_FILE,///< String of path to file containing text. May be absolute or relative. If relative, will be evaluated relative to OUT_DIR setting.
    TSK_TEXT_LANGUAGE ,///< String of the detected language in ISO 639-3 language code of TskBlackboard::TSK_TEXT data.
    TSK_ENTROPY,///< DOUBLE: Entropy value of file
    TSK_HASHSET_NAME,///< String of name of the hashset if a file was found in it
    TSK_INTERESTING_FILE,///< An interesting file hit, potentially file id, name, or path
    TSK_REFERRER,///<String Referrer URL
    TSK_LAST_ACCESSED,///<last time access, review this instead of DATETIME
    TSK_IP_ADDRESS,///<String IP Address
    TSK_PHONE_NUMBER,///<String phone number
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
     * @returns the artifact
     */
    virtual TskBlackboardArtifact getBlackboardArtifact(const long artifactID) = 0;

    /**
     * Get all artifacts that match the given condition
     * @param condition condition (implementation specific) to use for matching
     * @returns vector of matching artifacts
     */
    virtual vector<TskBlackboardArtifact> getMatchingArtifacts(const string& condition)const = 0;
    /**
     * Get all artifacts with the given type name and file id
     * @param file_id associated file id
     * @param artifactTypeName type name
     * @returns vector of matching artifacts
     */
    virtual vector<TskBlackboardArtifact> getArtifacts(const uint64_t file_id, const string& artifactTypeName)const = 0;
    /**
     * Get all artifacts with the given type id and file id
     * @param file_id associated file id
     * @param artifactTypeID type id
     * @returns vector of matching artifacts
     */
    virtual vector<TskBlackboardArtifact> getArtifacts(const uint64_t file_id, int artifactTypeID)const = 0;
    /**
     * Get all artifacts with the given type and file id
     * @param file_id associated file id
     * @param artifactType name
     * @returns vector of matching artifacts
     */
    virtual vector<TskBlackboardArtifact> getArtifacts(const uint64_t file_id, TSK_ARTIFACT_TYPE artifactType)const = 0;
    /**
     * Get all artifacts with the given type
     * @param artifactType type
     * @returns vector of matching artifacts
     */
    virtual vector<TskBlackboardArtifact> getArtifacts(const TSK_ARTIFACT_TYPE artifactType)const = 0;

    /**
     * Get all attributes that match the given condition 
     * @param condition (implementation specific) to use for matching
     * @returns vector of matching attributes
     */
    virtual vector<TskBlackboardAttribute> getMatchingAttributes(const string& condition)const = 0;   
    /**
     * Get all attributes with the given type name and file id
     * @param file_id associated file id
     * @param attributeTypeName type name
     * @returns vector of matching attributes
     */
    virtual vector<TskBlackboardAttribute> getAttributes(const uint64_t file_id, const string& attributeTypeName)const = 0;
    /**
     * Get all attributes with the given type and file id
     * @param file_id associated file id
     * @param attributeType name
     * @returns vector of matching attributes
     */
    virtual vector<TskBlackboardAttribute> getAttributes(const uint64_t file_id, int attributeTypeID)const = 0;
    /** Get all attributes with the given type and file id
     * @param file_id associated file id
     * @param attributeType name
     * @returns vector of matching attributes
     */
    virtual vector<TskBlackboardAttribute> getAttributes(const uint64_t file_id, TSK_ATTRIBUTE_TYPE attributeType)const = 0;
    /**
     * Get all attributes with the given type
     * @param attributeType type
     * @returns vector of matching attributes
     */
    virtual vector<TskBlackboardAttribute> getAttributes(const TSK_ATTRIBUTE_TYPE attributeType)const = 0;
    

    /**
     * Create a new blackboard artifact with the given type id and file id
     * @param artifactTypeID artifact type id
     * @param file_id associated file id
     * @returns the new artifact
     */
    virtual TskBlackboardArtifact createArtifact(const uint64_t file_id, const int artifactTypeID) = 0;
    /**
     * Create a new blackboard artifact with the given type and file id
     * @param artifactType artifact type
     * @param file_id associated file id
     * @returns the new artifact
     */
    virtual TskBlackboardArtifact createArtifact(const uint64_t file_id, const TSK_ARTIFACT_TYPE artifactType) = 0;
    /**
     * Add a new artifact type with the given name and display name
     * @param artifactTypeName type name (should already exist)
     * @param displayName display name
     */
    virtual TskBlackboardArtifact createArtifact(const uint64_t file_id, const string& artifactTypeName) = 0;

    /**
     * Add a new attribute to the general info artifact for the given file
     * @param file_id file id for the file to add the attribute to
     * @param attr and attribute populated with values. this attribute will have
     * its artifact_id and obj_id set by this method.
     * @param displayName display name
     */
    virtual void createGenInfoAttribute(const uint64_t file_id, TskBlackboardAttribute& attr) = 0;

    /**
     * Search the entire blackboard for all attribute types associated with any
     * artifact of the given type.
     * @param artifactTypeId artifact type to search
     * @returns a vector of attribute ids
     */
    virtual vector<int> findAttributeTypes(int artifactTypeId) = 0;

    /**
     * Convert attribute type id to display name
     * @param attributeTypeID attribute type id
     * @returns display name
     */
    static string attrTypeIDToTypeDisplayName(const int attributeTypeID);
    /**
     * Convert attribute type name to id
     * @param attributeTypeString attribute type name
     * @returns attribute type id
     */
    static int attrTypeNameToTypeID(const string& attributeTypeString);
    /**
     * Convert attribute type id to name
     * @param attributeTypeID id
     * @returns attribute type name
     */
    static string attrTypeIDToTypeName(const int attributeTypeID);

    /**
     * Add a new attribute type with the given name and display name
     * @param attributeTypeName name for the new attribute type. should be unique
     * @param displayName name to display for this type. need not be unique
     * @returns the new attribute type id generated for the type.
     */
    static int addAttributeType(const string& attributeTypeName, const string& displayName);

    /**
     * Convert artifact type id to display name
     * @param artifactTypeID artifact type id
     * @returns display name
     */
    static string artTypeIDToDisplayName(const int artifactTypeID);
    /**
     * Convert artifact type name to id
     * @param artifactTypeString artifact type name
     * @returns artifact type id
     */
    static int artTypeNameToTypeID(const string& artifactTypeString);
    /**
     * Convert artifact type id to name
     * @param artifactTypeID id
     * @returns artifact type name
     */
    static string artTypeIDToTypeName(const int artifactTypeID);

    /**
     * Add a new artifact type with the given name and display name
     * @param artifactTypeName name for the new attribute type. should be unique
     * @param displayName name to display for this type. need not be unique
     * @returns the new artifact type id generated for the type.
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
