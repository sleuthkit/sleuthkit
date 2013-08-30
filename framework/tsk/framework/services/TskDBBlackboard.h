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
* \file TskDBBlackboard.h
* Contains the definition for the TskDBBlackboard class.
*/

#ifndef _TSK_DB_BLACKBOARD_H
#define _TSK_DB_BLACKBOARD_H

#include <string>
#include "tsk/framework/utilities/TskException.h"
#include "tsk/framework/services/TskBlackboard.h"
#include "tsk/framework/services/TskImgDB.h"
#include "tsk/framework/services/TskServices.h"
#include "TskBlackboardArtifact.h"
#include "TskBlackboardAttribute.h"


/**
* An implementation of TskBlackboard that stores the name / value pairs
* in the TskImgDB. 
*/
class TSK_FRAMEWORK_API TskDBBlackboard : public TskBlackboard
{
public:
    // Singleton access
    static TskDBBlackboard& instance();

    virtual TskBlackboardArtifact getBlackboardArtifact(const long artifactID);

    virtual vector<TskBlackboardArtifact> getMatchingArtifacts(const string& condition)const;
    virtual vector<TskBlackboardArtifact> getArtifacts(const uint64_t file_id, const string& artifactTypeName)const;
    virtual vector<TskBlackboardArtifact> getArtifacts(const uint64_t file_id, int artifactTypeID)const;
    virtual vector<TskBlackboardArtifact> getArtifacts(const uint64_t file_id, TSK_ARTIFACT_TYPE artifactType)const;
    virtual vector<TskBlackboardArtifact> getArtifacts(const TSK_ARTIFACT_TYPE artifactType)const;

    virtual vector<TskBlackboardAttribute> getMatchingAttributes(const string& condition)const;   
    virtual vector<TskBlackboardAttribute> getAttributes(const uint64_t file_id, const string& attributeTypeName)const;
    virtual vector<TskBlackboardAttribute> getAttributes(const uint64_t file_id, int attributeTypeID)const;
    virtual vector<TskBlackboardAttribute> getAttributes(const uint64_t file_id, TSK_ATTRIBUTE_TYPE attributeType)const;
    virtual vector<TskBlackboardAttribute> getAttributes(const TSK_ATTRIBUTE_TYPE attributeType)const;


    virtual TskBlackboardArtifact createArtifact(const uint64_t file_id, const int artifactTypeID);
    virtual TskBlackboardArtifact createArtifact(const uint64_t file_id, const TSK_ARTIFACT_TYPE artifactType);
    virtual TskBlackboardArtifact createArtifact(const uint64_t file_id, const string& artifactTypeName);

    virtual void createGenInfoAttribute(const uint64_t file_id, TskBlackboardAttribute& attr);


    static string attrTypeIDToTypeDisplayName(const int attributeTypeID);
    static int attrTypeNameToTypeID(const string& attributeTypeString);
    static string attrTypeIDToTypeName(const int attributeTypeID);

    static int addAttributeType(const string& attributeTypeName, const string& displayName);

    static string artTypeIDToDisplayName(const int artifactTypeID);
    static int artTypeNameToTypeID(const string& artifactTypeString);
    static string artTypeIDToTypeName(const int artifactTypeID);

    static int addArtifactType(const string& artifactTypeName, const string& displayName);

    virtual vector<int> findAttributeTypes(int artifactTypeId);

    friend class TskBlackboardArtifact;

protected:
    virtual void addBlackboardAttribute(TskBlackboardAttribute& attr);
    // Default Constructor
    TskDBBlackboard() { 
        m_pImgDB = &(TskServices::Instance().getImgDB()); 
    };

    // Copy Constructor
    TskDBBlackboard(TskDBBlackboard const&) {};

    // Assignment operator
    TskDBBlackboard& operator=(TskDBBlackboard const&) { return *m_pInstance; };

    // Destructor
    virtual ~TskDBBlackboard() {};

    // Our one and only instance
    static TskDBBlackboard * m_pInstance;

    TskImgDB * m_pImgDB;

private: 

};
#endif
