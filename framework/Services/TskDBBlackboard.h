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
 * \file TskDBBlackboard.h
 * Contains the definition for the TskDBBlackboard class.
 */

#ifndef _TSK_DB_BLACKBOARD_H
#define _TSK_DB_BLACKBOARD_H

#include <string>
#include "Utilities/TskException.h"
#include "Services/TskBlackboard.h"
#include "Services/TskImgDB.h"
#include "Services/TskServices.h"
#include "TskBlackboardArtifact.h"
#include "TskBlackboardAttribute.h"


/**
 * An implementation of TskBlackboard that stores the name / value pairs
 * in the TskImgDB. 
 */
class TSK_FRAMEWORK_API TskDBBlackboard
{
public:
    // Singleton access
    static TskDBBlackboard& instance();

    virtual void addArtifactType(string artifactTypeName, string displayName);
    virtual void addAttributeType(string attributeTypeName, string displayName);
    virtual void addBlackboardAttribute(TskBlackboardAttribute attr);
    virtual string getArtifactTypeDisplayName(int artifactTypeID);
    virtual int getArtifactTypeID(string artifactTypeString);
    virtual string getArtifactTypeName(int artifactTypeID);
    virtual string getAttributeTypeDisplayName(int attributeTypeID);
    virtual int getAttributeTypeID(string attributeTypeString);
    virtual string getAttributeTypeName(int attributeTypeID);
    virtual TskBlackboardArtifact getBlackboardArtifact(long artifactID);
    virtual vector<TskBlackboardArtifact> getBlackboardArtifacts(string artifactTypeName, uint64_t file_id);
    virtual vector<TskBlackboardArtifact> getBlackboardArtifacts(int artifactTypeID, uint64_t file_id);
    virtual vector<TskBlackboardArtifact> getBlackboardArtifacts(ARTIFACT_TYPE artifactType, uint64_t file_id);
    //this might be better put in the TskDBBlackboard class
    virtual vector<TskBlackboardArtifact> getMatchingArtifacts(string whereClause);
    virtual vector<TskBlackboardAttribute> getMatchingAttributes(string whereClause);
    virtual TskBlackboardArtifact newBlackboardArtifact(int artifactTypeID, uint64_t file_id);
    virtual TskBlackboardArtifact newBlackboardArtifact(ARTIFACT_TYPE artifactType, uint64_t file_id);
protected:
    // Default Constructor
    TskDBBlackboard() { m_pImgDB = &(TskServices::Instance().getImgDB()); };

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


    
