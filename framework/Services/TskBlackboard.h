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

/**
 * An interface for setting and retrieving name/value pairs to the blackboard.
 * The blackboard is used to store data for use by later modules in the pipeline.
 * Can be registered with and retrieved from TskServices.
 */
class TSK_FRAMEWORK_API TskBlackboard
{
public:
    virtual void addArtifactType(string artifactTypeName, string displayName) = 0;
    virtual void addAttributeType(string attributeTypeName, string displayName) = 0;
    virtual void addBlackboardAttribute(TskBlackboardAttribute attr) = 0;
    virtual string getArtifactTypeDisplayName(int artifactTypeID) = 0;
    virtual int getArtifactTypeID(string artifactTypeString) = 0;
    virtual string getArtifactTypeName(int artifactTypeID) = 0;
    virtual string getAttributeTypeDisplayName(int attributeTypeID) = 0;
    virtual int getAttributeTypeID(string attributeTypeString) = 0;
    virtual string getAttributeTypeName(int attributeTypeID) = 0;
    virtual TskBlackboardArtifact getBlackboardArtifact(long artifactID) = 0;
    virtual vector<TskBlackboardArtifact> getBlackboardArtifacts(string artifactTypeName, uint64_t file_id) = 0;
    virtual vector<TskBlackboardArtifact> getBlackboardArtifacts(int artifactTypeID, uint64_t file_id) = 0;
    virtual vector<TskBlackboardArtifact> getBlackboardArtifacts(ARTIFACT_TYPE artifactType, uint64_t file_id) = 0;
    //this might be better put in the TskDBBlackboard class
    virtual vector<TskBlackboardArtifact> getMatchingArtifacts(string whereClause) = 0;
    virtual vector<TskBlackboardAttribute> getMatchingAttributes(string whereClause) = 0;
    virtual TskBlackboardArtifact newBlackboardArtifact(int artifactTypeID, uint64_t file_id) = 0;
    virtual TskBlackboardArtifact newBlackboardArtifact(ARTIFACT_TYPE artifactType, uint64_t file_id) = 0;

protected:
    /// Default Constructor
    TskBlackboard() {};

    /// Copy Constructor
    TskBlackboard(TskBlackboard const&) {};

    /// Destructor
    virtual ~TskBlackboard() {};
    
private:
};


#endif
