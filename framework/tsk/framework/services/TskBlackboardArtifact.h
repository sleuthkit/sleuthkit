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
* \file TskBlackboardArtifact.h
* Contains the definition for the TskBlackboardArtifact class.
*/
#ifndef _TSK_BLACKBOARD_ARTIFACT_H
#define _TSK_BLACKBOARD_ARTIFACT_H

#include <string>
#include <vector>
#include "tsk/framework/framework_i.h"

using namespace std;

class TskBlackboardAttribute;
class TskBlackboard;

/**
* Class that represents a blackboard artifact object.
*/
class TSK_FRAMEWORK_API TskBlackboardArtifact
{
public:
    /**
    * Get the artifact id for this artifact
    * @returns artifact id
    */
    uint64_t getArtifactID() const;
    /**
    * Get the object id for this artifact
    * @returns object id
    */
    uint64_t getObjectID() const;
    /**
    * Get the artifact type id for this artifact
    * @returns artifact type id
    */
    int getArtifactTypeID() const;
    /**
    * Get the artifact type name for this artifact
    * @returns artifact type name
    */
    string getArtifactTypeName() const;
    /**
    * Get the display name for this artifact
    * @returns display name
    */
    string getDisplayName() const;
    /**
    * Add an attribute to this artifact
    * @param attr attribute to be added
    */
    void addAttribute(TskBlackboardAttribute& attr);
    /**
    * Get all attributes associated with this artifact
    * @returns a vector of attributes
    */
    vector<TskBlackboardAttribute> getAttributes() const;	
    /*
    * destructor
    */
    ~TskBlackboardArtifact();

    friend class TskBlackboard;
    friend class TskFile;
    friend class TskImgDB;

protected:
    TskBlackboardArtifact(const uint64_t artifactID, const uint64_t objID, const int artifactTypeID);

private:
    uint64_t m_artifactID;
    uint64_t m_objID;
    int m_artifactTypeID;
};

#endif
