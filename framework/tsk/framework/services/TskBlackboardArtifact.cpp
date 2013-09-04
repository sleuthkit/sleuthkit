/*
* The Sleuth Kit
*
* Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
* Copyright (c) 2010-2012 Basis Technology Corporation. All Rights
* reserved.
*
* This software is distributed under the Common Public License 1.0
*/

#include <string>
#include <vector>
#include <iostream>
#include <sstream>
#include "tsk/framework/framework_i.h"
#include "TskBlackboard.h"
#include "TskBlackboardAttribute.h"
#include "tsk/framework/utilities/TskException.h"
#include "tsk/framework/services/TskServices.h"

#define BLACKBOARD() (TskServices::Instance().getBlackboard())

/**
* Default destructor
*/
TskBlackboardArtifact::~TskBlackboardArtifact(){

}

/**
* Get the artifact id
* @returns artifact id
*/
uint64_t TskBlackboardArtifact::getArtifactID()const{
    return m_artifactID;
}

/**
* Get the object id
* @returns object id
*/
uint64_t TskBlackboardArtifact::getObjectID()const{
    return m_objID;
}

/**
* Get the artifact type id
* @returns artifact type id
*/
int TskBlackboardArtifact::getArtifactTypeID()const{
    return m_artifactTypeID;
}

/**
* Get the artifact type name
* @returns artifact type name
*/
string TskBlackboardArtifact::getArtifactTypeName()const{
    return BLACKBOARD().artTypeIDToTypeName(m_artifactTypeID);
}

/**
* Get the display name
* @returns display name
*/
string TskBlackboardArtifact::getDisplayName()const{
    return BLACKBOARD().artTypeIDToDisplayName(m_artifactTypeID);
}

/**
* Add an attribute to this artifact
* @param attr attribute to be added
* @throws error if the given attribute has a bad type
*/
void TskBlackboardArtifact::addAttribute(TskBlackboardAttribute& attr){
    attr.setArtifactID(m_artifactID);
    attr.setObjectID(m_objID);
    BLACKBOARD().addBlackboardAttribute(attr);
}

/**
* Get all attributes associated with this artifact
* @returns a vector of attributes
*/
vector<TskBlackboardAttribute> TskBlackboardArtifact::getAttributes()const{
    std::stringstream whereClause;
    whereClause << "WHERE artifact_id = " << m_artifactID;

    return BLACKBOARD().getMatchingAttributes(whereClause.str());
}

/**
* Constructor
* @param artifactID artifact id 
* @param objID object id 
* @param artifactTypeID arifact type id 
*/	
TskBlackboardArtifact::TskBlackboardArtifact(uint64_t artifactID, uint64_t objID, int artifactTypeID)
: m_artifactID(artifactID), m_objID(objID), m_artifactTypeID(artifactTypeID) {}
