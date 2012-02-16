/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2011 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

#include <string>
#include <sstream>

#include "TskDBBlackboard.h"
#include "Services/TskImgDB.h"
#include "Services/TskServices.h"

TskDBBlackboard * TskDBBlackboard::m_pInstance = NULL;

#define IMGDB() (TskServices::Instance().getImgDB())

TskDBBlackboard& TskDBBlackboard::instance()
{
    if (!m_pInstance)
    {
        m_pInstance = new TskDBBlackboard();
    }
    return *m_pInstance;
}

void TskDBBlackboard::addArtifactType(string artifactTypeName, string displayName){
    IMGDB().addArtifactType(artifactTypeName, displayName);
}

void TskDBBlackboard::addAttributeType(string attributeTypeName, string displayName){
    IMGDB().addAttributeType(attributeTypeName, displayName);
}

void TskDBBlackboard::addBlackboardAttribute(TskBlackboardAttribute attr){
    IMGDB().addBlackboardAttribute(attr);
}

string TskDBBlackboard::getArtifactTypeDisplayName(int artifactTypeID){
    return IMGDB().getArtifactTypeDisplayName(artifactTypeID);
}

int TskDBBlackboard::getArtifactTypeID(string artifactTypeString){
    return IMGDB().getArtifactTypeID(artifactTypeString);
}

string TskDBBlackboard::getArtifactTypeName(int artifactTypeID){
    return IMGDB().getArtifactTypeName(artifactTypeID);
}

string TskDBBlackboard::getAttributeTypeDisplayName(int attributeTypeID){
    return IMGDB().getAttributeTypeDisplayName(attributeTypeID);
}

int TskDBBlackboard::getAttributeTypeID(string attributeTypeString){
    return IMGDB().getArtifactTypeID(attributeTypeString);
}
string TskDBBlackboard::getAttributeTypeName(int attributeTypeID){
    return IMGDB().getAttributeTypeName(attributeTypeID);
}

TskBlackboardArtifact TskDBBlackboard::getBlackboardArtifact(long artifactID){
    return IMGDB().getBlackboardArtifact(artifactID);
}

vector<TskBlackboardArtifact> TskDBBlackboard::getBlackboardArtifacts(string artifactTypeName, uint64_t file_id){
    return IMGDB().getBlackboardArtifacts(artifactTypeName, file_id);
}

vector<TskBlackboardArtifact> TskDBBlackboard::getBlackboardArtifacts(int artifactTypeID, uint64_t file_id){
    return IMGDB().getBlackboardArtifacts(artifactTypeID, file_id);
}

vector<TskBlackboardArtifact> TskDBBlackboard::getBlackboardArtifacts(ARTIFACT_TYPE artifactType, uint64_t file_id){
    return IMGDB().getBlackboardArtifacts(artifactType, file_id);
}

vector<TskBlackboardArtifact> TskDBBlackboard::getMatchingArtifacts(string whereClause){
    return IMGDB().getMatchingArtifacts(whereClause);
}

vector<TskBlackboardAttribute> TskDBBlackboard::getMatchingAttributes(string whereClause){
    return IMGDB().getMatchingAttributes(whereClause);

}

TskBlackboardArtifact TskDBBlackboard::newBlackboardArtifact(int artifactTypeID, uint64_t file_id){
    return IMGDB().newBlackboardArtifact(artifactTypeID, file_id);
}

TskBlackboardArtifact TskDBBlackboard::newBlackboardArtifact(ARTIFACT_TYPE artifactType, uint64_t file_id){
    return IMGDB().newBlackboardArtifact(artifactType, file_id);
}
