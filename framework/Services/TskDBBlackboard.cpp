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
#include "File/TskFileTsk.h"
#include "File/TskFile.h"

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

int TskDBBlackboard::addArtifactType(const string& artifactTypeName, const string& displayName){
    try{
        return TskBlackboard::artTypeNameToTypeID(artifactTypeName);
    }
    catch(TskException e){
        try{
            return IMGDB().getArtifactTypeID(artifactTypeName);
        }
        catch(TskException e){
            int id = TskBlackboard::addArtifactType(artifactTypeName, displayName);
            IMGDB().addArtifactType(id, artifactTypeName, displayName);
            return id;
        }
    }
}

int TskDBBlackboard::addAttributeType(const string& attributeTypeName, const string& displayName){
    try{
        return TskBlackboard::attrTypeNameToTypeID(attributeTypeName);
    }
    catch(TskException e){
        try{
            return IMGDB().getAttributeTypeID(attributeTypeName);
        }
        catch(TskException e){
            int id = TskBlackboard::addAttributeType(attributeTypeName, displayName);
            IMGDB().addAttributeType(id, attributeTypeName, displayName);
            return id;
        }
    }
}

void TskDBBlackboard::addBlackboardAttribute(TskBlackboardAttribute& attr){
    IMGDB().addBlackboardAttribute(attr);
}

string TskDBBlackboard::attrTypeIDToTypeDisplayName(const int attributeTypeID){
    try{
        return TskBlackboard::attrTypeIDToTypeDisplayName(attributeTypeID);
    }
    catch(TskException e){
        return IMGDB().getAttributeTypeDisplayName(attributeTypeID);
    }
}

int TskDBBlackboard::attrTypeNameToTypeID(const string& attributeTypeString){
    try{
        return TskBlackboard::attrTypeNameToTypeID(attributeTypeString);
    }
    catch(TskException e){
        return IMGDB().getAttributeTypeID(attributeTypeString);
    } 
}

string TskDBBlackboard::attrTypeIDToTypeName(const int attributeTypeID){
    try{
    return TskBlackboard::attrTypeIDToTypeName(attributeTypeID);
    }
    catch(TskException e){
        return IMGDB().getAttributeTypeName(attributeTypeID);
    }
}

string TskDBBlackboard::artTypeIDToDisplayName(const int artifactTypeID){
    try{
    return TskBlackboard::artTypeIDToDisplayName(artifactTypeID);}
    catch(TskException e){
        return IMGDB().getArtifactTypeDisplayName(artifactTypeID);
    }
}

int TskDBBlackboard::artTypeNameToTypeID(const string& artifactTypeString){
    try{
    return TskBlackboard::artTypeNameToTypeID(artifactTypeString);}
    catch(TskException e){
        return IMGDB().getArtifactTypeID(artifactTypeString);
    }
}
string TskDBBlackboard::artTypeIDToTypeName(const int artifactTypeID){
    try{
    return TskBlackboard::artTypeIDToTypeName(artifactTypeID);}
    catch(TskException e){
        return IMGDB().getArtifactTypeName(artifactTypeID);
    }
}

TskBlackboardArtifact TskDBBlackboard::getBlackboardArtifact(const long artifactID){
    stringstream condition;
    condition << " WHERE artifact_id = " << artifactID;
    return IMGDB().getMatchingArtifacts(condition.str())[0];
}

vector<TskBlackboardArtifact> TskDBBlackboard::getArtifacts(const uint64_t file_id, const string& artifactTypeName)const{
    stringstream condition;
    condition << " WHERE obj_id = " << file_id << " AND artifact_type_id = " << attrTypeNameToTypeID(artifactTypeName);
    return IMGDB().getMatchingArtifacts(condition.str());
}

vector<TskBlackboardArtifact> TskDBBlackboard::getArtifacts(const uint64_t file_id, int artifactTypeID)const{
    stringstream condition;
    condition << " WHERE obj_id = " << file_id << " AND artifact_type_id = " << artifactTypeID;
    return IMGDB().getMatchingArtifacts(condition.str());
}

vector<TskBlackboardArtifact> TskDBBlackboard::getArtifacts(const uint64_t file_id, TSK_ARTIFACT_TYPE artifactType)const{
    stringstream condition;
    condition << " WHERE obj_id = " << file_id << " AND artifact_type_id = " << artifactType;
    return IMGDB().getMatchingArtifacts(condition.str());
}

vector<TskBlackboardArtifact> TskDBBlackboard::getArtifacts(TSK_ARTIFACT_TYPE artifactType)const{
    stringstream condition;
    condition << " WHERE artifact_type_id = " << artifactType;
    return IMGDB().getMatchingArtifacts(condition.str());
}

vector<TskBlackboardArtifact> TskDBBlackboard::getMatchingArtifacts(const string& condition)const{
    return IMGDB().getMatchingArtifacts(condition);
}

vector<TskBlackboardAttribute> TskDBBlackboard::getAttributes(const uint64_t file_id, const string& attributeTypeName)const{
    stringstream condition;
    condition << " WHERE obj_id = " << file_id << " AND attribute_type_id = " << attrTypeNameToTypeID(attributeTypeName);
    return IMGDB().getMatchingAttributes(condition.str());
}
vector<TskBlackboardAttribute> TskDBBlackboard::getAttributes(const uint64_t file_id, int attributeTypeID)const{
    stringstream condition;
    condition << " WHERE obj_id = " << file_id << " AND attribute_type_id = " << attributeTypeID;
    return IMGDB().getMatchingAttributes(condition.str());
}
vector<TskBlackboardAttribute> TskDBBlackboard::getAttributes(const uint64_t file_id, TSK_ATTRIBUTE_TYPE attributeType)const{
    stringstream condition;
    condition << " WHERE obj_id = " << file_id << " AND attribute_type_id = " << attributeType;
    return IMGDB().getMatchingAttributes(condition.str());
}
vector<TskBlackboardAttribute> TskDBBlackboard::getAttributes(const TSK_ATTRIBUTE_TYPE attributeType)const{
    stringstream condition;
    condition << " WHERE attribute_type_id = " << attributeType;
    return IMGDB().getMatchingAttributes(condition.str());
}

vector<TskBlackboardAttribute> TskDBBlackboard::getMatchingAttributes(const string& condition)const{
    return IMGDB().getMatchingAttributes(condition);

}

TskBlackboardArtifact TskDBBlackboard::createArtifact(const uint64_t file_id, const int artifactTypeID){
    return IMGDB().createBlackboardArtifact(file_id, artifactTypeID);
}

TskBlackboardArtifact TskDBBlackboard::createArtifact(const uint64_t file_id, const TSK_ARTIFACT_TYPE artifactType){
    return IMGDB().createBlackboardArtifact(file_id, artifactType);
}

TskBlackboardArtifact TskDBBlackboard::createArtifact(const uint64_t file_id, const string& artifactTypeName){
    return IMGDB().createBlackboardArtifact(file_id, attrTypeNameToTypeID(artifactTypeName));
}

void TskDBBlackboard::createGenInfoAttribute(const uint64_t file_id, TskBlackboardAttribute& attr){
    TskFileTsk file(file_id);
    file.addGenInfoAttribute(attr);    
}

vector<int> TskDBBlackboard::findAttributeTypes(int artifactTypeId){
    return IMGDB().findAttributeTypes(artifactTypeId);
}