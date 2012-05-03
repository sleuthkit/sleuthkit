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
 * \file TskImgDB.cpp
 * Some common defines used by the framework data model.
 */

#include "TskImgDB.h"

/// Default constructor
TskImgDB::TskImgDB()
{
}

/// Destructor
TskImgDB::~TskImgDB()
{
}

TskBlackboardAttribute TskImgDB::createAttribute(uint64_t artifactID, int attributeTypeID, uint64_t objectID, string moduleName, string context,
		TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE valueType, int valueInt, uint64_t valueLong, double valueDouble, 
        string valueString, vector<unsigned char> valueBytes){

    return TskBlackboardAttribute(artifactID, attributeTypeID, objectID, moduleName, context,
		valueType, valueInt, valueLong, valueDouble, valueString, valueBytes);
}
TskBlackboardArtifact TskImgDB::createArtifact(uint64_t artifactID, uint64_t objID, int artifactTypeID){
    return TskBlackboardArtifact(artifactID, objID, artifactTypeID);
}

map<int, TskArtifactNames> TskImgDB::getAllArtifactTypes(){
    return TskBlackboard::getAllArtifactTypes();
}

map<int, TskAttributeNames> TskImgDB::getAllAttributeTypes(){
    return TskBlackboard::getAllAttributeTypes();
}