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

/**
 * Store meta_addr to object id mapping of the directory in a local cache map
 * @param fsObjId fs id of this directory
 * @param meta_addr meta_addr of this directory
 * @param objId object id of this directory from the objects table
 */
void TskImgDB::storeParObjId(const int64_t & fsObjId, const TSK_INUM_T & meta_addr, const int64_t & objId) {
	map<TSK_INUM_T,int64_t> &tmpMap = m_parentDirIdCache[fsObjId];
	//store only if does not exist
	if (tmpMap.count(meta_addr) == 0)
		tmpMap[meta_addr] = objId;
}

/**
 * Find parent object id of TSK_FS_FILE. Use local cache map, if not found, fall back to SQL
 * @param fsObjId fs id of this file
 * @param meta_addr Meta address to find parent obj id for
 * @returns parent obj id ( > 0), -1 on error
 */
int64_t TskImgDB::findParObjId(const int64_t & fsObjId, TSK_INUM_T meta_addr) {
    //get from cache by parent meta addr, if available
    map<TSK_INUM_T,int64_t> &tmpMap = m_parentDirIdCache[fsObjId];
    if (tmpMap.count(meta_addr) > 0) {
        return tmpMap[meta_addr];
    }

    return getFileId(fsObjId, meta_addr);
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
