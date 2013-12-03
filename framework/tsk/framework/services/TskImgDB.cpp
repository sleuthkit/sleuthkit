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

void TskImgDB::storeParObjId(const int64_t & fsObjId, const TSK_FS_FILE * fs_file, const int64_t & objId) {
    map<TSK_INUM_T, map<uint32_t, int64_t> > &fsMap = m_parentDirIdCache[fsObjId];
    //store only if does not exist -- otherwise '..' and '.' entries will overwrite
    if (fsMap.count(fs_file->name->meta_addr) == 0) {
        fsMap[fs_file->name->meta_addr][fs_file->name->meta_seq] = objId;
    }
    else {
        map<uint32_t, int64_t> &fileMap = fsMap[fs_file->name->meta_addr];
        if (fileMap.count(fs_file->name->meta_seq) == 0) {
            fileMap[fs_file->name->meta_seq] = objId;
        }
    }
}

int64_t TskImgDB::findParObjId(const TSK_FS_FILE * fs_file, const int64_t & fsObjId) {
    //get from cache by parent meta addr, if available
    map<TSK_INUM_T, map<uint32_t, int64_t> > &fsMap = m_parentDirIdCache[fsObjId];
    if (fsMap.count(fs_file->name->par_addr) > 0) {
        map<uint32_t, int64_t> &fileMap = fsMap[fs_file->name->par_addr];
        if (fileMap.count(fs_file->name->par_seq) > 0) {
            return fileMap[fs_file->name->par_seq];
        }
    }


    return getFileId(fsObjId, fs_file->name->par_addr);
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
