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
 * \file TskFile.cpp
 * Contains the implementation for the TskFile class.
 */

// System includes
#include <sstream>

// Framework includes
#include "TskFile.h"
#include "Services/TskServices.h"

/**
 * Delete the TskFile object.
 */
TskFile::~TskFile(void)
{
}

/**
 * 
 */
void TskFile::initialize()
{
    TskImgDB * imgDB = &TskServices::Instance().getImgDB();

    // XXX We never check the return value...
    if (imgDB != NULL)
        imgDB->getFileRecord(m_id, m_fileRecord);
}

/**
 * What is this files id?
 */
uint64_t TskFile::id() const
{
    return m_id;
}

/**
 * What is this files type id?
 */
int TskFile::typeId() const
{
    return m_fileRecord.typeId;
}

/**
 * What is this files name?
 */
std::string TskFile::name() const
{
    return m_fileRecord.name;
}

/**
 * What is this files extension?
 */
std::string TskFile::extension() const
{
    size_t pos = m_fileRecord.name.find_last_of(".");
    if (pos == std::string.npos)
        return std::string("");
    else
        return m_fileRecord.name.substr(pos + 1);
}

/**
 * What is this files parent file id?
 */
uint64_t TskFile::parentFileId() const
{
    return m_fileRecord.parentFileId;
}

/**
 * What is this files directory type?
 */
TSK_FS_NAME_TYPE_ENUM TskFile::dirType() const
{
    return m_fileRecord.dirType;
}
/**
 * What is this files metadata type?
 */
TSK_FS_META_TYPE_ENUM TskFile::metaType() const
{
    return m_fileRecord.metaType;
}

/**
 * What are this files directory flags?
 */
TSK_FS_NAME_FLAG_ENUM TskFile::dirFlags() const
{
    return m_fileRecord.dirFlags;
}

/**
 * What are this files metadata flags?
 */
TSK_FS_META_FLAG_ENUM TskFile::metaFlags() const
{
    return m_fileRecord.metaFlags;
}

/**
 * What is this files size?
 */
TSK_OFF_T TskFile::size() const
{
    return m_fileRecord.size;
}

/**
 * What is this files change time?
 */
time_t TskFile::ctime() const
{
    return m_fileRecord.ctime;
}

/**
 * What is this files creation time?
 */
time_t TskFile::crtime() const
{
    return m_fileRecord.crtime;
}

/**
 * What is this files access time?
 */
time_t TskFile::atime() const
{
    return m_fileRecord.atime;
}

/**
 * What is this files modify time?
 */
time_t TskFile::mtime() const
{
    return m_fileRecord.mtime;
}

/**
 * What is this files mode?
 */
TSK_FS_META_MODE_ENUM TskFile::mode() const
{
    return m_fileRecord.mode;
}

/**
 * What is this files user id?
 */
TSK_UID_T TskFile::uid() const
{
    return m_fileRecord.uid;
}

/**
 * What is this files group id?
 */
TSK_GID_T TskFile::gid() const
{
    return m_fileRecord.gid;
}

/**
 * What is this files status?
 */
int TskFile::status() const
{
    return m_fileRecord.status;
}

/*
 * What is this files full path
 */
std::string TskFile::fullPath() const
{
    return m_fileRecord.fullPath;
}

// Get the file hash
std::string TskFile::getHash(TskImgDB::HASH_TYPE hashType) const
{
    switch (hashType) {
    case TskImgDB::MD5:
        return m_fileRecord.md5;
        break;
    case TskImgDB::SHA1:
        return m_fileRecord.sha1;
        break;
    case TskImgDB::SHA2_256:
        return m_fileRecord.sha2_256;
        break;
    case TskImgDB::SHA2_512:
        return m_fileRecord.sha2_512;
        break;
    };
    return "";
}

// Set the file hash
void TskFile::setHash(TskImgDB::HASH_TYPE hashType, const std::string hash)
{
    switch (hashType) {
    case TskImgDB::MD5:
        m_fileRecord.md5 = hash;
        break;
    case TskImgDB::SHA1:
        m_fileRecord.sha1 = hash;
        break;
    case TskImgDB::SHA2_256:
        m_fileRecord.sha2_256 = hash;
        break;
    case TskImgDB::SHA2_512:
        m_fileRecord.sha2_512 = hash;
        break;
    };
    if (TskServices::Instance().getImgDB().setHash(m_fileRecord.fileId, hashType, hash)) {
        throw TskException("setHash failed.");
    }
}

/// Set the file status
void TskFile::setStatus(TskImgDB::FILE_STATUS status)
{
    m_fileRecord.status = status;
    TskServices::Instance().getImgDB().updateFileStatus(id(), status);
}

/**
 * Create a new artifact with the given type id
 * @param artifactTypeID type id
 * @returns the new artifact
 */
TskBlackboardArtifact TskFile::createArtifact(int artifactTypeID){
    return TskServices::Instance().getBlackboard().createArtifact(m_id, artifactTypeID);
}

/**
 * Create a new artifact with the given type
 * @param type artifact type
 * @returns the new artifact
 */
TskBlackboardArtifact TskFile::createArtifact(TSK_ARTIFACT_TYPE type){
    return TskServices::Instance().getBlackboard().createArtifact(m_id, type);
}

/**
 * Create a new artifact with the given type name
 * @param artifactTypeName artifact type name
 * @returns the new artifact
 */
TskBlackboardArtifact TskFile::createArtifact(string artifactTypeName){
    return TskServices::Instance().getBlackboard().createArtifact(m_id, artifactTypeName);
}

/**
 * Get all artifacts associated with this file with the given type name
 * @param artifactTypeName type name
 * @returns all matching artifacts
 */
vector<TskBlackboardArtifact> TskFile::getArtifacts(string artifactTypeName){
    return TskServices::Instance().getBlackboard().getArtifacts(m_id, artifactTypeName);
}

/**
 * Get all artifacts associated with this file with the given type id
 * @param artifactTypeID type id
 * @returns all matching artifacts
 */
vector<TskBlackboardArtifact> TskFile::getArtifacts(int artifactTypeID){
    return TskServices::Instance().getBlackboard().getArtifacts(m_id, artifactTypeID);
}

/**
 * Get all artifacts associated with this file with the given type
 * @param type artifact type
 * @returns all matching artifacts
 */
vector<TskBlackboardArtifact> TskFile::getArtifacts(TSK_ARTIFACT_TYPE type){
    return TskServices::Instance().getBlackboard().getArtifacts(m_id, type);
}

/**
 * Get all artifacts associated with this file
 * @returns all artifacts
 */
vector<TskBlackboardArtifact> TskFile::getAllArtifacts(){
    stringstream str;
    str << "WHERE obj_id = " << m_id;
    return TskServices::Instance().getBlackboard().getMatchingArtifacts(str.str());
}

/**
 * Get all artifacts associated with this file with the given type name
 * @param attributeTypeName type name
 * @returns all matching artifacts
 */
vector<TskBlackboardAttribute> TskFile::getAttributes(string attributeTypeName){
    stringstream str;
    str << "WHERE obj_id = " << m_id << " AND attribute_type_id = " << TskServices::Instance().getBlackboard().attrTypeNameToTypeID(attributeTypeName);
    return TskServices::Instance().getBlackboard().getMatchingAttributes(str.str());
}

/**
 * Get all artifacts associated with this file with the given type id
 * @param attributeTypeID type id
 * @returns all matching artifacts
 */
vector<TskBlackboardAttribute> TskFile::getAttributes(int attributeTypeID){
    stringstream str;
    str << "WHERE obj_id = " << m_id << " AND attribute_type_id = " << attributeTypeID;
    return TskServices::Instance().getBlackboard().getMatchingAttributes(str.str());
}

/**
 * Get all artifacts associated with this file with the given type
 * @param type artifact type
 * @returns all matching artifacts
 */
vector<TskBlackboardAttribute> TskFile::getAttributes(TSK_ATTRIBUTE_TYPE type){
    stringstream str;
    str << "WHERE obj_id = " << m_id << " AND attribute_type_id = " << type;
    return TskServices::Instance().getBlackboard().getMatchingAttributes(str.str());
}

/**
 * Get all artifacts associated with this file
 * @returns all artifacts
 */
vector<TskBlackboardAttribute> TskFile::getAllAttributes(){
    stringstream str;
    str << "WHERE obj_id = " << m_id;
    return TskServices::Instance().getBlackboard().getMatchingAttributes(str.str());
}

/**
 * Get the general info artifact for this file
 * @returns all matching artifacts
 */
TskBlackboardArtifact TskFile::getGenInfo(){
    TskBlackboard& blackboard = TskServices::Instance().getBlackboard();

    vector<TskBlackboardArtifact> artifacts;
    artifacts = getArtifacts(TSK_ART_GEN_INFO);

    if(artifacts.size() == 0)
        return createArtifact(TSK_ART_GEN_INFO);
    else
        return artifacts[0];
}

/**
 * Add an attribute to the general info artifact for this file
 * @param attr attribute to be added
 */
void TskFile::addGenInfoAttribute(TskBlackboardAttribute attr){
    getGenInfo().addAttribute(attr);
}
