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
 * \file TskFile.cpp
 * Contains the implementation for the TskFile class.
 */

// System includes
#include <sstream>

// Framework includes
#include "TskFile.h"
#include "tsk/framework/services/TskServices.h"

/**
 * Delete the TskFile object.
 */
TskFile::~TskFile(void)
{
}


void TskFile::initialize()
{
    TskImgDB * imgDB = &TskServices::Instance().getImgDB();
    // getDB will throw exception if ImgDB has not been setup

    if (imgDB != NULL) {
        if (imgDB->getFileRecord(m_id, m_fileRecord)) {
            throw TskException("TskFile::initialize: Error looking up file: " + m_id);
        }
    }
}

void TskFile::save()
{
    if (m_id == 0)
    {
        LOGERROR(L"TskFile::save - Attempt to save file with file id 0.");
        throw TskException("Attempt to save file with file id 0.");
    }

    // If the file already exists we have nothing to do.
    if (exists())
        return;

    // Make sure the file is open before saving.
    open();

    TskServices::Instance().getFileManager().saveFile(this);
}

/**
 * What is this files id?
 */
uint64_t TskFile::getId() const
{
    return m_id;
}

TskImgDB::FILE_TYPES TskFile::getTypeId() const
{
    return m_fileRecord.typeId;
}

/**
 * What is this files name?
 */
std::string TskFile::getName() const
{
    return m_fileRecord.name;
}

/**
 * What is this files extension?
 */
std::string TskFile::getExtension() const
{
    size_t pos = m_fileRecord.name.find_last_of(".");
    if (pos == std::string::npos)
        return std::string("");
    else
        return m_fileRecord.name.substr(pos + 1);
}

/**
 * What is this files parent file id?
 */
uint64_t TskFile::getParentFileId() const
{
    return m_fileRecord.parentFileId;
}

/**
 * What is this files directory type?
 */
TSK_FS_NAME_TYPE_ENUM TskFile::getDirType() const
{
    return m_fileRecord.dirType;
}
/**
 * What is this files metadata type?
 */
TSK_FS_META_TYPE_ENUM TskFile::getMetaType() const
{
    return m_fileRecord.metaType;
}

/**
 * What are this files directory flags?
 */
TSK_FS_NAME_FLAG_ENUM TskFile::getDirFlags() const
{
    return m_fileRecord.dirFlags;
}

/**
 * What are this files metadata flags?
 */
TSK_FS_META_FLAG_ENUM TskFile::getMetaFlags() const
{
    return m_fileRecord.metaFlags;
}

/**
 * What is this files size?
 */
TSK_OFF_T TskFile::getSize() const
{
    return m_fileRecord.size;
}

/**
 * What is this files change time?
 */
time_t TskFile::getCtime() const
{
    return m_fileRecord.ctime;
}

/**
 * What is this files creation time?
 */
time_t TskFile::getCrtime() const
{
    return m_fileRecord.crtime;
}

/**
 * What is this files access time?
 */
time_t TskFile::getAtime() const
{
    return m_fileRecord.atime;
}

/**
 * What is this files modify time?
 */
time_t TskFile::getMtime() const
{
    return m_fileRecord.mtime;
}

/**
 * What is this files mode?
 */
TSK_FS_META_MODE_ENUM TskFile::getMode() const
{
    return m_fileRecord.mode;
}

/**
 * What is this files user id?
 */
TSK_UID_T TskFile::getUid() const
{
    return m_fileRecord.uid;
}

/**
 * What is this files group id?
 */
TSK_GID_T TskFile::getGid() const
{
    return m_fileRecord.gid;
}

/**
 * What is this files status?
 */
TskImgDB::FILE_STATUS TskFile::getStatus() const
{
    return m_fileRecord.status;
}

/*
 * What is this files full path
 */
std::string TskFile::getFullPath() const
{
    return m_fileRecord.fullPath;
}

std::string TskFile::getUniquePath() const
{
    const uint64_t VOLUME_SHADOW_SNAPSHOT_FILE_PARENT_ID = 9223372036854775807;
    
    std::stringstream path;
    
    if (m_fileRecord.typeId == TskImgDB::IMGDB_FILES_TYPE_CARVED)
    {
        path << "/carved/" << m_fileRecord.fullPath;
    }
    else if (m_fileRecord.typeId == TskImgDB::IMGDB_FILES_TYPE_DERIVED)
    {
        if (m_fileRecord.parentFileId == VOLUME_SHADOW_SNAPSHOT_FILE_PARENT_ID)
        {
            // The full path will have an initial component of the form /Volume<N>_Snapshot<N> that
            // both makes the path unique and clearly indicates the source of the file. 
            path << m_fileRecord.fullPath;
        }
        else
        {
            uint64_t fileSystemSectorOffset = 0;
            uint64_t unusedUint = 0;
            int unusedInt = 0;

            // To determine the file system offset for a derived file we have to
            // find the top level parent it was derived from.
            // The top level parent may be a file system or carved file or we may
            // make it to the top of the hierarchy (e.g. for L01 or RAR input).
            TskFileRecord fileRecord = m_fileRecord;
            while (fileRecord.parentFileId != 0 && fileRecord.typeId == TskImgDB::IMGDB_FILES_TYPE_DERIVED)
            {
                TskServices::Instance().getImgDB().getFileRecord(fileRecord.parentFileId, fileRecord);
            }

            if (fileRecord.typeId == TskImgDB::IMGDB_FILES_TYPE_CARVED)
            {
                path << "/carved/" << m_fileRecord.fullPath;
            }
            else
            {
                TskServices::Instance().getImgDB().getFileUniqueIdentifiers(fileRecord.fileId, fileSystemSectorOffset, unusedUint, unusedInt, unusedInt);
                path << "/FsOffset-" << fileSystemSectorOffset << "/" << m_fileRecord.fullPath;
            }
        }
    }

    return path.str();
}

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

TskImgDB::KNOWN_STATUS TskFile::getKnownStatus() const
{
    return TskServices::Instance().getImgDB().getKnownStatus(getId());
}

void TskFile::setStatus(TskImgDB::FILE_STATUS status)
{
    m_fileRecord.status = status;
    TskServices::Instance().getImgDB().updateFileStatus(getId(), status);
}

/**
 * Create a new artifact with the given type id
 * @param artifactTypeID type id
 * @returns the new artifact
 * @throws error if the artifact type does not exist
 */
TskBlackboardArtifact TskFile::createArtifact(int artifactTypeID)
{
    return TskServices::Instance().getBlackboard().createArtifact(m_id, artifactTypeID);
}

/**
 * Create a new artifact with the given type
 * @param type artifact type
 * @returns the new artifact
 * @throws error if the artifact type does not exist
 */
TskBlackboardArtifact TskFile::createArtifact(TSK_ARTIFACT_TYPE type)
{
    return TskServices::Instance().getBlackboard().createArtifact(m_id, type);
}

/**
 * Create a new artifact with the given type name
 * @param artifactTypeName artifact type name
 * @returns the new artifact
 * @throws error if the artifact type does not exist
 */
TskBlackboardArtifact TskFile::createArtifact(string artifactTypeName)
{
    return TskServices::Instance().getBlackboard().createArtifact(m_id, artifactTypeName);
}

/**
 * Get all artifacts associated with this file with the given type name
 * @param artifactTypeName type name
 * @returns all matching artifacts will return an empty vector if there are no matches
 */
vector<TskBlackboardArtifact> TskFile::getArtifacts(string artifactTypeName)
{
    return TskServices::Instance().getBlackboard().getArtifacts(m_id, artifactTypeName);
}

/**
 * Get all artifacts associated with this file with the given type id
 * @param artifactTypeID type id
 * @returns all matching artifacts will return an empty vector if there are no matches
 */
vector<TskBlackboardArtifact> TskFile::getArtifacts(int artifactTypeID)
{
    return TskServices::Instance().getBlackboard().getArtifacts(m_id, artifactTypeID);
}

/**
 * Get all artifacts associated with this file with the given type
 * @param type artifact type
 * @returns all matching artifacts will return an empty vector if there are no matches
 */
vector<TskBlackboardArtifact> TskFile::getArtifacts(TSK_ARTIFACT_TYPE type)
{
    return TskServices::Instance().getBlackboard().getArtifacts(m_id, type);
}

/**
 * Get all artifacts associated with this file
 * @returns all artifacts
 */
vector<TskBlackboardArtifact> TskFile::getAllArtifacts()
{
    stringstream str;
    str << "WHERE obj_id = " << m_id;
    return TskServices::Instance().getBlackboard().getMatchingArtifacts(str.str());
}

/**
 * Get the general info artifact for this file
 * @returns the general info artifact or creates it if it has not already been made
 */
TskBlackboardArtifact TskFile::getGenInfo()
{
    vector<TskBlackboardArtifact> artifacts;
    artifacts = getArtifacts(TSK_GEN_INFO);

    if(artifacts.size() == 0)
        return createArtifact(TSK_GEN_INFO);
    else
        return artifacts[0];
}

/**
 * Add an attribute to the general info artifact for this file
 * @param attr attribute to be added
 */
void TskFile::addGenInfoAttribute(TskBlackboardAttribute attr)
{
    getGenInfo().addAttribute(attr);
}
