/*
 ** The Sleuth Kit
 **
 ** Brian Carrier [carrier <at> sleuthkit [dot] org]
 ** Copyright (c) 2020 Brian Carrier.  All Rights reserved
 **
 ** This software is distributed under the Common Public License 1.0
 **
 */

/**
 * \file auto_db_java.cpp
 * Contains code to populate database with volume and file system information from a specific image.
 */

#include "auto_db_java.h"
#include "jni.h"
#include "tsk/img/img_writer.h"
#if HAVE_LIBEWF
#include "tsk/img/ewf.h"
#include "tsk/img/tsk_img_i.h"
#endif
#include <string.h>

#include <algorithm>
#include <sstream>

using std::stringstream;
using std::for_each;

/**
 */
TskAutoDbJava::TskAutoDbJava()
{
    m_curImgId = 0;
    m_curVsId = 0;
    m_curVolId = 0;
    m_curFsId = 0;
    m_curFileId = 0;
    m_curUnallocDirId = 0;
    m_curDirAddr = 0;
    m_curDirPath = "";
    m_vsFound = false;
    m_volFound = false;
    m_poolFound = false;
    m_stopped = false;
    m_foundStructure = false;
    m_attributeAdded = false;
    m_addFileSystems = true;
    m_noFatFsOrphans = false;
    m_addUnallocSpace = false;
    m_minChunkSize = -1;
    m_maxChunkSize = -1;

    m_jniEnv = NULL;

    tsk_init_lock(&m_curDirPathLock);
}

TskAutoDbJava::~TskAutoDbJava()
{
    closeImage();
    tsk_deinit_lock(&m_curDirPathLock);
}

TSK_RETVAL_ENUM
TskAutoDbJava::initializeJni(JNIEnv * jniEnv, jobject jobj) {
    m_jniEnv = jniEnv;
    m_javaDbObj = m_jniEnv->NewGlobalRef(jobj); // TODO free this

    printf("\n#### initializeJni\n");
    fflush(stdout);

    jclass localCallbackClass = m_jniEnv->FindClass("org/sleuthkit/datamodel/JniDbHelper");
    if (localCallbackClass == NULL) {
        return TSK_ERR;
    }
    m_callbackClass = (jclass)m_jniEnv->NewGlobalRef(localCallbackClass);

    m_addImageMethodID = m_jniEnv->GetMethodID(m_callbackClass, "addImageInfo", "(IJLjava/lang/String;JLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)J");
    if (m_addImageMethodID == NULL) {
        printf("#### Error loading m_addImageMethodID\n");
        fflush(stdout);
        return TSK_ERR;
    }

    m_addImageNameMethodID = m_jniEnv->GetMethodID(m_callbackClass, "addImageName", "(JLjava/lang/String;J)I");
    if (m_addImageNameMethodID == NULL) {
        printf("#### Error loading m_addImageNameMethodID\n");
        fflush(stdout);
        return TSK_ERR;
    }

    m_addVolumeSystemMethodID = m_jniEnv->GetMethodID(m_callbackClass, "addVsInfo", "(JIJJ)J");
    if (m_addVolumeSystemMethodID == NULL) {
        printf("#### Error loading m_addVolumeSystemMethodID\n");
        fflush(stdout);
        return TSK_ERR;
    }

    m_addVolumeMethodID = m_jniEnv->GetMethodID(m_callbackClass, "addVolume", "(JJJJLjava/lang/String;J)J");
    if (m_addVolumeMethodID == NULL) {
        printf("#### Error loading m_addVolumeMethodID\n");
        fflush(stdout);
        return TSK_ERR;
    }

    m_addPoolMethodID = m_jniEnv->GetMethodID(m_callbackClass, "addPool", "(JI)J");
    if (m_addPoolMethodID == NULL) {
        printf("#### Error loading m_addPoolMethodID\n");
        fflush(stdout);
        return TSK_ERR;
    }


    m_addFileSystemMethodID = m_jniEnv->GetMethodID(m_callbackClass, "addFileSystem", "(JJIJJJJJ)J");
    if (m_addFileSystemMethodID == NULL) {
        printf("#### Error loading m_addFileSystemMethodID\n");
        fflush(stdout);
        return TSK_ERR;
    }

    m_addFileMethodID = m_jniEnv->GetMethodID(m_callbackClass, "addFile", "(JJJIIILjava/lang/String;JJIIIIJJJJJIIILjava/lang/String;Ljava/lang/String;)J");
    if (m_addFileMethodID == NULL) {
        printf("#### Error loading m_addFileMethodID\n");
        fflush(stdout);
        return TSK_ERR;
    }

    printf("\n#### Yay found method IDs!\n");
    fflush(stdout);
    return TSK_OK;
}

////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////




TSK_RETVAL_ENUM
TskAutoDbJava::addImageInfo(int type, TSK_OFF_T ssize, int64_t & objId, const string & timezone, TSK_OFF_T size, const string &md5,
    const string& sha1, const string& sha256, const string& deviceId, const string& collectionDetails) {

    printf("addImageInfo - preparing all the jstrings\n");
    fflush(stdout);

    const char *tz_cstr = timezone.c_str();
    jstring tzj = m_jniEnv->NewStringUTF(tz_cstr);

    const char *md5_cstr = md5.c_str();
    jstring md5j = m_jniEnv->NewStringUTF(md5_cstr);

    const char *sha1_cstr = sha1.c_str();
    jstring sha1j = m_jniEnv->NewStringUTF(sha1_cstr);

    const char *sha256_cstr = sha256.c_str();
    jstring sha256j = m_jniEnv->NewStringUTF(sha256_cstr);

    const char *devId_cstr = deviceId.c_str();
    jstring devIdj = m_jniEnv->NewStringUTF(devId_cstr);

    const char *coll_cstr = collectionDetails.c_str();
    jstring collj = m_jniEnv->NewStringUTF(coll_cstr);
    // TODO TODO free strings?

    printf("addImageInfo - making JNI call\n");
    fflush(stdout);

    if (m_addImageMethodID == NULL) {
        printf("#### Yikes addImageMethodID is null...\n");
        return TSK_ERR;
    }

    jlong objIdj = m_jniEnv->CallLongMethod(m_javaDbObj, m_addImageMethodID,
        type, ssize, tzj, size, md5j, sha1j, sha256j, devIdj, collj);
    objId = (int64_t)objIdj;
    printf("#### New image object ID: %lld\n", objId);
    fflush(stdout);

    if (objId < 0) {
        return TSK_ERR;
    }
    return TSK_OK;
}

TSK_RETVAL_ENUM
TskAutoDbJava::addImageName(int64_t objId, char const* imgName, int sequence) {
    printf("addImageName\n");

    if (m_addImageNameMethodID == NULL) {
        printf("#### Yikes m_addImageNameMethodID is null...\n");
        return TSK_ERR;
    }

    jstring imgNamej = m_jniEnv->NewStringUTF(imgName);

    jint res = m_jniEnv->CallIntMethod(m_javaDbObj, m_addImageNameMethodID,
        objId, imgNamej, (int64_t)sequence);

    if (res == 0) {
        return TSK_OK;
    }
    else {
        printf("Error in addImageName...\n");
        fflush(stdout);
        return TSK_ERR;
    }
}

TSK_RETVAL_ENUM
TskAutoDbJava::addVsInfo(const TSK_VS_INFO* vs_info, int64_t parObjId, int64_t& objId) {
    printf("addVsInfo\n");


    printf("addVsInfo - making JNI call\n");
    fflush(stdout);

    if (m_addVolumeSystemMethodID == NULL) {
        printf("#### Yikes m_addVolumeSystemMethodID is null...\n");
        return TSK_ERR;
    }

    jlong objIdj = m_jniEnv->CallLongMethod(m_javaDbObj, m_addVolumeSystemMethodID,
        parObjId, vs_info->vstype, vs_info->offset, (uint64_t)vs_info->block_size);
    objId = (int64_t)objIdj;
    printf("#### New volume system object ID: %lld\n", objId);
    fflush(stdout);

    if (objId < 0) {
        return TSK_ERR;
    }
    return TSK_OK;
}

TSK_RETVAL_ENUM
TskAutoDbJava::addPoolInfoAndVS(const TSK_POOL_INFO *pool_info, int64_t parObjId, int64_t& objId) {
    if (m_addPoolMethodID == NULL) {
        printf("#### Yikes m_addPoolMethodID is null...\n");
        return TSK_ERR;
    }

    jlong poolObjIdj = m_jniEnv->CallLongMethod(m_javaDbObj, m_addPoolMethodID,
        parObjId, pool_info->ctype);
    long poolObjId = (int64_t)poolObjIdj;
    printf("New pool object ID: %lld\n", objId);
    fflush(stdout);

    if (poolObjId < 0) {
        return TSK_ERR;
    }

    // "INSERT INTO tsk_vs_info (obj_id, vs_type, img_offset, block_size) VALUES (%" PRId64 ", %d,%" PRIuDADDR ",%d)", 
    // objId, TSK_VS_TYPE_APFS, pool_info->img_offset, pool_info->block_size); // TODO - offset
    if (m_addVolumeSystemMethodID == NULL) {
        printf("#### Yikes m_addVolumeSystemMethodID is null...\n");
        return TSK_ERR;
    }

    jlong objIdj = m_jniEnv->CallLongMethod(m_javaDbObj, m_addVolumeSystemMethodID,
        poolObjIdj, TSK_VS_TYPE_APFS, pool_info->img_offset, (uint64_t)pool_info->block_size);
    objId = (int64_t)objIdj;
    printf("New pool volume system object ID: %lld\n", objId);
    fflush(stdout);

    return TSK_OK;
}

TSK_RETVAL_ENUM
TskAutoDbJava::addPoolVolumeInfo(const TSK_POOL_VOLUME_INFO* pool_vol,
    int64_t parObjId, int64_t& objId) {
    printf("addPoolVolumeInfo\n");

    //objId, (int)pool_vol->index, pool_vol->block, pool_vol->num_blocks,
    //    pool_vol->desc, pool_vol->flags);
    if (m_addVolumeMethodID == NULL) {
        printf("#### Yikes m_addVolumeMethodID is null...\n");
        return TSK_ERR;
    }

    jstring descj = m_jniEnv->NewStringUTF(pool_vol->desc); // TODO free?

    jlong objIdj = m_jniEnv->CallLongMethod(m_javaDbObj, m_addVolumeMethodID,
        parObjId, (int64_t)pool_vol->index, pool_vol->block, pool_vol->num_blocks,
        descj, pool_vol->flags);
    objId = (int64_t)objIdj;
    printf("New volume object ID: %lld\n", objId);
    fflush(stdout);

    if (objId < 0) {
        return TSK_ERR;
    }
    return TSK_OK;
}


TSK_RETVAL_ENUM
TskAutoDbJava::addVolumeInfo(const TSK_VS_PART_INFO* vs_part,
    int64_t parObjId, int64_t& objId) {
    printf("addVolumeInfo\n");

    if (m_addVolumeMethodID == NULL) {
        printf("#### Yikes m_addVolumeMethodID is null...\n");
        return TSK_ERR;
    }

    jstring descj = m_jniEnv->NewStringUTF(vs_part->desc); // TODO free?

    jlong objIdj = m_jniEnv->CallLongMethod(m_javaDbObj, m_addVolumeMethodID,
        parObjId, (uint64_t)vs_part->addr, vs_part->start, vs_part->len,
        descj, vs_part->flags);
    objId = (int64_t)objIdj;
    printf("New volume object ID: %lld\n", objId);
    fflush(stdout);

    if (objId < 0) {
        return TSK_ERR;
    }
    return TSK_OK;
}

TSK_RETVAL_ENUM
TskAutoDbJava::addFsInfo(const TSK_FS_INFO* fs_info, int64_t parObjId,
    int64_t& objId) {
    printf("addFsInfo\n");

    if (m_addFileSystemMethodID == NULL) {
        printf("#### Yikes m_addFileSystemMethodID is null...\n");
        return TSK_ERR;
    }

    jlong objIdj = m_jniEnv->CallLongMethod(m_javaDbObj, m_addFileSystemMethodID,
        parObjId, fs_info->offset, (int)fs_info->ftype, (uint64_t)fs_info->block_size,
        fs_info->block_count, fs_info->root_inum, fs_info->first_inum,
        fs_info->last_inum);
    objId = (int64_t)objIdj;
    printf("#### New file system object ID: %lld\n", objId);
    fflush(stdout);

    if (objId < 0) {
        return TSK_ERR;
    }

    return TSK_OK;
}

TSK_RETVAL_ENUM
TskAutoDbJava::addFsFile(TSK_FS_FILE* fs_file,
    const TSK_FS_ATTR* fs_attr, const char* path,
    const unsigned char*const md5, const TSK_DB_FILES_KNOWN_ENUM known,
    int64_t fsObjId, int64_t& objId, int64_t dataSourceObjId) {

    printf("addFsFile\n");

    int64_t parObjId = 0;

    if (fs_file->name == NULL)
        return TSK_ERR;

    // Find the object id for the parent folder.

    /* Root directory's parent should be the file system object.
    * Make sure it doesn't have a name, so that we don't pick up ".." entries */
    if ((fs_file->fs_info->root_inum == fs_file->name->meta_addr) &&
        ((fs_file->name->name == NULL) || (strlen(fs_file->name->name) == 0)))
    {
        parObjId = fsObjId;
    }
    else
    {
        parObjId = findParObjId(fs_file, path, fsObjId);
        if (parObjId == -1)
        {
            //error
            return TSK_ERR;
        }
    }


    return addFile(fs_file, fs_attr, path, md5, known, fsObjId, parObjId, objId, dataSourceObjId);
}

/**
Extract the extension from the given file name and store it in the supplied string.

@param name A file name
@param extension The file name extension will be extracted to extension.
*/
void extractExtension(char *name, char *extension) {
    char *ext = strrchr(name, '.');

    //if ext is not null and is not the entire filename...
    if (ext && (name != ext)) {
        size_t extLen = strlen(ext);
        //... and doesn't only contain the '.' and isn't too long to be a real extension.
        if ((1 < extLen) && (extLen < 15)) {
            strncpy(extension, ext + 1, extLen - 1);
            //normalize to lower case, only works for ascii
            for (int i = 0; extension[i]; i++) {
                extension[i] = tolower(extension[i]);
            }
        }
    }
}

/**
* Store info about a directory in a complex map structure as a cache for the
* files who are a child of this directory and want to know its object id.
*
* @param fsObjId fs id of this directory
* @param fs_file File for the directory to store
* @param path Full path (parent and this file) of the directory
* @param objId object id of the directory
*/
void TskAutoDbJava::storeObjId(const int64_t& fsObjId, const TSK_FS_FILE* fs_file, const char* path, const int64_t& objId)
{
    // skip the . and .. entries
    if ((fs_file->name) && (fs_file->name->name) && (TSK_FS_ISDOT(fs_file->name->name)))
    {
        return;
    }

    uint32_t seq;
    uint32_t path_hash = hash((const unsigned char *)path);

    /* NTFS uses sequence, otherwise we hash the path. We do this to map to the
    * correct parent folder if there are two from the root dir that eventually point to
    * the same folder (one deleted and one allocated) or two hard links. */
    if (TSK_FS_TYPE_ISNTFS(fs_file->fs_info->ftype))
    {
        /* Use the sequence stored in meta (which could be one larger than the name value
        * if the directory is deleted. We do this because the par_seq gets added to the
        * name structure when it is added to the directory based on teh value stored in
        * meta. */
        seq = fs_file->meta->seq;
    }
    else
    {
        seq = path_hash;
    }

    map<TSK_INUM_T, map<uint32_t, map<uint32_t, int64_t> > >& fsMap = m_parentDirIdCache[fsObjId];
    if (fsMap.count(fs_file->name->meta_addr) == 0)
    {
        fsMap[fs_file->name->meta_addr][seq][path_hash] = objId;
    }
    else
    {
        map<uint32_t, map<uint32_t, int64_t> >& fileMap = fsMap[fs_file->name->meta_addr];
        if (fileMap.count(seq) == 0)
        {
            fileMap[seq][path_hash] = objId;
        }
    }
}


/**
* Add file data to the file table
* @param md5 binary value of MD5 (i.e. 16 bytes) or NULL
* @param dataSourceObjId The object ID for the data source
* Return 0 on success, 1 on error.
*/
TSK_RETVAL_ENUM
TskAutoDbJava::addFile(TSK_FS_FILE* fs_file,
    const TSK_FS_ATTR* fs_attr, const char* path,
    const unsigned char*const md5, const TSK_DB_FILES_KNOWN_ENUM known,
    int64_t fsObjId, int64_t parObjId,
    int64_t& objId, int64_t dataSourceObjId)
{
    time_t mtime = 0;
    time_t crtime = 0;
    time_t ctime = 0;
    time_t atime = 0;
    TSK_OFF_T size = 0;
    int meta_type = 0;
    int meta_flags = 0;
    int meta_mode = 0;
    int gid = 0;
    int uid = 0;
    int type = TSK_FS_ATTR_TYPE_NOT_FOUND;
    int idx = 0;
    char* zSQL;

    if (fs_file->name == NULL)
        return TSK_OK;

    if (fs_file->meta)
    {
        mtime = fs_file->meta->mtime;
        atime = fs_file->meta->atime;
        ctime = fs_file->meta->ctime;
        crtime = fs_file->meta->crtime;
        meta_type = fs_file->meta->type;
        meta_flags = fs_file->meta->flags;
        meta_mode = fs_file->meta->mode;
        gid = fs_file->meta->gid;
        uid = fs_file->meta->uid;
    }

    size_t attr_nlen = 0;
    if (fs_attr)
    {
        type = fs_attr->type;
        idx = fs_attr->id;
        size = fs_attr->size;
        if (fs_attr->name)
        {
            if ((fs_attr->type != TSK_FS_ATTR_TYPE_NTFS_IDXROOT) ||
                (strcmp(fs_attr->name, "$I30") != 0))
            {
                attr_nlen = strlen(fs_attr->name);
            }
        }
    }

    // sanity check
    if (size < 0) {
        size = 0;
    }

    // combine name and attribute name
    size_t len = strlen(fs_file->name->name);
    char * name;
    size_t nlen = len + attr_nlen + 11; // Extra space for possible colon and '-slack'
    if ((name = (char *)tsk_malloc(nlen)) == NULL) {
        return TSK_ERR;
    }

    strncpy(name, fs_file->name->name, nlen);

    char extension[24] = "";
    extractExtension(name, extension);

    // Add the attribute name
    if (attr_nlen > 0)
    {
        strncat(name, ":", nlen - strlen(name));
        strncat(name, fs_attr->name, nlen - strlen(name));
    }

    // clean up path
    // +2 = space for leading slash and terminating null
    size_t path_len = strlen(path) + 2;
    char* escaped_path;
    if ((escaped_path = (char *)tsk_malloc(path_len)) == NULL)
    {
        free(name);
        return TSK_ERR;
    }

    strncpy(escaped_path, "/", path_len);
    strncat(escaped_path, path, path_len - strlen(escaped_path));

    printf("#### Finally adding file\n");
    fflush(stdout);
    if (m_addFileMethodID == NULL) {
        printf("#### Yikes m_addFileMethodID is null...\n");
        return TSK_ERR;
    }

    jstring namej = m_jniEnv->NewStringUTF(name); // TODO free?
    jstring pathj = m_jniEnv->NewStringUTF(escaped_path); // TODO free?
    jstring extj = m_jniEnv->NewStringUTF(extension); // TODO free?
 

    // "INSERT INTO tsk_files (fs_obj_id, obj_id, data_source_obj_id, 
    // type, attr_type, attr_id, name, 
    // meta_addr, meta_seq, dir_type, meta_type, dir_flags, meta_flags, 
    // size, crtime, ctime, atime, mtime, mode, gid, uid, md5, known, parent_path, extension) "
    jlong objIdj = m_jniEnv->CallLongMethod(m_javaDbObj, m_addFileMethodID,
        parObjId, fsObjId,
        dataSourceObjId,
        TSK_DB_FILES_TYPE_FS,
        type, idx, namej,
        fs_file->name->meta_addr, (uint64_t)fs_file->name->meta_seq,
        fs_file->name->type, meta_type, fs_file->name->flags, meta_flags,
        size,
        (unsigned long long)crtime, (unsigned long long)ctime, (unsigned long long) atime, (unsigned long long) mtime,
        meta_mode, gid, uid, // md5TextPtr, known,
        pathj, extj);
    objId = (int64_t)objIdj;

    if (objId < 0) {
        return TSK_ERR;
    }

    /*
    zSQL = sqlite3_mprintf(
        "INSERT INTO tsk_files (fs_obj_id, obj_id, data_source_obj_id, type, attr_type, attr_id, name, meta_addr, meta_seq, dir_type, meta_type, dir_flags, meta_flags, size, crtime, ctime, atime, mtime, mode, gid, uid, md5, known, parent_path, extension) "
        "VALUES ("
        "%" PRId64 ",%" PRId64 ","
        "%" PRId64 ","
        "%d,"
        "%d,%d,'%q',"
        "%" PRIuINUM ",%d,"
        "%d,%d,%d,%d,"
        "%" PRId64 ","
        "%llu,%llu,%llu,%llu,"
        "%d,%d,%d,%Q,%d,"
        "'%q','%q')",
        fsObjId, objId, // done
        dataSourceObjId, // done
        TSK_DB_FILES_TYPE_FS, // dont' need type
        type, idx, name, // attrType, attrId, name   done
        fs_file->name->meta_addr, fs_file->name->meta_seq, // done
        fs_file->name->type, meta_type, fs_file->name->flags, meta_flags, // used meta_flags
        size,  // done
        (unsigned long long)crtime, (unsigned long long)ctime, (unsigned long long) atime, (unsigned long long) mtime,
        meta_mode, gid, uid, md5TextPtr, known,
        escaped_path, extension);
        */


/*
if (!TSK_FS_ISDOT(name))
    {
        std::string full_description = std::string(escaped_path).append(name);

        // map from time to event type ids
        const std::map<int64_t, time_t> timeMap = {
            { 4, mtime },
            { 5, atime },
            { 6, crtime },
            { 7, ctime }
        };

        //insert MAC time events for the file
        if (addMACTimeEvents(dataSourceObjId, objId, timeMap, full_description.c_str()))
        {
            free(name);
            free(escaped_path);
            sqlite3_free(zSQL);
            return 1;
        };
    }*/

    //if dir, update parent id cache (do this before objId may be changed creating the slack file)
    if (TSK_FS_IS_DIR_META(meta_type))
    {
        std::string fullPath = std::string(path) + fs_file->name->name;
        storeObjId(fsObjId, fs_file, fullPath.c_str(), objId);
    }

    /*
    // Add entry for the slack space.
    // Current conditions for creating a slack file:
    //   - File name is not empty, "." or ".."
    //   - Data is non-resident
    //   - The allocated size is greater than the initialized file size
    //     See github issue #756 on why initsize and not size.
    //   - The data is not compressed
    if ((fs_attr != NULL)
        && ((strlen(name) > 0) && (!TSK_FS_ISDOT(name)))
        && (!(fs_file->meta->flags & TSK_FS_META_FLAG_COMP))
        && (fs_attr->flags & TSK_FS_ATTR_NONRES)
        && (fs_attr->nrd.allocsize > fs_attr->nrd.initsize)) {
        strncat(name, "-slack", 6);
        if (strlen(extension) > 0) {
            strncat(extension, "-slack", 6);
        }
        TSK_OFF_T slackSize = fs_attr->nrd.allocsize - fs_attr->nrd.initsize;

        if (addObject(TSK_DB_OBJECT_TYPE_FILE, parObjId, objId)) {
            free(name);
            free(escaped_path);
            return 1;
        }

        // Run the same insert with the new name, size, and type
        zSQL = sqlite3_mprintf(
            "INSERT INTO tsk_files (fs_obj_id, obj_id, data_source_obj_id, type, attr_type, attr_id, name, meta_addr, meta_seq, dir_type, meta_type, dir_flags, meta_flags, size, crtime, ctime, atime, mtime, mode, gid, uid, md5, known, parent_path,extension) "
            "VALUES ("
            "%" PRId64 ",%" PRId64 ","
            "%" PRId64 ","
            "%d,"
            "%d,%d,'%q',"
            "%" PRIuINUM ",%d,"
            "%d,%d,%d,%d,"
            "%" PRId64 ","
            "%llu,%llu,%llu,%llu,"
            "%d,%d,%d,NULL,%d,"
            "'%q','%q')",
            fsObjId, objId,
            dataSourceObjId,
            TSK_DB_FILES_TYPE_SLACK,
            type, idx, name,
            fs_file->name->meta_addr, fs_file->name->meta_seq,
            TSK_FS_NAME_TYPE_REG, TSK_FS_META_TYPE_REG, fs_file->name->flags, meta_flags,
            slackSize,
            (unsigned long long)crtime, (unsigned long long)ctime, (unsigned long long) atime, (unsigned long long) mtime,
            meta_mode, gid, uid, known,
            escaped_path, extension);

        if (attempt_exec(zSQL, "TskDbSqlite::addFile: Error adding data to tsk_files table: %s\n")) {
            free(name);
            free(escaped_path);
            sqlite3_free(zSQL);
            return 1;
        }
    }

    sqlite3_free(zSQL);*/

    free(name);
    free(escaped_path);

    return TSK_OK;
}

TSK_RETVAL_ENUM
addFileWithLayoutRange(const TSK_DB_FILES_TYPE_ENUM dbFileType, const int64_t parentObjId,
    const int64_t fsObjId, const uint64_t size,
    vector<TSK_DB_FILE_LAYOUT_RANGE>& ranges, int64_t& objId,
    int64_t dataSourceObjId) {
    printf("addFileWithLayoutRange\n");
    return TSK_OK;
}

TSK_RETVAL_ENUM
addUnallocBlockFile(const int64_t parentObjId, const int64_t fsObjId, const uint64_t size,
    vector<TSK_DB_FILE_LAYOUT_RANGE>& ranges, int64_t& objId,
    int64_t dataSourceObjId) {
    printf("addUnallocBlockFile\n");
    return addFileWithLayoutRange(TSK_DB_FILES_TYPE_UNALLOC_BLOCKS, parentObjId, fsObjId, size, ranges, objId,
        dataSourceObjId);
}

TSK_RETVAL_ENUM
addUnusedBlockFile(const int64_t parentObjId, const int64_t fsObjId, const uint64_t size,
    vector<TSK_DB_FILE_LAYOUT_RANGE>& ranges, int64_t& objId,
    int64_t dataSourceObjId) {
    printf("addUnusedBlockFile\n");
    return addFileWithLayoutRange(TSK_DB_FILES_TYPE_UNUSED_BLOCKS, parentObjId, fsObjId, size, ranges, objId,
        dataSourceObjId);
}



TSK_RETVAL_ENUM
TskAutoDbJava::addUnallocFsBlockFilesParent(const int64_t fsObjId, int64_t& objId,
    int64_t dataSourceObjId) {
    printf("addUnallocFsBlockfilesParent\n");
    return TSK_OK;
}

/**
* return a hash of the passed in string. We use this
* for full paths.
* From: http://www.cse.yorku.ca/~oz/hash.html
*/
uint32_t 
TskAutoDbJava::hash(const unsigned char* str)
{
    uint32_t hash = 5381;
    int c;

    while ((c = *str++))
    {
        // skip slashes -> normalizes leading/ending/double slashes
        if (c == '/')
            continue;
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }

    return hash;
}

/*
* Utility method to break up path into parent folder and folder/file name.
* @param path Path of folder that we want to analyze
* @param ret_parent_path pointer to parent path (begins and ends with '/')
* @param ret_name pointer to final folder/file name
* @returns 0 on success, 1 on error
*/
bool 
TskAutoDbJava::getParentPathAndName(const char *path, const char **ret_parent_path, const char **ret_name) {
    // Need to break up 'path' in to the parent folder to match in 'parent_path' and the folder 
    // name to match with the 'name' column in tsk_files table

    // reset all arrays
    parent_name[0] = '\0';
    parent_path[0] = '\0';

    size_t path_len = strlen(path);
    if (path_len >= MAX_PATH_LENGTH_JAVA_DB_LOOKUP) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr("TskDb::getParentPathAndName: Path is too long. Length = %zd, Max length = %d", path_len, MAX_PATH_LENGTH_JAVA_DB_LOOKUP);
        // assign return values to pointers
        *ret_parent_path = "";
        *ret_name = "";
        return 1;
    }

    // check if empty path or just "/" were passed in
    if (path_len == 0 || (strcmp(path, "/") == 0)) {
        *ret_name = "";
        *ret_parent_path = "/";
        return 0;
    }


    // step 1, copy everything into parent_path and clean it up
    // add leading slash if its not in input.  
    if (path[0] != '/') {
        sprintf(parent_path, "%s", "/");
    }

    strncat(parent_path, path, MAX_PATH_LENGTH_JAVA_DB_LOOKUP);

    // remove trailing slash
    if (parent_path[strlen(parent_path) - 1] == '/') {
        parent_path[strlen(parent_path) - 1] = '\0';
    }

    // replace all non-UTF8 characters
    tsk_cleanupUTF8(parent_path, '^');

    // Step 2, move the final folder/file to parent_file

    // Find the last '/' 
    char *chptr = strrchr(parent_path, '/');
    if (chptr) {
        // character found in the string
        size_t position = chptr - parent_path;

        sprintf(parent_name, "%s", chptr + 1);  // copy everything after slash into parent_name
        *ret_name = parent_name;

        parent_path[position + 1] = '\0';   // add terminating null after last "/"
        *ret_parent_path = parent_path;
    }
    else {
        // "/" character not found. the entire path is parent file name. parent path is "/"
        *ret_name = parent_path;
        *ret_parent_path = "/";
    }
    return 0;
}


/**
* Find parent object id of TSK_FS_FILE. Use local cache map, if not found, fall back to SQL
* @param fs_file file to find parent obj id for
* @param parentPath Path of parent folder that we want to match
* @param fsObjId fs id of this file
* @returns parent obj id ( > 0), -1 on error
*/
int64_t 
TskAutoDbJava::findParObjId(const TSK_FS_FILE* fs_file, const char* parentPath, const int64_t& fsObjId)
{
    uint32_t seq;
    uint32_t path_hash = hash((const unsigned char *)parentPath);

    /* NTFS uses sequence, otherwise we hash the path. We do this to map to the
    * correct parent folder if there are two from the root dir that eventually point to
    * the same folder (one deleted and one allocated) or two hard links. */
    if (TSK_FS_TYPE_ISNTFS(fs_file->fs_info->ftype))
    {
        seq = fs_file->name->par_seq;
    }
    else
    {
        seq = path_hash;
    }

    //get from cache by parent meta addr, if available
    map<TSK_INUM_T, map<uint32_t, map<uint32_t, int64_t> > >& fsMap = m_parentDirIdCache[fsObjId];
    if (fsMap.count(fs_file->name->par_addr) > 0)
    {
        map<uint32_t, map<uint32_t, int64_t> >& fileMap = fsMap[fs_file->name->par_addr];
        if (fileMap.count(seq) > 0)
        {
            map<uint32_t, int64_t>& pathMap = fileMap[seq];
            if (pathMap.count(path_hash) > 0)
            {
                return pathMap[path_hash];
            }
        }
        else
        {
            printf("Miss: %zu\n", fileMap.count(seq));
            fflush(stdout);
        }
    }

    printf("Miss: %s (%" PRIu64  " - %" PRIu64 ")\n", fs_file->name->name, fs_file->name->meta_addr,
                   fs_file->name->par_addr);
    fflush(stdout);

    // Need to break up 'path' in to the parent folder to match in 'parent_path' and the folder 
    // name to match with the 'name' column in tsk_files table
    const char *parent_name = "";
    const char *parent_path = "";
    if (getParentPathAndName(parentPath, &parent_path, &parent_name))
    {
        return -1;
    }

    // TODO TODO DATABASE CALL
    printf("#### SKIPPING PAR OBJ ID DATABASE LOOKUP TODO \n");
    fflush(stdout);
    int64_t parObjId = 2;

    return parObjId;
}


////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////

void
 TskAutoDbJava::closeImage()
{
    TskAuto::closeImage();
}

void TskAutoDbJava::setAddFileSystems(bool addFileSystems)
{
    m_addFileSystems = addFileSystems;
}

void TskAutoDbJava::setNoFatFsOrphans(bool noFatFsOrphans)
{
    m_noFatFsOrphans = noFatFsOrphans;
}

void TskAutoDbJava::setAddUnallocSpace(bool addUnallocSpace)
{
    setAddUnallocSpace(addUnallocSpace, -1);
}

void TskAutoDbJava::setAddUnallocSpace(bool addUnallocSpace, int64_t minChunkSize)
{
    m_addUnallocSpace = addUnallocSpace;
    m_minChunkSize = minChunkSize;
    m_maxChunkSize = -1;
}

void TskAutoDbJava::setAddUnallocSpace(int64_t minChunkSize, int64_t maxChunkSize)
{
    m_addUnallocSpace = true;
    m_minChunkSize = minChunkSize;
    m_maxChunkSize = maxChunkSize;
}

/**
 * Adds an image to the database.
 *
 * @param a_num Number of image parts
 * @param a_images Array of paths to the image parts
 * @param a_type Image type
 * @param a_ssize Size of device sector in bytes (or 0 for default)
 * @param a_deviceId An ASCII-printable identifier for the device associated with the data source that is intended to be unique across multiple cases (e.g., a UUID).
 * @return 0 for success, 1 for failure
 */
uint8_t
    TskAutoDbJava::openImageUtf8(int a_num, const char *const a_images[],
    TSK_IMG_TYPE_ENUM a_type, unsigned int a_ssize, const char* a_deviceId)
{
    uint8_t retval =
        TskAuto::openImageUtf8(a_num, a_images, a_type, a_ssize);
    if (retval != 0) {
        return retval;
    }

    if (addImageDetails(a_deviceId)) {
        return 1;
    }
    return 0;
}

/**
 * Adds an image to the database.
 *
 * @param a_num Number of image parts
 * @param a_images Array of paths to the image parts
 * @param a_type Image type
 * @param a_ssize Size of device sector in bytes (or 0 for default)
 * @param a_deviceId An ASCII-printable identifier for the device associated with the data source that is intended to be unique across multiple cases (e.g., a UUID).
 * @return 0 for success, 1 for failure
 */
uint8_t
    TskAutoDbJava::openImage(int a_num, const TSK_TCHAR * const a_images[],
    TSK_IMG_TYPE_ENUM a_type, unsigned int a_ssize, const char* a_deviceId)
{

#ifdef TSK_WIN32

    uint8_t retval = TskAuto::openImage(a_num, a_images, a_type, a_ssize);

    if (retval != 0) {
        return retval;
    }

    return (addImageDetails(a_deviceId));
#else
    return openImageUtf8(a_num, a_images, a_type, a_ssize, a_deviceId);
#endif
}

/**
* Adds an image to the database. Requires that m_img_info is already initialized
*
* @param a_deviceId An ASCII-printable identifier for the device associated with the data source that is intended to be unique across multiple cases (e.g., a UUID).
* @return 0 for success, 1 for failure
*/
uint8_t
TskAutoDbJava::openImage(const char* a_deviceId)
{
    if (m_img_info == NULL) {
        return 1;
    }

    return(addImageDetails(a_deviceId));
}

/**
 * Adds image details to the existing database tables.
 *
 * @param deviceId An ASCII-printable identifier for the device associated with the data source that is intended to be unique across multiple cases (e.g., a UUID).
 * @return Returns 0 for success, 1 for failure
 */
uint8_t
TskAutoDbJava::addImageDetails(const char* deviceId)
{
   string md5 = "";
   string sha1 = "";
   string collectionDetails = "";
#if HAVE_LIBEWF 
   if (m_img_info->itype == TSK_IMG_TYPE_EWF_EWF) {
     // @@@ This should really probably be inside of a tsk_img_ method
       IMG_EWF_INFO *ewf_info = (IMG_EWF_INFO *)m_img_info;
       if (ewf_info->md5hash_isset) {
           md5 = ewf_info->md5hash;
       }
       if (ewf_info->sha1hash_isset) {
           sha1 = ewf_info->sha1hash;
       }

       collectionDetails = ewf_get_details(ewf_info);   
   }
#endif

    string devId;
    if (NULL != deviceId) {
        devId = deviceId; 
    } else {
        devId = "";
    }
    if (TSK_OK != addImageInfo(m_img_info->itype, m_img_info->sector_size,
          m_curImgId, m_curImgTZone, m_img_info->size, md5, sha1, "", devId, collectionDetails)) {
        registerError();
        return 1;
    }



    char **img_ptrs;
#ifdef TSK_WIN32
    // convert image paths to UTF-8
    img_ptrs = (char **)tsk_malloc(m_img_info->num_img * sizeof(char *));
    if (img_ptrs == NULL) {
        return 1;
    }

    for (int i = 0; i < m_img_info->num_img; i++) {
        char * img2 = (char*)tsk_malloc(1024 * sizeof(char));
        UTF8 *ptr8;
        UTF16 *ptr16;

        ptr8 = (UTF8 *)img2;
        ptr16 = (UTF16 *)m_img_info->images[i];

        uint8_t retval =
            tsk_UTF16toUTF8_lclorder((const UTF16 **)&ptr16, (UTF16 *)
                & ptr16[TSTRLEN(m_img_info->images[i]) + 1], &ptr8,
                (UTF8 *)((uintptr_t)ptr8 + 1024), TSKlenientConversion);
        if (retval != TSKconversionOK) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_AUTO_UNICODE);
            tsk_error_set_errstr("Error converting image to UTF-8\n");
            return 1;
        }
        img_ptrs[i] = img2;
    }
#else 
    img_ptrs = m_img_info->images;
#endif

    // Add the image names
    for (int i = 0; i < m_img_info->num_img; i++) {
        const char *img_ptr = img_ptrs[i];

        if (TSK_OK != addImageName(m_curImgId, img_ptr, i)) {
            registerError();
            return 1;
        }
    }

#ifdef TSK_WIN32
    //cleanup
    for (int i = 0; i < m_img_info->num_img; ++i) {
        free(img_ptrs[i]);
    }
    free(img_ptrs);
#endif

    return 0;
}


TSK_FILTER_ENUM TskAutoDbJava::filterVs(const TSK_VS_INFO * vs_info)
{
    m_vsFound = true;
    if (TSK_OK != addVsInfo(vs_info, m_curImgId, m_curVsId)) {
        registerError();
        return TSK_FILTER_STOP;
    }

    return TSK_FILTER_CONT;
}

TSK_FILTER_ENUM
TskAutoDbJava::filterPool(const TSK_POOL_INFO * pool_info)
{
    m_poolFound = true;

    if (m_volFound && m_vsFound) {
        // there's a volume system and volume
        if (TSK_OK != addPoolInfoAndVS(pool_info, m_curVolId, m_curPoolVs)) {
            registerError();
            return TSK_FILTER_STOP;
        }
    }
    else {
        // pool doesn't live in a volume, use image as parent
        if (TSK_OK != addPoolInfoAndVS(pool_info, m_curImgId, m_curPoolVs)) {
            registerError();
            return TSK_FILTER_STOP;
        }
    }

    

    return TSK_FILTER_CONT;
}

TSK_FILTER_ENUM
TskAutoDbJava::filterPoolVol(const TSK_POOL_VOLUME_INFO * pool_vol)
{

    if (TSK_OK != addPoolVolumeInfo(pool_vol, m_curPoolVs, m_curPoolVol)) {
        registerError();
        return TSK_FILTER_STOP;
    }

    return TSK_FILTER_CONT;
}

TSK_FILTER_ENUM
TskAutoDbJava::filterVol(const TSK_VS_PART_INFO * vs_part)
{
    m_volFound = true;
    m_foundStructure = true;
    m_poolFound = false;

    if (TSK_OK != addVolumeInfo(vs_part, m_curVsId, m_curVolId)) {
        registerError();
        return TSK_FILTER_STOP;
    }

    return TSK_FILTER_CONT;
}


TSK_FILTER_ENUM
TskAutoDbJava::filterFs(TSK_FS_INFO * fs_info)
{
    TSK_FS_FILE *file_root;
    m_foundStructure = true;

    if (m_poolFound) {
        // there's a pool
        if (TSK_OK != addFsInfo(fs_info, m_curPoolVol, m_curFsId)) {
            registerError();
            return TSK_FILTER_STOP;
        }
    }
    else if (m_volFound && m_vsFound) {
        // there's a volume system and volume
        if (TSK_OK != addFsInfo(fs_info, m_curVolId, m_curFsId)) {
            registerError();
            return TSK_FILTER_STOP;
        }
    }
    else {
        // file system doesn't live in a volume, use image as parent
        if (TSK_OK != addFsInfo(fs_info, m_curImgId, m_curFsId)) {
            registerError();
            return TSK_FILTER_STOP;
        }
    }


    // We won't hit the root directory on the walk, so open it now 
    if ((file_root = tsk_fs_file_open(fs_info, NULL, "/")) != NULL) {
        processFile(file_root, "");
        tsk_fs_file_close(file_root);
        file_root = NULL;
    }


    // make sure that flags are set to get all files -- we need this to
    // find parent directory
     
    TSK_FS_DIR_WALK_FLAG_ENUM filterFlags = (TSK_FS_DIR_WALK_FLAG_ENUM)
        (TSK_FS_DIR_WALK_FLAG_ALLOC | TSK_FS_DIR_WALK_FLAG_UNALLOC);

    //check if to skip processing of FAT orphans
    if (m_noFatFsOrphans 
        && TSK_FS_TYPE_ISFAT(fs_info->ftype) ) {
            filterFlags = (TSK_FS_DIR_WALK_FLAG_ENUM) (filterFlags | TSK_FS_DIR_WALK_FLAG_NOORPHAN);
    }

    setFileFilterFlags(filterFlags);

    return TSK_FILTER_CONT;
}

/* Insert the file data into the file table.
 * @param md5 Binary MD5 value (i.e. 16 bytes) or NULL
 * Returns TSK_ERR on error.
 */
TSK_RETVAL_ENUM
    TskAutoDbJava::insertFileData(TSK_FS_FILE * fs_file,
    const TSK_FS_ATTR * fs_attr, const char *path)
{
    printf("### insertFileData\n");
    fflush(stdout);

    if (-1 == addFsFile(fs_file, fs_attr, path, NULL, TSK_DB_FILES_KNOWN_UNKNOWN, m_curFsId, m_curFileId,
            m_curImgId)) {
        registerError();
        return TSK_ERR;
    }

    return TSK_OK;
}

/**
 * Analyzes the open image and adds image info to a database.
 * Does not deal with transactions and such.  Refer to startAddImage()
 * for more control. 
 * @returns 1 if a critical error occurred (DB doesn't exist, no file system, etc.), 2 if errors occurred at some point adding files to the DB (corrupt file, etc.), and 0 otherwise.  Errors will have been registered.
 */
uint8_t TskAutoDbJava::addFilesInImgToDb()
{
    printf("\n#### addFilesInImgToDb...\n");
    fflush(stdout);

    // @@@ This seems bad because we are overriding what the user may
    // have set. We should remove the public API if we are going to 
    // override it -- presumably this was added so that we always have
    // unallocated volume space...
    setVolFilterFlags((TSK_VS_PART_FLAG_ENUM) (TSK_VS_PART_FLAG_ALLOC |
            TSK_VS_PART_FLAG_UNALLOC));

    uint8_t retVal = 0;
    if (findFilesInImg()) {
        // map the boolean return value from findFiles to the three-state return value we use
        // @@@ findFiles should probably return this three-state enum too
        if (m_foundStructure == false) {
            retVal = 1;
        }
        else {
            retVal = 2;
        }
    }

    TSK_RETVAL_ENUM addUnallocRetval = TSK_OK;
    if (m_addUnallocSpace)
        addUnallocRetval = addUnallocSpaceToDb();

    // findFiles return value trumps unalloc since it can return either 2 or 1.
    if (retVal) {
        return retVal;
    }
    else if (addUnallocRetval == TSK_ERR) {
        return 2;
    }
    else {
        return 0;
    }
}


/**
 * Start the process to add image/file metadata to database inside of a transaction. 
 * User must call either commitAddImage() to commit the changes,
 * or revertAddImage() to revert them.
 *
 * @param numImg Number of image parts
 * @param imagePaths Array of paths to the image parts
 * @param imgType Image type
 * @param sSize Size of device sector in bytes (or 0 for default)
 * @param deviceId An ASCII-printable identifier for the device associated with the data source that is intended to be unique across multiple cases (e.g., a UUID)
 * @return 0 for success, 1 for failure
 */
uint8_t
    TskAutoDbJava::startAddImage(int numImg, const TSK_TCHAR * const imagePaths[],
    TSK_IMG_TYPE_ENUM imgType, unsigned int sSize, const char* deviceId)
{
    if (tsk_verbose)
        tsk_fprintf(stderr, "TskAutoDbJava::startAddImage: Starting add image process\n");

    if (openImage(numImg, imagePaths, imgType, sSize, deviceId)) {
        tsk_error_set_errstr2("TskAutoDbJava::startAddImage");
        registerError();
        return 1;
    }

    if (m_imageWriterEnabled) {
        tsk_img_writer_create(m_img_info, m_imageWriterPath);
    }
    
    if (m_addFileSystems) {
        return addFilesInImgToDb();
    } else {
        return 0;
    }
}

/**
* Start the process to add image/file metadata to database inside of a transaction.
* User must call either commitAddImage() to commit the changes,
* or revertAddImage() to revert them.
*
* @param img_info Previously initialized TSK_IMG_INFO object
* @param deviceId An ASCII-printable identifier for the device associated with the data source that is intended to be unique across multiple cases (e.g., a UUID)
* @return 0 for success, 1 for failure
*/
uint8_t
TskAutoDbJava::startAddImage(TSK_IMG_INFO * img_info, const char* deviceId)
{
    openImageHandle(img_info);

    if (m_img_info == NULL) {
        return 1;
    }

    if (tsk_verbose)
        tsk_fprintf(stderr, "TskAutoDbJava::startAddImage: Starting add image process\n");

    if (openImage(deviceId)) {
        tsk_error_set_errstr2("TskAutoDbJava::startAddImage");
        registerError();
        return 1;
    }

    if (m_imageWriterEnabled) {
        if (tsk_img_writer_create(m_img_info, m_imageWriterPath)) {
            registerError();
            return 1;
        }
    }

    if (m_addFileSystems) {
        return addFilesInImgToDb();
    }
    else {
        return 0;
    }
}


#ifdef WIN32
/**
 * Start the process to add image/file metadata to database inside of a transaction. 
 * Same functionality as addFilesInImgToDb().  Reverts
 * all changes on error. User must call either commitAddImage() to commit the changes,
 * or revertAddImage() to revert them.
 *
 * @param numImg Number of image parts
 * @param imagePaths Array of paths to the image parts
 * @param imgType Image type
 * @param sSize Size of device sector in bytes (or 0 for default)
 * @param deviceId An ASCII-printable identifier for the device associated with the data source that is intended to be unique across multiple cases (e.g., a UUID)
 * @return 0 for success 1, for failure
 */
uint8_t
    TskAutoDbJava::startAddImage(int numImg, const char *const imagePaths[],
    TSK_IMG_TYPE_ENUM imgType, unsigned int sSize, const char* deviceId)
{
    if (tsk_verbose) 
        tsk_fprintf(stderr, "TskAutoDbJava::startAddImage_utf8: Starting add image process\n");

    if (openImageUtf8(numImg, imagePaths, imgType, sSize, deviceId)) {
        tsk_error_set_errstr2("TskAutoDbJava::startAddImage");
        registerError();
        return 1;
    }
    if (m_imageWriterEnabled) {
        tsk_img_writer_create(m_img_info, m_imageWriterPath);
    }

    if (m_addFileSystems) {
        return addFilesInImgToDb();
    } else {
        return 0;
    }
}
#endif


/**
 * Cancel the running process.  Will not be handled immediately. 
 */
void
 TskAutoDbJava::stopAddImage()
{
    if (tsk_verbose)
        tsk_fprintf(stderr, "TskAutoDbJava::stopAddImage: Stop request received\n");
    
    m_stopped = true;
    setStopProcessing();
    // flag is checked every time processFile() is called
}

/**
 * Set the current image's timezone
 */
void
TskAutoDbJava::setTz(string tzone)
{
    m_curImgTZone = tzone;
}

TSK_RETVAL_ENUM
TskAutoDbJava::processFile(TSK_FS_FILE * fs_file, const char *path)
{
    printf("#### processFile\n");
    fflush(stdout);
    // Check if the process has been canceled
     if (m_stopped) {
        if (tsk_verbose)
            tsk_fprintf(stderr, "TskAutoDbJava::processFile: Stop request detected\n");
        return TSK_STOP;
    }

    /* Update the current directory, which can be used to show
     * progress.  If we get a directory, then use its name.  We
     * do this so that when we are searching for orphan files, then
     * we at least show $OrphanFiles as status.  The secondary check
     * is to grab the parent folder from files once we return back 
     * into a folder when we are doing our depth-first recursion. */
    if (isDir(fs_file)) {
        m_curDirAddr = fs_file->name->meta_addr;
        tsk_take_lock(&m_curDirPathLock);
        m_curDirPath = string(path) + fs_file->name->name;
        tsk_release_lock(&m_curDirPathLock);
    }
    else if (m_curDirAddr != fs_file->name->par_addr) {
        m_curDirAddr = fs_file->name->par_addr;
        tsk_take_lock(&m_curDirPathLock);
        m_curDirPath = path;
        tsk_release_lock(&m_curDirPathLock);
    }

    /* process the attributes.  The case of having 0 attributes can occur
     * with virtual / sparse files and HFS directories.  
     * At some point, this can probably be cleaned
     * up if TSK is more consistent about if there should always be an 
     * attribute or not.  Sometimes, none of the attributes are added
     * because of their type and we always want to add a reference to 
     * every file. */
    TSK_RETVAL_ENUM retval = TSK_OK;
    m_attributeAdded = false;
    if (tsk_fs_file_attr_getsize(fs_file) > 0) {
        retval = processAttributes(fs_file, path);
    }

    // insert a general row if we didn't add a specific attribute one
    if ((retval == TSK_OK) && (m_attributeAdded == false)) {
        retval = insertFileData(fs_file, NULL, path);
    }
    
    // reset the file id
    m_curFileId = 0;

    if (retval == TSK_STOP)
        return TSK_STOP;
    else 
        return TSK_OK;
}


// we return only OK or STOP -- errors are registered only and OK is returned. 
TSK_RETVAL_ENUM
TskAutoDbJava::processAttribute(TSK_FS_FILE * fs_file,
    const TSK_FS_ATTR * fs_attr, const char *path)
{
    // add the file metadata for the default attribute type
    if (isDefaultType(fs_file, fs_attr)) {

        if (insertFileData(fs_attr->fs_file, fs_attr, path) == TSK_ERR) {
            registerError();
            return TSK_OK;
        }
        else {
            m_attributeAdded = true;
        }
    }

    return TSK_OK;
}


/**
* Callback invoked per every unallocated block in the filesystem
* Creates file ranges and file entries 
* A single file entry per consecutive range of blocks
* @param a_block block being walked
* @param a_ptr a pointer to an UNALLOC_BLOCK_WLK_TRACK struct
* @returns TSK_WALK_CONT if continue, otherwise TSK_WALK_STOP if stop processing requested
*/
TSK_WALK_RET_ENUM TskAutoDbJava::fsWalkUnallocBlocksCb(const TSK_FS_BLOCK *a_block, void *a_ptr) {
    UNALLOC_BLOCK_WLK_TRACK * unallocBlockWlkTrack = (UNALLOC_BLOCK_WLK_TRACK *) a_ptr;

    if (unallocBlockWlkTrack->tskAutoDbJava.m_stopAllProcessing)
        return TSK_WALK_STOP;

    // initialize if this is the first block
    if (unallocBlockWlkTrack->isStart) {
        unallocBlockWlkTrack->isStart = false;
        unallocBlockWlkTrack->curRangeStart = a_block->addr;
        unallocBlockWlkTrack->prevBlock = a_block->addr;
        unallocBlockWlkTrack->size = unallocBlockWlkTrack->fsInfo.block_size;
        unallocBlockWlkTrack->nextSequenceNo = 0;
        return TSK_WALK_CONT;
    }

    // We want to keep consecutive blocks in the same run, so simply update prevBlock and the size
    // if this one is consecutive with the last call. But, if we have hit the max chunk
    // size, then break up this set of consecutive blocks.
    if ((a_block->addr == unallocBlockWlkTrack->prevBlock + 1) && ((unallocBlockWlkTrack->maxChunkSize <= 0) ||
            (unallocBlockWlkTrack->size < unallocBlockWlkTrack->maxChunkSize))) {
        unallocBlockWlkTrack->prevBlock = a_block->addr;
		unallocBlockWlkTrack->size += unallocBlockWlkTrack->fsInfo.block_size;
        return TSK_WALK_CONT;
    }

    // this block is not contiguous with the previous one or we've hit the maximum size; create and add a range object
    const uint64_t rangeStartOffset = unallocBlockWlkTrack->curRangeStart * unallocBlockWlkTrack->fsInfo.block_size 
        + unallocBlockWlkTrack->fsInfo.offset;
    const uint64_t rangeSizeBytes = (1 + unallocBlockWlkTrack->prevBlock - unallocBlockWlkTrack->curRangeStart) 
        * unallocBlockWlkTrack->fsInfo.block_size;
    unallocBlockWlkTrack->ranges.push_back(TSK_DB_FILE_LAYOUT_RANGE(rangeStartOffset, rangeSizeBytes, unallocBlockWlkTrack->nextSequenceNo++));

    // Return (instead of adding this run) if we are going to:
    // a) Make one big file with all unallocated space (minChunkSize == 0)
    // or
    // b) Only make an unallocated file once we have at least chunkSize bytes
    // of data in our current run (minChunkSize > 0)
    // In either case, reset the range pointers and add this block to the size
    if ((unallocBlockWlkTrack->minChunkSize == 0) ||
        ((unallocBlockWlkTrack->minChunkSize > 0) &&
        (unallocBlockWlkTrack->size < unallocBlockWlkTrack->minChunkSize))) {

        unallocBlockWlkTrack->size += unallocBlockWlkTrack->fsInfo.block_size;
        unallocBlockWlkTrack->curRangeStart = a_block->addr;
        unallocBlockWlkTrack->prevBlock = a_block->addr;
        return TSK_WALK_CONT;
    }
    
    // at this point we are either chunking and have reached the chunk limit
    // or we're not chunking. Either way we now add what we've got to the DB
    int64_t fileObjId = 0;
    if (-1 == addUnallocBlockFile(unallocBlockWlkTrack->tskAutoDbJava.m_curUnallocDirId,
        unallocBlockWlkTrack->fsObjId, unallocBlockWlkTrack->size, unallocBlockWlkTrack->ranges, fileObjId, unallocBlockWlkTrack->tskAutoDbJava.m_curImgId) == TSK_ERR) {
            // @@@ Handle error -> Don't have access to registerError() though...
    }

    // reset
    unallocBlockWlkTrack->curRangeStart = a_block->addr;
    unallocBlockWlkTrack->prevBlock = a_block->addr;
    unallocBlockWlkTrack->size = unallocBlockWlkTrack->fsInfo.block_size; // The current block is part of the new range
    unallocBlockWlkTrack->ranges.clear();
    unallocBlockWlkTrack->nextSequenceNo = 0;

    //we don't know what the last unalloc block is in advance
    //and will handle the last range in addFsInfoUnalloc()
    
    return TSK_WALK_CONT;
}


/**
* Add unallocated space for the given file system to the database.
* Create files for consecutive unalloc block ranges.
* @param dbFsInfo fs to process
* @returns TSK_OK on success, TSK_ERR on error
*/
TSK_RETVAL_ENUM TskAutoDbJava::addFsInfoUnalloc(const TSK_DB_FS_INFO & dbFsInfo) {

    // Unalloc space is not yet implemented for APFS
    if (dbFsInfo.fType == TSK_FS_TYPE_APFS) {
        return TSK_OK;
    }

    //open the fs we have from database
    TSK_FS_INFO * fsInfo = tsk_fs_open_img(m_img_info, dbFsInfo.imgOffset, dbFsInfo.fType);
    if (fsInfo == NULL) {
        tsk_error_set_errstr2("TskAutoDbJava::addFsInfoUnalloc: error opening fs at offset %" PRIdOFF, dbFsInfo.imgOffset);
        registerError();
        return TSK_ERR;
    }

    //create a "fake" dir to hold the unalloc files for the fs
    if (-1 == addUnallocFsBlockFilesParent(dbFsInfo.objId, m_curUnallocDirId, m_curImgId) == TSK_ERR) {
        tsk_error_set_errstr2("addFsInfoUnalloc: error creating dir for unallocated space");
        registerError();
        return TSK_ERR;
    }

    //walk unalloc blocks on the fs and process them
    //initialize the unalloc block walk tracking 
    UNALLOC_BLOCK_WLK_TRACK unallocBlockWlkTrack(*this, *fsInfo, dbFsInfo.objId, m_minChunkSize, m_maxChunkSize);
    uint8_t block_walk_ret = tsk_fs_block_walk(fsInfo, fsInfo->first_block, fsInfo->last_block, (TSK_FS_BLOCK_WALK_FLAG_ENUM)(TSK_FS_BLOCK_WALK_FLAG_UNALLOC | TSK_FS_BLOCK_WALK_FLAG_AONLY), 
        fsWalkUnallocBlocksCb, &unallocBlockWlkTrack);

    if (block_walk_ret == 1) {
        stringstream errss;
        tsk_fs_close(fsInfo);
        errss << "TskAutoDbJava::addFsInfoUnalloc: error walking fs unalloc blocks, fs id: ";
        errss << unallocBlockWlkTrack.fsObjId;
        tsk_error_set_errstr2("%s", errss.str().c_str());
        registerError();
        return TSK_ERR;
    }

    if(m_stopAllProcessing) {
        tsk_fs_close(fsInfo);
        return TSK_OK;
    }

    // handle creation of the last range
    // make range inclusive from curBlockStart to prevBlock
    const uint64_t byteStart = unallocBlockWlkTrack.curRangeStart * fsInfo->block_size + fsInfo->offset;
    const uint64_t byteLen = (1 + unallocBlockWlkTrack.prevBlock - unallocBlockWlkTrack.curRangeStart) * fsInfo->block_size;
    unallocBlockWlkTrack.ranges.push_back(TSK_DB_FILE_LAYOUT_RANGE(byteStart, byteLen, unallocBlockWlkTrack.nextSequenceNo++));
    int64_t fileObjId = 0;

    if (-1 == addUnallocBlockFile(m_curUnallocDirId, dbFsInfo.objId, unallocBlockWlkTrack.size, unallocBlockWlkTrack.ranges, fileObjId, m_curImgId) == TSK_ERR) {
        registerError();
        tsk_fs_close(fsInfo);
        return TSK_ERR;
    }
    
    //cleanup 
    tsk_fs_close(fsInfo);

    return TSK_OK; 
}

/**
* Process all unallocated space for this disk image and create "virtual" files with layouts
* @returns TSK_OK on success, TSK_ERR on error
*/
TSK_RETVAL_ENUM TskAutoDbJava::addUnallocSpaceToDb() {
    if (m_stopAllProcessing) {
        return TSK_OK;
    }

    size_t numVsP = 0;
    size_t numFs = 0;

    TSK_RETVAL_ENUM retFsSpace = addUnallocFsSpaceToDb(numFs);
    TSK_RETVAL_ENUM retVsSpace = addUnallocVsSpaceToDb(numVsP);

    //handle case when no fs and no vs partitions
    TSK_RETVAL_ENUM retImgFile = TSK_OK;
    if (numVsP == 0 && numFs == 0) {
        retImgFile = addUnallocImageSpaceToDb();
    }
    
    
    if (retFsSpace == TSK_ERR || retVsSpace == TSK_ERR || retImgFile == TSK_ERR)
        return TSK_ERR;
    else
        return TSK_OK;
}


/**
* Process each file system in the database and add its unallocated sectors to virtual files. 
* @param numFs (out) number of filesystems found
* @returns TSK_OK on success, TSK_ERR on error (if some or all fs could not be processed)
*/
TSK_RETVAL_ENUM TskAutoDbJava::addUnallocFsSpaceToDb(size_t & numFs) {

    vector<TSK_DB_FS_INFO> fsInfos;

    if(m_stopAllProcessing) {
        return TSK_OK;
    }


    printf("SKIPPING addUnallocFsSpaceToDb!!!!\n"); // TODO TODO
/*
    uint16_t ret = m_db->getFsInfos(m_curImgId, fsInfos);
    if (ret) {
        tsk_error_set_errstr2("addUnallocFsSpaceToDb: error getting fs infos from db");
        registerError();
        return TSK_ERR;
    }

    numFs = fsInfos.size();

    TSK_RETVAL_ENUM allFsProcessRet = TSK_OK;
    for (vector<TSK_DB_FS_INFO>::iterator it = fsInfos.begin(); it!= fsInfos.end(); ++it) {
        if (m_stopAllProcessing) {
            break;
        }
        if (addFsInfoUnalloc(*it) == TSK_ERR)
            allFsProcessRet = TSK_ERR;
    }

    //TODO set parent_path for newly created virt dir/file hierarchy for consistency

    return allFsProcessRet;*/
    return TSK_OK;
}

/**
* Process each volume in the database and add its unallocated sectors to virtual files. 
* @param numVsP (out) number of vs partitions found
* @returns TSK_OK on success, TSK_ERR on error
*/
TSK_RETVAL_ENUM TskAutoDbJava::addUnallocVsSpaceToDb(size_t & numVsP) {

    vector<TSK_DB_VS_PART_INFO> vsPartInfos;


    printf("SKIPPING addUnallocVsSpaceToDb!!!!\n"); // TODO TODO
    /*
    TSK_RETVAL_ENUM retVsPartInfos = m_db->getVsPartInfos(m_curImgId, vsPartInfos);
    if (retVsPartInfos == TSK_ERR) {
        tsk_error_set_errstr2("addUnallocVsSpaceToDb: error getting vs part infos from db");
        registerError();
        return TSK_ERR;
    }
    numVsP = vsPartInfos.size();

    //get fs infos to see if this vspart has fs
    vector<TSK_DB_FS_INFO> fsInfos;
    uint16_t retFsInfos = m_db->getFsInfos(m_curImgId, fsInfos);
    if (retFsInfos) {
        tsk_error_set_errstr2("addUnallocVsSpaceToDb: error getting fs infos from db");
        registerError();
        return TSK_ERR;
    }

    for (vector<TSK_DB_VS_PART_INFO>::const_iterator it = vsPartInfos.begin();
            it != vsPartInfos.end(); ++it) {
        if (m_stopAllProcessing) {
            break;
        }
        const TSK_DB_VS_PART_INFO &vsPart = *it;

        //interested in unalloc, meta, or alloc and no fs
        if ( (vsPart.flags & (TSK_VS_PART_FLAG_UNALLOC | TSK_VS_PART_FLAG_META)) == 0 ) {
            //check if vspart has no fs
            bool hasFs = false;
            for (vector<TSK_DB_FS_INFO>::const_iterator itFs = fsInfos.begin();
               itFs != fsInfos.end(); ++itFs) {
               const TSK_DB_FS_INFO & fsInfo = *itFs;

               TSK_DB_OBJECT fsObjInfo;
               if (m_db->getObjectInfo(fsInfo.objId, fsObjInfo) == TSK_ERR ) {
                   stringstream errss;
                   errss << "addUnallocVsSpaceToDb: error getting object info for fs from db, objId: " << fsInfo.objId;
                   tsk_error_set_errstr2("%s", errss.str().c_str());
                   registerError();
                   return TSK_ERR;
               }

               if (fsObjInfo.parObjId == vsPart.objId) {
                   hasFs = true;
                   break;
               }
            }
        
            if (hasFs == true) {
                //skip processing this vspart
                continue;
            }
        } //end checking vspart flags

        //get sector size and image offset from parent vs info

        //get parent id of this vs part
        TSK_DB_OBJECT vsPartObj;     
        if (m_db->getObjectInfo(vsPart.objId, vsPartObj) == TSK_ERR) {
            stringstream errss;
            errss << "addUnallocVsSpaceToDb: error getting object info for vs part from db, objId: " << vsPart.objId;
            tsk_error_set_errstr2("%s", errss.str().c_str());
            registerError();
            return TSK_ERR;
        }

        TSK_DB_VS_INFO vsInfo;
        if (m_db->getVsInfo(vsPartObj.parObjId, vsInfo) ) {
            stringstream errss;
            errss << "addUnallocVsSpaceToDb: error getting volume system info from db, objId: " << vsPartObj.parObjId;
            tsk_error_set_errstr2("%s", errss.str().c_str());
            registerError();
            return TSK_ERR;
        }

        //create an unalloc file with unalloc part, with vs part as parent
        vector<TSK_DB_FILE_LAYOUT_RANGE> ranges;
        const uint64_t byteStart = vsInfo.offset + vsInfo.block_size * vsPart.start;
        const uint64_t byteLen = vsInfo.block_size * vsPart.len; 
        TSK_DB_FILE_LAYOUT_RANGE tempRange(byteStart, byteLen, 0);
        ranges.push_back(tempRange);
        int64_t fileObjId = 0;
        if (m_db->addUnallocBlockFile(vsPart.objId, 0, tempRange.byteLen, ranges, fileObjId, m_curImgId) == TSK_ERR) {
            registerError();
            return TSK_ERR;
        }
    }*/

    return TSK_OK;
}


/**
* Adds unalloc space for the image if there is no volumes and no file systems.
*
* @returns TSK_OK on success, TSK_ERR on error
*/
TSK_RETVAL_ENUM TskAutoDbJava::addUnallocImageSpaceToDb() {

    const TSK_OFF_T imgSize = getImageSize();
    if (imgSize == -1) {
        tsk_error_set_errstr("addUnallocImageSpaceToDb: error getting current image size, can't create unalloc block file for the image.");
        registerError();
        return TSK_ERR;
    }
    else {
        TSK_DB_FILE_LAYOUT_RANGE tempRange(0, imgSize, 0);
        //add unalloc block file for the entire image
        vector<TSK_DB_FILE_LAYOUT_RANGE> ranges;
        ranges.push_back(tempRange);
        int64_t fileObjId = 0;
        if (-1 == addUnallocBlockFile(m_curImgId, 0, imgSize, ranges, fileObjId, m_curImgId)) {
            return TSK_ERR;
        }
    }
    return TSK_OK;
}

/**
* Returns the directory currently being analyzed by processFile().
* Safe to use from another thread than processFile().
*
* @returns curDirPath string representing currently analyzed directory
*/
const std::string TskAutoDbJava::getCurDir() {
    string curDirPath;
    tsk_take_lock(&m_curDirPathLock);
    curDirPath = m_curDirPath;
    tsk_release_lock(&m_curDirPathLock);
    return curDirPath;
}
