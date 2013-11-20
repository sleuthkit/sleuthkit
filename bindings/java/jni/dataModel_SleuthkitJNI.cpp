/*
 ** dataModel_SleuthkitJNI
 ** The Sleuth Kit 
 **
 ** Brian Carrier [carrier <at> sleuthkit [dot] org]
 ** Copyright (c) 2010-2013 Brian Carrier.  All Rights reserved
 **
 ** This software is distributed under the Common Public License 1.0
 **
 */
#include "tsk/tsk_tools_i.h"
#include "tsk/auto/tsk_case_db.h"
#include "tsk/hashdb/sqlite_index.h"
#include "jni.h"
#include "dataModel_SleuthkitJNI.h"
#include <locale.h>
#include <time.h>
#include <vector>
#include <map>
#include <string>
#include <algorithm>
#include <sstream>
using std::string;
using std::vector;
using std::map;
using std::stringstream;
using std::for_each;

static int m_nsrlHandle = -1;
static std::vector<TSK_HDB_INFO *> m_hashDbs;

/*
* JNI file handle structure encapsulates both
* TSK_FS_FILE file handle and TSK_FS_ATTR attribute
* to support multiple attributes for the same file.
* TSK_FS_FILE still needs be maintained for opening and closing.
*/
typedef struct {
    uint32_t tag; 
    TSK_FS_FILE *fs_file; 
    TSK_FS_ATTR *fs_attr; 
} TSK_JNI_FILEHANDLE;
#define TSK_JNI_FILEHANDLE_TAG 0x10101214

//stack-allocated buffer size for read method
#define FIXED_BUF_SIZE (16 * 1024)

/**
* Sets flag to throw an TskCoreException back up to the Java code with a specific message.
* Note: exception is thrown to Java code after the native function returns
* not when setThrowTskCoreError() is invoked - this must be addressed in the code following the exception 
* @param the java environment to send the exception to
* @param msg message string
 */
static void
setThrowTskCoreError(JNIEnv * env, const char *msg)
{
    jclass exception;
    exception = env->FindClass("org/sleuthkit/datamodel/TskCoreException");
    env->ThrowNew(exception, msg);
}

/**
* Sets flag to throw an TskCoreException back up to the Java code with the currently set error message.
* Note: exception is thrown to Java code after the native function returns
* not when setThrowTskCoreError() is invoked - this must be addressed in the code following the exception 
* @param the java environment to send the exception to
*/
static void
setThrowTskCoreError(JNIEnv * env)
{
    const char *msg = tsk_error_get();
    setThrowTskCoreError(env, msg);
}

/**
* Sets flag to throw an TskDataException back up to the Java code with a specific message.
* Note: exception is thrown to Java code after the native function returns
* not when setThrowTskDataError() is invoked - this must be addressed in the code following the exception 
* @param the java environment to send the exception to
* @param msg message string
 */
static void
setThrowTskDataError(JNIEnv * env, const char *msg)
{
    jclass exception;
    exception = env->FindClass("org/sleuthkit/datamodel/TskDataException");
    env->ThrowNew(exception, msg);
}

/**
* Sets flag to throw an TskDataException back up to the Java code with the currently set error message.
* Note: exception is thrown to Java code after the native function returns
* not when setThrowTskDataError() is invoked - this must be addressed in the code following the exception 
* @param the java environment to send the exception to
*/
static void
setThrowTskDataError(JNIEnv * env)
{
    const char *msg = tsk_error_get();
    setThrowTskDataError(env, msg);
}


/***** Methods to cast from jlong to data type and check tags
 They all throw an exception if the incorrect type is passed in. *****/
static TSK_IMG_INFO *
castImgInfo(JNIEnv * env, jlong ptr)
{
    TSK_IMG_INFO *lcl = (TSK_IMG_INFO *) ptr;
    if (lcl->tag != TSK_IMG_INFO_TAG) {
        setThrowTskCoreError(env, "Invalid IMG_INFO object");
        return 0;
    }
    return lcl;
}


static TSK_VS_INFO *
castVsInfo(JNIEnv * env, jlong ptr)
{
    TSK_VS_INFO *lcl = (TSK_VS_INFO *) ptr;
    if (lcl->tag != TSK_VS_INFO_TAG) {
        setThrowTskCoreError(env, "Invalid VS_INFO object");
        return 0;
    }

    return lcl;
}

static TSK_VS_PART_INFO *
castVsPartInfo(JNIEnv * env, jlong ptr)
{
    TSK_VS_PART_INFO *lcl = (TSK_VS_PART_INFO *) ptr;
    if (lcl->tag != TSK_VS_PART_INFO_TAG) {
        setThrowTskCoreError(env, "Invalid VS_PART_INFO object");
        return 0;
    }

    return lcl;
}

static TSK_FS_INFO *
castFsInfo(JNIEnv * env, jlong ptr)
{
    TSK_FS_INFO *lcl = (TSK_FS_INFO *) ptr;
    if (lcl->tag != TSK_FS_INFO_TAG) {
        setThrowTskCoreError(env, "Invalid FS_INFO object");
        return 0;
    }
    return lcl;
}


static TSK_JNI_FILEHANDLE *
castFsFile(JNIEnv * env, jlong ptr)
{
    TSK_JNI_FILEHANDLE *lcl = (TSK_JNI_FILEHANDLE *) ptr;
    if (lcl->tag != TSK_JNI_FILEHANDLE_TAG) {
        setThrowTskCoreError(env, "Invalid TSK_JNI_FILEHANDLE object");
        return 0;
    }
    return lcl;
}

static TskCaseDb * 
castCaseDb(JNIEnv * env, jlong ptr)
{
    TskCaseDb *lcl = ((TskCaseDb *) ptr);
    if (lcl->m_tag != TSK_CASE_DB_TAG) {
        setThrowTskCoreError(env,
            "Invalid TskCaseDb object");
        return 0;
    }

    return lcl;
}

static int
toTCHAR(JNIEnv * env, TSK_TCHAR * buffer, size_t size, jstring strJ)
{
    jboolean isCopy;
    char *str8 = (char *) env->GetStringUTFChars(strJ, &isCopy);

    int ret = TSNPRINTF(buffer, size, _TSK_T("%") PRIcTSK, str8);
    env->ReleaseStringUTFChars(strJ, str8);
    return ret;
}


/*
 * Open a TskCaseDb with an associated database
 * @return the pointer to the case
 * @param env pointer to java environment this was called from
 * @param dbPath location for the database
 * @rerurns 0 on error (sets java exception), pointer to newly opened TskCaseDb object on success
 */
JNIEXPORT jlong JNICALL
    Java_org_sleuthkit_datamodel_SleuthkitJNI_newCaseDbNat(JNIEnv * env,
    jclass obj, jstring dbPathJ) {

    TSK_TCHAR dbPathT[1024];
    toTCHAR(env, dbPathT, 1024, dbPathJ);

    TskCaseDb *tskCase = TskCaseDb::newDb(dbPathT);

    if (tskCase == NULL) {
        setThrowTskCoreError(env);
        return 0;               
    }

    return (jlong) tskCase;
}


/*
 * Open a TskCaseDb with an associated database
 * @return the pointer to the case
 * @param env pointer to java environment this was called from
 * @param dbPath location for the database
 * @return Returns pointer to object or exception on error
 */
JNIEXPORT jlong JNICALL
    Java_org_sleuthkit_datamodel_SleuthkitJNI_openCaseDbNat(JNIEnv * env,
    jclass obj, jstring dbPathJ) {

    TSK_TCHAR dbPathT[1024];
    toTCHAR(env, dbPathT, 1024, dbPathJ);

    TskCaseDb *tskCase = TskCaseDb::openDb(dbPathT);

    if (tskCase == NULL) {
        setThrowTskCoreError(env);
        return 0;
    }

    return (jlong) tskCase;
}

/*
 * Close (cleanup) a case
 * @param env pointer to java environment this was called from
 * @param obj the java object this was called from
 * @param caseHandle the pointer to the case
 */
JNIEXPORT void JNICALL
    Java_org_sleuthkit_datamodel_SleuthkitJNI_closeCaseDbNat(JNIEnv * env,
    jclass obj, jlong caseHandle) {

    TskCaseDb *tskCase = castCaseDb(env, caseHandle);
    if (tskCase == 0) {
        //exception already set
        return;
    }

    delete tskCase;
    return;
}


/*
 * Open a hash database to use for hash lookups. It's added to the list.
 * @param env pointer to java environment this was called from
 * @param obj the java object this was called from
 * @param pathJ the path to the database
 * @return a handle for the known bad database
 */
JNIEXPORT jint JNICALL
    Java_org_sleuthkit_datamodel_SleuthkitJNI_hashDbOpenNat(JNIEnv * env,
    jclass obj, jstring pathJ) {

    TSK_TCHAR pathT[1024];
    toTCHAR(env, pathT, 1024, pathJ);

    ///@todo Check if the db_file passed in is really an index filename

    TSK_HDB_OPEN_ENUM flags = TSK_HDB_OPEN_TRY;
    TSK_HDB_INFO * temp = tsk_hdb_open(pathT, flags);

    if(temp == NULL)
    {
        setThrowTskCoreError(env);
        return -1;
    }

    m_hashDbs.push_back(temp);
    
    return m_hashDbs.size();
}

/*
 * Create a new hash db.
 * @param env pointer to java environment this was called from
 * @param obj the java object this was called from
 * @param pathJ the path to the database
 * @return a handle for the database
 */
JNIEXPORT jint JNICALL
    Java_org_sleuthkit_datamodel_SleuthkitJNI_hashDbNewNat(JNIEnv * env,
    jclass obj, jstring pathJ)
{
    TSK_TCHAR pathT[1024];
    toTCHAR(env, pathT, 1024, pathJ);

    TSK_HDB_INFO * temp = tsk_hdb_new(pathT);

    if(temp == NULL)
    {
        setThrowTskCoreError(env);
        return -1;
    }

    m_hashDbs.push_back(temp);
    
    return m_hashDbs.size();
}

/*
 * Add entry to hash db.
 * @param env pointer to java environment this was called from
 * @param obj the java object this was called from
 * @param filenameJ Name of the file that was hashed (can be empty)
 * @param hashMd5J Text of MD5 hash (can be empty)
 * @param hashSha1J Text of SHA1 hash (can be empty)
 * @param hashSha256J Text of SHA256 hash (can be empty)
 * @param dbHandle Which DB.
 * @return 1 on error and 0 on success
 */
JNIEXPORT jint JNICALL
    Java_org_sleuthkit_datamodel_SleuthkitJNI_hashDbAddRecordNat(JNIEnv * env,
    jclass obj, jstring filenameJ, jstring hashMd5J, jstring hashSha1J, jstring hashSha256J,
    jstring commentJ, jint dbHandle)
{
    int8_t retval = 0;

    if((size_t) dbHandle > m_hashDbs.size()) {
        setThrowTskCoreError(env, "Invalid database handle");
        retval = 1;
    } else {
        jboolean isCopy;
        const char * name = filenameJ ? (const char *) env->GetStringUTFChars(filenameJ, &isCopy) : NULL;
        const char * md5 = hashMd5J ? (const char *) env->GetStringUTFChars(hashMd5J, &isCopy) : NULL;
        const char * sha1 = hashSha1J ? (const char *) env->GetStringUTFChars(hashSha1J, &isCopy) : NULL;
        const char * sha256 = hashSha256J ? (const char *) env->GetStringUTFChars(hashSha256J, &isCopy) : NULL;
        const char * comment = commentJ ? (const char *) env->GetStringUTFChars(commentJ, &isCopy) : NULL;
   
        //TSK_TCHAR filenameT[1024];
        //toTCHAR(env, filenameT, 1024, filenameJ);

        TSK_HDB_INFO * db = m_hashDbs.at(dbHandle-1);

        if(db != NULL) {
            retval = tsk_hdb_add_str(db, name, md5, sha1, sha256, comment);

            if (retval == 1) {
                setThrowTskCoreError(env);
            }
        }

        if (filenameJ) {
            env->ReleaseStringUTFChars(filenameJ, (const char *) name);
        }
        if (hashMd5J) { 
            env->ReleaseStringUTFChars(hashMd5J, (const char *) md5);
        }
        if (hashSha1J) {
            env->ReleaseStringUTFChars(hashSha1J, (const char *) sha1);
        }
        if (hashSha256J) {
            env->ReleaseStringUTFChars(hashSha256J, (const char *) sha256);
        }
        if (commentJ) {
            env->ReleaseStringUTFChars(commentJ, (const char *) comment);
        }
    }

    return retval;
}

/*
 * Get updateable state.
 * @param env pointer to java environment this was called from
 * @param obj the java object this was called from
 * @param dbHandle Which DB.
 * @return true if db can be updated
 */
JNIEXPORT jboolean JNICALL
    Java_org_sleuthkit_datamodel_SleuthkitJNI_hashDbIsUpdateableNat(JNIEnv * env,
    jclass obj, jint dbHandle)
{
    bool retval = false;

    if((size_t) dbHandle > m_hashDbs.size()) {
        setThrowTskCoreError(env, "Invalid database handle");
    } else {
        TSK_HDB_INFO * db = m_hashDbs.at(dbHandle-1);

        if(db != NULL) {
            retval = (db->idx_info->updateable == 1) ? true : false;
        }
    }
    return retval;
}

/*
 * Get reindexable state.
 * @param env pointer to java environment this was called from
 * @param obj the java object this was called from
 * @param dbHandle Which DB.
 * @return true if db is allowed to be reindexed
 */
JNIEXPORT jboolean JNICALL
    Java_org_sleuthkit_datamodel_SleuthkitJNI_hashDbIsReindexableNat(JNIEnv * env,
    jclass obj, jint dbHandle)
{
    bool retval = false;

    if((size_t) dbHandle > m_hashDbs.size()) {
        setThrowTskCoreError(env, "Invalid database handle");
    } else {
        TSK_HDB_INFO * db = m_hashDbs.at(dbHandle-1);

        if(db != NULL) {
            if (db->hDb != NULL) {
                retval = true;
            }
        }
    }
    return retval;
}
    
/*
 * Get path.
 * @param env pointer to java environment this was called from
 * @param obj the java object this was called from
 * @param dbHandle Which DB.
 * @return path
 */
JNIEXPORT jstring JNICALL
    Java_org_sleuthkit_datamodel_SleuthkitJNI_hashDbPathNat(JNIEnv * env,
    jclass obj, jint dbHandle)
{
    char cpath[1024];
    char * none = "None";   //on error or if no name is available

    if((size_t) dbHandle > m_hashDbs.size()) {
        setThrowTskCoreError(env, "Invalid database handle");
        return env->NewStringUTF(none);
    } else {
        TSK_HDB_INFO * db = m_hashDbs.at(dbHandle-1);


        // Index might not be set up yet
        if(tsk_hdb_idxsetup(db, db->hash_type)) {
            // If this is a Tsk SQLite db+index, then use index fname as db fname.
            if ((db->db_type == TSK_HDB_DBTYPE_IDXONLY_ID) && 
                (db->idx_info->index_type == TSK_HDB_ITYPE_SQLITE_V1)) {

                snprintf(cpath, 1024, "%" PRIttocTSK, db->idx_info->idx_fname);
                jstring jname = env->NewStringUTF(cpath);
                return jname;
            }      
        }

        // Otherwise, try using the db fname.
        if((db != NULL) && (db->hDb != NULL)) {
            snprintf(cpath, 1024, "%" PRIttocTSK, db->db_fname);
            jstring jname = env->NewStringUTF(cpath);
            return jname;
        } else {
            return env->NewStringUTF(none);
        }

    }
}


/*
 * Get index path.
 * @param env pointer to java environment this was called from
 * @param obj the java object this was called from
 * @param dbHandle Which DB.
 * @return path
 */
JNIEXPORT jstring JNICALL
    Java_org_sleuthkit_datamodel_SleuthkitJNI_hashDbIndexPathNat(JNIEnv * env,
    jclass obj, jint dbHandle)
{
    char cpath[1024];
    char * none = "None";   //on error or if no name is available

    if((size_t) dbHandle > m_hashDbs.size()) {
        setThrowTskCoreError(env, "Invalid database handle");
        return env->NewStringUTF(none);
    } else {
        TSK_HDB_INFO * db = m_hashDbs.at(dbHandle-1);
        if (db == NULL) {
            setThrowTskCoreError(env, "Invalid database");
            return env->NewStringUTF(none);
        }

        ///@todo there isn't a db type for this (would be needed to get legacy index filename)
        /*if(db->db_type == TSK_HDB_DBTYPE_NSRL_SHA1_ID) {
            db->hash_type = TSK_HDB_HTYPE_SHA1_ID;
        }*/
        //else {
            db->hash_type = TSK_HDB_HTYPE_MD5_ID;
        //}

        // Call setup to populate the idx_info struct so we can get the filename
        tsk_hdb_idxsetup(db, db->hash_type);

        if(db->idx_info != NULL) {
            snprintf(cpath, 1024, "%" PRIttocTSK, db->idx_info->idx_fname);
            jstring jname = env->NewStringUTF(cpath);
            return jname;
        } else {
            return env->NewStringUTF(none);
        }
    }  
}


/*
 * Test for index only (no original Db file) legacy (IDX format).
 * @param env pointer to java environment this was called from
 * @param obj the java object this was called from
 * @param dbHandle Which DB.
 * @return true if index only AND is legacy
 */
JNIEXPORT jboolean JNICALL
    Java_org_sleuthkit_datamodel_SleuthkitJNI_hashDbIsIdxOnlyNat(JNIEnv * env,
    jclass obj, jint dbHandle)
{
    bool retval = false;

    if((size_t) dbHandle > m_hashDbs.size()) {
        setThrowTskCoreError(env, "Invalid database handle");
    } else {
        TSK_HDB_INFO * db = m_hashDbs.at(dbHandle-1);

        if(db != NULL) {
            retval = (tsk_hdb_is_idxonly(db) == 1) ? true : false;
        }
    }
    return retval;
}


/*
 * Get the name of the database pointed to by path
 * @param env pointer to java environment this was called from
 * @param obj the java object this was called from
 * @param dbHandle Which DB.
 */
JNIEXPORT jstring JNICALL Java_org_sleuthkit_datamodel_SleuthkitJNI_hashDbGetName
  (JNIEnv * env, jclass obj, jint dbHandle)
{
    if((size_t) dbHandle > m_hashDbs.size()) {
        setThrowTskCoreError(env, "Invalid database handle");
        return env->NewStringUTF("-1");
    } else {
        TSK_HDB_INFO * temp = m_hashDbs.at(dbHandle-1);
        if (temp == NULL) {
            setThrowTskCoreError(env, "Error: database object is null");
            return env->NewStringUTF("-1");
        }


        jstring jname = env->NewStringUTF(temp->db_name);
        return jname;
    }
}

/*
 * Close all hash dbs and destroy associated memory structures.
 * And it resets the handle counting.
 * @param env pointer to java environment this was called from
 * @param obj the java object this was called from
 * @param dbHandle Which DB.
 */
JNIEXPORT void JNICALL
    Java_org_sleuthkit_datamodel_SleuthkitJNI_hashDbCloseAll(JNIEnv * env,
    jclass obj) {

    for_each(m_hashDbs.begin(), m_hashDbs.end(), tsk_hdb_close);
   
    m_hashDbs.clear();

    m_nsrlHandle = -1;
}

/*
 * Close a hash db and destroy associated memory structures.
 * Existing handles are not affected.
 * @param env pointer to java environment this was called from
 * @param obj the java object this was called from
 * @param dbHandle Which DB.
 */
JNIEXPORT void JNICALL
    Java_org_sleuthkit_datamodel_SleuthkitJNI_hashDbClose(JNIEnv * env,
    jclass obj, jint dbHandle) {

    if((size_t) dbHandle > m_hashDbs.size()) {
        setThrowTskCoreError(env, "Invalid database handle");
    } else {
        TSK_HDB_INFO * db = m_hashDbs.at(dbHandle-1);

        if(db != NULL) {
            tsk_hdb_close(db);

            // We do NOT erase the element because that would shift the indices,
            // messing up the existing handles.
            m_hashDbs.at(dbHandle-1) = NULL;

            if (m_nsrlHandle == dbHandle) {
                m_nsrlHandle = -1;
            }
        }
    }
}


/*
 * Class:     org_sleuthkit_datamodel_SleuthkitJNI
 * Method:    hashDbLookup
 * Signature: (Ljava/lang/String;)I
 */
JNIEXPORT jboolean JNICALL Java_org_sleuthkit_datamodel_SleuthkitJNI_hashDbLookup
(JNIEnv * env, jclass obj, jstring hash, jint dbHandle) {

    if((size_t) dbHandle > m_hashDbs.size()) {
        setThrowTskCoreError(env, "Invalid database handle");
        return -1;
    }

    jboolean isCopy;

    const char *md5 = (const char *) env->GetStringUTFChars(hash, &isCopy);

    //TSK_DB_FILES_KNOWN_ENUM file_known = TSK_DB_FILES_KNOWN_UNKNOWN;
    jboolean file_known = false;
    

    TSK_HDB_INFO * db = m_hashDbs.at(dbHandle-1);

    if(db != NULL) {
        int8_t retval = tsk_hdb_lookup_str(db, md5, TSK_HDB_FLAG_QUICK, NULL, NULL);

        if (retval == -1) {
            setThrowTskCoreError(env);
        } else if (retval) {
            //file_known = TSK_DB_FILES_KNOWN_KNOWN_BAD;
            file_known = true;
        }
    }

    env->ReleaseStringUTFChars(hash, (const char *) md5);

    return (int) file_known;
}

/*
 * Class:     org_sleuthkit_datamodel_SleuthkitJNI
 * Method:    hashDbLookupVerbose
 * Signature: (Ljava/lang/String;)I
 */
JNIEXPORT jobject JNICALL Java_org_sleuthkit_datamodel_SleuthkitJNI_hashDbLookupVerbose
(JNIEnv * env, jclass obj, jstring hash, jint dbHandle) {
    jobject object = NULL;
    SQliteHashStruct * hdata = NULL;

    if((size_t) dbHandle > m_hashDbs.size()) {
        setThrowTskCoreError(env, "Invalid database handle");
        return NULL;
    }

    jboolean isCopy;
    const char *inputHash = (const char *) env->GetStringUTFChars(hash, &isCopy);

    TSK_HDB_INFO * db = m_hashDbs.at(dbHandle-1);
    if (db != NULL) {
        // tsk_hdb_lookup_str will also make sure the index struct is setup
        int64_t hashId = tsk_hdb_lookup_str_id(db, inputHash);

        if ((hashId > 0) && (db->idx_info->getAllData != NULL)) {
            // Find the data associated with this hash
            hdata = (SQliteHashStruct *)(db->idx_info->getAllData(db, hashId));

            // Build the Java version of the HashInfo object
            jclass clazz;
            clazz = env->FindClass("org/sleuthkit/datamodel/HashInfo");
            // get methods
            jmethodID ctor = env->GetMethodID(clazz, "<init>", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V");
            jmethodID addName = env->GetMethodID(clazz, "addName", "(Ljava/lang/String;)V");
            jmethodID addComment = env->GetMethodID(clazz, "addComment", "(Ljava/lang/String;)V");

            //convert hashes
            const char *md5 = hdata->hashMd5.c_str();
            jstring md5j = env->NewStringUTF(md5);
            
            const char *sha1 = hdata->hashSha1.c_str();
            jstring sha1j = env->NewStringUTF(sha1);
            
            const char *sha256 = hdata->hashSha2_256.c_str();
            jstring sha256j = env->NewStringUTF(sha256);

            // make the object
            object = env->NewObject(clazz, ctor, md5j, sha1j, sha256j);

            // finish populating the object
            std::vector<std::string>::iterator name_it = hdata->names.begin();
            for (; name_it != hdata->names.end(); ++name_it) {
                const char *name = name_it->c_str();
                jstring namej = env->NewStringUTF(name);
                env->CallVoidMethod(object, addName, namej);
            }

            std::vector<std::string>::iterator comment_it = hdata->comments.begin();
            for (; comment_it != hdata->comments.end(); ++comment_it) {
                const char *comment = comment_it->c_str();
                jstring commentj = env->NewStringUTF(comment);
                env->CallVoidMethod(object, addComment, commentj);
            }

        }
    }

    // Cleanup
    env->ReleaseStringUTFChars(hash, (const char *) inputHash);
    delete hdata;

    return object;
}

/*
 * Create an add-image process that can later be run with specific inputs
 * @return the pointer to the process or NULL on error
 * @param env pointer to java environment this was called from
 * @partam caseHandle pointer to case to add image to
 * @param timezone timezone for the image
 * @param addUnallocSpace whether to process unallocated filesystem blocks and volumes in the image
 * @param noFatFsOrphans whether to skip processing orphans on FAT filesystems
 */
JNIEXPORT jlong JNICALL
    Java_org_sleuthkit_datamodel_SleuthkitJNI_initAddImgNat(JNIEnv * env,
    jclass obj, jlong caseHandle, jstring timezone, jboolean addUnallocSpace, jboolean noFatFsOrphans) {
    jboolean isCopy;

    TskCaseDb *tskCase = castCaseDb(env, caseHandle);
    if (tskCase == 0) {
        //exception already set
        return 0;
    }

    if (env->GetStringUTFLength(timezone) > 0) {
        const char *tzstr = env->GetStringUTFChars(timezone, &isCopy);

        if (strlen(tzstr) > 64) {
            env->ReleaseStringUTFChars(timezone, tzstr);
            stringstream ss;
            ss << "Timezone is too long";
            setThrowTskCoreError(env, ss.str().c_str());
            return 0;
        }

        char envstr[70];
        snprintf(envstr, 70, "TZ=%s", tzstr);
        env->ReleaseStringUTFChars(timezone, tzstr);

        if (0 != putenv(envstr)) {
            stringstream ss;
            ss << "Error setting timezone environment, using: ";
            ss << envstr;
            setThrowTskCoreError(env, ss.str().c_str());
            return 0;
        }

        /* we should be checking this somehow */
        TZSET();
    }

    TskAutoDb *tskAuto = tskCase->initAddImage();
    if (tskAuto == NULL) {
        setThrowTskCoreError(env, "Error getting tskAuto handle from initAddImage");
        return 0;
    }

    // set the options flags
    if (addUnallocSpace) {
        tskAuto->setAddUnallocSpace(true, 500*1024*1024);
    }
    else {
        tskAuto->setAddUnallocSpace(false);
    }
    tskAuto->setNoFatFsOrphans(noFatFsOrphans?true:false);

    // we don't use the block map and it slows it down
    tskAuto->createBlockMap(false);

    // ingest modules calc hashes
    tskAuto->hashFiles(false);

    return (jlong) tskAuto;
}



/*
 * Create a database for the given image using a pre-created process which can be cancelled.
 * MUST call commitAddImg or revertAddImg afterwards once runAddImg returns.  If there is an 
 * error, you do not need to call revert or commit and the 'process' handle will be deleted.
 * @return the 0 for success 1 for failure
 * @param env pointer to java environment this was called from
 * @param obj the java object this was called from
 * @param process the add-image process created by initAddImgNat
 * @param paths array of strings from java, the paths to the image parts
 * @param num_imgs number of image parts
 * @param timezone the timezone the image is from
 */
JNIEXPORT void JNICALL
    Java_org_sleuthkit_datamodel_SleuthkitJNI_runAddImgNat(JNIEnv * env,
    jclass obj, jlong process, jobjectArray paths, jint num_imgs, jstring timezone) {
    jboolean isCopy;

    TskAutoDb *tskAuto = ((TskAutoDb *) process);
    if (!tskAuto || tskAuto->m_tag != TSK_AUTO_TAG) {
        setThrowTskCoreError(env,
            "runAddImgNat: Invalid TskAutoDb object passed in");
        return;
    }


    // move the strings into the C++ world

    // get pointers to each of the file names
    char **imagepaths8 = (char **) tsk_malloc(num_imgs * sizeof(char *));
    if (imagepaths8 == NULL) {
        setThrowTskCoreError(env);
        return;
    }
    for (int i = 0; i < num_imgs; i++) {
        jstring jsPath = (jstring) env->GetObjectArrayElement(paths,
                i);
        imagepaths8[i] =
            (char *) env->
            GetStringUTFChars(jsPath, &isCopy);
        if (imagepaths8[i] == NULL) {
            setThrowTskCoreError(env,
                "runAddImgNat: Can't convert path strings.");
            // @@@ should cleanup here paths that have been converted in imagepaths8[i]
            return;
        }
    }
    
    if (env->GetStringLength(timezone) > 0) {
        const char * tzchar = env->
            GetStringUTFChars(timezone, &isCopy);

        tskAuto->setTz(string(tzchar));
        env->ReleaseStringUTFChars(timezone, tzchar);
    }

    // process the image (parts)
    uint8_t ret = 0;
    if ( (ret = tskAuto->startAddImage((int) num_imgs, imagepaths8,
        TSK_IMG_TYPE_DETECT, 0)) != 0) {
        stringstream msgss;
        msgss << "Errors occured while ingesting image " << std::endl;
        vector<TskAuto::error_record> errors = tskAuto->getErrorList();
        for (size_t i = 0; i < errors.size(); i++) {
            msgss << (i+1) << ". ";
            msgss << (TskAuto::errorRecordToString(errors[i]));
            msgss << " " << std::endl;
        }

        if (ret == 1) {
            //fatal error
            setThrowTskCoreError(env, msgss.str().c_str());
        }
        else if (ret == 2) {
            //non fatal error
            setThrowTskDataError(env, msgss.str().c_str());
        }
    }

    // @@@ SHOULD WE CLOSE HERE before we commit / revert etc.
    //close image first before freeing the image paths
    tskAuto->closeImage();

    // cleanup
    for (int i = 0; i < num_imgs; i++) {
        jstring jsPath = (jstring)
            env->GetObjectArrayElement(paths, i);
        env->
            ReleaseStringUTFChars(jsPath, imagepaths8[i]);
        env->DeleteLocalRef(jsPath);
    }
    free(imagepaths8);

    // if process completes successfully, must call revertAddImgNat or commitAddImgNat to free the TskAutoDb
}



/*
 * Cancel the given add-image process.
 * @param env pointer to java environment this was called from
 * @param obj the java object this was called from
 * @param process the add-image process created by initAddImgNat
 */
JNIEXPORT void JNICALL
    Java_org_sleuthkit_datamodel_SleuthkitJNI_stopAddImgNat(JNIEnv * env,
    jclass obj, jlong process) {
    TskAutoDb *tskAuto = ((TskAutoDb *) process);
    if (!tskAuto || tskAuto->m_tag != TSK_AUTO_TAG) {
        setThrowTskCoreError(env,
            "stopAddImgNat: Invalid TskAutoDb object passed in");
        return;
    }
    tskAuto->stopAddImage();
}


/*
 * Revert the given add-image process.  Deletes the 'process' handle.
 * @param env pointer to java environment this was called from
 * @param obj the java object this was called from
 * @param process the add-image process created by initAddImgNat
 */
JNIEXPORT void JNICALL
    Java_org_sleuthkit_datamodel_SleuthkitJNI_revertAddImgNat(JNIEnv * env,
    jclass obj, jlong process) {
    TskAutoDb *tskAuto = ((TskAutoDb *) process);
    if (!tskAuto || tskAuto->m_tag != TSK_AUTO_TAG) {
        setThrowTskCoreError(env,
            "revertAddImgNat: Invalid TskAutoDb object passed in");
        return;
    }
    if (tskAuto->revertAddImage()) {
        setThrowTskCoreError(env);
        return;
    }
    delete tskAuto;
    tskAuto = 0;
}


/*
 * Commit the given add-image process. Deletes the 'process' handle.
 * @param env pointer to java environment this was called from
 * @param obj the java object this was called from
 * @param process the add-image process created by initAddImgNat
 */
JNIEXPORT jlong JNICALL
    Java_org_sleuthkit_datamodel_SleuthkitJNI_commitAddImgNat(JNIEnv * env,
    jclass obj, jlong process) {
    TskAutoDb *tskAuto = ((TskAutoDb *) process);
    if (!tskAuto || tskAuto->m_tag != TSK_AUTO_TAG) {
        setThrowTskCoreError(env,
             "commitAddImgNat: Invalid TskAutoDb object passed in");
        return -1;
    }
    int64_t imgId = tskAuto->commitAddImage();
    delete tskAuto;
    tskAuto = 0;
    if (imgId == -1) {
        setThrowTskCoreError(env);
        return -1;
    }
    return imgId;
}



/*
 * Open an image pointer for the given image
 * @return the created TSK_IMG_INFO pointer
 * @param env pointer to java environment this was called from
 * @param obj the java object this was called from
 * @param paths the paths to the image parts
 * @param num_imgs number of image parts
 */
JNIEXPORT jlong JNICALL
    Java_org_sleuthkit_datamodel_SleuthkitJNI_openImgNat(JNIEnv * env,
    jclass obj, jobjectArray paths, jint num_imgs) {
    TSK_IMG_INFO *img_info;
    jboolean isCopy;

    // get pointers to each of the file names
    char **imagepaths8 = (char **) tsk_malloc(num_imgs * sizeof(char *));
    if (imagepaths8 == NULL) {
        setThrowTskCoreError(env);
        return 0;
    }
    for (int i = 0; i < num_imgs; i++) {
        imagepaths8[i] =
            (char *) env->
            GetStringUTFChars((jstring) env->GetObjectArrayElement(paths,
                i), &isCopy);
        // @@@ Error check
    }

    // open the image
    img_info =
        tsk_img_open_utf8((int) num_imgs, imagepaths8, TSK_IMG_TYPE_DETECT,
        0);
    if (img_info == NULL) {
        setThrowTskCoreError(env, tsk_error_get());
    }

    // cleanup
    for (int i = 0; i < num_imgs; i++) {
        env->
            ReleaseStringUTFChars((jstring)
            env->GetObjectArrayElement(paths, i), imagepaths8[i]);
    }
    free(imagepaths8);

    return (jlong) img_info;
}



/*
 * Open the volume system at the given offset
 * @return the created TSK_VS_INFO pointer
 * @param env pointer to java environment this was called from
 * @param obj the java object this was called from
 * @param a_img_info the pointer to the parent img object
 * @param vsOffset the offset of the volume system in bytes
 */
JNIEXPORT jlong JNICALL Java_org_sleuthkit_datamodel_SleuthkitJNI_openVsNat
    (JNIEnv * env, jclass obj, jlong a_img_info, jlong vsOffset) {
    TSK_IMG_INFO *img_info = castImgInfo(env, a_img_info);
    if (img_info == 0) {
        //exception already set
        return 0;
    }
    TSK_VS_INFO *vs_info;

    vs_info = tsk_vs_open(img_info, vsOffset, TSK_VS_TYPE_DETECT);
    if (vs_info == NULL) {
        setThrowTskCoreError(env, tsk_error_get());
    }
    return (jlong) vs_info;
}


/*
 * Open volume with the given id from the given volume system
 * @return the created TSK_VS_PART_INFO pointer
 * @param env pointer to java environment this was called from
 * @param obj the java object this was called from
 * @param a_vs_info the pointer to the parent vs object
 * @param vol_id the id of the volume to get
 */
JNIEXPORT jlong JNICALL
Java_org_sleuthkit_datamodel_SleuthkitJNI_openVolNat(JNIEnv * env,
    jclass obj, jlong a_vs_info, jlong vol_id)
{
    TSK_VS_INFO *vs_info = castVsInfo(env, a_vs_info);
    if (vs_info == 0) {
        //exception already set
        return 0;
    }
    const TSK_VS_PART_INFO *vol_part_info;

    vol_part_info = tsk_vs_part_get(vs_info, (TSK_PNUM_T) vol_id);
    if (vol_part_info == NULL) {
        setThrowTskCoreError(env, tsk_error_get());
    }
    return (jlong) vol_part_info;
}


/*
 * Open file system with the given offset
 * @return the created TSK_FS_INFO pointer
 * @param env pointer to java environment this was called from
 * @param obj the java object this was called from
 * @param a_img_info the pointer to the parent img object
 * @param fs_offset the offset in bytes to the file system 
 */
JNIEXPORT jlong JNICALL Java_org_sleuthkit_datamodel_SleuthkitJNI_openFsNat
    (JNIEnv * env, jclass obj, jlong a_img_info, jlong fs_offset) {
    TSK_IMG_INFO *img_info = castImgInfo(env, a_img_info);
    if (img_info == 0) {
        //exception already set
        return 0;
    }
    TSK_FS_INFO *fs_info;

    fs_info =
        tsk_fs_open_img(img_info, (TSK_OFF_T) fs_offset,
        TSK_FS_TYPE_DETECT);
    if (fs_info == NULL) {
        setThrowTskCoreError(env, tsk_error_get());
    }
    return (jlong) fs_info;
}


/*
 * Open the file with the given id in the given file system
 * @return the created TSK_JNI_FILEHANDLE pointer, set throw exception on error
 * @param env pointer to java environment this was called from
 * @param obj the java object this was called from
 * @param a_fs_info the pointer to the parent file system object
 * @param file_id id of the file to open
 * @param attr_type type of the file attribute to open
 * @param attr_id id of the file attribute to open
 */
JNIEXPORT jlong JNICALL
Java_org_sleuthkit_datamodel_SleuthkitJNI_openFileNat(JNIEnv * env,
    jclass obj, jlong a_fs_info, jlong file_id, jint attr_type, jint attr_id)
{
    TSK_FS_INFO *fs_info = castFsInfo(env, a_fs_info);
    if (fs_info == 0) {
        //exception already set
        return 0;
    }

	
    TSK_FS_FILE *file_info;
    //open file
    file_info = tsk_fs_file_open_meta(fs_info, NULL, (TSK_INUM_T) file_id);
    if (file_info == NULL) {
        setThrowTskCoreError(env, tsk_error_get());
        return 0;
    }

    //open attribute
    const TSK_FS_ATTR * tsk_fs_attr = 
        tsk_fs_file_attr_get_type(file_info, (TSK_FS_ATTR_TYPE_ENUM)attr_type, (uint16_t)attr_id, 1);
    if (tsk_fs_attr == NULL) {
        tsk_fs_file_close(file_info);
        setThrowTskCoreError(env, tsk_error_get());
        return 0;
    }

    //allocate file handle structure to encapsulate file and attribute
    TSK_JNI_FILEHANDLE * fileHandle = 
        (TSK_JNI_FILEHANDLE *) tsk_malloc(sizeof(TSK_JNI_FILEHANDLE));
    if (fileHandle == NULL) {
        tsk_fs_file_close(file_info);
        setThrowTskCoreError(env, "Could not allocate memory for TSK_JNI_FILEHANDLE");
        return 0;
    }

    fileHandle->tag = TSK_JNI_FILEHANDLE_TAG;
    fileHandle->fs_file = file_info;
    fileHandle->fs_attr = const_cast<TSK_FS_ATTR*>(tsk_fs_attr);

    return (jlong)fileHandle;
}


/** move a local buffer into a new Java array.
 * @param env JNI env
 * @param buf Buffer to copy from
 * @param len Length of bytes in buf
 * @returns Pointer to newly created java byte array or NULL if there is an error
 */
#if 0
static jbyteArray
copyBufToByteArray(JNIEnv * env, const char *buf, ssize_t len)
{
    jbyteArray return_array = env->NewByteArray(len);
    if (return_array == NULL) {
        setThrowTskCoreError(env, "NewByteArray returned error while getting an array to copy buffer into.");
        return 0;
    }
    env->SetByteArrayRegion(return_array, 0, len, (jbyte*)buf);

    return return_array;
}
#endif

/** move a local buffer into an existing Java array.
 * @param env JNI env
 * @param jbuf Buffer to copy to
 * @param buf Buffer to copy from
 * @param len Length of bytes in buf
 * @returns number of bytes copied or -1 on error
 */
inline static ssize_t
copyBufToByteArray(JNIEnv * env, jbyteArray jbuf, const char *buf, ssize_t len)
{
    env->SetByteArrayRegion(jbuf, 0, len, (jbyte*)buf);
    return len;
}

/*
 * Read bytes from the given image
 * @return number of bytes read from the image, -1 on error
 * @param env pointer to java environment this was called from
 * @param obj the java object this was called from
 * @param a_img_info the pointer to the image object
 * @param offset the offset in bytes to start at
 * @param len number of bytes to read
 */
JNIEXPORT jint JNICALL
Java_org_sleuthkit_datamodel_SleuthkitJNI_readImgNat(JNIEnv * env,
    jclass obj, jlong a_img_info, jbyteArray jbuf, jlong offset, jlong len)
{
    //use fixed size stack-allocated buffer if possible
    char fixed_buf [FIXED_BUF_SIZE];

    char * buf = fixed_buf;
    bool dynBuf = false;
    if (len > FIXED_BUF_SIZE) {
        dynBuf = true;
        buf = (char *) tsk_malloc((size_t) len);
        if (buf == NULL) {
            setThrowTskCoreError(env);
            return -1;
        }
    }

    TSK_IMG_INFO *img_info = castImgInfo(env, a_img_info);
    if (img_info == 0) {
        if (dynBuf) {
            free(buf);
        }
        //exception already set
        return -1;
    }

    ssize_t bytesread =
        tsk_img_read(img_info, (TSK_OFF_T) offset, buf, (size_t) len);
    if (bytesread == -1) {
        if (dynBuf) {
            free(buf);
        }
        setThrowTskCoreError(env, tsk_error_get());
        return -1;
    }

    // package it up for return
    // adjust number bytes to copy
    ssize_t copybytes = bytesread;
    jsize jbuflen = env->GetArrayLength(jbuf);
    if (jbuflen < copybytes)
        copybytes = jbuflen;

    ssize_t copiedbytes = copyBufToByteArray(env, jbuf, buf, copybytes);
    if (dynBuf) {
        free(buf);
    }
	if (copiedbytes == -1) {
        setThrowTskCoreError(env, tsk_error_get());
    }
    return copiedbytes;
}


/*
 * Read bytes from the given volume system
 * @return number of bytes read from the volume system, -1 on error
 * @param env pointer to java environment this was called from
 * @param obj the java object this was called from
 * @param a_vs_info the pointer to the volume system object
 * @param offset the offset in bytes to start at
 * @param len number of bytes to read
 */
JNIEXPORT jint JNICALL
Java_org_sleuthkit_datamodel_SleuthkitJNI_readVsNat(JNIEnv * env,
    jclass obj, jlong a_vs_info, jbyteArray jbuf, jlong offset, jlong len)
{
    //use fixed size stack-allocated buffer if possible
    char fixed_buf [FIXED_BUF_SIZE];

    char * buf = fixed_buf;
    bool dynBuf = false;
    if (len > FIXED_BUF_SIZE) {
        dynBuf = true;
        buf = (char *) tsk_malloc((size_t) len);
        if (buf == NULL) {
            setThrowTskCoreError(env);
            return -1;
        }
    }

    TSK_VS_INFO *vs_info = castVsInfo(env, a_vs_info);
    if (vs_info == 0) {
        //exception already set
        if (dynBuf) {
            free(buf);
        }
        return -1;
    }

    ssize_t bytesread = tsk_vs_read_block(vs_info, (TSK_DADDR_T) offset, buf,
        (size_t) len);
    if (bytesread == -1) {
        setThrowTskCoreError(env, tsk_error_get());
        if (dynBuf) {
            free(buf);
        }
        return -1;
    }

    // package it up for return
	// adjust number bytes to copy
    ssize_t copybytes = bytesread;
    jsize jbuflen = env->GetArrayLength(jbuf);
    if (jbuflen < copybytes)
        copybytes = jbuflen;

    ssize_t copiedbytes = copyBufToByteArray(env, jbuf, buf, copybytes);
    if (dynBuf) {
        free(buf);
    }
    if (copiedbytes == -1) {
        setThrowTskCoreError(env, tsk_error_get());
    }
    return copiedbytes;
}


/*
 * Read bytes from the given volume
 * @return number of bytes read from the volume or -1 on error
 * @param env pointer to java environment this was called from
 * @param obj the java object this was called from
 * @param a_vol_info the pointer to the volume object
 * @param offset the offset in bytes to start at
 * @param len number of bytes to read
 */

JNIEXPORT jint JNICALL
Java_org_sleuthkit_datamodel_SleuthkitJNI_readVolNat(JNIEnv * env,
    jclass obj, jlong a_vol_info, jbyteArray jbuf, jlong offset, jlong len)
{
    //use fixed size stack-allocated buffer if possible
    char fixed_buf [FIXED_BUF_SIZE];

    char * buf = fixed_buf;
    bool dynBuf = false;
    if (len > FIXED_BUF_SIZE) {
        dynBuf = true;
        buf = (char *) tsk_malloc((size_t) len);
        if (buf == NULL) {
            setThrowTskCoreError(env);
            return -1;
        }
    }

    TSK_VS_PART_INFO *vol_part_info = castVsPartInfo(env, a_vol_info);
    if (vol_part_info == 0) {
        if (dynBuf) {
            free(buf);
        }
        //exception already set
        return -1;
    }
    ssize_t bytesread =
        tsk_vs_part_read(vol_part_info, (TSK_OFF_T) offset, buf,
        (size_t) len);
    if (bytesread == -1) {
        setThrowTskCoreError(env, tsk_error_get());
        if (dynBuf) {
            free(buf);
        }
        return -1;
    }

    // package it up for return
    // adjust number bytes to copy
    ssize_t copybytes = bytesread;
    jsize jbuflen = env->GetArrayLength(jbuf);
    if (jbuflen < copybytes)
        copybytes = jbuflen;

    ssize_t copiedbytes = copyBufToByteArray(env, jbuf, buf, copybytes);
    if (dynBuf) {
        free(buf);
    }
    if (copiedbytes == -1) {
        setThrowTskCoreError(env, tsk_error_get());
    }
    return copiedbytes;
}


/*
 * Read bytes from the given file system
 * @return number of bytes read from the file system, -1 on error
 * @param env pointer to java environment this was called from
 * @param obj the java object this was called from
 * @param a_fs_info the pointer to the file system object
 * @param offset the offset in bytes to start at
 * @param len number of bytes to read
 */
JNIEXPORT jint JNICALL
Java_org_sleuthkit_datamodel_SleuthkitJNI_readFsNat(JNIEnv * env,
    jclass obj, jlong a_fs_info, jbyteArray jbuf, jlong offset, jlong len)
{
    //use fixed size stack-allocated buffer if possible
    char fixed_buf [FIXED_BUF_SIZE];

    char * buf = fixed_buf;
    bool dynBuf = false;
    if (len > FIXED_BUF_SIZE) {
        dynBuf = true;
        buf = (char *) tsk_malloc((size_t) len);
        if (buf == NULL) {
            setThrowTskCoreError(env);
            return -1;
        }
    }

    TSK_FS_INFO *fs_info = castFsInfo(env, a_fs_info);
    if (fs_info == 0) {
        if (dynBuf) {
            free(buf);
        }
        //exception already set
        return -1;
    }

    ssize_t bytesread =
        tsk_fs_read(fs_info, (TSK_OFF_T) offset, buf, (size_t) len);
    if (bytesread == -1) {
        if (dynBuf) {
            free(buf);
        }
        setThrowTskCoreError(env, tsk_error_get());
        return -1;
    }

    // package it up for return
    // adjust number bytes to copy
    ssize_t copybytes = bytesread;
    jsize jbuflen = env->GetArrayLength(jbuf);
    if (jbuflen < copybytes)
        copybytes = jbuflen;

    ssize_t copiedbytes = copyBufToByteArray(env, jbuf, buf, copybytes);
    if (dynBuf) {
        free(buf);
    }
    if (copiedbytes == -1) {
        setThrowTskCoreError(env, tsk_error_get());
    }
    return copiedbytes;
}



/*
 * Read bytes from the given file
 * @return number of bytes read, or -1 on error
 * @param env pointer to java environment this was called from
 * @param obj the java object this was called from
 * @param a_file_handle the pointer to the TSK_JNI_FILEHANDLE object
 * @param jbuf jvm allocated buffer to read to
 * @param offset the offset in bytes to start at
 * @param len number of bytes to read
 */
JNIEXPORT jint JNICALL
Java_org_sleuthkit_datamodel_SleuthkitJNI_readFileNat(JNIEnv * env,
    jclass obj, jlong a_file_handle, jbyteArray jbuf, jlong offset, jlong len)
{
	//use fixed size stack-allocated buffer if possible
    char fixed_buf [FIXED_BUF_SIZE];

    char * buf = fixed_buf;
    bool dynBuf = false;
    if (len > FIXED_BUF_SIZE) {
        dynBuf = true;
        buf = (char *) tsk_malloc((size_t) len);
        if (buf == NULL) {
            setThrowTskCoreError(env);
            return -1;
        }
    }

    const TSK_JNI_FILEHANDLE *file_handle = castFsFile(env, a_file_handle);
    if (file_handle == 0) {
        if (dynBuf) {
            free(buf);
        }
        //exception already set
        return -1;
    }

    TSK_FS_ATTR * tsk_fs_attr = file_handle->fs_attr;

    //read attribute
    ssize_t bytesread = tsk_fs_attr_read(tsk_fs_attr,  (TSK_OFF_T) offset, buf, (size_t) len,
        TSK_FS_FILE_READ_FLAG_NONE);
    if (bytesread == -1) {
        if (dynBuf) {
            free(buf);
        }
        setThrowTskCoreError(env, tsk_error_get());
        return -1;
    }

    // package it up for return
    // adjust number bytes to copy
	ssize_t copybytes = bytesread;
	jsize jbuflen = env->GetArrayLength(jbuf);
	if (jbuflen < copybytes)
		copybytes = jbuflen;

    ssize_t copiedbytes = copyBufToByteArray(env, jbuf, buf, copybytes);
    if (dynBuf) {
        free(buf);
    }
    if (copiedbytes == -1) {
        setThrowTskCoreError(env, tsk_error_get());
    }
    return copiedbytes;
}


/*
 * Close the given image
 * @param env pointer to java environment this was called from
 * @param obj the java object this was called from
 * @param a_img_info the pointer to the image object
 */
JNIEXPORT void JNICALL
Java_org_sleuthkit_datamodel_SleuthkitJNI_closeImgNat(JNIEnv * env,
    jclass obj, jlong a_img_info)
{
    TSK_IMG_INFO *img_info = castImgInfo(env, a_img_info);
    if (img_info == 0) {
        //exception already set
        return;
    }
    tsk_img_close(img_info);
}

/*
 * Close the given volume system
 * @param env pointer to java environment this was called from
 * @param obj the java object this was called from
 * @param a_vs_info the pointer to the volume system object
 */
JNIEXPORT void JNICALL Java_org_sleuthkit_datamodel_SleuthkitJNI_closeVsNat
    (JNIEnv * env, jclass obj, jlong a_vs_info) {
    TSK_VS_INFO *vs_info = castVsInfo(env, a_vs_info);
    if (vs_info == 0) {
        //exception already set
        return;
    }
    tsk_vs_close(vs_info);
}

/*
 * Close the given volume system
 * @param env pointer to java environment this was called from
 * @param obj the java object this was called from
 * @param a_fs_info the pointer to the file system object
 */
JNIEXPORT void JNICALL Java_org_sleuthkit_datamodel_SleuthkitJNI_closeFsNat
    (JNIEnv * env, jclass obj, jlong a_fs_info) {
    TSK_FS_INFO *fs_info = castFsInfo(env, a_fs_info);
    if (fs_info == 0) {
        //exception already set
        return;
    }
    tsk_fs_close(fs_info);
}

/*
 * Close the given file
 * @param env pointer to java environment this was called from
 * @param obj the java object this was called from
 * @param a_file_info the pointer to the file object
 */
JNIEXPORT void JNICALL
Java_org_sleuthkit_datamodel_SleuthkitJNI_closeFileNat(JNIEnv * env,
    jclass obj, jlong a_file_info)
{
    TSK_JNI_FILEHANDLE *file_handle = castFsFile(env, a_file_info);
    if (file_handle == 0) {
        //exception already set
        return;
    }
	
    TSK_FS_FILE * file_info = file_handle->fs_file;
    tsk_fs_file_close(file_info); //also closes the attribute

    file_handle->fs_file = NULL;
    file_handle->fs_attr = NULL;
    file_handle->tag = 0;
    free (file_handle);
}

/*
 * Get the current Sleuthkit version number
 * @return the version string
 * @param env pointer to java environment this was called from
 * @param obj the java object this was called from
 */
JNIEXPORT jstring JNICALL
Java_org_sleuthkit_datamodel_SleuthkitJNI_getVersionNat(JNIEnv * env,
    jclass obj)
{
    const char *cversion = tsk_version_get_str();
    jstring jversion = (*env).NewStringUTF(cversion);
    return jversion;
}

/*
 * Get the current directory being analyzed during AddImage
 * @return the path of the current directory
 *
 */
JNIEXPORT jstring JNICALL
    Java_org_sleuthkit_datamodel_SleuthkitJNI_getCurDirNat
    (JNIEnv * env,jclass obj, jlong dbHandle)
{
    TskAutoDb *tskAuto = ((TskAutoDb *) dbHandle);
    const std::string curDir = tskAuto->getCurDir();
    jstring jdir = (*env).NewStringUTF(curDir.c_str());
    return jdir;
}

/*
 * Enable verbose logging and redirect stderr to the given log file.
 * @param env pointer to java environment this was called from
 * @param obj the java object this was called from
 * @param logPath The log file to append to.
 */
JNIEXPORT void JNICALL
Java_org_sleuthkit_datamodel_SleuthkitJNI_startVerboseLoggingNat
    (JNIEnv * env, jclass obj, jstring logPath)
{
    jboolean isCopy;
    char *str8 = (char *) env->GetStringUTFChars(logPath, &isCopy);
    if (freopen(str8, "a", stderr) == NULL) {
        env->ReleaseStringUTFChars(logPath, str8);
        setThrowTskCoreError(env, "Couldn't open verbose log file for appending.");
        return;
    }
    env->ReleaseStringUTFChars(logPath, str8);
    tsk_verbose++;
}


/*
 * Create an index for the given database
 * @param env pointer to java environment this was called from
 * @param obj the java object this was called from
 * @param overwrite flag indicating if the old db (if it exists) can be deleted
 * @param dbHandle handle for the database
 */
JNIEXPORT void JNICALL
Java_org_sleuthkit_datamodel_SleuthkitJNI_hashDbCreateIndexNat (JNIEnv * env,
    jclass obj, jint dbHandle, jboolean overwrite)
{
    if((size_t) dbHandle > m_hashDbs.size()) {
        setThrowTskCoreError(env, "Invalid database handle");
        return;
    } else {
        TSK_HDB_INFO * db = m_hashDbs.at(dbHandle-1);
        if (db == NULL) {
            setThrowTskCoreError(env, "Error: database object is null");
            return;
        }

        if (db->db_type == TSK_HDB_DBTYPE_IDXONLY_ID) {
            setThrowTskCoreError(env, "Error: index only");
            return;
        }

        TSK_TCHAR dbType[1024];

        if(db->db_type == TSK_HDB_DBTYPE_MD5SUM_ID) {
            TSNPRINTF(dbType, 1024, _TSK_T("%") PRIcTSK, TSK_HDB_DBTYPE_MD5SUM_STR);
        }
        else if(db->db_type == TSK_HDB_DBTYPE_HK_ID) {
            TSNPRINTF(dbType, 1024, _TSK_T("%") PRIcTSK, TSK_HDB_DBTYPE_HK_STR);
        }
        else if(db->db_type == TSK_HDB_DBTYPE_ENCASE_ID) {
            TSNPRINTF(dbType, 1024, _TSK_T("%") PRIcTSK, TSK_HDB_DBTYPE_ENCASE_STR);
        }
        else {
            TSNPRINTF(dbType, 1024, _TSK_T("%") PRIcTSK, TSK_HDB_DBTYPE_NSRL_MD5_STR);
        }
  
        // [Re]create the hash information and file
        if (tsk_hdb_regenerate_index(db, dbType, (overwrite ? 1 : 0)) == 0) {
            setThrowTskCoreError(env, "Error: index regeneration");
            return;
        }

        return;
    }
}


/*
 * Check if a lookup index exists for the given hash database.
 * @param env pointer to java environment this was called from
 * @param obj the java object this was called from
 * @param dbHandle handle for the database
 */
JNIEXPORT jboolean JNICALL Java_org_sleuthkit_datamodel_SleuthkitJNI_hashDbIndexExistsNat
  (JNIEnv * env, jclass obj, jint dbHandle) {

    if((size_t) dbHandle > m_hashDbs.size()) {
        setThrowTskCoreError(env, "Invalid database handle");
        return (jboolean) false;
    } else {
        TSK_HDB_INFO * temp = m_hashDbs.at(dbHandle-1);
        if (temp == NULL) {
            return (jboolean) false;
        }

        uint8_t retval = tsk_hdb_hasindex(temp, TSK_HDB_HTYPE_MD5_ID);

        return (jboolean) retval == 1;
    }
}

///*
// * Get the size of the index for the database at the given path
// * @param env pointer to java environment this was called from
// * @param obj the java object this was called from
// * @param dbPathJ the path for the database
// * @return -1 on error, otherwise size of index
// */
//JNIEXPORT jint JNICALL Java_org_sleuthkit_datamodel_SleuthkitJNI_getIndexSizeNat
//  (JNIEnv * env, jclass obj, jstring dbPathJ) {
//
//    TSK_TCHAR dbPathT[1024];
//    toTCHAR(env, dbPathT, 1024, dbPathJ);
//
//    TSK_HDB_OPEN_ENUM flags = TSK_HDB_OPEN_IDXONLY;
//    TSK_HDB_INFO * temp = tsk_hdb_open(dbPathT, flags);
//    if (temp == NULL) {
//        return -1;
//    }
//
//    if(tsk_hdb_idxsetup(temp, TSK_HDB_HTYPE_MD5_ID)) {
//        return (jint) ((temp->idx_info->idx_struct.idx_binsrch->idx_size - temp->idx_info->idx_struct.idx_binsrch->idx_off) / (temp->idx_info->idx_struct.idx_binsrch->idx_llen));
//    }
//
//
//    tsk_hdb_close(temp);
//    return -1;
//}


/*
 * Query and get size of the device (such as physical disk, or image) pointed by the path
 * Might require elevated priviletes to work (otherwise will error)
 * @param env pointer to java environment this was called from
 * @param obj the java object this was called from
 * @param devPathJ the device path
 * @return size of device, set throw jni exception on error
 */
JNIEXPORT jlong JNICALL Java_org_sleuthkit_datamodel_SleuthkitJNI_findDeviceSizeNat
  (JNIEnv * env, jclass obj, jstring devPathJ) {
     
      jlong devSize = 0;
      const char* devPath = env->GetStringUTFChars(devPathJ, 0);

      // open the image to get the size
      TSK_IMG_INFO * img_info =
        tsk_img_open_utf8_sing(devPath, TSK_IMG_TYPE_DETECT, 0);
      if (img_info == NULL) {
        setThrowTskCoreError(env, tsk_error_get());
        env->ReleaseStringUTFChars(devPathJ , devPath); 
        return -1;
      }

      TSK_OFF_T imgSize = img_info->size;
      devSize = imgSize;

      //cleanup
      tsk_img_close(img_info);
      env->ReleaseStringUTFChars(devPathJ , devPath); 

      return devSize;
}
