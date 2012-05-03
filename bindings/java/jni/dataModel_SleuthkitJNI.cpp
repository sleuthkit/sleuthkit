/*
 ** dataModel_SleuthkitJNI
 ** The Sleuth Kit 
 **
 ** Brian Carrier [carrier <at> sleuthkit [dot] org]
 ** Copyright (c) 2010-2011 Brian Carrier.  All Rights reserved
 **
 ** This software is distributed under the Common Public License 1.0
 **
 */
#include "tsk3/tsk_tools_i.h"
#include "tsk3/auto/tsk_case_db.h"
#include "jni.h"
#include "dataModel_SleuthkitJNI.h"
#include <locale.h>
#include <time.h>
#include <string>

static TSK_HDB_INFO * m_NSRLDb = NULL;
static TSK_HDB_INFO * m_knownBadDb = NULL;

/** Throw an TSK exception back up to the Java code with a specific message.
 */
static void
throwTskError(JNIEnv * env, const char *msg)
{
    jclass exception;
    exception = env->FindClass("org/sleuthkit/datamodel/TskException");

    env->ThrowNew(exception, msg);
}

/* Throw and exception to java
 * @param the java environment to send the exception to
 */
static void
throwTskError(JNIEnv * env)
{
    const char *msg = tsk_error_get();
    throwTskError(env, msg);
}


/***** Methods to cast from jlong to data type and check tags
 They all throw an exception if the incorrect type is passed in. *****/
static TSK_IMG_INFO *
castImgInfo(JNIEnv * env, jlong ptr)
{
    TSK_IMG_INFO *lcl = (TSK_IMG_INFO *) ptr;
    if (lcl->tag != TSK_IMG_INFO_TAG) {
        throwTskError(env, "Invalid IMG_INFO object");
    }
    return lcl;
}


static TSK_VS_INFO *
castVsInfo(JNIEnv * env, jlong ptr)
{
    TSK_VS_INFO *lcl = (TSK_VS_INFO *) ptr;
    if (lcl->tag != TSK_VS_INFO_TAG) {
        throwTskError(env, "Invalid VS_INFO object");
    }

    return lcl;
}

static TSK_VS_PART_INFO *
castVsPartInfo(JNIEnv * env, jlong ptr)
{
    TSK_VS_PART_INFO *lcl = (TSK_VS_PART_INFO *) ptr;
    if (lcl->tag != TSK_VS_PART_INFO_TAG) {
        throwTskError(env, "Invalid VS_PART_INFO object");
    }

    return lcl;
}

static TSK_FS_INFO *
castFsInfo(JNIEnv * env, jlong ptr)
{
    TSK_FS_INFO *lcl = (TSK_FS_INFO *) ptr;
    if (lcl->tag != TSK_FS_INFO_TAG) {
        throwTskError(env, "Invalid FS_INFO object");
    }
    return lcl;
}


static TSK_FS_FILE *
castFsFile(JNIEnv * env, jlong ptr)
{
    TSK_FS_FILE *lcl = (TSK_FS_FILE *) ptr;
    if (lcl->tag != TSK_FS_FILE_TAG) {
        throwTskError(env, "Invalid FS_FILE object");
    }
    return lcl;
}

static TskCaseDb * 
castCaseDb(JNIEnv * env, jlong ptr)
{
    TskCaseDb *lcl = ((TskCaseDb *) ptr);
    if (lcl->m_tag != TSK_CASE_DB_TAG) {
        throwTskError(env,
            "Invalid TskCaseDb object");
    }

    return lcl;
}

static int
toTCHAR(JNIEnv * env, TSK_TCHAR * buffer, size_t size, jstring strJ)
{
    jboolean isCopy;
    char *str8 = (char *) env->GetStringUTFChars(strJ, &isCopy);

    return TSNPRINTF(buffer, size, _TSK_T("%") PRIcTSK, str8);
}


/*
 * Open a TskCaseDb with an associated database
 * @return the pointer to the case
 * @param env pointer to java environment this was called from
 * @param dbPath location for the database
 * @rerurns NULL on error
 */
JNIEXPORT jlong JNICALL
    Java_org_sleuthkit_datamodel_SleuthkitJNI_newCaseDbNat(JNIEnv * env,
    jclass obj, jstring dbPathJ) {

    TSK_TCHAR dbPathT[1024];
    toTCHAR(env, dbPathT, 1024, dbPathJ);

    TskCaseDb *tskCase = TskCaseDb::newDb(dbPathT);

    if (tskCase == NULL) {
        throwTskError(env);
        return NULL;               
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
        throwTskError(env);
        return NULL;
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

    delete tskCase;
    return;
}

/*
 * Set the NSRL database to use for hash lookups.
 * @param env pointer to java environment this was called from
 * @param obj the java object this was called from
 * @param caseHandle the pointer to the case
 */
JNIEXPORT void JNICALL
    Java_org_sleuthkit_datamodel_SleuthkitJNI_setDbNSRLNat(JNIEnv * env,
    jclass obj, jstring pathJ) {

    if (m_NSRLDb != NULL) {
        tsk_hdb_close(m_NSRLDb);
        m_NSRLDb = NULL;
    }
    TSK_TCHAR pathT[1024];
    toTCHAR(env, pathT, 1024, pathJ);

    TSK_HDB_OPEN_ENUM flags = TSK_HDB_OPEN_IDXONLY;
    m_NSRLDb = tsk_hdb_open(pathT, flags);
    
    return;
}

/*
 * Set the "known bad" database to use for hash lookups.
 * @param env pointer to java environment this was called from
 * @param obj the java object this was called from
 * @param caseHandle the pointer to the case
 */
JNIEXPORT void JNICALL
    Java_org_sleuthkit_datamodel_SleuthkitJNI_setDbKnownBadNat(JNIEnv * env,
    jclass obj, jstring pathJ) {

    if (m_knownBadDb != NULL) {
        tsk_hdb_close(m_knownBadDb);
        m_knownBadDb = NULL;
    }

    TSK_TCHAR pathT[1024];
    toTCHAR(env, pathT, 1024, pathJ);

    TSK_HDB_OPEN_ENUM flags = TSK_HDB_OPEN_IDXONLY;
    m_knownBadDb = tsk_hdb_open(pathT, flags);
}


JNIEXPORT void JNICALL
    Java_org_sleuthkit_datamodel_SleuthkitJNI_closeDbLookupsNat(JNIEnv * env,
    jclass obj) {

    if (m_NSRLDb != NULL) {
        tsk_hdb_close(m_NSRLDb);
        m_NSRLDb = NULL;
    }

    if (m_knownBadDb != NULL) {
        tsk_hdb_close(m_knownBadDb);
        m_knownBadDb = NULL;
    }
}

/*
 * Class:     org_sleuthkit_datamodel_SleuthkitJNI
 * Method:    hashDBLookup
 * Signature: (Ljava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_org_sleuthkit_datamodel_SleuthkitJNI_hashDBLookup
(JNIEnv * env, jclass obj, jstring hash){

    jboolean isCopy;

    const char *md5 = (const char *) env->GetStringUTFChars(hash, &isCopy);

    TSK_AUTO_CASE_KNOWN_FILE_ENUM file_known = TSK_AUTO_CASE_FILE_KNOWN_UNKNOWN;

    if (m_NSRLDb != NULL) {
        int8_t retval = tsk_hdb_lookup_str(m_NSRLDb, md5, TSK_HDB_FLAG_QUICK, NULL, NULL);

        if (retval == -1) {
            throwTskError(env);
        } else if (retval) {
            file_known = TSK_AUTO_CASE_FILE_KNOWN_KNOWN;
        }
    }

    if (m_knownBadDb != NULL) {
        int8_t retval = tsk_hdb_lookup_str(m_knownBadDb, md5, TSK_HDB_FLAG_QUICK, NULL, NULL);

        if (retval == -1) {
            throwTskError(env);
        } else if (retval) {
            file_known = TSK_AUTO_CASE_FILE_KNOWN_BAD;
        }
    }

    env->ReleaseStringUTFChars(hash, (const char *) md5);

    return (int) file_known;
}

/*
 * Create an add-image process that can later be run with specific inputs
 * @return the pointer to the process
 * @param env pointer to java environment this was called from
 * @partam caseHandle pointer to case to add image to
 * @param timezone timezone for the image
 * @param noFatFsOrphans whether to skip processing orphans on FAT filesystems
 */
JNIEXPORT jlong JNICALL
    Java_org_sleuthkit_datamodel_SleuthkitJNI_initAddImgNat(JNIEnv * env,
    jclass obj, jlong caseHandle, jstring timezone, jboolean noFatFsOrphans) {
    jboolean isCopy;

    TskCaseDb *tskCase = castCaseDb(env, caseHandle);

    char envstr[32];
    snprintf(envstr, 32, "TZ=%s", env->GetStringUTFChars(timezone,
            &isCopy));
    if (0 != putenv(envstr)) {
        throwTskError(env, "Error setting timezone environment");
        return 1;
    }

    /* we should be checking this somehow */
    TZSET();
    TskAutoDb *tskAuto = tskCase->initAddImage();

    const bool noFatFsOrhpansBool = noFatFsOrphans?true:false;
    tskAuto->setNoFatFsOrphans(noFatFsOrhpansBool);

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
 */
JNIEXPORT void JNICALL
    Java_org_sleuthkit_datamodel_SleuthkitJNI_runAddImgNat(JNIEnv * env,
    jclass obj, jlong process, jobjectArray paths, jint num_imgs) {
    jboolean isCopy;

    TskAutoDb *tskAuto = ((TskAutoDb *) process);
    if (tskAuto->m_tag != TSK_AUTO_TAG) {
        throwTskError(env,
            "runAddImgNat: Invalid TskAutoDb object passed in");
        return;
    }

    //change to true when autopsy needs the block table.
    tskAuto->createBlockMap(false);
    //change to false if hashes aren't needed
    tskAuto->hashFiles(false);

    

    // move the strings into the C++ world

    // get pointers to each of the file names
    char **imagepaths8 = (char **) tsk_malloc(num_imgs * sizeof(char *));
    if (imagepaths8 == NULL) {
        throwTskError(env);
        return;
    }
    for (int i = 0; i < num_imgs; i++) {
        imagepaths8[i] =
            (char *) env->
            GetStringUTFChars((jstring) env->GetObjectArrayElement(paths,
                i), &isCopy);
        if (imagepaths8[i] == NULL) {
            throwTskError(env,
                "runAddImgNat: Can't convert path strings.");
            return;
        }
    }

    // flag to free tskAuto if the process is interuppted
    bool deleteProcess = false;

    // process the image (parts)
    if (tskAuto->startAddImage((int) num_imgs, imagepaths8,
            TSK_IMG_TYPE_DETECT, 0)) {
        std::string msg = "Errors occured while ingesting image\n";
        std::vector<TskAuto::error_record> errors = tskAuto->getErrorList();
        for (size_t i = 0; i < errors.size(); i++) {
            msg.append(TskAuto::errorRecordToString(errors[i]));
            msg.append("\n");
        }

        throwTskError(env);
        // @@@ We never get past this point now to do any cleanup
        deleteProcess = true;
    }

    // cleanup
    for (int i = 0; i < num_imgs; i++) {
        env->
            ReleaseStringUTFChars((jstring)
            env->GetObjectArrayElement(paths, i), imagepaths8[i]);
    }
    free(imagepaths8);
    // @@@ SHOULD WE CLOSE HERE before we commit / revert etc.
    tskAuto->closeImage();

    if (deleteProcess) {
        delete tskAuto;
    }
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
    if (tskAuto->m_tag != TSK_AUTO_TAG) {
        throwTskError(env,
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
    if (tskAuto->m_tag != TSK_AUTO_TAG) {
        throwTskError(env,
            "revertAddImgNat: Invalid TskAutoDb object passed in");
        return;
    }
    if (tskAuto->revertAddImage()) {
        throwTskError(env);
        return;
    }
    delete tskAuto;
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
    if (tskAuto->m_tag != TSK_AUTO_TAG) {
        throwTskError(env,
             "commitAddImgNat: Invalid TskAutoDb object passed in");
        return -1;
    }
    int64_t imgId = tskAuto->commitAddImage();
    delete tskAuto;
    if (imgId == -1) {
        throwTskError(env);
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
        throwTskError(env);
        return NULL;
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
        throwTskError(env, tsk_error_get());
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
    TSK_VS_INFO *vs_info;

    vs_info = tsk_vs_open(img_info, vsOffset, TSK_VS_TYPE_DETECT);
    if (vs_info == NULL) {
        throwTskError(env, tsk_error_get());
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
    const TSK_VS_PART_INFO *vol_part_info;

    vol_part_info = tsk_vs_part_get(vs_info, (TSK_PNUM_T) vol_id);
    if (vol_part_info == NULL) {
        throwTskError(env, tsk_error_get());
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
    TSK_FS_INFO *fs_info;

    fs_info =
        tsk_fs_open_img(img_info, (TSK_OFF_T) fs_offset,
        TSK_FS_TYPE_DETECT);
    if (fs_info == NULL) {
        throwTskError(env, tsk_error_get());
    }
    return (jlong) fs_info;
}


/*
 * Open the file with the given id in the given file system
 * @return the created TSK_FS_FILE pointer
 * @param env pointer to java environment this was called from
 * @param obj the java object this was called from
 * @param a_fs_info the pointer to the parent file system object
 * @param file_id id of the file to open 
 */
JNIEXPORT jlong JNICALL
Java_org_sleuthkit_datamodel_SleuthkitJNI_openFileNat(JNIEnv * env,
    jclass obj, jlong a_fs_info, jlong file_id)
{
    TSK_FS_INFO *fs_info = castFsInfo(env, a_fs_info);
    TSK_FS_FILE *file_info;

    file_info = tsk_fs_file_open_meta(fs_info, NULL, (TSK_INUM_T) file_id);
    if (file_info == NULL) {
        throwTskError(env, tsk_error_get());
    }

    return (jlong) file_info;
}


/** move a local buffer into a new Java array.
 * @param env JNI env
 * @param buf Buffer to copy from
 * @param len Length of bytes in buf
 * @returns Pointer to newly created java byte array or NULL if there is an error
 */
static jbyteArray
copyBufToByteArray(JNIEnv * env, const char *buf, ssize_t len)
{
    jbyteArray return_array = env->NewByteArray(len);
    if (return_array == NULL) {
        throwTskError(env, "NewByteArray returned error while getting an array to copy buffer into.");
        return NULL;
    }
    env->SetByteArrayRegion(return_array, 0, len, (jbyte*)buf);

    return return_array;
}

/** move a local buffer into an existing Java array.
 * @param env JNI env
 * @param jbuf Buffer to copy to
 * @param buf Buffer to copy from
 * @param len Length of bytes in buf
 * @returns number of bytes copied or -1 on error
 */
static ssize_t
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
    char *buf = (char *) tsk_malloc((size_t) len);
    if (buf == NULL) {
        throwTskError(env, tsk_error_get());
        return -1;
    }

    TSK_IMG_INFO *img_info = castImgInfo(env, a_img_info);

    ssize_t bytesread =
        tsk_img_read(img_info, (TSK_OFF_T) offset, buf, (size_t) len);
    if (bytesread == -1) {
        free(buf);
        throwTskError(env, tsk_error_get());
        return -1;
    }

    // package it up for return
    // adjust number bytes to copy
    ssize_t copybytes = bytesread;
    jsize jbuflen = env->GetArrayLength(jbuf);
    if (jbuflen < copybytes)
        copybytes = jbuflen;

    ssize_t copiedbytes = copyBufToByteArray(env, jbuf, buf, copybytes);
    free(buf);
	if (copiedbytes == -1) {
        throwTskError(env, tsk_error_get());
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
    char *buf = (char *) tsk_malloc((size_t) len);
    if (buf == NULL) {
        throwTskError(env);
        return -1;
    }
    TSK_VS_INFO *vs_info = castVsInfo(env, a_vs_info);

    ssize_t bytesread = tsk_vs_read_block(vs_info, (TSK_DADDR_T) offset, buf,
        (size_t) len);
    if (bytesread == -1) {
        throwTskError(env, tsk_error_get());
    }

    // package it up for return
	// adjust number bytes to copy
    ssize_t copybytes = bytesread;
    jsize jbuflen = env->GetArrayLength(jbuf);
    if (jbuflen < copybytes)
        copybytes = jbuflen;

    ssize_t copiedbytes = copyBufToByteArray(env, jbuf, buf, copybytes);
    free(buf);
    if (copiedbytes == -1) {
        throwTskError(env, tsk_error_get());
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
    char *buf = (char *) tsk_malloc((size_t) len);
    if (buf == NULL) {
        throwTskError(env);
        return -1;
    }

    TSK_VS_PART_INFO *vol_part_info = castVsPartInfo(env, a_vol_info);

    ssize_t bytesread =
        tsk_vs_part_read(vol_part_info, (TSK_OFF_T) offset, buf,
        (size_t) len);
    if (bytesread == -1) {
        throwTskError(env, tsk_error_get());
        free(buf);
        return -1;
    }

    // package it up for return
    // adjust number bytes to copy
    ssize_t copybytes = bytesread;
    jsize jbuflen = env->GetArrayLength(jbuf);
    if (jbuflen < copybytes)
        copybytes = jbuflen;

    ssize_t copiedbytes = copyBufToByteArray(env, jbuf, buf, copybytes);
    free(buf);
    if (copiedbytes == -1) {
        throwTskError(env, tsk_error_get());
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
    char *buf = (char *) tsk_malloc((size_t) len);
    if (buf == NULL) {
        throwTskError(env);
        return -1;
    }
    TSK_FS_INFO *fs_info = castFsInfo(env, a_fs_info);

    ssize_t bytesread =
        tsk_fs_read(fs_info, (TSK_OFF_T) offset, buf, (size_t) len);
    if (bytesread == -1) {
        free(buf);
        throwTskError(env, tsk_error_get());
        return -1;
    }

    // package it up for return
    // adjust number bytes to copy
    ssize_t copybytes = bytesread;
    jsize jbuflen = env->GetArrayLength(jbuf);
    if (jbuflen < copybytes)
        copybytes = jbuflen;

    ssize_t copiedbytes = copyBufToByteArray(env, jbuf, buf, copybytes);
    free(buf);
    if (copiedbytes == -1) {
        throwTskError(env, tsk_error_get());
    }
    return copiedbytes;
}



/*
 * Read bytes from the given file
 * @return number of bytes read, or -1 on error
 * @param env pointer to java environment this was called from
 * @param obj the java object this was called from
 * @param a_file_info the pointer to the file object
 * @param jbuf jvm allocated buffer to read to
 * @param offset the offset in bytes to start at
 * @param len number of bytes to read
 */
JNIEXPORT jint JNICALL
Java_org_sleuthkit_datamodel_SleuthkitJNI_readFileNat(JNIEnv * env,
    jclass obj, jlong a_file_info, jbyteArray jbuf, jlong offset, jlong len)
{
    char *buf = (char *) tsk_malloc((size_t) len);
    if (buf == NULL) {
        throwTskError(env);
        return -1;
    }

    TSK_FS_FILE *file_info = castFsFile(env, a_file_info);

    ssize_t bytesread =
        tsk_fs_file_read(file_info, (TSK_OFF_T) offset, buf, (size_t) len,
        TSK_FS_FILE_READ_FLAG_NONE);
    if (bytesread == -1) {
		free(buf);
        throwTskError(env, tsk_error_get());
		return -1;
    }

    // package it up for return
	// adjust number bytes to copy
	ssize_t copybytes = bytesread;
	jsize jbuflen = env->GetArrayLength(jbuf);
	if (jbuflen < copybytes)
		copybytes = jbuflen;

    ssize_t copiedbytes = copyBufToByteArray(env, jbuf, buf, copybytes);
    free(buf);
    if (copiedbytes == -1) {
        throwTskError(env, tsk_error_get());
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
    TSK_FS_FILE *file_info = castFsFile(env, a_file_info);
    tsk_fs_file_close(file_info);
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
        throwTskError(env, "Couldn't open verbose log file for appending.");
        return;
    }
    tsk_verbose++;
}

/*
 * Create an index for the given database path
 * @param env pointer to java environment this was called from
 * @param obj the java object this was called from
 * @param dbPathJ path for the database
 */
JNIEXPORT void JNICALL
Java_org_sleuthkit_datamodel_SleuthkitJNI_createLookupIndexNat (JNIEnv * env,
    jclass obj, jstring dbPathJ)
{
    TSK_TCHAR dbPathT[1024];
    toTCHAR(env, dbPathT, 1024, dbPathJ);

    TSK_HDB_OPEN_ENUM flags = TSK_HDB_OPEN_NONE;
    TSK_HDB_INFO * temp = tsk_hdb_open(dbPathT, flags);
    if (temp == NULL) {
        throwTskError(env);
        return;
    }

    TSK_TCHAR dbType[1024];

    if(temp->db_type == TSK_HDB_DBTYPE_MD5SUM_ID) {
        TSNPRINTF(dbType, 1024, _TSK_T("%") PRIcTSK, TSK_HDB_DBTYPE_MD5SUM_STR);
    }
    else if(temp->db_type == TSK_HDB_DBTYPE_HK_ID) {
        TSNPRINTF(dbType, 1024, _TSK_T("%") PRIcTSK, TSK_HDB_DBTYPE_HK_STR);
    }
    else if(temp->db_type == TSK_HDB_DBTYPE_ENCASE_ID) {
        TSNPRINTF(dbType, 1024, _TSK_T("%") PRIcTSK, TSK_HDB_DBTYPE_ENCASE_STR);
    }
    else {
        TSNPRINTF(dbType, 1024, _TSK_T("%") PRIcTSK, TSK_HDB_DBTYPE_NSRL_MD5_STR);
    }

    if (tsk_hdb_makeindex(temp, dbType)) {
        throwTskError(env);
    }

    tsk_hdb_close(temp);
}

/*
 * Check if an index exists for the given database path.
 * @param env pointer to java environment this was called from
 * @param obj the java object this was called from
 * @param dbPathJ path for the database
 */
JNIEXPORT jboolean JNICALL Java_org_sleuthkit_datamodel_SleuthkitJNI_lookupIndexExistsNat
  (JNIEnv * env, jclass obj, jstring dbPathJ) {

    TSK_TCHAR dbPathT[1024];
    toTCHAR(env, dbPathT, 1024, dbPathJ);

    TSK_HDB_OPEN_ENUM flags = TSK_HDB_OPEN_IDXONLY;
    TSK_HDB_INFO * temp = tsk_hdb_open(dbPathT, flags);
    if (temp == NULL) {
        return (jboolean) false;
    }

    uint8_t retval = tsk_hdb_hasindex(temp, TSK_HDB_HTYPE_MD5_ID);

    tsk_hdb_close(temp);
    return (jboolean) retval == 1;
}
    
