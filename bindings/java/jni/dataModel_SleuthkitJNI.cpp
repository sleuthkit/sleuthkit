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
    Java_org_sleuthkit_datamodel_SleuthkitJNI_setCaseDbNSRLNat(JNIEnv * env,
    jclass obj, jlong caseHandle, jstring pathJ) {

    TskCaseDb *tskCase = castCaseDb(env, caseHandle);

    TSK_TCHAR pathT[1024];
    toTCHAR(env, pathT, 1024, pathJ);

    tskCase->setNSRLHashDb(pathT);
    return;
}

/*
 * Set the "known bad" database to use for hash lookups.
 * @param env pointer to java environment this was called from
 * @param obj the java object this was called from
 * @param caseHandle the pointer to the case
 */
JNIEXPORT void JNICALL
    Java_org_sleuthkit_datamodel_SleuthkitJNI_setCaseDbKnownBadNat(JNIEnv * env,
    jclass obj, jlong caseHandle, jstring pathJ) {

    TskCaseDb *tskCase = castCaseDb(env, caseHandle);

    TSK_TCHAR pathT[1024];
    toTCHAR(env, pathT, 1024, pathJ);

    tskCase->setKnownBadHashDb(pathT);
    return;
}


JNIEXPORT void JNICALL
    Java_org_sleuthkit_datamodel_SleuthkitJNI_clearCaseDbLookupsNat(JNIEnv * env,
    jclass obj, jlong caseHandle) {

    TskCaseDb *tskCase = castCaseDb(env, caseHandle);
    tskCase->clearLookupDatabases();
}

/*
 * Create an add-image process that can later be run with specific inputs
 * @return the pointer to the process
 * @param env pointer to java environment this was called from
 * @partam caseHandle pointer to case to add image to
 * @param timezone timezone for the image
 */
JNIEXPORT jlong JNICALL
    Java_org_sleuthkit_datamodel_SleuthkitJNI_initAddImgNat(JNIEnv * env,
    jclass obj, jlong caseHandle, jstring timezone) {
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
 * @param outDir the output directory
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
    tskAuto->hashFiles(true);

    

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
        throwTskError(env, tsk_error_get());
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
    tskAuto->revertAddImage();
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


/** move a local buffer into a Java array.
 * @param env JNI env
 * @param buf Buffer to copy from
 * @param len Length of bytes in buf
 * @returns Pointer to java byte array or NULL if there is an error
 */
static jbyteArray
copyBufToByteArray(JNIEnv * env, const char *buf, ssize_t len)
{
    jbyteArray return_array = env->NewByteArray(len);
    if (return_array == NULL) {
        throwTskError(env, "NewByteArray returned error while getting an array to copy buffer into.");
        return NULL;
    }

    jbyte * jBytes= env->GetByteArrayElements(return_array, 0);
    if (jBytes == NULL) {
        throwTskError(env, "GetByteArrayElements returned error while getting elements to copy buffer into.");   
        return NULL;
    }

    for (int i = 0; i < len; i++) {
        jBytes[i] = buf[i];
    }

    env->ReleaseByteArrayElements(return_array, jBytes, 0);

    return return_array;
}

/*
 * Read bytes from the given image
 * @return array of bytes read from the image
 * @param env pointer to java environment this was called from
 * @param obj the java object this was called from
 * @param a_img_info the pointer to the image object
 * @param offset the offset in bytes to start at
 * @param len number of bytes to read
 */
JNIEXPORT jbyteArray JNICALL
Java_org_sleuthkit_datamodel_SleuthkitJNI_readImgNat(JNIEnv * env,
    jclass obj, jlong a_img_info, jlong offset, jlong len)
{
    char *buf = (char *) tsk_malloc((size_t) len);
    if (buf == NULL) {
        throwTskError(env, tsk_error_get());
        return NULL;
    }

    TSK_IMG_INFO *img_info = castImgInfo(env, a_img_info);

    ssize_t retval =
        tsk_img_read(img_info, (TSK_OFF_T) offset, buf, (size_t) len);
    if (retval == -1) {
        throwTskError(env, tsk_error_get());
    }

    // package it up for return
    jbyteArray return_array = copyBufToByteArray(env, buf, retval);
    free(buf);
    return return_array;
}


/*
 * Read bytes from the given volume system
 * @return array of bytes read from the volume system
 * @param env pointer to java environment this was called from
 * @param obj the java object this was called from
 * @param a_vs_info the pointer to the volume system object
 * @param offset the offset in bytes to start at
 * @param len number of bytes to read
 */
JNIEXPORT jbyteArray JNICALL
Java_org_sleuthkit_datamodel_SleuthkitJNI_readVsNat(JNIEnv * env,
    jclass obj, jlong a_vs_info, jlong offset, jlong len)
{
    char *buf = (char *) tsk_malloc((size_t) len);
    if (buf == NULL) {
        throwTskError(env);
        return NULL;
    }
    TSK_VS_INFO *vs_info = castVsInfo(env, a_vs_info);

    ssize_t retval = tsk_vs_read_block(vs_info, (TSK_DADDR_T) offset, buf,
        (size_t) len);
    if (retval == -1) {
        throwTskError(env, tsk_error_get());
    }

    // package it up for return
    jbyteArray return_array = copyBufToByteArray(env, buf, retval);
    free(buf);
    return return_array;
}


/*
 * Read bytes from the given volume
 * @return array of bytes read from the volume or NULL on error
 * @param env pointer to java environment this was called from
 * @param obj the java object this was called from
 * @param a_vol_info the pointer to the volume object
 * @param offset the offset in bytes to start at
 * @param len number of bytes to read
 */

JNIEXPORT jbyteArray JNICALL
Java_org_sleuthkit_datamodel_SleuthkitJNI_readVolNat(JNIEnv * env,
    jclass obj, jlong a_vol_info, jlong offset, jlong len)
{
    char *buf = (char *) tsk_malloc((size_t) len);
    if (buf == NULL) {
        throwTskError(env);
        return NULL;
    }

    TSK_VS_PART_INFO *vol_part_info = castVsPartInfo(env, a_vol_info);

    ssize_t retval =
        tsk_vs_part_read(vol_part_info, (TSK_OFF_T) offset, buf,
        (size_t) len);
    if (retval == -1) {
        throwTskError(env, tsk_error_get());
        free(buf);
        return NULL;
    }

    // package it up for return
    jbyteArray return_array = copyBufToByteArray(env, buf, retval);
    // no point checking for error. copyBufToByteArray will call throwTskError and return NULL itself

    free(buf);
    return return_array;
}


/*
 * Read bytes from the given file system
 * @return array of bytes read from the file system
 * @param env pointer to java environment this was called from
 * @param obj the java object this was called from
 * @param a_fs_info the pointer to the file system object
 * @param offset the offset in bytes to start at
 * @param len number of bytes to read
 */
JNIEXPORT jbyteArray JNICALL
Java_org_sleuthkit_datamodel_SleuthkitJNI_readFsNat(JNIEnv * env,
    jclass obj, jlong a_fs_info, jlong offset, jlong len)
{
    char *buf = (char *) tsk_malloc((size_t) len);
    if (buf == NULL) {
        throwTskError(env);
        return NULL;
    }
    TSK_FS_INFO *fs_info = castFsInfo(env, a_fs_info);

    ssize_t retval =
        tsk_fs_read(fs_info, (TSK_OFF_T) offset, buf, (size_t) len);
    if (retval == -1) {
        throwTskError(env, tsk_error_get());
    }

    // package it up for return
    jbyteArray return_array = copyBufToByteArray(env, buf, retval);
    free(buf);
    return return_array;
}


/*
 * Read bytes from the given file
 * @return array of bytes read from the file
 * @param env pointer to java environment this was called from
 * @param obj the java object this was called from
 * @param a_file_info the pointer to the file object
 * @param offset the offset in bytes to start at
 * @param len number of bytes to read
 */
JNIEXPORT jbyteArray JNICALL
Java_org_sleuthkit_datamodel_SleuthkitJNI_readFileNat(JNIEnv * env,
    jclass obj, jlong a_file_info, jlong offset, jlong len)
{
    char *buf = (char *) tsk_malloc((size_t) len);
    if (buf == NULL) {
        throwTskError(env);
        return NULL;
    }

    TSK_FS_FILE *file_info = castFsFile(env, a_file_info);

    ssize_t retval =
        tsk_fs_file_read(file_info, (TSK_OFF_T) offset, buf, (size_t) len,
        TSK_FS_FILE_READ_FLAG_NONE);
    if (retval == -1) {
        throwTskError(env, tsk_error_get());
    }

    // package it up for return
    jbyteArray return_array = copyBufToByteArray(env, buf, retval);
    free(buf);
    return return_array;
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
        return;
    }

    TSK_TCHAR dbType[1024];
    TSNPRINTF(dbType, 1024, _TSK_T("%") PRIcTSK, TSK_HDB_DBTYPE_NSRL_MD5_STR);

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
    
