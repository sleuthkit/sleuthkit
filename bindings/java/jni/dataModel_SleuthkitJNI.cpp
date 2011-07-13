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
#include "jni.h"
#include "dataModel_SleuthkitJNI.h"
#include "tskAutoDbJNI.h"
#include <locale.h>
#include <time.h>


TskAutoDbJNI::TskAutoDbJNI(){
    m_cancelled = false;
    TskAutoDb::TskAutoDb();
}

/**
 * Overriden processFile method to stop processing files if the 
 * cancelProcess method is called
 * @return STOP if cancelled otherwise use return value from super class
 * @param fs_file file details
 * @param path full path of parent directory
 */
TSK_RETVAL_ENUM 
TskAutoDbJNI::processFile(TSK_FS_FILE * fs_file,
                                          const char *path) {
    if(m_cancelled)
        return TSK_STOP;
    else
        return TskAutoDb::processFile(fs_file, path);
}
/**
 * Cancel the running process
 */
void TskAutoDbJNI::cancelProcess(){
    m_cancelled = true;
}


static void throwTskError(JNIEnv *env, const char *msg){
    jclass exception;
    exception = env->FindClass("org/sleuthkit/datamodel/TskException");

    env->ThrowNew(exception, msg);
}

/* Throw and exception to java
 * @param the java environment to send the exception to
 */
static void throwTskError(JNIEnv *env){
    const char* msg = tsk_error_get();
    throwTskError(env, msg);
}

/*
 * Create a database for the given image (process cannot be cancelled)
 * @return the 0 for success 1 for failure
 * @param env pointer to java environment this was called from
 * @param obj the java object this was called from
 * @param paths array of strings from java, the paths to the image parts
 * @param num_imgs number of image parts
 * @param outDir the output directory
 */
JNIEXPORT jlong JNICALL Java_org_sleuthkit_datamodel_SleuthkitJNI_loaddbNat
(JNIEnv *env, jclass obj, jobjectArray paths, jint num_imgs, jstring outDir){
    TskAutoDb tskDb;
    //change to true when autopsy needs the block table.
    tskDb.createBlockMap(false);

#ifdef TSK_WIN32
    jboolean isCopy;
    char *cOutDir8 = (char *)env->GetStringUTFChars(outDir, &isCopy);

    if(cOutDir8 == NULL){
        throwTskError(env);
        return NULL;
    }
    // get pointers to each of the file names
    char ** imagepaths8 = (char**) tsk_malloc(num_imgs * sizeof(char *));
    if(imagepaths8 == NULL){
        throwTskError(env);
        return NULL;
    }
    for(int i =0; i < num_imgs; i++){
        imagepaths8[i] = (char *)env->GetStringUTFChars((jstring)env->GetObjectArrayElement(paths, i), &isCopy);
    }

    if (tskDb.openImageUtf8(num_imgs, imagepaths8, TSK_IMG_TYPE_DETECT, 0, cOutDir8)) {
        tsk_error_print(stderr);
        throwTskError(env);
        return 1;
    }
#else
#error "Only Win32 is currently supported"
#endif

    if (tskDb.addFilesInImgToDB()) {
        tsk_error_print(stderr);
        throwTskError(env);
        return 1;
    }
    for(int i = 0; i < num_imgs; i++){
        env->ReleaseStringUTFChars((jstring)env->GetObjectArrayElement(paths, i), imagepaths8[i]);
    }
    free(imagepaths8);
    
    env->ReleaseStringUTFChars(outDir, cOutDir8);
    tskDb.closeImage();
    return 0;
}

/*
 * Create a loaddb process that can later be run with specific inputs
 * @return the pointer to the process
 * @param env pointer to java environment this was called from
 * @param timezone timezone for the image
 */
JNIEXPORT jlong JNICALL Java_org_sleuthkit_datamodel_SleuthkitJNI_startloaddbNat
(JNIEnv *env, jclass obj, jstring timezone){
    jboolean isCopy;
    char envstr[32];
    _snprintf(envstr, 32, ("TZ=%s"), (char *)env->GetStringUTFChars(timezone, &isCopy));
    if (0 != _putenv(envstr)) { 
        throwTskError(env); 
        return 1; }

    /* we should be checking this somehow */
    TZSET();
    TskAutoDbJNI *tskDb = new TskAutoDbJNI();
    return (jlong)tskDb;
}

/*
 * Create a database for the given image using a pre-created process which can be cancelled
 * @return the 0 for success 1 for failure
 * @param env pointer to java environment this was called from
 * @param obj the java object this was called from
 * @param process the loaddb proces created by startloaddbNat
 * @param paths array of strings from java, the paths to the image parts
 * @param num_imgs number of image parts
 * @param outDir the output directory
 */
JNIEXPORT void JNICALL Java_org_sleuthkit_datamodel_SleuthkitJNI_runloaddbNat
(JNIEnv * env, jclass obj, jlong process, jobjectArray paths, jint num_imgs, jstring outDir){
    jboolean isCopy;

    
    TskAutoDbJNI * tskDb = ((TskAutoDbJNI*)process);

    //change to true when autopsy needs the block table.
    tskDb->createBlockMap(false);
#ifdef TSK_WIN32
    char *cOutDir8 = (char *)env->GetStringUTFChars(outDir, &isCopy);

    if(cOutDir8 == NULL){
        throwTskError(env);
        return;
    }
    // get pointers to each of the file names
    char ** imagepaths8 = (char**) tsk_malloc(num_imgs * sizeof(char *));
    if(imagepaths8 == NULL){
        throwTskError(env);
        return;
    }
    for(int i =0; i < num_imgs; i++){
        imagepaths8[i] = (char *)env->GetStringUTFChars((jstring)env->GetObjectArrayElement(paths, i), &isCopy);
    }
#else
#error "Only Win32 is currently supported
#endif

    if (tskDb->openImageUtf8((int)num_imgs, imagepaths8, TSK_IMG_TYPE_DETECT, 0, cOutDir8)) {
        tskDb->closeImage();
        throwTskError(env);
    }

    if (tskDb->addFilesInImgToDB()) {
        tskDb->closeImage();
        tsk_error_print(stderr);
        throwTskError(env);
        
    }
    for(int i = 0; i < num_imgs; i++){
        env->ReleaseStringUTFChars((jstring)env->GetObjectArrayElement(paths, i), imagepaths8[i]);
    }
    free(imagepaths8);
    
    env->ReleaseStringUTFChars(outDir, cOutDir8);
    tskDb->closeImage();
}

/*
 * Cancel the given loaddb process
 * @param env pointer to java environment this was called from
 * @param obj the java object this was called from
 * @param process the loaddb proces created by startloaddbNat
 */
JNIEXPORT void JNICALL Java_org_sleuthkit_datamodel_SleuthkitJNI_stoploaddbNat
(JNIEnv * env, jclass obj, jlong process){
    ((TskAutoDbJNI*)process)->cancelProcess();  
}




/*
 * Open an image pointer for the given image
 * @return the created TSK_IMG_INFO pointer
 * @param env pointer to java environment this was called from
 * @param obj the java object this was called from
 * @param paths the paths to the image parts
 * @param num_imgs number of image parts
 */
JNIEXPORT jlong JNICALL Java_org_sleuthkit_datamodel_SleuthkitJNI_openImageNat
(JNIEnv *env, jclass obj, jobjectArray paths, jint num_imgs){
    TSK_IMG_INFO * img_info;
        jboolean isCopy;
#ifdef TSK_WIN32
    // get pointers to each of the file names
    char ** imagepaths8 = (char**) tsk_malloc(num_imgs * sizeof(char *));
    if(imagepaths8 == NULL){
        throwTskError(env);
        return NULL;
    }
    for(int i =0; i < num_imgs; i++){
        imagepaths8[i] = (char *)env->GetStringUTFChars((jstring)env->GetObjectArrayElement(paths, i), &isCopy);
    }

#else
#error Only Win32 is currently supported
#endif
    img_info = tsk_img_open_utf8((int)num_imgs, imagepaths8, TSK_IMG_TYPE_DETECT, 0);

    for(int i = 0; i < num_imgs; i++){
        env->ReleaseStringUTFChars((jstring)env->GetObjectArrayElement(paths, i), imagepaths8[i]);
    }
    free(imagepaths8);
    if(img_info == NULL){
        throwTskError(env);
    }
    return (jlong)img_info;
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
(JNIEnv * env, jclass obj, jlong a_img_info, jlong vsOffset){ 
    TSK_IMG_INFO * img_info = (TSK_IMG_INFO *) a_img_info;
    TSK_VS_INFO * vs_info;

    vs_info = tsk_vs_open(img_info, vsOffset, TSK_VS_TYPE_DETECT);
    if(vs_info == NULL){
        throwTskError(env);
    }
    return (jlong)vs_info;
}

/*
 * Open volume with the given id from the given volume system
 * @return the created TSK_VS_PART_INFO pointer
 * @param env pointer to java environment this was called from
 * @param obj the java object this was called from
 * @param a_vs_info the pointer to the parent vs object
 * @param vol_id the id of the volume to get
 */
JNIEXPORT jlong JNICALL Java_org_sleuthkit_datamodel_SleuthkitJNI_openVolNat
(JNIEnv * env, jclass obj, jlong a_vs_info, jlong vol_id){
    TSK_VS_INFO * vs_info = (TSK_VS_INFO *) a_vs_info;
    TSK_VS_PART_INFO * vol_info;
    vol_info = (TSK_VS_PART_INFO *) tsk_vs_part_get(vs_info, (TSK_PNUM_T) vol_id);
    if(vol_info == NULL){
        throwTskError(env);
    }
    return (jlong)vol_info;
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
(JNIEnv * env, jclass obj, jlong a_img_info, jlong fs_offset){
    TSK_IMG_INFO * img = (TSK_IMG_INFO *) a_img_info;
    TSK_FS_INFO * fs_info;

    fs_info = tsk_fs_open_img(img, (TSK_OFF_T) fs_offset /** img->sector_size*/, TSK_FS_TYPE_DETECT);
    if(fs_info == NULL){
        throwTskError(env);
        return NULL;
    }
    return (jlong)fs_info;
}

/*
 * Open the file with the given id in the given file system
 * @return the created TSK_FS_FILE pointer
 * @param env pointer to java environment this was called from
 * @param obj the java object this was called from
 * @param a_fs_info the pointer to the parent file system object
 * @param file_id id of the file to open 
 */
JNIEXPORT jlong JNICALL Java_org_sleuthkit_datamodel_SleuthkitJNI_openFileNat
(JNIEnv * env, jclass obj, jlong a_fs_info, jlong file_id){
    TSK_FS_INFO * fs_info = (TSK_FS_INFO *) a_fs_info;
    TSK_FS_FILE * file_info;

    if (fs_info->tag != TSK_FS_INFO_TAG) {
        throwTskError(env, "openFile: Invalid FS_INFO object"); 
        return NULL;
    }

    file_info = tsk_fs_file_open_meta(fs_info, NULL, (TSK_INUM_T) file_id);    if(file_info == NULL){        throwTskError(env);
    }
    return (jlong)file_info;
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
JNIEXPORT jbyteArray JNICALL Java_org_sleuthkit_datamodel_SleuthkitJNI_readImgNat
(JNIEnv * env, jclass obj, jlong a_img_info, jlong offset, jlong len){
    char * buf = (char *) tsk_malloc((size_t)len);
    if(buf == NULL){
        throwTskError(env);
        return NULL;
    }
    TSK_IMG_INFO * img_info = (TSK_IMG_INFO *) a_img_info;

    ssize_t retval = tsk_img_read(img_info, (TSK_OFF_T) offset, buf, (size_t) len);

    if (retval != -1){
        jbyteArray return_array = env->NewByteArray(retval);

        jbyte * jBytes = env->GetByteArrayElements(return_array, 0);

        for(int i = 0; i<(retval); i++){
            jBytes[i] = buf[i];
        }

        env->ReleaseByteArrayElements(return_array, jBytes, 0);
        free(buf);
        return return_array;
    }
    else{
        throwTskError(env);
    }
    free(buf);
    return NULL;
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
JNIEXPORT jbyteArray JNICALL Java_org_sleuthkit_datamodel_SleuthkitJNI_readVsNat
(JNIEnv * env, jclass obj, jlong a_vs_info, jlong offset, jlong len){
    char * buf = (char *) tsk_malloc((size_t) len);
    if(buf == NULL){
        throwTskError(env);
        return NULL;
    }
    TSK_VS_INFO * vs_info = (TSK_VS_INFO *) a_vs_info;

    ssize_t retval = tsk_vs_read_block(vs_info, (TSK_DADDR_T) offset, buf, (size_t) len);

    if (retval != -1){
        jbyteArray return_array = env->NewByteArray(retval);

        jbyte * jBytes = env->GetByteArrayElements(return_array, 0);

        for(int i = 0; i<(retval); i++){
            jBytes[i] = buf[i];
        }

        env->ReleaseByteArrayElements(return_array, jBytes, 0);
        free(buf);
        return return_array;
    }
    else{
        throwTskError(env);
    }
    free(buf);
    return NULL;
}
/*
 * Read bytes from the given volume
 * @return array of bytes read from the volume
 * @param env pointer to java environment this was called from
 * @param obj the java object this was called from
 * @param a_vol_info the pointer to the volume object
 * @param offset the offset in bytes to start at
 * @param len number of bytes to read
 */

JNIEXPORT jbyteArray JNICALL Java_org_sleuthkit_datamodel_SleuthkitJNI_readVolNat
(JNIEnv * env, jclass obj, jlong a_vol_info, jlong offset, jlong len){
    char * buf = (char *) tsk_malloc((size_t) len);
    if(buf == NULL){
        throwTskError(env);
        return NULL;
    }
    TSK_VS_PART_INFO * vol_info = (TSK_VS_PART_INFO *) a_vol_info;

    ssize_t retval = tsk_vs_part_read(vol_info, (TSK_OFF_T) offset, buf, (size_t) len);

    if (retval != -1){
        jbyteArray return_array = env->NewByteArray(retval);

        jbyte * jBytes = env->GetByteArrayElements(return_array, 0);

        for(int i = 0; i<(retval); i++){
            jBytes[i] = buf[i];
        }

        env->ReleaseByteArrayElements(return_array, jBytes, 0);
        free(buf);
        return return_array;
    }
    else{
        throwTskError(env);
    }
    free(buf);
    return NULL;
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
JNIEXPORT jbyteArray JNICALL Java_org_sleuthkit_datamodel_SleuthkitJNI_readFsNat
(JNIEnv * env, jclass obj, jlong a_fs_info, jlong offset, jlong len){
    char * buf = (char *) tsk_malloc((size_t) len);
    if(buf == NULL){
        throwTskError(env);
        return NULL;
    }
    TSK_FS_INFO * fs_info = (TSK_FS_INFO *) a_fs_info;
    if (fs_info->tag != TSK_FS_INFO_TAG) {
        throwTskError(env, "readFsNat: Invalid TSK_FS_INFO object");
        return NULL;
    }

    ssize_t retval = tsk_fs_read(fs_info, (TSK_OFF_T) offset, buf, (size_t) len);

    if (retval != -1){
        jbyteArray return_array = env->NewByteArray(retval);

        jbyte * jBytes = env->GetByteArrayElements(return_array, 0);

        for(int i = 0; i<(retval); i++){
            jBytes[i] = buf[i];
        }

        env->ReleaseByteArrayElements(return_array, jBytes, 0);
        free(buf);
        return return_array;
    }
    else{
        throwTskError(env);
    }
    free(buf);
    return NULL;
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
JNIEXPORT jbyteArray JNICALL Java_org_sleuthkit_datamodel_SleuthkitJNI_readFileNat
(JNIEnv * env, jclass obj, jlong a_file_info, jlong offset, jlong len){
    char * buf = (char *) tsk_malloc((size_t) len);
    if(buf == NULL){
        throwTskError(env);
        return NULL;
    }
    TSK_FS_FILE * file_info = (TSK_FS_FILE *) a_file_info;
    if (file_info->tag != TSK_FS_FILE_TAG) {
        throwTskError(env, "readFile: Invalid TSK_FS_FILE address");
        return NULL;
    }

    ssize_t retval = tsk_fs_file_read(file_info, (TSK_OFF_T) offset, buf, (size_t) len, TSK_FS_FILE_READ_FLAG_NONE);

    if (retval != -1){
        jbyteArray return_array = env->NewByteArray(retval);

        jbyte * jBytes = env->GetByteArrayElements(return_array, 0);

        for(int i = 0; i<(retval); i++){
            jBytes[i] = buf[i];
        }

        env->ReleaseByteArrayElements(return_array, jBytes, 0);
        free(buf);
        return return_array;
    }
    else{
        throwTskError(env);
    }
    free(buf);
    return NULL;
}

/*
 * Close the given image
 * @param env pointer to java environment this was called from
 * @param obj the java object this was called from
 * @param a_img_info the pointer to the image object
 */
JNIEXPORT void JNICALL Java_org_sleuthkit_datamodel_SleuthkitJNI_closeImgNat
(JNIEnv * env, jclass obj, jlong a_img_info){
    tsk_img_close((TSK_IMG_INFO *) a_img_info);
}

/*
 * Close the given volume system
 * @param env pointer to java environment this was called from
 * @param obj the java object this was called from
 * @param a_vs_info the pointer to the volume system object
 */
JNIEXPORT void JNICALL Java_org_sleuthkit_datamodel_SleuthkitJNI_closeVsNat
(JNIEnv *env, jclass obj, jlong a_vs_info){
    tsk_vs_close((TSK_VS_INFO *) a_vs_info);
}

/*
 * Close the given volume system
 * @param env pointer to java environment this was called from
 * @param obj the java object this was called from
 * @param a_fs_info the pointer to the file system object
 */
JNIEXPORT void JNICALL Java_org_sleuthkit_datamodel_SleuthkitJNI_closeFsNat
(JNIEnv * env, jclass obj, jlong a_fs_info){
    TSK_FS_INFO *fs_info = (TSK_FS_INFO *)a_fs_info;
    if (fs_info->tag != TSK_FS_INFO_TAG) {
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
JNIEXPORT void JNICALL Java_org_sleuthkit_datamodel_SleuthkitJNI_closeFileNat
(JNIEnv * env, jclass obj, jlong a_file_info){
    TSK_FS_FILE *file_info = (TSK_FS_FILE *)a_file_info;
    if (file_info->tag != TSK_FS_FILE_TAG) {
        return;
    }
    tsk_fs_file_close(file_info);
}

/*
 * Get the current Sleuthkit version number
 * @return the version string
 * @param env pointer to java environment this was called from
 * @param obj the java object this was called from
 */
JNIEXPORT jstring JNICALL Java_org_sleuthkit_datamodel_SleuthkitJNI_getVersionNat
(JNIEnv * env, jclass obj){
    const char * cversion = tsk_version_get_str();
    jstring jversion = (*env).NewStringUTF(cversion);
    return jversion; 
}
