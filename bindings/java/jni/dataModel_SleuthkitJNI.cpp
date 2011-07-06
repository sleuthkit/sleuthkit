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


TSK_RETVAL_ENUM 
TskAutoDbJNI::processFile(TSK_FS_FILE * fs_file,
                                          const char *path) {
    if(m_cancelled)
        return TSK_STOP;
    else
        return TskAutoDb::processFile(fs_file, path);
}
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
 * Class:     datamodel_SleuthkitJNI
 * Method:    loaddb
 * Signature: (Ljava/lang/String;I)J
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
 * Class:     datamodel_SleuthkitJNI
 * Method:    loaddb
 * Signature: (Ljava/lang/String;I)J
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
* Class:     datamodel_SleuthkitJNI
* Method:    runloaddbNat
* Signature: (J)V
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
* Class:     datamodel_SleuthkitJNI
* Method:    runloaddbNat
* Signature: (J)V
*/
JNIEXPORT void JNICALL Java_org_sleuthkit_datamodel_SleuthkitJNI_stoploaddbNat
(JNIEnv * env, jclass obj, jlong process){
    ((TskAutoDbJNI*)process)->cancelProcess();  
}





/*
* Class:     datamodel_SleuthkitJNI
* Method:    openImage
* Signature: (Ljava/lang/String;I)J
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
* Class:     datamodel_SleuthkitJNI
* Method:    openVol
* Signature: (J)J
*/
JNIEXPORT jlong JNICALL Java_org_sleuthkit_datamodel_SleuthkitJNI_openVsNat
(JNIEnv * env, jclass obj, jlong img_info, jlong vsOffset){ 
    TSK_IMG_INFO * img = (TSK_IMG_INFO *) img_info;
    TSK_VS_INFO * vsInfo;

    vsInfo = tsk_vs_open(img, vsOffset, TSK_VS_TYPE_DETECT);
    if(vsInfo == NULL){
        throwTskError(env);
    }
    return (jlong)vsInfo;
}

/*
 * Class:     datamodel_SleuthkitJNI
 * Method:    openVol
 * Signature: (JJ)J
 */
JNIEXPORT jlong JNICALL Java_org_sleuthkit_datamodel_SleuthkitJNI_openVolNat
(JNIEnv * env, jclass obj, jlong vs_info, jlong vol_id){
    TSK_VS_INFO * vsInfo = (TSK_VS_INFO *) vs_info;
    TSK_VS_PART_INFO * volInfo;

    volInfo = (TSK_VS_PART_INFO *) tsk_vs_part_get(vsInfo, (TSK_PNUM_T) vol_id);
    if(volInfo == NULL){
        throwTskError(env);
    }
    return (jlong)volInfo;
}

/*
* Class:     datamodel_SleuthkitJNI
* Method:    openFs
* Signature: (J)J
*/
JNIEXPORT jlong JNICALL Java_org_sleuthkit_datamodel_SleuthkitJNI_openFsNat
(JNIEnv * env, jclass obj, jlong img_info, jlong fs_offset){
    TSK_IMG_INFO * img = (TSK_IMG_INFO *) img_info;
    TSK_FS_INFO * fsInfo;

    fsInfo = tsk_fs_open_img(img, (TSK_OFF_T) fs_offset /** img->sector_size*/, TSK_FS_TYPE_DETECT);
    if(fsInfo == NULL){
        throwTskError(env);
        return NULL;
    }
    return (jlong)fsInfo;
}

/*
* Class:     datamodel_SleuthkitJNI
* Method:    openFile
* Signature: (JJ)J
*/
JNIEXPORT jlong JNICALL Java_org_sleuthkit_datamodel_SleuthkitJNI_openFileNat
(JNIEnv * env, jclass obj, jlong fs_info, jlong file_id){
    TSK_FS_INFO * fs = (TSK_FS_INFO *) fs_info;
    TSK_FS_FILE * file;

    if (fs->tag != TSK_FS_INFO_TAG) {
        throwTskError(env, "openFile: Invalid FS_INFO object"); 
        return NULL;
    }

    file = tsk_fs_file_open_meta(fs, NULL, (TSK_INUM_T) file_id);
    if(file == NULL){
        throwTskError(env);
    }
    return (jlong)file;
}

/*
* Class:     datamodel_SleuthkitJNI
* Method:    readImgNat
* Signature: (JJ)[B
*/
JNIEXPORT jbyteArray JNICALL Java_org_sleuthkit_datamodel_SleuthkitJNI_readImgNat
(JNIEnv * env, jclass obj, jlong img_info, jlong offset, jlong len){
    char * buf = (char *) tsk_malloc((size_t)len);
    if(buf == NULL){
        throwTskError(env);
        return NULL;
    }
    TSK_IMG_INFO * img = (TSK_IMG_INFO *) img_info;

    ssize_t retval = tsk_img_read(img, (TSK_OFF_T) offset, buf, (size_t) len);

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
 * Class:     datamodel_SleuthkitJNI
 * Method:    readVsNat
 * Signature: (JJJ)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_sleuthkit_datamodel_SleuthkitJNI_readVsNat
(JNIEnv * env, jclass obj, jlong vs_info, jlong offset, jlong len){
    char * buf = (char *) tsk_malloc((size_t) len);
    if(buf == NULL){
        throwTskError(env);
        return NULL;
    }
    TSK_VS_INFO * vs = (TSK_VS_INFO *) vs_info;

    ssize_t retval = tsk_vs_read_block(vs, (TSK_DADDR_T) offset, buf, (size_t) len);

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
* Class:     datamodel_SleuthkitJNI
* Method:    readVolNat
* Signature: (JJJ)[B
*/

JNIEXPORT jbyteArray JNICALL Java_org_sleuthkit_datamodel_SleuthkitJNI_readVolNat
(JNIEnv * env, jclass obj, jlong vol_info, jlong offset, jlong len){
    char * buf = (char *) tsk_malloc((size_t) len);
    if(buf == NULL){
        throwTskError(env);
        return NULL;
    }
    TSK_VS_PART_INFO * vs = (TSK_VS_PART_INFO *) vol_info;

    ssize_t retval = tsk_vs_part_read(vs, (TSK_OFF_T) offset, buf, (size_t) len);

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
* Class:     datamodel_SleuthkitJNI
* Method:    readFsNat
* Signature: (JJJ)[B
*/
JNIEXPORT jbyteArray JNICALL Java_org_sleuthkit_datamodel_SleuthkitJNI_readFsNat
(JNIEnv * env, jclass obj, jlong fs_info, jlong offset, jlong len){
    char * buf = (char *) tsk_malloc((size_t) len);
    if(buf == NULL){
        throwTskError(env);
        return NULL;
    }

    TSK_FS_INFO * fs = (TSK_FS_INFO *) fs_info;
    if (fs->tag != TSK_FS_INFO_TAG) {
        throwTskError(env, "readFsNat: Invalid TSK_FS_INFO object");
        return NULL;
    }

    ssize_t retval = tsk_fs_read(fs, (TSK_OFF_T) offset, buf, (size_t) len);

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
* Class:     datamodel_SleuthkitJNI
* Method:    readFileNat
* Signature: (JJJ)[B
*/
JNIEXPORT jbyteArray JNICALL Java_org_sleuthkit_datamodel_SleuthkitJNI_readFileNat
(JNIEnv * env, jclass obj, jlong file_info, jlong offset, jlong len){
    char * buf = (char *) tsk_malloc((size_t) len);
    if(buf == NULL){
        throwTskError(env);
        return NULL;
    }
    TSK_FS_FILE * file = (TSK_FS_FILE *) file_info;
    if (file->tag != TSK_FS_FILE_TAG) {
        throwTskError(env, "readFile: Invalid TSK_FS_FILE address");
        return NULL;
    }

    ssize_t retval = tsk_fs_file_read(file, (TSK_OFF_T) offset, buf, (size_t) len, TSK_FS_FILE_READ_FLAG_NONE);

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
* Class:     datamodel_SleuthkitJNI
* Method:    closeImgNat
* Signature: ()V
*/
JNIEXPORT void JNICALL Java_org_sleuthkit_datamodel_SleuthkitJNI_closeImgNat
(JNIEnv * env, jclass obj, jlong img_info){
    tsk_img_close((TSK_IMG_INFO *) img_info);
}

/*
 * Class:     datamodel_SleuthkitJNI
 * Method:    closeVsNat
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_sleuthkit_datamodel_SleuthkitJNI_closeVsNat
(JNIEnv *env, jclass obj, jlong vsInfo){
    tsk_vs_close((TSK_VS_INFO *) vsInfo);
}

/*
* Class:     datamodel_SleuthkitJNI
* Method:    closeVolNat
* Signature: (J)V
*/
JNIEXPORT void JNICALL Java_org_sleuthkit_datamodel_SleuthkitJNI_closeVolNat
(JNIEnv * env, jclass obj, jlong vol_info){
}

/*
* Class:     datamodel_SleuthkitJNI
* Method:    closeFsNat
* Signature: ()V
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
* Class:     datamodel_SleuthkitJNI
* Method:    closeFileNat
* Signature: (J)V
*/
JNIEXPORT void JNICALL Java_org_sleuthkit_datamodel_SleuthkitJNI_closeFileNat
(JNIEnv * env, jclass obj, jlong file_info){
    TSK_FS_FILE *file = (TSK_FS_FILE *)file_info;
    if (file->tag != TSK_FS_FILE_TAG) {
        return;
    }
    tsk_fs_file_close(file);
}

/*
* Class:     datamodel_SleuthkitJNI
* Method:    getVersionNat
* Signature: ()J
*/
JNIEXPORT jstring JNICALL Java_org_sleuthkit_datamodel_SleuthkitJNI_getVersionNat
(JNIEnv * env, jclass obj){
    const char * cversion = tsk_version_get_str();
    jstring jversion = (*env).NewStringUTF(cversion);
    return jversion; 
}
