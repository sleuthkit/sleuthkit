/*
 ** The Sleuth Kit
 **
 ** Brian Carrier [carrier <at> sleuthkit [dot] org]
 ** Copyright (c) 2010-2013 Brian Carrier.  All Rights reserved
 **
 ** This software is distributed under the Common Public License 1.0
 **
 */

/**
 * \file auto.cpp
 * Contains C++ code that creates the base file extraction automation class.
 */

#include "tsk_auto_i.h"
#include "tsk/fs/tsk_fatfs.h"


// @@@ Follow through some error paths for sanity check and update docs somewhere to relfect the new scheme

TskAuto::TskAuto()
{
    m_img_info = NULL;
    m_tag = TSK_AUTO_TAG;
    m_volFilterFlags = (TSK_VS_PART_FLAG_ENUM)(TSK_VS_PART_FLAG_ALLOC | TSK_VS_PART_FLAG_UNALLOC);
    m_fileFilterFlags = TSK_FS_DIR_WALK_FLAG_RECURSE;
    m_stopAllProcessing = false;
    m_internalOpen = false;
    m_curVsPartValid = false;
    m_curVsPartDescr = "";
}


TskAuto::~TskAuto()
{
    closeImage();
    m_tag = 0;
}


void TskAuto::setCurVsPart(const TSK_VS_PART_INFO *partInfo) {
    if (partInfo->desc)
        m_curVsPartDescr = partInfo->desc;
    else
        m_curVsPartDescr = "";
    m_curVsPartFlag = partInfo->flags;
    m_curVsPartValid = true;
}

std::string TskAuto::getCurVsPartDescr() const {
    return m_curVsPartDescr;
}

TSK_VS_PART_FLAG_ENUM TskAuto::getCurVsPartFlag() const {
    return m_curVsPartFlag;
}

bool TskAuto::isCurVsValid() const {
    return m_curVsPartValid;
}

/**
 * Opens the disk image to be analyzed.  This must be called before any
 * of the findFilesInXXX() methods.
 *
 * @param a_numImg The number of images to open (will be > 1 for split images).
 * @param a_images The path to the image files (the number of files must
 * be equal to num_img and they must be in a sorted order)
 * @param a_imgType The disk image type (can be autodetection)
 * @param a_sSize Size of device sector in bytes (or 0 for default)
 * @returns 1 on error (messages were NOT registered), 0 on success
 */
uint8_t
    TskAuto::openImage(int a_numImg, const TSK_TCHAR * const a_images[],
    TSK_IMG_TYPE_ENUM a_imgType, unsigned int a_sSize)
{
    resetErrorList();
    if (m_img_info)
        closeImage();

    m_internalOpen = true;
    m_img_info = tsk_img_open(a_numImg, a_images, a_imgType, a_sSize);
    if (m_img_info)
        return 0;
    else
        return 1;
}

/**
 * Opens the disk image to be analyzed.  This must be called before any
 * of the findFilesInXXX() methods. Always uses the utf8 tsk_img_open
 * even in windows.
 *
 * @param a_numImg The number of images to open (will be > 1 for split images).
 * @param a_images The path to the image files (the number of files must
 * be equal to num_img and they must be in a sorted order)
 * @param a_imgType The disk image type (can be autodetection)
 * @param a_sSize Size of device sector in bytes (or 0 for default)
 * @returns 1 on error (messages were NOT registered), 0 on success
 */
uint8_t
    TskAuto::openImageUtf8(int a_numImg, const char *const a_images[],
    TSK_IMG_TYPE_ENUM a_imgType, unsigned int a_sSize)
{
    resetErrorList();
    if (m_img_info)
        closeImage();

    m_internalOpen = true;
    m_img_info = tsk_img_open_utf8(a_numImg, a_images, a_imgType, a_sSize);
    if (m_img_info)
        return 0;
    else
        return 1;
}

/**
 * Uses the already opened image for future analysis. This must be called before any
 * of the findFilesInXXX() methods. Note that the TSK_IMG_INFO will not
 * be freed when the TskAuto class is closed.
 * @param a_img_info Handle to an already opened disk image.
 * @returns 1 on error (messages were NOT registered) and 0 on success
 */
uint8_t TskAuto::openImageHandle(TSK_IMG_INFO * a_img_info)
{
    resetErrorList();
    if (m_img_info)
        closeImage();

    m_internalOpen = false;
    m_img_info = a_img_info;
    return 0;
}



/**
 * Closes the handles to the open disk image. Should be called after
 * you have completed analysis of the image.
 */
void
 TskAuto::closeImage()
{
    if ((m_img_info) && (m_internalOpen)) {
        tsk_img_close(m_img_info);
    }
    m_img_info = NULL;
}


/**
 * Set the attributes for the volumes that should be processed.
 * The default settings are for Allocated Non-Meta volumes only.
 * This must be called before the findFilesInXX() method.
 * @param vs_flags Flags to use for filtering
 */
void
 TskAuto::setVolFilterFlags(TSK_VS_PART_FLAG_ENUM vs_flags)
{
    m_volFilterFlags = vs_flags;
}


/**
 * Set the attributes for the files that should be processed.
 * The default settings are for all files (allocated and deleted).
 * This must be called before the findFilesInXX() method.
 * @param file_flags Flags to use for filtering
 */
void
 TskAuto::setFileFilterFlags(TSK_FS_DIR_WALK_FLAG_ENUM file_flags)
{
    m_fileFilterFlags = file_flags;
}

/**
 * @return The size of the image in bytes or -1 if the 
 * image is not open.
 */
TSK_OFF_T TskAuto::getImageSize() const
{
    if (m_img_info == NULL)
        return -1;

    return m_img_info->size;
}

TSK_FILTER_ENUM 
TskAuto::filterVs(const TSK_VS_INFO * vs_info) 
{
    return TSK_FILTER_CONT;
}

TSK_FILTER_ENUM 
TskAuto::filterVol(const TSK_VS_PART_INFO * vs_part) 
{
    return TSK_FILTER_CONT;
}

TSK_FILTER_ENUM 
TskAuto::filterFs(TSK_FS_INFO * fs_info) {
    return TSK_FILTER_CONT;
};



/**
 * Starts in sector 0 of the opened disk images and looks for a
 * volume or file system. Will call processFile() on each file
 * that is found.
 * @return 1 if an error occured (message will have been registered) and 0 on success
 */
uint8_t
TskAuto::findFilesInImg()
{
    if (!m_img_info) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_NOTOPEN);
        tsk_error_set_errstr("findFilesInImg -- img_info");
        registerError();
        return 1;
    }

    return findFilesInVs(0);
}


/** \internal
 * Volume system walk callback function that will analyze
 * each volume to find a file system.
 * Does not return ERROR because all errors have been registered 
 * and returning an error would indicate to TSK that errno and such are set. 
 */
TSK_WALK_RET_ENUM
    TskAuto::vsWalkCb(TSK_VS_INFO * a_vs_info,
    const TSK_VS_PART_INFO * a_vs_part, void *a_ptr)
{
    TskAuto *tsk = (TskAuto *) a_ptr;
    if (tsk->m_tag != TSK_AUTO_TAG) {
        // we have no way to register an error...
        return TSK_WALK_STOP;
    }

    //save the current volume description
    tsk->setCurVsPart(a_vs_part);

    // see if the super class wants to continue with this.
    TSK_FILTER_ENUM retval1 = tsk->filterVol(a_vs_part);
    if (retval1 == TSK_FILTER_SKIP)
        return TSK_WALK_CONT;
    else if ((retval1 == TSK_FILTER_STOP) || (tsk->getStopProcessing()))
        return TSK_WALK_STOP;    

    // process it
    TSK_RETVAL_ENUM retval2 =
        tsk->findFilesInFsRet(a_vs_part->start *
        a_vs_part->vs->block_size, TSK_FS_TYPE_DETECT);
    if ((retval2 == TSK_STOP) || (tsk->getStopProcessing())) {
        return TSK_WALK_STOP;
    }

    //all errors would have been registered

    return TSK_WALK_CONT;
}


/**
 * Starts in a specified byte offset of the opened disk images and looks for a
 * volume system or file system. Will call processFile() on each file
 * that is found.
 * @param a_start Byte offset to start analyzing from.
 * @param a_vtype Volume system type to analyze
 * @return 1 if an error occured (messages will have been registered) and 0 on success
 */
uint8_t
TskAuto::findFilesInVs(TSK_OFF_T a_start, TSK_VS_TYPE_ENUM a_vtype)
{
    if (!m_img_info) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_NOTOPEN);
        tsk_error_set_errstr("findFilesInVs -- img_info");
        registerError();
        return 1;
    }

    TSK_VS_INFO *vs_info;
    // USE mm_walk to get the volumes
    if ((vs_info = tsk_vs_open(m_img_info, a_start, a_vtype)) == NULL) {
        /* we're going to ignore this error to avoid confusion if the
         * fs_open passes. */
        tsk_error_reset();

        if(tsk_verbose)
            fprintf(stderr, "findFilesInVs: Error opening volume system, trying as a file system\n");

        /* There was no volume system, but there could be a file system 
         * Errors will have been registered */
        findFilesInFs(a_start);
    }
    // process the volume system
    else {
        TSK_FILTER_ENUM retval = filterVs(vs_info);
        if ((retval == TSK_FILTER_STOP) || (retval == TSK_FILTER_SKIP)|| (m_stopAllProcessing))
            return m_errors.empty() ? 0 : 1;

        /* Walk the allocated volumes (skip metadata and unallocated volumes) */
        if (tsk_vs_part_walk(vs_info, 0, vs_info->part_count - 1,
                m_volFilterFlags, vsWalkCb, this)) {
            registerError();
            tsk_vs_close(vs_info);
            return 1;
        }
        tsk_vs_close(vs_info);
    }
    return m_errors.empty() ? 0 : 1;
}

/**
 * Starts in a specified byte offset of the opened disk images and looks for a
 * volume system or file system. Will call processFile() on each file
 * that is found.
 * @param a_start Byte offset to start analyzing from.
 * @return 1 if an error occured (message will have been registered), 0 on success
 */
uint8_t
TskAuto::findFilesInVs(TSK_OFF_T a_start)
{
    return findFilesInVs(a_start, TSK_VS_TYPE_DETECT);
}


/**
 * Starts in a specified byte offset of the opened disk images and looks for a
 * file system. Will call processFile() on each file
 * that is found.  Same as findFilesInFs, but gives more detailed return values.
 * @param a_start Byte offset to start analyzing from. 
 * @param a_ftype File system type.
 * @returns Error (messages will have been registered), OK, or STOP.
 */
TSK_RETVAL_ENUM
    TskAuto::findFilesInFsRet(TSK_OFF_T a_start, TSK_FS_TYPE_ENUM a_ftype)
{
    if (!m_img_info) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_NOTOPEN);
        tsk_error_set_errstr("findFilesInFsRet -- img_info");
        registerError();
        return TSK_ERR;
    }

    TSK_FS_INFO *fs_info;
    if ((fs_info = tsk_fs_open_img(m_img_info, a_start, a_ftype)) == NULL) {
        if (isCurVsValid() == false) {
            tsk_error_set_errstr2 ("Sector offset: %" PRIuOFF, a_start/512);
            registerError();
            return TSK_ERR;
        }
        else if (getCurVsPartFlag() & TSK_VS_PART_FLAG_ALLOC) {
            tsk_error_set_errstr2 ("Sector offset: %" PRIuOFF ", Partition Type: %s",
                a_start/512, getCurVsPartDescr().c_str() );
            registerError();
            return TSK_ERR;
        }
        else {
            tsk_error_reset();
            return TSK_OK;
        }
    }

    TSK_RETVAL_ENUM retval = findFilesInFsInt(fs_info, fs_info->root_inum);
    tsk_fs_close(fs_info);
    if (m_errors.empty() == false)
        return TSK_ERR;
    else 
        return retval;
}


/**
 * Starts in a specified byte offset of the opened disk images and looks for a
 * file system. Will call processFile() on each file
 * that is found.
 *
 * @param a_start Byte offset of file system starting location.
 *
 * @returns 1 if an error occured (messages will have been registered) and 0 on success
 */
uint8_t
TskAuto::findFilesInFs(TSK_OFF_T a_start)
{
    return findFilesInFs(a_start, TSK_FS_TYPE_DETECT);
}


/**
 * Starts in a specified byte offset of the opened disk images and looks for a
 * file system. Will call processFile() on each file
 * that is found.
 *
 * @param a_start Byte offset of file system starting location.
 * @param a_ftype Type of file system that is located at the offset.
 *
 * @returns 1 if an error occured (messages will have been registered) and 0 on success
 */
uint8_t
TskAuto::findFilesInFs(TSK_OFF_T a_start, TSK_FS_TYPE_ENUM a_ftype)
{
    findFilesInFsRet(a_start, a_ftype);
    return m_errors.empty() ? 0 : 1;
}

/**
 * Starts in a specified byte offset of the opened disk images and looks for a
 * file system. Will start processing the file system at a specified
 * file system. Will call processFile() on each file
 * that is found in that directory.
 *
 * @param a_start Byte offset of file system starting location.
 * @param a_ftype Type of file system that will be analyzed.
 * @param a_inum inum to start walking files system at.
 *
 * @returns 1 if an error occured (messages will have been registered) and 0 on success
 */
uint8_t
    TskAuto::findFilesInFs(TSK_OFF_T a_start, TSK_FS_TYPE_ENUM a_ftype,
    TSK_INUM_T a_inum)
{
    if (!m_img_info) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_NOTOPEN);
        tsk_error_set_errstr("findFilesInFs -- img_info ");
        registerError();
        return 1;
    }

    TSK_FS_INFO *fs_info;
    if ((fs_info = tsk_fs_open_img(m_img_info, a_start, a_ftype)) == NULL) {
        if (isCurVsValid() == false) {
            tsk_error_set_errstr2 ("Sector offset: %" PRIuOFF, a_start/512);
            registerError();
            return TSK_ERR;
        }
        else if (getCurVsPartFlag() & TSK_VS_PART_FLAG_ALLOC) {
            tsk_error_set_errstr2(
                "Sector offset: %" PRIuOFF ", Partition Type: %s",
                a_start / 512, getCurVsPartDescr().c_str());
            registerError();
            return 1;
        }
        else {
            tsk_error_reset();
            return 0;
        }
    }

    findFilesInFsInt(fs_info, a_inum);
    tsk_fs_close(fs_info);
    return m_errors.empty() ? 0 : 1;
}


/**
 * Starts in a specified byte offset of the opened disk images and looks for a
 * file system. Will start processing the file system at a specified
 * file system. Will call processFile() on each file
 * that is found in that directory.
 *
 * @param a_start Byte offset of file system starting location.
 * @param a_inum inum to start walking files system at.
 *
 * @returns 1 if an error occured (messages will have been registered) and 0 on success
 */
uint8_t
TskAuto::findFilesInFs(TSK_OFF_T a_start, TSK_INUM_T a_inum)
{
    return TskAuto::findFilesInFs(a_start, TSK_FS_TYPE_DETECT, a_inum);
}

/** 
 * Processes the file system represented by the given TSK_FS_INFO
 * pointer. Will Call processFile() on each file that is found.
 *
 * @param a_fs_info Pointer to a previously opened file system.
 *
 * @returns 1 if an error occured (messages will have been registered) and 0 on success
 */
uint8_t
TskAuto::findFilesInFs(TSK_FS_INFO * a_fs_info)
{
    if (a_fs_info == NULL) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_NOTOPEN);
        tsk_error_set_errstr("findFilesInFs - fs_info");
        registerError();
        return 1;
    }
    
    findFilesInFsInt(a_fs_info, a_fs_info->root_inum);
    return m_errors.empty() ? 0 : 1;
}

/** \internal
 * file name walk callback.  Walk the contents of each file
 * that is found.
 *
 * Does not return ERROR because all errors have been registered 
 * and returning an error would indicate to TSK that errno and such are set. 
 */
TSK_WALK_RET_ENUM
    TskAuto::dirWalkCb(TSK_FS_FILE * a_fs_file, const char *a_path,
    void *a_ptr)
{
    TskAuto *tsk = (TskAuto *) a_ptr;
    if (tsk->m_tag != TSK_AUTO_TAG) {
        // we have no way to register an error...
        return TSK_WALK_STOP;
    }
    
    TSK_RETVAL_ENUM retval = tsk->processFile(a_fs_file, a_path);
    if ((retval == TSK_STOP) || (tsk->getStopProcessing()))
        return TSK_WALK_STOP;
    else 
        return TSK_WALK_CONT;
}


/** \internal
 * Internal method that the other findFilesInFs can call after they
 * have opened FS_INFO.
 * @returns OK, STOP, or ERR (error message will already have been registered)
 */
TSK_RETVAL_ENUM
    TskAuto::findFilesInFsInt(TSK_FS_INFO * a_fs_info, TSK_INUM_T a_inum)
{
    // see if the super class wants us to proceed
    TSK_FILTER_ENUM retval = filterFs(a_fs_info);
    if ((retval == TSK_FILTER_STOP) || (m_stopAllProcessing))
        return TSK_STOP;
    else if (retval == TSK_FILTER_SKIP)
        return TSK_OK;

    /* Walk the files, starting at the given inum */
    if (tsk_fs_dir_walk(a_fs_info, a_inum,
            (TSK_FS_DIR_WALK_FLAG_ENUM) (TSK_FS_DIR_WALK_FLAG_RECURSE |
                m_fileFilterFlags), dirWalkCb, this)) {

        tsk_error_set_errstr2(
            "Error walking directory in file system at offset %" PRIuOFF, a_fs_info->offset);
        registerError();
        return TSK_ERR;
    }
    
    if (m_stopAllProcessing)
        return TSK_STOP;

    /* We could do some analysis of unallocated blocks at this point...  */

    return TSK_OK;
}


/**
 * Method that can be used from within processFile() to look at each
 * attribute that a file may have.  This will call the processAttribute()
 * method (which you must implement) on each of the attributes in the file.
 * @param fs_file file  details
 * @param path full path of parent directory
 * @returns STOP if the file system processing should stop and not process more files or OK.
 */
TSK_RETVAL_ENUM
    TskAuto::processAttributes(TSK_FS_FILE * fs_file, const char *path)
{
    int
     count = tsk_fs_file_attr_getsize(fs_file), i;
    for (i = 0; i < count; i++) {
        TSK_RETVAL_ENUM retval =
            processAttribute(fs_file, tsk_fs_file_attr_get_idx(fs_file, i),
            path);
        if ((retval == TSK_STOP) || (m_stopAllProcessing))
            return TSK_STOP;
    }
    return TSK_OK;
}


TSK_RETVAL_ENUM 
TskAuto::processAttribute(TSK_FS_FILE * fs_file,
                                         const TSK_FS_ATTR * fs_attr, const char *path) 
{
    return TSK_OK;
};


void TskAuto::setStopProcessing() {
    m_stopAllProcessing = true;
}

bool TskAuto::getStopProcessing() const {
    return m_stopAllProcessing;
}

uint8_t TskAuto::registerError() {
    // add to our list of errors
    error_record er;
    er.code = tsk_error_get_errno();
    er.msg1 = tsk_error_get_errstr();
    er.msg2 = tsk_error_get_errstr2();
    m_errors.push_back(er);
    
    // call super class implementation
    uint8_t retval = handleError();

    tsk_error_reset();
    return retval;
}

 
const std::vector<TskAuto::error_record> TskAuto::getErrorList() {
    return m_errors;
}

void TskAuto::resetErrorList() {
    m_errors.clear();
}

std::string TskAuto::errorRecordToString(error_record &rec) {
    tsk_error_reset();
    tsk_error_set_errno(rec.code);
    tsk_error_set_errstr("%s", rec.msg1.c_str());
    tsk_error_set_errstr2("%s", rec.msg2.c_str());
    const char *msg = tsk_error_get();
    std::string ret;
    if  (msg != NULL)
        ret = msg;
    tsk_error_reset();
    return ret;
}

uint8_t 
TskAuto::handleError() {
    return 0;
};


/**
 * Utility method to help determine if a file is an NTFS file system file (such as $MFT).
 *
 * @returns 1 if the file is an NTFS System file, 0 if not.
 */
uint8_t
    TskAuto::isNtfsSystemFiles(TSK_FS_FILE * a_fs_file, const char *a_path)
{
    if ((a_fs_file) && (a_fs_file->fs_info)
        && (TSK_FS_TYPE_ISNTFS(a_fs_file->fs_info->ftype))
        && (a_fs_file->name) && (a_fs_file->name->name[0] == '$')
        && (a_fs_file->name->meta_addr < 20))
        return 1;
    else
        return 0;
}

/**
 * Utility method to help determine if a file is a FAT file system file (such as $MBR).
 *
 * @returns 1 if the file is an FAT System file, 0 if not.
 */
uint8_t
TskAuto::isFATSystemFiles(TSK_FS_FILE * a_fs_file)
{
    if ((a_fs_file) && (a_fs_file->fs_info)
        && (TSK_FS_TYPE_ISFAT(a_fs_file->fs_info->ftype))
        && (a_fs_file->name->meta_addr == FATFS_MBRINO(a_fs_file->fs_info)
            || a_fs_file->name->meta_addr ==
            FATFS_FAT1INO(a_fs_file->fs_info)
            || a_fs_file->name->meta_addr ==
            FATFS_FAT2INO(a_fs_file->fs_info)))
        return 1;
    else
        return 0;
}


/**
 * Utility method to help determine if a file is a . or .. directory.
 * @param a_fs_file File to evaluate
 *
 * @returns 1 if the file is a dot directory, 0 if not. 
 */
uint8_t
TskAuto::isDotDir(TSK_FS_FILE * a_fs_file)
{
    if ((!a_fs_file) || (!a_fs_file->name)
        || (a_fs_file->name->type != TSK_FS_NAME_TYPE_DIR))
        return 0;

    if ((a_fs_file->name->name_size >= 2)
        && (a_fs_file->name->name[0] == '.')
        && ((a_fs_file->name->name[1] == '\0')
            || ((a_fs_file->name->name_size > 2)
                && (a_fs_file->name->name[1] == '.')
                && (a_fs_file->name->name[2] == '\0'))))
        return 1;
    else
        return 0;
}

/**
 * Utility method to help determine if a file is a directory.
 *
 * @returns 1 if the file is a directory, 0 if not. 
 */
uint8_t
TskAuto::isDir(TSK_FS_FILE * a_fs_file)
{
    if ((a_fs_file) && (a_fs_file->name)) {
        if (a_fs_file->name->type == TSK_FS_NAME_TYPE_DIR) {
            return 1;
        }
        else if (a_fs_file->name->type == TSK_FS_NAME_TYPE_UNDEF) {
            if ((a_fs_file->meta)
                && (a_fs_file->meta->type == TSK_FS_META_TYPE_DIR)) {
                return 1;
            }
        }
    }
    return 0;
}

/**
 * Utility method to help determine if a file is a file (and not a directory).
 *
 * @returns 1 if the file is a file, 0 if not. 
 */
uint8_t
TskAuto::isFile(TSK_FS_FILE * a_fs_file)
{
    if ((a_fs_file) && (a_fs_file->name)) {
        if (a_fs_file->name->type == TSK_FS_NAME_TYPE_REG) {
            return 1;
        }
        else if (a_fs_file->name->type == TSK_FS_NAME_TYPE_UNDEF) {
            if ((a_fs_file->meta)
                && (a_fs_file->meta->type == TSK_FS_META_TYPE_REG)) {
                return 1;
            }
        }
    }
    return 0;
}

/**
 * Utility method to help determine if an attribute is the default type for the file/dir.
 *
 * @returns 1 if the attribute is a default type, 0 if not.
 */
uint8_t
    TskAuto::isDefaultType(TSK_FS_FILE * a_fs_file,
    const TSK_FS_ATTR * a_fs_attr)
{
    if ((a_fs_file) && (a_fs_file->fs_info)
        && (a_fs_file->fs_info->get_default_attr_type(a_fs_file) ==
            a_fs_attr->type))
        return 1;
    else
        return 0;
}

/**
 * Utility method to help determine if an attribute is non-resident (meaning it uses blocks to store data)
 *
 * @returns 1 if the attribute is non-resident, 0 if not.
 */
uint8_t
TskAuto::isNonResident(const TSK_FS_ATTR * a_fs_attr)
{
    if ((a_fs_attr) && (a_fs_attr->flags & TSK_FS_ATTR_NONRES))
        return 1;
    else
        return 0;
}
