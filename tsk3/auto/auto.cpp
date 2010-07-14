/*
 ** The Sleuth Kit 
 **
 ** Brian Carrier [carrier <at> sleuthkit [dot] org]
 ** Copyright (c) 2010 Brian Carrier.  All Rights reserved
 **
 ** This software is distributed under the Common Public License 1.0
 **
 */
#include "tsk_auto.h"
#include "tsk3/fs/tsk_fatfs.h"


TskAuto::TskAuto()
{
    m_img_info = NULL;
    m_tag = TSK_AUTO_TAG;
    m_volFilterFlags = TSK_VS_PART_FLAG_ALLOC;
    m_fileFilterFlags = TSK_FS_DIR_WALK_FLAG_RECURSE;
}


TskAuto::~TskAuto()
{
    closeImage();
    m_tag = NULL;
}



/**
 * Set the attributes for the volumes that should be processed.
 * The default settings are for Allocated volumes only.
 * @param vs_flags Flags to use for filtering
 */
void
 TskAuto::setVolFilterFlags(TSK_VS_PART_FLAG_ENUM vs_flags)
{
    m_volFilterFlags = vs_flags;
}


/**
 * Set the attributes for the files that should be processed.
 * The default settings are for all files.
 * @param file_flags Flags to use for filtering
 */
void
 TskAuto::setFileFilterFlags(TSK_FS_DIR_WALK_FLAG_ENUM file_flags)
{
    m_fileFilterFlags = file_flags;
}


/**
 * File filter to ignore NTFS system files.
 *
 * @returns 1 if the file is an NTFS System file. 
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
 * File filter to ignore FAT system files.
 *
 * @returns 1 if the file is an FAT System file. 
 */
uint8_t TskAuto::isFATSystemFiles(TSK_FS_FILE * a_fs_file)
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
 * File filter to ignore dot ("." and "..") directories.
 * @returns 1 if the file is a dot directory
 */
uint8_t TskAuto::isDotDir(TSK_FS_FILE * a_fs_file, const char *a_path)
{
    if ((!a_fs_file) || (!a_fs_file->name)
        || ((a_fs_file->name->flags & TSK_FS_NAME_TYPE_DIR) == 0))
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

uint8_t TskAuto::isDir(TSK_FS_FILE * a_fs_file)
{
    if ((a_fs_file) && (a_fs_file->name)
        && (a_fs_file->name->type == TSK_FS_NAME_TYPE_DIR))
        return 1;
    else
        return 0;
}



/**
 * file name walk callback.  Walk the contents of each file 
 * that is found.
 */
TSK_WALK_RET_ENUM
    TskAuto::dirWalkCb(TSK_FS_FILE * a_fs_file, const char *a_path,
    void *a_ptr)
{
    TskAuto *tsk = (TskAuto *) a_ptr;
    if (tsk->m_tag != TSK_AUTO_TAG)
        return TSK_WALK_STOP;

    if (tsk->processFile(a_fs_file, a_path))
        return TSK_WALK_STOP;
    else
        return TSK_WALK_CONT;
}



/** 
 * Analyze the volume starting at byte offset 'start' 
 * and walk each file that can be found.
 *
 * @param a_start Byte offset of volume starting location.
 *
 * @return 1 on error and 0 on success
 */
uint8_t
TskAuto::findFilesInFs(TSK_OFF_T a_start)
{
    if (!m_img_info) {
        // @@@
        return 1;
    }

    TSK_FS_INFO *fs_info;
    /* Try it as a file system */
    if ((fs_info =
            tsk_fs_open_img(m_img_info, a_start,
                TSK_FS_TYPE_DETECT)) == NULL) {
        tsk_error_print(stderr);

        /* We could do some carving on the volume data at this point */

        return 1;
    }

    if (filterFs(fs_info)) {
        return 1;
    }

    /* Walk the files, starting at the root directory */
    if (tsk_fs_dir_walk(fs_info, fs_info->root_inum,
            (TSK_FS_DIR_WALK_FLAG_ENUM) (TSK_FS_DIR_WALK_FLAG_RECURSE |
                m_fileFilterFlags), dirWalkCb, this)) {
        tsk_error_print(stderr);
        tsk_fs_close(fs_info);
        return 1;
    }

    /* We could do some analysis of unallocated blocks at this point...  */


    tsk_fs_close(fs_info);
    return 0;
}


/**
 * Volume system walk callback function that will analyze 
 * each volume to find a file system.
 */

TSK_WALK_RET_ENUM
    TskAuto::vsWalkCb(TSK_VS_INFO * a_vs_info,
    const TSK_VS_PART_INFO * a_vs_part, void *a_ptr)
{
    TskAuto *tsk = (TskAuto *) a_ptr;
    if (tsk->m_tag != TSK_AUTO_TAG)
        return TSK_WALK_STOP;

    if (tsk->filterVol(a_vs_part))
        return TSK_WALK_CONT;

    if (tsk->findFilesInFs(a_vs_part->start * a_vs_part->vs->block_size)) {
        // if we return ERROR here, then the walk will stop.  But, the 
        // error could just be because we looked into an unallocated volume.
        // do any special error handling / reporting here.
        tsk_error_reset();
        return TSK_WALK_CONT;
    }

    return TSK_WALK_CONT;
}


/**
 * Process the data as a volume system to find the partitions
 * and volumes.  
 * File system analysis will be performed on each partition.
 *
 * @param a_start Byte offset to start analyzing from. 
 *
 * @return 1 on error and 0 on success
 */
uint8_t
TskAuto::findFilesInVs(TSK_OFF_T a_start)
{
    if (!m_img_info) {
        // @@@
        return 1;
    }

    TSK_VS_INFO *vs_info;
    // USE mm_walk to get the volumes 
    if ((vs_info =
            tsk_vs_open(m_img_info, a_start,
                TSK_VS_TYPE_DETECT)) == NULL) {
        if (tsk_verbose)
            fprintf(stderr,
                "Error determining volume system -- trying file systems\n");

        /* There was no volume system, but there could be a file system */
        tsk_error_reset();
        if (findFilesInFs(a_start)) {
            return 1;
        }
    }
    else {
        /* Walk the allocated volumes (skip metadata and unallocated volumes) */
        if (tsk_vs_part_walk(vs_info, 0, vs_info->part_count - 1,
                m_volFilterFlags, vsWalkCb, this)) {
            tsk_vs_close(vs_info);
            return 1;
        }
        tsk_vs_close(vs_info);
    }
    return 0;
}


uint8_t
TskAuto::findFilesInImg()
{
    if (!m_img_info) {
        // @@@
        return 1;
    }
    if (findFilesInVs(0)) {
        tsk_error_print(stderr);
        return 1;
    }

    return 0;
}



uint8_t
    TskAuto::openImage(int a_numImg, const TSK_TCHAR * const a_images[],
    TSK_IMG_TYPE_ENUM a_imgType, unsigned int a_sSize)
{
    if (m_img_info)
        closeImage();

    m_img_info = tsk_img_open(a_numImg, a_images, a_imgType, a_sSize);
    if (m_img_info)
        return 0;
    else
        return 1;
}

void
TskAuto::closeImage()
{
    if (m_img_info) {
        tsk_img_close(m_img_info);
        m_img_info = NULL;
    }
}
