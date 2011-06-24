/*
 ** The Sleuth Kit 
 **
 ** Brian Carrier [carrier <at> sleuthkit [dot] org]
 ** Copyright (c) 2010-2011 Brian Carrier.  All Rights reserved
 **
 ** This software is distributed under the Common Public License 1.0
 **
 */

/**
 * \file tsk_auto.h
 * Contains the class definitions for the automated file extraction classes.   
 * Note that this file is not meant to be directly included.  
 * It is included by libtsk.h.
 */

/**
 * \defgroup autolib File Extraction Automation Functionality
 */

#ifndef _TSK_AUTO_H
#define _TSK_AUTO_H

#ifdef __cplusplus

// Include the other TSK header files
#include "tsk3/base/tsk_base.h"
#include "tsk3/img/tsk_img.h"
#include "tsk3/vs/tsk_vs.h"
#include "tsk3/fs/tsk_fs.h"

#define TSK_AUTO_TAG 0x9191ABAB


typedef enum {
    TSK_FILTER_CONT = 0x00,     ///< Framework should continue to process this object
    TSK_FILTER_STOP = 0x01,     ///< Framework should stop processing the image
    TSK_FILTER_SKIP = 0x02,     ///< Framework should skip this object and go on to the next
} TSK_FILTER_ENUM;

/** \ingroup autolib
 * C++ class that automatically analyzes a disk image to extract files from it.  This class
 * hides many of the details that are required to use lower-level TSK APIs to analyze volume 
 * and file systems. 
 * 
 * The processFile() method must be implemented and it will be called for each file and 
 * directory that is found. 
 * 
 * An image file must be first opened using openImage().  It can then be analyzed using one
 * of the findFilesInXXXX() methods.  The filterXX() methods can be used to skip volumes
 * and file systems. 
 */
class TskAuto {
  public:
    unsigned int m_tag;


     TskAuto();
     virtual ~ TskAuto();

    virtual uint8_t openImage(int, const TSK_TCHAR * const images[],
        TSK_IMG_TYPE_ENUM, unsigned int a_ssize);
    virtual uint8_t openImageUtf8(int, const char *const images[],
        TSK_IMG_TYPE_ENUM, unsigned int a_ssize);
    virtual uint8_t openImage(TSK_IMG_INFO *);
    virtual void closeImage();

    TSK_OFF_T getImageSize() const;
    uint8_t findFilesInImg();
    uint8_t findFilesInVs(TSK_OFF_T start);
    uint8_t findFilesInVs(TSK_OFF_T start, TSK_VS_TYPE_ENUM vtype);
    uint8_t findFilesInFs(TSK_OFF_T start);
    uint8_t findFilesInFs(TSK_OFF_T start, TSK_FS_TYPE_ENUM ftype);
    uint8_t findFilesInFs(TSK_OFF_T start, TSK_INUM_T inum);
    uint8_t findFilesInFs(TSK_OFF_T start, TSK_FS_TYPE_ENUM ftype,
        TSK_INUM_T inum);
    uint8_t findFilesInFs(TSK_FS_INFO *a_fs_info);
    TSK_RETVAL_ENUM findFilesInFsRet(TSK_OFF_T start,
        TSK_FS_TYPE_ENUM a_ftype);

    void setFileFilterFlags(TSK_FS_DIR_WALK_FLAG_ENUM);
    void setVolFilterFlags(TSK_VS_PART_FLAG_ENUM);

    /**
     * TskAuto calls this method before it processes the volume system that is found in an 
     * image. You can use this to learn about the volume system before it is processed
     * and you can force TskAuto to skip this volume system. 
     * @param vs_info volume system details
     * @returns Value to show if Vs should be processed, skipped, or process should stop.
     */
    virtual TSK_FILTER_ENUM filterVs(const TSK_VS_INFO * vs_info) {
        return TSK_FILTER_CONT;
    };

    /**
     * TskAuto calls this method before it processes each volume that is found in a 
     * volume system. You can use this to learn about each volume before it is processed
     * and you can force TskAuto to skip this volume.  The setvolFilterFlags() method can be
     * used to configure if TskAuto should process unallocated space. 
     *
     * @param vs_part Parition details
     * @returns Value to show if volume should be processed, skipped, or process should stop.
     */
    virtual TSK_FILTER_ENUM filterVol(const TSK_VS_PART_INFO * vs_part) {
        return TSK_FILTER_CONT;
    };

    /**
     * TskAuto calls this method before it processes each file system that is found in a 
     * volume. You can use this to learn about each file system before it is processed
     * and you can force TskAuto to skip this file system. 
     * @param fs_info file system details
     * @returns Value to show if FS should be processed, skipped, or process should stop.
     */
    virtual TSK_FILTER_ENUM filterFs(TSK_FS_INFO * fs_info) {
        return TSK_FILTER_CONT;
    };

    /**
     * TskAuto calls this method for each file and directory that it finds in an image. 
     * The setFileFilterFlags() method can be used to set the criteria for what types of
     * files this should be called for. There are several methods, such as isDir() that
     * can be used by this method to help focus in on the files that you care about. 
     *
     * @param fs_file file  details
     * @param path full path of parent directory
     * @returns Whether to stop processing, an error occured, or if the processing should continue
     */
    virtual TSK_RETVAL_ENUM processFile(TSK_FS_FILE * fs_file,
        const char *path) = 0;

    /**
     * TskAuto calls this method when it encounters issues while processing an image,
     * e.g. when opening various volume and file systems fail. This method allows users
     * of the TskAuto class to choose an appropriate mechanism to present this information.
     * The implementation of this method in the base class is a no-op.
     *
     * @param msg A text message describing the issue that was encountered.
     */
    virtual void handleNotification(const char * msg) {};

  private:
    TSK_VS_PART_FLAG_ENUM m_volFilterFlags;
    TSK_FS_DIR_WALK_FLAG_ENUM m_fileFilterFlags;

    static TSK_WALK_RET_ENUM dirWalkCb(TSK_FS_FILE * fs_file,
        const char *path, void *ptr);
    static TSK_WALK_RET_ENUM vsWalkCb(TSK_VS_INFO * vs_info,
        const TSK_VS_PART_INFO * vs_part, void *ptr);

    TSK_RETVAL_ENUM findFilesInFsInt(TSK_FS_INFO *, TSK_INUM_T inum);


  protected:
    TSK_IMG_INFO * m_img_info;
    bool m_internalOpen;        ///< True if m_img_info was opened in TskAuto and false if passed in
    uint8_t isNtfsSystemFiles(TSK_FS_FILE * fs_file, const char *path);
    uint8_t isFATSystemFiles(TSK_FS_FILE * fs_file);
    uint8_t isDotDir(TSK_FS_FILE * fs_file, const char *path);
    uint8_t isDir(TSK_FS_FILE * fs_file);
    uint8_t isFile(TSK_FS_FILE * fs_file);
    uint8_t isDefaultType(TSK_FS_FILE * fs_file,
        const TSK_FS_ATTR * fs_attr);
    uint8_t isNonResident(const TSK_FS_ATTR * fs_attr);


    TSK_RETVAL_ENUM processAttributes(TSK_FS_FILE * fs_file,
        const char *path);

    /** 
     * Method that is called from processAttributes() for each attribute that a file
     * has.  processAttributes() is not called by default.  It exists so that implementations
     * of processFile() can choose to call it if they want to look at all of the attributes. 
     * You must implement this method to see each attribute and modify processFile() so that
     * it calls processAttributes().
     *
     * @param fs_file File being analyzed.
     * @param fs_attr Attribute of the file.
     * @param path full path of parent directory
     * @returns Whether to stop processing, an error occured, or if the processing should continue. 
     */
    virtual TSK_RETVAL_ENUM processAttribute(TSK_FS_FILE * fs_file,
        const TSK_FS_ATTR * fs_attr, const char *path) {
        return TSK_OK;
    };
};


typedef struct sqlite3 sqlite3;

/** \internal
 * C++ class that implements TskAuto to load file metadata into a SQLite database. 
 */
class TskAutoDb:public TskAuto {
  public:
    TskAutoDb();
    virtual ~ TskAutoDb();
    virtual uint8_t openImage(int, const TSK_TCHAR * const images[],
        TSK_IMG_TYPE_ENUM, unsigned int a_ssize);
    virtual uint8_t openImageUtf8(int, const char *const images[],
        TSK_IMG_TYPE_ENUM, unsigned int a_ssize);
    uint8_t openImage(int, const TSK_TCHAR * const images[],
        TSK_IMG_TYPE_ENUM, unsigned int a_ssize, TSK_TCHAR * output_dir);
    uint8_t openImageUtf8(int, const char *const images[],
        TSK_IMG_TYPE_ENUM, unsigned int a_ssize, char *output_dir);
    virtual void closeImage();

    uint8_t addFilesInImgToDB();
    virtual TSK_FILTER_ENUM filterVs(const TSK_VS_INFO * vs_info);
    virtual TSK_FILTER_ENUM filterVol(const TSK_VS_PART_INFO * vs_part);
    virtual TSK_FILTER_ENUM filterFs(TSK_FS_INFO * fs_info);
    virtual TSK_RETVAL_ENUM processFile(TSK_FS_FILE * fs_file,
        const char *path);
    virtual void createBlockMap(bool flag);

  private:
     sqlite3 * m_db;
    int m_curFsId;
    int m_curVsId;
    bool m_blkMapFlag;
    bool m_vsFound;
    bool m_volFound;

    uint8_t initDatabase(char **, int);
    TSK_RETVAL_ENUM insertFileData(TSK_FS_FILE * fs_file,
        const TSK_FS_ATTR *, const char *path);
    virtual TSK_RETVAL_ENUM processAttribute(TSK_FS_FILE *,
        const TSK_FS_ATTR * fs_attr, const char *path);
    uint8_t createParentDirIndex();
};

#endif

#endif
