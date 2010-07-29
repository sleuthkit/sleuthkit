/*
 ** tsk_recover
 ** The Sleuth Kit 
 **
 ** Brian Carrier [carrier <at> sleuthkit [dot] org]
 ** Copyright (c) 2010 Brian Carrier.  All Rights reserved
 **
 ** This software is distributed under the Common Public License 1.0
 **
 */

#ifndef _TSK_AUTO_H
#define _TSK_AUTO_H

#ifdef __cplusplus

// Include the other internal TSK header files
#include "tsk3/base/tsk_base_i.h"
#include "tsk3/img/tsk_img_i.h"
#include "tsk3/vs/tsk_vs_i.h"
#include "tsk3/fs/tsk_fs_i.h"
#include <map>
#include <string>

#define TSK_AUTO_TAG 0x9191ABAB


typedef enum {
    TSK_FILTER_CONT = 0x00,    ///< Framework should continue to process this object
    TSK_FILTER_STOP = 0x01,    ///< Framework should stop processing the image
    TSK_FILTER_SKIP = 0x02,   ///< Framework should skip this object and go on to the next
} TSK_FILTER_ENUM;

class TskAuto {
  public:
    unsigned int m_tag;

     TskAuto();
     virtual ~ TskAuto();

    virtual uint8_t openImage(int, const TSK_TCHAR * const images[],
        TSK_IMG_TYPE_ENUM, unsigned int a_ssize);
    virtual void closeImage();

    uint8_t findFilesInImg();
    uint8_t findFilesInVs(TSK_OFF_T start);
    uint8_t findFilesInFs(TSK_OFF_T start);
    uint8_t findFilesInFs(TSK_OFF_T start, TSK_INUM_T inum);
    TSK_RETVAL_ENUM findFilesInFsRet(TSK_OFF_T start);

    void setFileFilterFlags(TSK_FS_DIR_WALK_FLAG_ENUM);
    void setVolFilterFlags(TSK_VS_PART_FLAG_ENUM);

    /**
     * Gets called for each partition that is found in a volume system.
     * @param vs_part Parition details
     * @returns Value to show if volume should be processed, skipped, or process should stop.
     */
    virtual TSK_FILTER_ENUM filterVol(const TSK_VS_PART_INFO * vs_part) {
        return TSK_FILTER_CONT;
    };

    /**
     * Gets called for each file system that is found.
     * @param fs_info file system details
     * @returns Value to show if FS should be processed, skipped, or process should stop.
     */
    virtual TSK_FILTER_ENUM filterFs(TSK_FS_INFO * fs_info) {
        return TSK_FILTER_CONT;
    };

    /**
     * Gets called for each file that is found during search.  This is where the subclass should
     * process file content using other TSK methods. 
     *
     * @param fs_file file  details
     * @param path full path of parent directory
     * @returns 1 if the file system processing should stop and not process more files. 
     */
    virtual uint8_t processFile(TSK_FS_FILE * fs_file, const char *path) =
        0;

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
    uint8_t isNtfsSystemFiles(TSK_FS_FILE * fs_file, const char *path);
    uint8_t isFATSystemFiles(TSK_FS_FILE * fs_file);
    uint8_t isDotDir(TSK_FS_FILE * fs_file, const char *path);
    uint8_t isDir(TSK_FS_FILE * fs_file);
};

typedef struct sqlite3 sqlite3;

class TskAutoDb:public TskAuto {
  public:
    TskAutoDb();
    virtual ~ TskAutoDb();
    virtual uint8_t openImage(int, const TSK_TCHAR * const images[],
        TSK_IMG_TYPE_ENUM, unsigned int a_ssize);
    virtual void closeImage();

    virtual TSK_FILTER_ENUM filterVol(const TSK_VS_PART_INFO * vs_part);
    virtual TSK_FILTER_ENUM filterFs(TSK_FS_INFO * fs_info);
    virtual uint8_t processFile(TSK_FS_FILE * fs_file, const char *path);
  private:
     sqlite3 * m_db;
    int m_curFsId;
    int m_curVsId;

    // maps dir name to its inode.  Used to find parent dir inum based on name. 
     std::map < std::string, TSK_INUM_T > m_par_inodes;
};

#endif

#endif
