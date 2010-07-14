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

#ifdef TSK_WIN32
#include <windows.h>
#include "shlobj.h"
#endif


class TskRecover:public TskAuto {
  public:
    TskRecover(TSK_TCHAR * a_base_dir);
    virtual uint8_t processFile(TSK_FS_FILE * fs_file, const char *path);
    virtual uint8_t filterVol(const TSK_VS_PART_INFO * vs_part);
    virtual uint8_t filterFs(TSK_FS_INFO * fs_info);
    bool findFiles(bool all, TSK_OFF_T soffset);


  private:
     TSK_TCHAR * m_base_dir;
    uint8_t writeFile(TSK_FS_FILE * a_fs_file, const char *a_path);
    int m_vsCount;
    TSK_TCHAR m_vsName[FILENAME_MAX];
    bool m_writeVolumeDir;
};
