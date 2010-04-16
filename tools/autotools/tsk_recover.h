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

class TskRecover : public TskAuto {
public:
    TskRecover(TSK_TCHAR *a_base_dir);
    virtual uint8_t processFile(TSK_FS_FILE * fs_file, const char *path);    
    
private:
    TSK_TCHAR *m_base_dir;
    uint8_t writeFile(TSK_FS_FILE *a_fs_file, const char *a_path);
};