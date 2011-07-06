#ifndef _TSK_AUTODB_JNI_H
#define _TSK_AUTODB_JNI_H

class TskAutoDbJNI:public TskAutoDb {
private:
    bool m_cancelled;

public:  
    TskAutoDbJNI();
    virtual TSK_RETVAL_ENUM processFile(TSK_FS_FILE * fs_file,
        const char *path);
    void cancelProcess();
};

#endif