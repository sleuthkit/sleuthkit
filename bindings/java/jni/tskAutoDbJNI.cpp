/*
 ** tskAutoDbJNI
 ** The Sleuth Kit 
 **
 ** Brian Carrier [carrier <at> sleuthkit [dot] org]
 ** Copyright (c) 2010-2011 Brian Carrier.  All Rights reserved
 **
 ** This software is distributed under the Common Public License 1.0
 **
 */
#include "tsk3/tsk_tools_i.h"
#include "tskAutoDbJNI.h"



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
