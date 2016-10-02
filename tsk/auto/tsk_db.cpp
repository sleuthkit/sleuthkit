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
* \file tsk_db.cpp
* Contains code related to abstract TSK database handling class. 
*/

#include "tsk_db.h"

/**
* Set the locations and logging object.  Must call
* open() before the object can be used.
*/
TskDb::TskDb(const char *a_dbFilePathUtf8, bool a_blkMapFlag)
{

}

#ifdef TSK_WIN32
//@@@@
TskDb::TskDb(const TSK_TCHAR * a_dbFilePath, bool a_blkMapFlag)
{

}
#endif

/**
* Store database connection info. NO-OP for single-user database. Multi-user database class
* needs to derive and implement this method.
*/
TSK_RETVAL_ENUM TskDb::setConnectionInfo(CaseDbConnectionInfo * info){
    return TSK_OK;
}

/*
* Utility method to break up path into parent folder and folder/file name. 
* @param path Path of folder that we want to analyze
* @param ret_parent_path pointer to parent path (begins and ends with '/')
* @param ret_name pointer to final folder/file name
* @returns 0 on success, 1 on error
*/
bool TskDb::getParentPathAndName(const char *path, char **ret_parent_path, char **ret_name){
    // Need to break up 'path' in to the parent folder to match in 'parent_path' and the folder 
    // name to match with the 'name' column in tsk_files table

    // reset all arrays
    parent_name[0] = '\0';
    parent_path[0] = '\0';

    size_t path_len = strlen(path);
    if (path_len >= MAX_PATH_LENGTH) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr("TskDb::getParentPathAndName: Path is too long. Length = %d, Max length = %d", path_len, MAX_PATH_LENGTH);
        // assign return values to pointers
        *ret_parent_path = "";
        *ret_name = "";
        return 1;
    }

    // check if empty path or just "/" were passed in
    if (path_len == 0 || (strcmp(path, "/") == 0)) {
        *ret_name = "";
        *ret_parent_path = "/";
        return 0;
    } 
    
    
    // step 1, copy everything into parent_path and clean it up
    // add leading slash if its not in input.  
    if (path[0] != '/') {
        sprintf(parent_path, "%s", "/");     
    }

    strncat(parent_path, path, MAX_PATH_LENGTH);

    // remove trailing slash
    if (parent_path[strlen(parent_path)-1] == '/') {
        parent_path[strlen(parent_path)-1] = '\0';
    }

    // replace all non-UTF8 characters
    tsk_cleanupUTF8(parent_path, '^');

    // Step 2, move the final folder/file to parent_file

    // Find the last '/' 
    char *chptr = strrchr(parent_path, '/');
    if (chptr) {
        // character found in the string
        size_t position = chptr - parent_path;

        sprintf(parent_name, "%s", chptr+1);  // copy everything after slash into parent_name
        *ret_name = parent_name;

        parent_path[position + 1] = '\0';   // add terminating null after last "/"
        *ret_parent_path = parent_path;
    } else {
        // "/" character not found. the entire path is parent file name. parent path is "/"
        *ret_name = parent_path;
        *ret_parent_path = "/";
    } 
    return 0;
}
