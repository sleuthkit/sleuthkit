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
* @param ret_parent_path pointer to parent path
* @param ret_name pointer to where folder/file name
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
    if (path_len == 0 || (path_len == 1 && strcmp(&path[0], "/") == 0)) {
        *ret_name = "";
        *ret_parent_path = "/";
        return 0;
    } else {
        // path usually ends with "/" which needs to be stripped off.
        // input is "const car*" so we must copy into memory that we can modify.
        // check if the first character in input path is slash
        if (strcmp(&path[0], "/") != 0) {
            sprintf(&parent_path[0], "%s", "/");           // add leasing slash to the parent path (sprintf also adds terminating null)
        }
        if (strcmp(&path[path_len - 1], "/") == 0) {
            strncpy(&parent_path[1], path, path_len - 1);   // remove trailing slash
            parent_path[path_len] = '\0';                   // add terminating null
        } else {
            sprintf(&parent_path[1], "%s", path);           // copy input path
        }
    }

    // replace all non-UTF8 characters
    tsk_cleanupUTF8(parent_path, '^');

    // Find the last '/' 
    char *ch = "/";    
    char *chptr = strrchr(parent_path, *ch);
    if (chptr) {
        // character found in the string
        size_t position = chptr - parent_path;

        sprintf(&parent_name[0], "%s", chptr+1);  // copy everything after slash into patent_name
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
