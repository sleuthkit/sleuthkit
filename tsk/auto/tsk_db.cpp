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

#define MAX_PATH_LENGTH 2048
static char cleaned_parent_path[MAX_PATH_LENGTH];
static char parent_file_name[MAX_PATH_LENGTH];
static char parent_path[MAX_PATH_LENGTH + 2]; // +2 is for leading slash and trailing slash

/*
* Utility method to break up path into parent folder and folder/file name.
* @param path Path of folder that we want to analyze
* @param ret_parent_path pointer to where parent path should be stored
* @param ret_name pointer to where folder/file name should be stored
*/
void TskDb::getParentPathAndName(const char *path, char **ret_parent_path, char **ret_name){
    // Need to break up 'path' in to the parent folder to match in 'parent_path' and the folder 
    // name to match with the 'name' column in tsk_files table

    // reset all static arrays
    cleaned_parent_path[0] = '\0';
    parent_file_name[0] = '\0';
    parent_path[0] = '\0';

    // path usually ends with "/" which needs to be stripped off
    size_t path_len = strlen(path);  
    size_t cleaned_path_len = strlen(path) + 1;
    const char *ch = "/";  
    if (path_len == 0) {
        cleaned_parent_path[0] = '\0';  // add terminating null to the empty path
    } else {
        if (strcmp(&path[path_len - 1], ch) == 0) {
            strncpy(&cleaned_parent_path[0], path, path_len - 1);   // remove trailing slash
            cleaned_parent_path[path_len - 1] = '\0';               // add terminating null
        } else {
            strncpy(&cleaned_parent_path[0], path, path_len);       // name doesn't contain trailing slash
        }
    }

    parent_path[0] = '/';  // add leasing slash to the parent path  
    
    // Find the last instance of "/"
    const char *chptr = strrchr(cleaned_parent_path, *ch);
    if (chptr) {
        // character found in the string
        size_t position = chptr - cleaned_parent_path;

        // everythig to the left is 'parent_path'
        strncpy(&parent_path[1], &cleaned_parent_path[0], position+1);   // copy after leading slash, include the trailing slash
        parent_path[position + 2] = '\0';  // add terminating null after the trailing slash

        // everything to the right is 'name'
        strcpy(&parent_file_name[0], chptr+1);
    } else {
        // "/" character not found. the entire path is parent file name. parent path is "/"
        strncpy(&parent_file_name[0], &cleaned_parent_path[0], cleaned_path_len); // copies the terminating null character as well
        parent_path[1] = '\0';  // add terminating null after the leading slash
    }

    // replace all non-UTF8 characters
    tsk_cleanupUTF8(&parent_path[0], '^');
    tsk_cleanupUTF8(&parent_file_name[0], '^');

    // assign return values to pointers
    *ret_parent_path = &parent_path[0];
    *ret_name = &parent_file_name[0];
}
