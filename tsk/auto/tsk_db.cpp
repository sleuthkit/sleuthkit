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
* NOTE: input path may be modified inside this method!
* @param path Path of folder that we want to analyze
* @param ret_parent_path pointer to parent path
* @param ret_name pointer to where folder/file name
* @returns 0 on success, 1 on error
*/
void TskDb::getParentPathAndName(char *path, char **ret_parent_path, char **ret_name){
    // Need to break up 'path' in to the parent folder to match in 'parent_path' and the folder 
    // name to match with the 'name' column in tsk_files table

    // replace all non-UTF8 characters
    tsk_cleanupUTF8(path, '^');

    size_t path_len = strlen(path);
    const char *ch = "/";

    // check if just "/" was passed in
    if (path_len == 1 && strcmp(&path[0], ch) == 0) {
        // set pointers to return "/" and ""
        *ret_parent_path = path;
        *ret_name = "";
        return;
    }

    // check if it ends with a '/' 
    if (strcmp(&path[path_len - 1], ch) == 0) {
        // remove it by setting it to '\0'
        path[path_len - 1] = '\0'; 
    }

    // Find the last '/'. Set the pointer for the file name to the char after it. Set '/' to '\0'
    char *chptr = strrchr(path, *ch);
    if (chptr) {
        // character found in the string
        size_t position = chptr - path;
        *ret_name = chptr+1;
        path[position] = '\0';
        *ret_parent_path = path;
    } else {
        // "/" character not found. the entire path is parent file name. parent path is "/"
        *ret_name = path;
        *ret_parent_path = "/";
    }
}
