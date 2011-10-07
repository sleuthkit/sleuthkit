/*
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2011 Brian Carrier, Basis Technology.  All rights reserved
 *
 * mult_files
 *
 * This software is distributed under the Common Public License 1.0
 *
 */


/**
 * \file mult_files.c
 * Internal code to find remainder of files in a split / E01 / etc. set
 */

#include "tsk_img_i.h"



/** 
 * @param a_baseName The name minus the incrementing part of hte name ("test.E" for example).  Must include '.'
 * @param a_baseExt The first extention to use "01" for example -- must not have '.' and can only be 2 long and it is case sensitive
 * @param a_nameList List to add names to.  Must be of correct size.  No checking is done internally.  If NULL,
 * then no values will be added and instead the method will only count how many files would have been copied.
 * @param a_numFound The number of files found so far (i.e. starting point into a_nameList and will have the
 * final number of entries in a_nameList at the end.
 * @returns 1 on error (memory, args, etc.)
 */
static uint8_t 
findFiles2(const TSK_TCHAR *a_baseName, const TSK_TCHAR *a_baseExt, TSK_TCHAR **a_nameList, int *a_numFound) 
{
    TSK_TCHAR tmpName[2048];
    TSK_TCHAR curExt[3];
    int i;
    uint8_t isNumeric;
    memset(tmpName, 0, 2048*sizeof(TSK_TCHAR));
    memset(curExt, 0, 3*sizeof(TSK_TCHAR));

    if (TSTRLEN(a_baseExt) > 2) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_IMG_ARG;
        snprintf(tsk_errstr, TSK_ERRSTR_L, "findFiles2: extention is too short: %"PRIttocTSK, a_baseExt);
        return 1;
    }
    TSTRNCPY(curExt, a_baseExt, 3);
    
    // @@@ There are problms here if they specify non-standard things (like 00)
    // could probably use atoi equivalent instead
    if (TSTRCMP(a_baseExt, _TSK_T("01")) == 0) {
        isNumeric = 1;
        i = 1;
    }
    else {
        isNumeric = 0;
        i = 0;
    }

    while (1) {
        struct STAT_STR stat_buf;
        
        // make the name
        if (isNumeric) {
            TSNPRINTF(tmpName, 2048, _TSK_T("%s%.2d"), a_baseName, i);
        }
        else {
            // The use of a_base_ext here is not entirely correct if they did not specify AA or aa... HACK
            TSK_TCHAR a = a_baseExt[0] + (i / 26);
            TSK_TCHAR b = a_baseExt[0] + (i % 26);
            TSNPRINTF(tmpName, 2048, _TSK_T("%s%c%c"), a_baseName, a, b);
        }
        
        // does the file exist?
        if (TSTAT(tmpName, &stat_buf) < 0) {
            break;
        }
        
        if (tsk_verbose) 
            tsk_fprintf(stderr, "tsk_img_findFiles: %"PRIttocTSK" found\n", tmpName);
                                            
        // save it, if they gave us a buffer
        if (a_nameList) {
            TSK_TCHAR *tmpName2;
            if ((tmpName2 = (TSK_TCHAR *)tsk_malloc((TSTRLEN(tmpName)+1) * sizeof(TSK_TCHAR))) == NULL) {
                return 1;
            }
            TSTRNCPY(tmpName2, tmpName, TSTRLEN(tmpName)+1);
            a_nameList[*a_numFound] = tmpName2;
        }
        (*a_numFound)++;
        i++;
    }
    
    return 0;
}


// makes a copy of the passed image name into a ** struct.
static TSK_TCHAR **
copyInBase(const TSK_TCHAR *a_image)
{
 
    TSK_TCHAR **tmpName;
    
    if ((tmpName = tsk_malloc(sizeof(TSK_TCHAR *))) == NULL) {
        return NULL;
    }
    
    if ((tmpName[0] = tsk_malloc((TSTRLEN(a_image)+1) * sizeof(TSK_TCHAR))) == NULL) {
        free(tmpName);
        return NULL;
    }
    TSTRNCPY(tmpName[0], a_image, TSTRLEN(a_image)+1);
    return tmpName;
}

/**
 * @param a_startingName First name in the list (must be full name)
 * @param [out] a_numFound Number of images that are in returned list
 * @returns array of names that caller must free (NULL on error or if supplied file does not exist)
 */
TSK_TCHAR **
tsk_img_findFiles(const TSK_TCHAR *a_startingName, int *a_numFound) 
{
    TSK_TCHAR **retNames = NULL;
    *a_numFound = 0;
    
    // we can't do anything with this...
    if (TSTRLEN(a_startingName) < 3) {
        *a_numFound = 1;
        return copyInBase(a_startingName);
    }

    // E01 file
    if ((TSTRICMP(&a_startingName[TSTRLEN(a_startingName)-4], _TSK_T(".e01")) == 0) || 
        (TSTRICMP(&a_startingName[TSTRLEN(a_startingName)-4], _TSK_T(".s01")) == 0)) {
        TSK_TCHAR *baseName;
        int fileCount = 0;
        
        if ((baseName = (TSK_TCHAR *)tsk_malloc(TSTRLEN(a_startingName) * sizeof(TSK_TCHAR))) == NULL) {
            return NULL;
        }
        TSTRNCPY(baseName, a_startingName, TSTRLEN(a_startingName)-2);
        
        // first lets get a count
        fileCount = 0;
        if (findFiles2(baseName, _TSK_T("01"), NULL, &fileCount)) {
            free(baseName);
            return NULL;
        }
        
        if (fileCount == 99) {
            if (findFiles2(baseName, _TSK_T("AA"), NULL, &fileCount)) {
                free(baseName);
                return NULL;
            }
        }
        if (tsk_verbose) 
            tsk_fprintf(stderr, "tsk_img_findFiles: %d total images found\n", fileCount);
        
        if (fileCount == 0) {
            free(baseName);
            return NULL;
        }
        
        // now we copy them
        if ((retNames = (TSK_TCHAR **)tsk_malloc(fileCount * sizeof(TSK_TCHAR *))) == NULL) {
            free(baseName);
            return NULL;
        }
        
        *a_numFound = 0;
        if (findFiles2(baseName, _TSK_T("01"), retNames, a_numFound)) {
            free(baseName);
            free(retNames);
            return NULL;
        }
        
        if (*a_numFound == 99) {
            if (findFiles2(baseName, _TSK_T("AA"), retNames, a_numFound)) {
                free(baseName);
                free(retNames);
                return NULL;
            }
        }
        free(baseName);
    }
    else if (TSTRICMP(&a_startingName[TSTRLEN(a_startingName)-3], _TSK_T(".aa")) == 0) {
        TSK_TCHAR *baseName;
        int fileCount = 0;
        
        if ((baseName = (TSK_TCHAR *)tsk_malloc(TSTRLEN(a_startingName) * sizeof(TSK_TCHAR))) == NULL) {
            return NULL;
        }
        
        TSTRNCPY(baseName, a_startingName, TSTRLEN(a_startingName)-2);
        
        // first lets get a count
        fileCount = 0;
        if (findFiles2(baseName, &a_startingName[TSTRLEN(a_startingName)-1], NULL, &fileCount)) {
            free(baseName);
            return NULL;
        }
        
        if (tsk_verbose) 
            tsk_fprintf(stderr, "tsk_img_findFiles: %d total images found\n", fileCount);

        if (fileCount == 0) {
            free(baseName);
            return NULL;
        }
        
        // now lets copy them
        if ((retNames = (TSK_TCHAR **)tsk_malloc(fileCount * sizeof(TSK_TCHAR *))) == NULL) {
            free(baseName);
            return NULL;
        }

        *a_numFound = 0;
        if (findFiles2(baseName, &a_startingName[TSTRLEN(a_startingName)-1], retNames, a_numFound)) {
            free(baseName);
            free(retNames);
            return NULL;
        }
        free(baseName);
    }
    return retNames;
}
