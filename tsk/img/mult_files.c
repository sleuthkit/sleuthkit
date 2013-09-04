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
 * Internal code to find remainder of files in a split raw set
 */

#include "tsk_img_i.h"


// return non-zero if str ends with suffix, ignoring case
static int
endsWith(const TSK_TCHAR * str, const TSK_TCHAR * suffix)
{

    if (TSTRLEN(str) >= TSTRLEN(suffix)) {
        return (TSTRICMP(&str[TSTRLEN(str) - TSTRLEN(suffix)],
                suffix) == 0);
    }
    return 0;
}


/** Generate the name of the Nth segment of an image, given the starting name.
 * If the name scheme isn't recognized, just returns the starting name for
 * segment 1 and NULL for subsequent segments.
 *
 * @param a_startingName First name in the list (must be full name)
 * @param a_segmentNumber The file number to generate a name for (starting at 1)
 * @returns newly-allocated file name for this segment number or NULL on error
 */
static TSK_TCHAR *
getSegmentName(const TSK_TCHAR * a_startingName, int a_segmentNumber)
{

    size_t nameLen = TSTRLEN(a_startingName);
    TSK_TCHAR *newName =
        (TSK_TCHAR *) tsk_malloc((nameLen + 32) * sizeof(TSK_TCHAR));
    // (extra space to allow for .NNN.dmgpart for .dmg file names and for
    // large segment numbers, which could be 10 digits for 32-bit int)

    if (newName == NULL)
        return NULL;

    // segment 1 uses the original file name always
    TSTRNCPY(newName, a_startingName, nameLen + 1);
    if (a_segmentNumber == 1) {
        return newName;
    }

    // .dmg case: second part is .002.dmgpart (etc.)
    if (endsWith(a_startingName, _TSK_T(".dmg"))) {
        TSNPRINTF(newName + nameLen - 3, 35, _TSK_T("%03d.dmgpart"),
            a_segmentNumber);
        return newName;
    }

    // numeric counter case, 3 digit
    if (endsWith(a_startingName, _TSK_T(".001")) ||
        endsWith(a_startingName, _TSK_T("_001"))) {

        // don't limit to 3 digits (FTK produces files named
        // foo.1000 for 1000-part DD images)
        TSNPRINTF(newName + nameLen - 3, 35, _TSK_T("%03d"),
            a_segmentNumber);
        return newName;
    }

    // 0-based numeric counter case, 3 digit
    if (endsWith(a_startingName, _TSK_T(".000")) ||
        endsWith(a_startingName, _TSK_T("_000"))) {

        TSNPRINTF(newName + nameLen - 3, 35, _TSK_T("%03d"),
            a_segmentNumber - 1);
        return newName;
    }

    // numeric counter case, 2 digit
    if (endsWith(a_startingName, _TSK_T(".01")) ||
        endsWith(a_startingName, _TSK_T("_01"))) {

        TSNPRINTF(newName + nameLen - 2, 34, _TSK_T("%02d"),
            a_segmentNumber);
        return newName;
    }

    // 0-based numeric counter case, 2 digit
    if (endsWith(a_startingName, _TSK_T(".00")) ||
        endsWith(a_startingName, _TSK_T("_00"))) {

        TSNPRINTF(newName + nameLen - 2, 34, _TSK_T("%02d"),
            a_segmentNumber - 1);
        return newName;
    }

    // alphabetic counter, 3 character
    if (endsWith(a_startingName, _TSK_T(".aaa")) ||
        endsWith(a_startingName, _TSK_T("xaaa")) ||
        endsWith(a_startingName, _TSK_T("_aaa"))) {

        // preserve case for the alpha characters
        a_segmentNumber--;
        newName[nameLen - 1] += (a_segmentNumber % 26);
        a_segmentNumber /= 26;
        newName[nameLen - 2] += (a_segmentNumber % 26);
        a_segmentNumber /= 26;
        newName[nameLen - 3] += (a_segmentNumber % 26);
        a_segmentNumber /= 26;
        if (a_segmentNumber > 0) {
            // too many segments for format
            free(newName);
            return NULL;
        }
        return newName;
    }

    // alphabetic counter, 2 character
    if (endsWith(a_startingName, _TSK_T(".aa")) ||
        endsWith(a_startingName, _TSK_T("xaa")) ||
        endsWith(a_startingName, _TSK_T("_aa"))) {

        // preserve case for the alpha characters
        a_segmentNumber--;
        newName[nameLen - 1] += (a_segmentNumber % 26);
        a_segmentNumber /= 26;
        newName[nameLen - 2] += (a_segmentNumber % 26);
        a_segmentNumber /= 26;
        if (a_segmentNumber > 0) {
            // too many segments for format
            free(newName);
            return NULL;
        }
        return newName;
    }

	// numeric counter, variable width
    if (endsWith(a_startingName, _TSK_T(".bin"))) {
		TSNPRINTF(newName + nameLen - 4, 36, _TSK_T("(%d).bin"),
            a_segmentNumber);
        return newName;
    }

    // unknown name format
    free(newName);
    return NULL;
}


/**
 * @param a_startingName First name in the list (must be full name)
 * @param [out] a_numFound Number of images that are in returned list
 * @returns array of names that caller must free (NULL on error or if supplied file does not exist)
 */
TSK_TCHAR **
tsk_img_findFiles(const TSK_TCHAR * a_startingName, int *a_numFound)
{
    TSK_TCHAR **retNames = NULL;
    TSK_TCHAR *nextName;
    TSK_TCHAR **tmpNames;
    int fileCount = 0;
    struct STAT_STR stat_buf;

    *a_numFound = 0;

    // iterate through potential segment names
    while ((nextName =
            getSegmentName(a_startingName, fileCount + 1)) != NULL) {

        // does the file exist?
        if (TSTAT(nextName, &stat_buf) < 0) {
            free(nextName);
            break;
        }

        if (tsk_verbose)
            tsk_fprintf(stderr,
                "tsk_img_findFiles: %" PRIttocTSK " found\n", nextName);

        // add to list
        fileCount++;
        if (fileCount == 1)
            tmpNames = (TSK_TCHAR **) tsk_malloc(sizeof(TSK_TCHAR *));
        else
            tmpNames =
                (TSK_TCHAR **) tsk_realloc(retNames,
                fileCount * sizeof(TSK_TCHAR *));
        if (tmpNames == NULL) {
            if (retNames != NULL)
                free(retNames);
            return NULL;
        }
        retNames = tmpNames;
        retNames[fileCount - 1] = nextName;
    }

    if (fileCount <= 0)
        return NULL;

    if (tsk_verbose)
        tsk_fprintf(stderr, "tsk_img_findFiles: %d total segments found\n",
            fileCount);
    *a_numFound = fileCount;

    return retNames;
}
