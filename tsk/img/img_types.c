/*
** img_types
** The Sleuth Kit 
**
** Identify the type of image file being used
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2006-2011 Brian Carrier.  All rights reserved 
**
** This software is distributed under the Common Public License 1.0
*/

/** \file img_types.c
 * Contains basic functions to parse and print the names of the supported disk image types. 
 */
#include "tsk_img_i.h"

/** \internal
  * used to parse and print supported types
  */
typedef struct {
    char *name;
    uint16_t code;
    char *comment;
} IMG_TYPES;

/** \internal
 * The table used to parse input strings 
 * - in order of expected usage
 */
static IMG_TYPES img_open_table[] = {
    {"raw", TSK_IMG_TYPE_RAW, "Single or split raw file (dd)"},
#if HAVE_LIBAFFLIB
    {"aff", TSK_IMG_TYPE_AFF_AFF, "Advanced Forensic Format"},
    {"afd", TSK_IMG_TYPE_AFF_AFD, "AFF Multiple File"},
    {"afm", TSK_IMG_TYPE_AFF_AFM, "AFF with external metadata"},
    {"afflib", TSK_IMG_TYPE_AFF_ANY,
        "All AFFLIB image formats (including beta ones)"},
#endif
#if HAVE_LIBEWF
    {"ewf", TSK_IMG_TYPE_EWF_EWF, "Expert Witness Format (EnCase)"},
#endif
#if HAVE_LIBVMDK
    {"vmdk", TSK_IMG_TYPE_VMDK_VMDK, "Virtual Machine Disk (VmWare, Virtual Box)"},
#endif
#if HAVE_LIBVHDI
    {"vhd", TSK_IMG_TYPE_VHD_VHD, "Virtual Hard Drive (Microsoft)"},
#endif
    {0},
};


/**
 * \ingroup imglib
 * Parses a string that specifies an image format to determine the 
 * associated type ID.  This is used by the TSK command line tools to
 * parse the type given on the command line. 
 *
 * @param str String of image format type, always UTF-8
 * @return ID of image type
 */
TSK_IMG_TYPE_ENUM
tsk_img_type_toid_utf8(const char *str)
{
    IMG_TYPES *sp;

    for (sp = img_open_table; sp->name; sp++) {
        if (strcmp(str, sp->name) == 0) {
            return sp->code;
        }
    }
    return TSK_IMG_TYPE_UNSUPP;
}


/**
 * \ingroup imglib
 * Parses a string that specifies an image format to determine the 
 * associated type ID.  This is used by the TSK command line tools to
 * parse the type given on the command line. 
 *
 * @param str String of image format type
 * @return ID of image type
 */
TSK_IMG_TYPE_ENUM
tsk_img_type_toid(const TSK_TCHAR * str)
{
    char tmp[16];
    int i;

    // convert to char
    for (i = 0; i < 15 && str[i] != '\0'; i++) {
        tmp[i] = (char) str[i];
    }
    tmp[i] = '\0';

    return tsk_img_type_toid_utf8(tmp);
}


/**
 * \ingroup imglib
 * Prints the name and description of the supported image types to a handle.
 * This is used by the TSK command line tools to print the supported types
 * to the console.
 * @param hFile Handle to print names and descriptions to.
 */
void
tsk_img_type_print(FILE * hFile)
{
    IMG_TYPES *sp;
    tsk_fprintf(hFile, "Supported image format types:\n");
    for (sp = img_open_table; sp->name; sp++)
        tsk_fprintf(hFile, "\t%s (%s)\n", sp->name, sp->comment);
}

/**
 * \ingroup imglib
 * Returns the name of an image format type, given its type ID.
 * @param type ID of image type
 * @returns Pointer to string of the name.
 */
const char *
tsk_img_type_toname(TSK_IMG_TYPE_ENUM type)
{
    IMG_TYPES *sp;
    for (sp = img_open_table; sp->name; sp++)
        if (sp->code == type)
            return sp->name;

    return NULL;
}

/**
 * \ingroup imglib
 * Returns the description of an image format type, given its type ID.
 * @param type ID of image type
 * @returns Pointer to string of the description
 */
const char *
tsk_img_type_todesc(TSK_IMG_TYPE_ENUM type)
{
    IMG_TYPES *sp;
    for (sp = img_open_table; sp->name; sp++)
        if (sp->code == type)
            return sp->comment;

    return NULL;
}

/**
 * \ingroup imglib
 * Returns the supported file format types.
 * @returns A bit in the return value is set to 1 if the type is supported.
 */
TSK_IMG_TYPE_ENUM
tsk_img_type_supported()
{
    TSK_IMG_TYPE_ENUM sup_types = 0;
    IMG_TYPES *sp;
    for (sp = img_open_table; sp->name; sp++) {
        sup_types |= sp->code;
    }
    return sup_types;
}
