/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2003-2011 Brian Carrier.  All rights reserved
 *
 * This software is distributed under the Common Public License 1.0
 */

/** \file mm_types.c
 * Contains the code to parse and print the strings for the supported volume system types.
 */

#include "tsk_vs_i.h"

typedef struct {
    char *name;
    TSK_VS_TYPE_ENUM code;
    char *comment;
} VS_TYPES;


VS_TYPES vs_open_table[] = {
    {"dos", TSK_VS_TYPE_DOS,
        "DOS Partition Table"},
    {"mac", TSK_VS_TYPE_MAC, "MAC Partition Map"},
    {"bsd", TSK_VS_TYPE_BSD,
        "BSD Disk Label"},
    {"sun", TSK_VS_TYPE_SUN,
        "Sun Volume Table of Contents (Solaris)"},
    {"gpt", TSK_VS_TYPE_GPT, "GUID Partition Table (EFI)"},
    {0},
};

/**
 * \ingroup vslib
 * Parse a string with the volume system type and return its internal ID.
 *
 * @param str String to parse.
 * @returns ID of string (or unsupported if the name is unknown)
 */
TSK_VS_TYPE_ENUM
tsk_vs_type_toid(const TSK_TCHAR * str)
{
    char tmp[16];
    int i;

    // convert to char
    for (i = 0; i < 15 && str[i] != '\0'; i++) {
        tmp[i] = (char) str[i];
    }
    tmp[i] = '\0';

    return tsk_vs_type_toid_utf8(tmp);
}


/**
 * \ingroup vslib
 * Parse a string with the volume system type and return its internal ID.
 *
 * @param str String to parse (always in UTF-8).
 * @returns ID of string (or unsupported if the name is unknown)
 */
TSK_VS_TYPE_ENUM
tsk_vs_type_toid_utf8(const char *str)
{
    VS_TYPES *types;

    for (types = vs_open_table; types->name; types++) {
        if (strcmp(str, types->name) == 0) {
            return types->code;
        }
    }
    return TSK_VS_TYPE_UNSUPP;
}

/**
 * \ingroup vslib
 * Print the supported volume system type names to an open handle.
 * @param hFile Handle to print to.
 */
void
tsk_vs_type_print(FILE * hFile)
{
    VS_TYPES *types;
    tsk_fprintf(hFile, "Supported partition types:\n");
    for (types = vs_open_table; types->name; types++)
        tsk_fprintf(hFile, "\t%s (%s)\n", types->name, types->comment);
}

/**
 * \ingroup vslib
 * Return the supported volume system types. 
 * @returns The bit in the return value is 1 if the type is supported.
 */
TSK_VS_TYPE_ENUM
tsk_vs_type_supported()
{
    TSK_VS_TYPE_ENUM sup_types = 0;
    VS_TYPES *types;
    for (types = vs_open_table; types->name; types++) {
        sup_types |= types->code;
    }
    return sup_types;
}



/**
 * \ingroup vslib
 * Return the string name of a partition type ID.
 *
 * @param type Volume system type
 * @returns name of type or NULL on error
 */
const char *
tsk_vs_type_toname(TSK_VS_TYPE_ENUM type)
{
    VS_TYPES *types;
    for (types = vs_open_table; types->name; types++) {
        if (types->code == type) {
            return types->name;
        }
    }
    if (type == TSK_VS_TYPE_DBFILLER) {
        return "DB Filler";
    }
    return NULL;
}


/**
 * \ingroup vslib
 * Return the string description of a partition type ID.
 *
 * @param type Volume system type
 * @returns description of type or NULL on error
 */
const char *
tsk_vs_type_todesc(TSK_VS_TYPE_ENUM type)
{
    VS_TYPES *types;
    for (types = vs_open_table; types->name; types++) {
        if (types->code == type) {
            return types->comment;
        }
    }

    return NULL;
}
