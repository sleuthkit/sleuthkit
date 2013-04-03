/*
** fs_types
** The Sleuth Kit 
**
** Identify the type of file system being used
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2006-2011 Brian Carrier, Basis Technology.  All Rights reserved
** Copyright (c) 2003-2005 Brian Carrier.  All rights reserved 
**
** TASK
** Copyright (c) 2002 Brian Carrier, @stake Inc.  All rights reserved
**
** This software is distributed under the Common Public License 1.0
**
*/

/**
 * \file fs_types.c
 * Contains TSK functions that deal with parsing and printing file system type strings.
 */

#include "tsk_fs_i.h"

/**
 * \internal
 */
typedef struct {
    char *name;
    TSK_FS_TYPE_ENUM code;
    char *comment;
} FS_TYPES;

/** \internal
 * The table used to parse input strings - supports
 * legacy strings - in order of expected usage
 */
static FS_TYPES fs_type_table[] = {
    {"ntfs", TSK_FS_TYPE_NTFS_DETECT, "NTFS"},
    {"fat", TSK_FS_TYPE_FAT_DETECT, "FAT (Auto Detection)"},
    {"ext", TSK_FS_TYPE_EXT_DETECT, "ExtX (Auto Detection)"},
    {"iso9660", TSK_FS_TYPE_ISO9660_DETECT, "ISO9660 CD"},
#if TSK_USE_HFS
    {"hfs", TSK_FS_TYPE_HFS_DETECT, "HFS+"},
#endif
    {"ufs", TSK_FS_TYPE_FFS_DETECT, "UFS (Auto Detection)"},
    {"raw", TSK_FS_TYPE_RAW_DETECT, "Raw Data"},
    {"swap", TSK_FS_TYPE_SWAP_DETECT, "Swap Space"},
    {"fat12", TSK_FS_TYPE_FAT12, "FAT12"},
    {"fat16", TSK_FS_TYPE_FAT16, "FAT16"},
    {"fat32", TSK_FS_TYPE_FAT32, "FAT32"},
    {"ext2", TSK_FS_TYPE_EXT2, "Ext2"},
    {"ext3", TSK_FS_TYPE_EXT3, "Ext3"},
    {"ext4", TSK_FS_TYPE_EXT4, "Ext4"},
    {"ufs1", TSK_FS_TYPE_FFS1, "UFS1"},
    {"ufs2", TSK_FS_TYPE_FFS2, "UFS2"},
    {"yaffs2", TSK_FS_TYPE_YAFFS2, "YAFFS2"},
    {0},
};

static FS_TYPES fs_legacy_type_table[] = {
    // legacy CLI arg names
    {"linux-ext", TSK_FS_TYPE_EXT_DETECT, "auto-detect Linux EXTxFS"},
    {"linux-ext2", TSK_FS_TYPE_EXT2, "Linux TSK_FS_TYPE_EXT_2"},
    {"linux-ext3", TSK_FS_TYPE_EXT3, "Linux TSK_FS_TYPE_EXT_3"},
    {"linux-ext4", TSK_FS_TYPE_EXT4, "Linux TSK_FS_TYPE_EXT_4"},
    {"bsdi", TSK_FS_TYPE_FFS1, "BSDi FFS"},
    {"freebsd", TSK_FS_TYPE_FFS1, "FreeBSD FFS"},
    {"netbsd", TSK_FS_TYPE_FFS1, "NetBSD FFS"},
    {"openbsd", TSK_FS_TYPE_FFS1, "OpenBSD FFS"},
    {"solaris", TSK_FS_TYPE_FFS1B, "Solaris FFS"},
    {0},
};



/**
 * \ingroup fslib
 * Parse a string with the file system type and return its internal ID.
 *
 * @param str String to parse, always UTF-8.
 * @returns ID of string (or unsupported if the name is unknown)
 */
TSK_FS_TYPE_ENUM
tsk_fs_type_toid_utf8(const char *str)
{
    FS_TYPES *sp;

    for (sp = fs_type_table; sp->name; sp++) {
        if (strcmp(str, sp->name) == 0) {
            return sp->code;
        }
    }
    // look at the legacy names
    for (sp = fs_legacy_type_table; sp->name; sp++) {
        if (strcmp(str, sp->name) == 0) {
            return sp->code;
        }
    }
    return TSK_FS_TYPE_UNSUPP;
}


/**
 * \ingroup fslib
 * Parse a string with the file system type and return its internal ID.
 *
 * @param str String to parse.
 * @returns ID of string (or unsupported if the name is unknown)
 */
TSK_FS_TYPE_ENUM
tsk_fs_type_toid(const TSK_TCHAR * str)
{
    char tmp[16];
    int i;

    // convert to char
    for (i = 0; i < 15 && str[i] != '\0'; i++) {
        tmp[i] = (char) str[i];
    }
    tmp[i] = '\0';

    return tsk_fs_type_toid_utf8(tmp);
}


/**
 * \ingroup fslib
 * Print the supported file system types to a file handle
 * @param hFile File handle to print to
 */
void
tsk_fs_type_print(FILE * hFile)
{
    FS_TYPES *sp;
    tsk_fprintf(hFile, "Supported file system types:\n");
    for (sp = fs_type_table; sp->name; sp++)
        tsk_fprintf(hFile, "\t%s (%s)\n", sp->name, sp->comment);
}

/**
 * \ingroup fslib
 * Return the string name of a file system type id.
 * @param ftype File system type id
 * @returns Name or NULL on error
 */
const char *
tsk_fs_type_toname(TSK_FS_TYPE_ENUM ftype)
{
    FS_TYPES *sp;
    for (sp = fs_type_table; sp->name; sp++)
        if (sp->code == ftype)
            return sp->name;

    return NULL;
}

/**
 * \ingroup fslib
 * Return the supported file system types. 
 * @returns The bit in the return value is 1 if the type is supported.
 */
TSK_FS_TYPE_ENUM
tsk_fs_type_supported()
{
    TSK_FS_TYPE_ENUM sup_types = 0;
    FS_TYPES *types;
    for (types = fs_type_table; types->name; types++) {
        sup_types |= types->code;
    }
    return sup_types;
}
