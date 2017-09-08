/*
** fatfs_dent
** The Sleuth Kit
**
** file name layer support for the FAT file system
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2006-2013 Brian Carrier, Basis Technology.  All Rights reserved
** Copyright (c) 2003-2005 Brian Carrier.  All rights reserved
**
** TASK
** Copyright (c) 2002 Brian Carrier, @stake Inc.  All rights reserved
**
**
** This software is distributed under the Common Public License 1.0
**
** Unicode added with support from I.D.E.A.L. Technology Corp (Aug '05)
**
*/

/**
* \file fatfs_dent.cpp
* Contains the internal TSK FAT file name processing code.
*/

#include "tsk_fs_i.h"
#include "tsk_fatxxfs.h"
#include "tsk_exfatfs.h"
#include "tsk_fatfs.h"

#include <map>

/*
* DESIGN NOTES
*
* the basic goal of this code is to parse directory entry structures for
* file names.  The main function is fatfs_parse_buf, which parses
* a buffer and stores the entries in FS_DIR.  That structure is then
* used by dir_get() or dir_walk() to provide the data back to the user.
*
* One of the odd aspects of this code is that the 'inode' values are
* the 'slot-address'.  Refer to the document on how FAT was implemented
* for more details. This means that we need to search for the actual
* 'inode' address for the '.' and '..' entries though!  The search
* for '..' is quite painful if this code is called from a random
* location.  It does save what the parent is though, so the search
* only has to be done once per session.
*/

/*
* name_walk callback used when finding the parent directory.  It
* forces the walking process to stop when we hit a target directory.
* A list of directory to parent directory mappings is built up during
* the walk and this function is used to stop that building process.
*/
TSK_WALK_RET_ENUM
    fatfs_find_parent_act(TSK_FS_FILE * fs_file, const char *a_path, void *ptr)
{
    TSK_INUM_T par_inum = *(TSK_INUM_T *) ptr;

    if ((fs_file->meta == NULL)
        || ( ! TSK_FS_IS_DIR_META(fs_file->meta->type)))
        return TSK_WALK_CONT;

    if (fs_file->meta->addr == par_inum)
        return TSK_WALK_STOP;

    return TSK_WALK_CONT;
}

/** \internal
* Casts the void * to a map.  This obfuscation is done so that the rest of the library
* can remain as C and only this code needs to be C++.
*
* Assumes that you already have the lock
*/
static std::map<TSK_INUM_T, TSK_INUM_T> * getParentMap(FATFS_INFO *fatfs) {
    // allocate it if it hasn't already been 
    if (fatfs->inum2par == NULL) {
        fatfs->inum2par = new std::map<TSK_INUM_T, TSK_INUM_T>;
    }
    return (std::map<TSK_INUM_T, TSK_INUM_T> *)fatfs->inum2par;
}

/**
* Adds an entry to the parent directory map.  Used to make further processing
* faster.
* @param fatfs File system
* @param par_inum Parent folder meta data address.
* @param dir_inum Sub-folder meta data address.
* @returns 0
*/
uint8_t
    fatfs_dir_buf_add(FATFS_INFO * fatfs, TSK_INUM_T par_inum,
    TSK_INUM_T dir_inum)
{
    tsk_take_lock(&fatfs->dir_lock);
    std::map<TSK_INUM_T, TSK_INUM_T> *tmpMap = getParentMap(fatfs);
    (*tmpMap)[dir_inum] = par_inum;
    tsk_release_lock(&fatfs->dir_lock);

    return 0;
}

/**
* Looks up the parent meta address for a child from the cached list.
* @param fatfs File system
* @param dir_inum Inode of sub-directory to look up
* @param par_inum [out] Result of lookup
* @returns 0 if found and 1 if not. 
*/
uint8_t
    fatfs_dir_buf_get(FATFS_INFO * fatfs, TSK_INUM_T dir_inum,
    TSK_INUM_T *par_inum)
{
    uint8_t retval = 1;
    tsk_take_lock(&fatfs->dir_lock);
    std::map<TSK_INUM_T, TSK_INUM_T> *tmpMap = getParentMap(fatfs);
    if (tmpMap->count( dir_inum) > 0) {
        *par_inum = (*tmpMap)[dir_inum];
        retval = 0;
    }
    tsk_release_lock(&fatfs->dir_lock);

    return retval;
}

/**
* Frees the memory associated with the parent map
*/
void fatfs_dir_buf_free(FATFS_INFO *fatfs) {
    tsk_take_lock(&fatfs->dir_lock);
    if (fatfs->inum2par != NULL) {
        std::map<TSK_INUM_T, TSK_INUM_T> *tmpMap = getParentMap(fatfs);
        delete tmpMap;
        fatfs->inum2par = NULL;
    }
    tsk_release_lock(&fatfs->dir_lock);
}

/**************************************************************************
*
* dent_walk
*
*************************************************************************/

/* values used to copy the directory contents into a buffer */


typedef struct {
    /* ptr to the current location in a local buffer */
    char *curdirptr;

    /* number of bytes left in curdirptr */
    size_t dirleft;

    /* ptr to a local buffer for the stack of sector addresses */
    TSK_DADDR_T *addrbuf;

    /* num of entries allocated to addrbuf */
    size_t addrsize;

    /* The current index in the addrbuf stack */
    size_t addridx;

} FATFS_LOAD_DIR;



/**
* file walk callback that is used to load directory contents
* into a buffer
*/
static TSK_WALK_RET_ENUM
    fatfs_dent_action(TSK_FS_FILE * fs_file, TSK_OFF_T a_off, TSK_DADDR_T addr,
    char *buf, size_t size, TSK_FS_BLOCK_FLAG_ENUM flags, void *ptr)
{
    FATFS_LOAD_DIR *load = (FATFS_LOAD_DIR *) ptr;

    /* how much of the buffer are we copying */
    size_t len = (load->dirleft < size) ? load->dirleft : size;

    /* Copy the sector into a buffer and increment the pointers */
    memcpy(load->curdirptr, buf, len);
    load->curdirptr = (char *) ((uintptr_t) load->curdirptr + len);
    load->dirleft -= len;

    /* fill in the stack of addresses of sectors
    *
    * if we are at the last entry, then realloc more */
    if (load->addridx == load->addrsize) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr
            ("fatfs_dent_walk: Trying to put more sector address in stack than were allocated (%lu)",
            (long) load->addridx);
        return TSK_WALK_ERROR;
    }

    /* Add this sector to the stack */
    load->addrbuf[load->addridx++] = addr;

    if (load->dirleft)
        return TSK_WALK_CONT;
    else
        return TSK_WALK_STOP;
}


/** \internal
* Process a directory and load up FS_DIR with the entries. If a pointer to
* an already allocated FS_DIR structure is given, it will be cleared.  If no existing
* FS_DIR structure is passed (i.e. NULL), then a new one will be created. If the return
* value is error or corruption, then the FS_DIR structure could
* have entries (depending on when the error occurred).
*
* @param a_fs File system to analyze
* @param a_fs_dir Pointer to FS_DIR pointer. Can contain an already allocated
* structure or a new structure.
* @param a_addr Address of directory to process.
* @returns error, corruption, ok etc.
*/

TSK_RETVAL_ENUM
    fatfs_dir_open_meta(TSK_FS_INFO * a_fs, TSK_FS_DIR ** a_fs_dir,
    TSK_INUM_T a_addr)
{
    const char *func_name = "fatfs_dir_open_meta";
    TSK_OFF_T size, len;
    FATFS_INFO *fatfs = (FATFS_INFO *) a_fs;
    char *dirbuf;
    TSK_DADDR_T *addrbuf;
    FATFS_LOAD_DIR load;
    TSK_RETVAL_ENUM retval;

    TSK_FS_DIR *fs_dir;

    if ((a_addr < a_fs->first_inum) || (a_addr > a_fs->last_inum)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("%s: invalid a_addr value: %"
            PRIuINUM "\n", func_name, a_addr);
        return TSK_ERR;
    }
    else if (a_fs_dir == NULL) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr
            ("%s: NULL fs_attr argument given", func_name);
        return TSK_ERR;
    }

    fs_dir = *a_fs_dir;
    if (fs_dir) {
        tsk_fs_dir_reset(fs_dir);
        fs_dir->addr = a_addr;
    }
    else {
        if ((*a_fs_dir = fs_dir =
            tsk_fs_dir_alloc(a_fs, a_addr, 128)) == NULL) {
                return TSK_ERR;
        }
    }

    //  handle the orphan directory if its contents were requested
    if (a_addr == TSK_FS_ORPHANDIR_INUM(a_fs)) {
        return tsk_fs_dir_find_orphans(a_fs, fs_dir);
    }

    fs_dir->fs_file = tsk_fs_file_open_meta(a_fs, NULL, a_addr);
    if (fs_dir->fs_file == NULL) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_INODE_NUM);
        tsk_error_set_errstr("%s: %" PRIuINUM
            " is not a valid inode", func_name, a_addr);
        return TSK_COR;
    }

    size = fs_dir->fs_file->meta->size;
    len = roundup(size, fatfs->ssize);

    if (tsk_verbose) {
        tsk_fprintf(stderr,
        "%s: Processing directory %" PRIuINUM "\n",
        func_name, a_addr);
    }

    if (size == 0) {
        if (tsk_verbose)
            tsk_fprintf(stderr,
            "%s: directory has 0 size\n", func_name);
        return TSK_OK;
    }

    /* Make a copy of the directory contents using file_walk */
    if ((dirbuf = (char *)tsk_malloc((size_t) len)) == NULL) {
        return TSK_ERR;
    }
    load.curdirptr = dirbuf;
    load.dirleft = (size_t) size;

    /* We are going to save the address of each sector in the directory
    * in a stack - they are needed to determine the inode address.
    */
    load.addrsize = (size_t) (len / fatfs->ssize);
    addrbuf =
        (TSK_DADDR_T *) tsk_malloc(load.addrsize * sizeof(TSK_DADDR_T));
    if (addrbuf == NULL) {
        free(dirbuf);
        return TSK_ERR;
    }

    /* Set the variables that are used during the copy */
    load.addridx = 0;
    load.addrbuf = addrbuf;

    /* save the directory contents into dirbuf */
    if (tsk_fs_file_walk(fs_dir->fs_file,
        TSK_FS_FILE_WALK_FLAG_SLACK,
        fatfs_dent_action, (void *) &load)) {
            tsk_error_errstr2_concat("- %s", func_name);
            free(dirbuf);
            free(addrbuf);
            return TSK_COR;
    }

    /* We did not copy the entire directory, which occurs if an error occurred */
    if (load.dirleft > 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_FWALK);
        tsk_error_set_errstr
            ("%s: Error reading directory %" PRIuINUM,
            func_name, a_addr);

        /* Free the local buffers */
        free(dirbuf);
        free(addrbuf);
        return TSK_COR;
    }

    if (tsk_verbose)
        fprintf(stderr,
        "%s: Parsing directory %" PRIuINUM "\n",
        func_name, a_addr);

    retval = fatfs->dent_parse_buf(fatfs, fs_dir, dirbuf, len, addrbuf);

    free(dirbuf);
    free(addrbuf);

    // if we are listing the root directory, add the Orphan directory and special FAT file entries
    if (a_addr == a_fs->root_inum) {
        TSK_FS_NAME *fs_name = tsk_fs_name_alloc(256, 0);
        if (fs_name == NULL)
            return TSK_ERR;

        // MBR Entry
        strncpy(fs_name->name, FATFS_MBRNAME, fs_name->name_size);
        fs_name->meta_addr = fatfs->mbr_virt_inum;
        fs_name->type = TSK_FS_NAME_TYPE_VIRT;
        fs_name->flags = TSK_FS_NAME_FLAG_ALLOC;
        if (tsk_fs_dir_add(fs_dir, fs_name)) {
            tsk_fs_name_free(fs_name);
            return TSK_ERR;
        }

        // FAT1 Entry
        strncpy(fs_name->name, FATFS_FAT1NAME, fs_name->name_size);
        fs_name->meta_addr = fatfs->fat1_virt_inum;
        fs_name->type = TSK_FS_NAME_TYPE_VIRT;
        fs_name->flags = TSK_FS_NAME_FLAG_ALLOC;
        if (tsk_fs_dir_add(fs_dir, fs_name)) {
            tsk_fs_name_free(fs_name);
            return TSK_ERR;
        }

        // FAT2 Entry
        if (fatfs->numfat == 2) {
            strncpy(fs_name->name, FATFS_FAT2NAME, fs_name->name_size);
            fs_name->meta_addr = fatfs->fat2_virt_inum;
            fs_name->type = TSK_FS_NAME_TYPE_VIRT;
            fs_name->flags = TSK_FS_NAME_FLAG_ALLOC;
            if (tsk_fs_dir_add(fs_dir, fs_name)) {
                tsk_fs_name_free(fs_name);
                return TSK_ERR;
            }
        }

        // orphan directory
        if (tsk_fs_dir_make_orphan_dir_name(a_fs, fs_name)) {
            tsk_fs_name_free(fs_name);
            return TSK_ERR;
        }
        if (tsk_fs_dir_add(fs_dir, fs_name)) {
            tsk_fs_name_free(fs_name);
            return TSK_ERR;
        }
        tsk_fs_name_free(fs_name);
    }

    return retval;
}

int
fatfs_name_cmp(TSK_FS_INFO * a_fs_info, const char *s1, const char *s2)
{
    return strcasecmp(s1, s2);
}
