/*
** ntfs_dent
** The Sleuth Kit
**
** name layer support for the NTFS file system
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2006-2011 Brian Carrier, Basis Technology.  All Rights reserved
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
#include "tsk_fs_i.h"
#include "tsk_ntfs.h"

/**
 * \file ntfs_dent.cpp
 * NTFS file name processing internal functions.
 */

#include <map>
#include <vector>



/* When we list a directory, we need to also look at MFT entries and what
 * they list as their parents. We used to do this only for orphan files, but 
 * we were pointed to a case whereby allocated files were not in IDX_ALLOC, but were
 * shown in Windows (when mounted).  They must have been found via the MFT entry, so 
 * we now load all parent to child relationships into the map. 
 * 
 * One of these classes is created per parent folder */
class NTFS_PAR_MAP  {
private:
        // maps sequence number to list of inums for the folder at that seq.
        std::map <uint32_t, std::vector <TSK_INUM_T> > seq2addrs;
public:
        /**
         * Add a child to this parent.
         * @param seq Sequence of the parent that this child belonged to
         * @param inum Address of child in the folder.
         */
        void add (uint32_t seq, TSK_INUM_T inum) {
            seq2addrs[seq].push_back(inum);
        }

        /**
         * Test if there are any children for this directory at a given sequence.
         * @param seq Sequence to test.
         * @returns true if children exist
         */
        bool exists (uint32_t seq) {
            if (seq2addrs.count(seq) > 0) 
                return true;
            else
                return false;
        }

        /** 
         * Get the children for this folder at a given sequence.  Use exists first. 
         * @param seq Sequence number to retrieve children for.
         * @returns list of INUMS for children.
         */
        std::vector <TSK_INUM_T> & get (uint32_t seq) {
            return seq2addrs[seq];
        }
 };



/** \internal
* Casts the void * to a map.  This obfuscation is done so that the rest of the library
* can remain as C and only this code needs to be C++.
*
* Assumes that you already have the lock
*/
static std::map<TSK_INUM_T, NTFS_PAR_MAP> * getParentMap(NTFS_INFO *ntfs) {
    // allocate it if it hasn't already been 
    if (ntfs->orphan_map == NULL) {
        ntfs->orphan_map = new std::map<TSK_INUM_T, NTFS_PAR_MAP>;
    }
    return (std::map<TSK_INUM_T, NTFS_PAR_MAP> *)ntfs->orphan_map;
}



/** \internal
 * Add a parent and child pair to the map stored in NTFS_INFO
 *
 * Note: This routine assumes &ntfs->orhpan_map_lock is locked by the caller.
 *
 * @param ntfs structure to add the pair to
 * @param par Parent address
 * @param child Child address
 * @returns 1 on error
 */
static uint8_t
ntfs_parent_map_add(NTFS_INFO * ntfs, TSK_FS_META_NAME_LIST *name_list, TSK_INUM_T child)
{
    std::map<TSK_INUM_T, NTFS_PAR_MAP> *tmpParentMap = getParentMap(ntfs);
    NTFS_PAR_MAP &tmpParMap = (*tmpParentMap)[name_list->par_inode];
    tmpParMap.add(name_list->par_seq, child);
    return 0;
}

/** \internal
 * Returns if a parent has children or not.
 *
 * Note: This routine assumes &ntfs->orhpan_map_lock is locked by the caller.
 *
 * @param ntfs File system that has already been analyzed
 * @param par Parent inode to find child files for
 * @seq seq Sequence of parent folder 
 * @returns true if parent has children.
 */
static bool 
ntfs_parent_map_exists(NTFS_INFO *ntfs, TSK_INUM_T par, uint32_t seq) 
{
    std::map<TSK_INUM_T, NTFS_PAR_MAP> *tmpParentMap = getParentMap(ntfs);
    if (tmpParentMap->count(par) > 0) {
        NTFS_PAR_MAP &tmpParMap = (*tmpParentMap)[par];
        if (tmpParMap.exists(seq))
            return true;
    }
    return false;
}

/** \internal
 * Look up a map entry by the parent address. You should call ntfs_parent_map_exists() before this, otherwise
 * an empty entry could be created. 
 *
 * Note: This routine assumes &ntfs->orhpan_map_lock is locked by the caller.
 *
 * @param ntfs File system that has already been analyzed
 * @param par Parent inode to find child files for
 * @param seq Sequence of parent inode 
 * @returns address of children files in the parent directory
 */
static std::vector <TSK_INUM_T> &
ntfs_parent_map_get(NTFS_INFO * ntfs, TSK_INUM_T par, uint32_t seq)
{
    std::map<TSK_INUM_T, NTFS_PAR_MAP> *tmpParentMap = getParentMap(ntfs);
    NTFS_PAR_MAP &tmpParMap = (*tmpParentMap)[par];
    return tmpParMap.get(seq);
}



// note that for consistency, this should be called parent_map_free, but
// that would have required an API change in a point release and this better
// matches the name in NTFS_INFO
void
ntfs_orphan_map_free(NTFS_INFO * a_ntfs)
{
    // This routine is only called from ntfs_close, so it wouldn't
    // normally need a lock.  However, it's an extern function, so be
    // safe in case someone else calls it.  (Perhaps it's extern by
    // mistake?)

    tsk_take_lock(&a_ntfs->orphan_map_lock);

    if (a_ntfs->orphan_map == NULL) {
        tsk_release_lock(&a_ntfs->orphan_map_lock);
        return;
    }
    std::map<TSK_INUM_T, NTFS_PAR_MAP> *tmpParentMap = getParentMap(a_ntfs);

    delete tmpParentMap;
    a_ntfs->orphan_map = NULL;
    tsk_release_lock(&a_ntfs->orphan_map_lock);
}


/* inode_walk callback that is used to populate the orphan_map
 * structure in NTFS_INFO */
static TSK_WALK_RET_ENUM
ntfs_parent_act(TSK_FS_FILE * fs_file, void *ptr)
{
    NTFS_INFO *ntfs = (NTFS_INFO *) fs_file->fs_info;
    TSK_FS_META_NAME_LIST *fs_name_list;

    /* go through each file name structure */
    fs_name_list = fs_file->meta->name2;
    while (fs_name_list) {
        if (ntfs_parent_map_add(ntfs, fs_name_list,
                fs_file->meta->addr))
            return TSK_WALK_ERROR;
        fs_name_list = fs_name_list->next;
    }
    return TSK_WALK_CONT;
}



/****************/

static uint8_t
ntfs_dent_copy(NTFS_INFO * ntfs, ntfs_idxentry * idxe,
    TSK_FS_NAME * fs_name)
{
    ntfs_attr_fname *fname = (ntfs_attr_fname *) & idxe->stream;
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & ntfs->fs_info;
    UTF16 *name16;
    UTF8 *name8;
    int retVal;

    fs_name->meta_addr = tsk_getu48(fs->endian, idxe->file_ref);
    fs_name->meta_seq = tsk_getu16(fs->endian, idxe->seq_num);

    name16 = (UTF16 *) & fname->name;
    name8 = (UTF8 *) fs_name->name;

    retVal = tsk_UTF16toUTF8(fs->endian, (const UTF16 **) &name16,
        (UTF16 *) ((uintptr_t) name16 +
            fname->nlen * 2), &name8,
        (UTF8 *) ((uintptr_t) name8 +
            fs_name->name_size), TSKlenientConversion);

    if (retVal != TSKconversionOK) {
        *name8 = '\0';
        if (tsk_verbose)
            tsk_fprintf(stderr,
                "Error converting NTFS name to UTF8: %d %" PRIuINUM,
                retVal, fs_name->meta_addr);
    }

    /* Make sure it is NULL Terminated */
    if ((uintptr_t) name8 > (uintptr_t) fs_name->name + fs_name->name_size)
        fs_name->name[fs_name->name_size] = '\0';
    else
        *name8 = '\0';

    if (tsk_getu64(fs->endian, fname->flags) & NTFS_FNAME_FLAGS_DIR)
        fs_name->type = TSK_FS_NAME_TYPE_DIR;
    else
        fs_name->type = TSK_FS_NAME_TYPE_REG;

    fs_name->flags = (TSK_FS_NAME_FLAG_ENUM)0;

    return 0;
}




/* This is a sanity check to see if the time is valid
 * it is divided by 100 to keep it in a 32-bit integer
 */

static uint8_t
is_time(uint64_t t)
{
#define SEC_BTWN_1601_1970_DIV100 ((369*365 + 89) * 24 * 36)
#define SEC_BTWN_1601_2020_DIV100 (SEC_BTWN_1601_1970_DIV100 + (50*365 + 6) * 24 * 36)

    t /= 1000000000;            /* put the time in seconds div by additional 100 */

    if (!t)
        return 0;

    if (t < SEC_BTWN_1601_1970_DIV100)
        return 0;

    if (t > SEC_BTWN_1601_2020_DIV100)
        return 0;

    return 1;
}



/**
 * Process a lsit of index entries and add to FS_DIR
 *
 * @param a_is_del Set to 1 if these entries are for a deleted directory
 * @param idxe Buffer with index entries to process
 * @param idxe_len Length of idxe buffer (in bytes)
 * @param used_len Length of data as reported by idexlist header (everything
 * after which and less then idxe_len is considered deleted)
 *
 * @returns 1 to stop, 0 on success, and -1 on error
 */

// @@@ Should make a_idxe const and use internal pointer in function loop
static TSK_RETVAL_ENUM
ntfs_proc_idxentry(NTFS_INFO * a_ntfs, TSK_FS_DIR * a_fs_dir,
    uint8_t a_is_del, ntfs_idxentry * a_idxe, uint32_t a_idxe_len,
    uint32_t a_used_len)
{
    uintptr_t endaddr, endaddr_alloc;
    TSK_FS_NAME *fs_name;
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & a_ntfs->fs_info;

    if ((fs_name = tsk_fs_name_alloc(NTFS_MAXNAMLEN_UTF8, 0)) == NULL) {
        return TSK_ERR;
    }

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "ntfs_proc_idxentry: Processing index entry: %" PRIu64
            "  Size: %" PRIu32 "  Len: %" PRIu32 "\n",
            (uint64_t) ((uintptr_t) a_idxe), a_idxe_len, a_used_len);

    /* Sanity check */
    if (a_idxe_len < a_used_len) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr
            ("ntfs_proc_idxentry: Allocated length of index entries is larger than buffer length");
        return TSK_ERR;
    }

    /* where is the end of the buffer */
    endaddr = ((uintptr_t) a_idxe + a_idxe_len);

    /* where is the end of the allocated data */
    endaddr_alloc = ((uintptr_t) a_idxe + a_used_len);

    /* cycle through the index entries, based on provided size */
    while (((uintptr_t) & (a_idxe->stream) + sizeof(ntfs_attr_fname)) <
        endaddr) {

        ntfs_attr_fname *fname = (ntfs_attr_fname *) & a_idxe->stream;


        if (tsk_verbose)
            tsk_fprintf(stderr,
                "ntfs_proc_idxentry: New IdxEnt: %" PRIu64
                " $FILE_NAME Entry: %" PRIu64 "  File Ref: %" PRIu64
                "  IdxEnt Len: %" PRIu16 "  StrLen: %" PRIu16 "\n",
                (uint64_t) ((uintptr_t) a_idxe),
                (uint64_t) ((uintptr_t) fname),
                (uint64_t) tsk_getu48(fs->endian, a_idxe->file_ref),
                tsk_getu16(fs->endian, a_idxe->idxlen),
                tsk_getu16(fs->endian, a_idxe->strlen));

        /* perform some sanity checks on index buffer head
         * and advance by 4-bytes if invalid
         */
        if ((tsk_getu48(fs->endian, a_idxe->file_ref) > fs->last_inum) ||
            (tsk_getu48(fs->endian, a_idxe->file_ref) < fs->first_inum) ||
            (tsk_getu16(fs->endian,
                    a_idxe->idxlen) <= tsk_getu16(fs->endian,
                    a_idxe->strlen))
            || (tsk_getu16(fs->endian, a_idxe->idxlen) % 4)
            || (tsk_getu16(fs->endian, a_idxe->idxlen) > a_idxe_len)) {
            a_idxe = (ntfs_idxentry *) ((uintptr_t) a_idxe + 4);
            continue;
        }

        /* do some sanity checks on the deleted entries
         */
        if ((tsk_getu16(fs->endian, a_idxe->strlen) == 0) ||
            (((uintptr_t) a_idxe + tsk_getu16(fs->endian,
                        a_idxe->idxlen)) > endaddr_alloc)) {

            /* name space checks */
            if ((fname->nspace != NTFS_FNAME_POSIX) &&
                (fname->nspace != NTFS_FNAME_WIN32) &&
                (fname->nspace != NTFS_FNAME_DOS) &&
                (fname->nspace != NTFS_FNAME_WINDOS)) {
                a_idxe = (ntfs_idxentry *) ((uintptr_t) a_idxe + 4);
                if (tsk_verbose)
                    tsk_fprintf(stderr,
                        "ntfs_proc_idxentry: Skipping because of invalid name space\n");
                continue;
            }

            if ((tsk_getu64(fs->endian, fname->alloc_fsize) <
                    tsk_getu64(fs->endian, fname->real_fsize))
                || (fname->nlen == 0)
                || (*(uint8_t *) & fname->name == 0)) {

                a_idxe = (ntfs_idxentry *) ((uintptr_t) a_idxe + 4);
                if (tsk_verbose)
                    tsk_fprintf(stderr,
                        "ntfs_proc_idxentry: Skipping because of reported file sizes, name length, or NULL name\n");
                continue;
            }

            if ((is_time(tsk_getu64(fs->endian, fname->crtime)) == 0) ||
                (is_time(tsk_getu64(fs->endian, fname->atime)) == 0) ||
                (is_time(tsk_getu64(fs->endian, fname->mtime)) == 0)) {

                a_idxe = (ntfs_idxentry *) ((uintptr_t) a_idxe + 4);
                if (tsk_verbose)
                    tsk_fprintf(stderr,
                        "ntfs_proc_idxentry: Skipping because of invalid times\n");
                continue;
            }
        }

        /* For all fname entries, there will exist a DOS style 8.3
         * entry.  We don't process those because we already processed
         * them before in their full version.  If the type is
         * full POSIX or WIN32 that does not satisfy DOS, then a
         * type NTFS_FNAME_DOS will exist.  If the name is WIN32,
         * but already satisfies DOS, then a type NTFS_FNAME_WINDOS
         * will exist
         *
         * Note that we could be missing some info from deleted files
         * if the windows version was deleted and the DOS wasn't...
         *
         * @@@ This should be added to the shrt_name entry of TSK_FS_NAME.  The short
         * name entry typically comes after the long name
         */

        if (fname->nspace == NTFS_FNAME_DOS) {
            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "ntfs_proc_idxentry: Skipping because of name space: %d\n",
                    fname->nspace);

            goto incr_entry;
        }

        /* Copy it into the generic form */
        if (ntfs_dent_copy(a_ntfs, a_idxe, fs_name)) {
            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "ntfs_proc_idxentry: Skipping because error copying dent_entry\n");
            goto incr_entry;
        }

        /*
         * Check if this entry is deleted
         *
         * The final check is to see if the end of this entry is
         * within the space that the idxallocbuf claimed was valid OR
         * if the parent directory is deleted
         */
        if ((a_is_del == 1) ||
            (tsk_getu16(fs->endian, a_idxe->strlen) == 0) ||
            (((uintptr_t) a_idxe + tsk_getu16(fs->endian,
                        a_idxe->idxlen)) > endaddr_alloc)) {
            fs_name->flags = TSK_FS_NAME_FLAG_UNALLOC;
        }
        else {
            fs_name->flags = TSK_FS_NAME_FLAG_ALLOC;
        }

        if (tsk_verbose)
            tsk_fprintf(stderr,
                "ntfs_proc_idxentry: Entry Details of %s: Str Len: %"
                PRIu16 "  Len to end after current: %" PRIu64
                "  flags: %x\n", fs_name->name, tsk_getu16(fs->endian,
                    a_idxe->strlen),
                (uint64_t) (endaddr_alloc - (uintptr_t) a_idxe -
                    tsk_getu16(fs->endian, a_idxe->idxlen)),
                fs_name->flags);

        if (tsk_fs_dir_add(a_fs_dir, fs_name)) {
            tsk_fs_name_free(fs_name);
            return TSK_ERR;
        }

      incr_entry:

        /* the theory here is that deleted entries have strlen == 0 and
         * have been found to have idxlen == 16
         *
         * if the strlen is 0, then guess how much the indexlen was
         * before it was deleted
         */

        /* 16: size of idxentry before stream
         * 66: size of fname before name
         * 2*nlen: size of name (in unicode)
         */
        if (tsk_getu16(fs->endian, a_idxe->strlen) == 0) {
            a_idxe =
                (ntfs_idxentry
                *) ((((uintptr_t) a_idxe + 16 + 66 + 2 * fname->nlen +
                        3) / 4) * 4);
        }
        else {
            a_idxe =
                (ntfs_idxentry *) ((uintptr_t) a_idxe +
                tsk_getu16(fs->endian, a_idxe->idxlen));
        }

    }                           /* end of loop of index entries */

    tsk_fs_name_free(fs_name);
    return TSK_OK;
}




/*
 * remove the update sequence values that are changed in the last two
 * bytes of each sector
 *
 * return 1 on error and 0 on success
 */
static uint8_t
ntfs_fix_idxrec(NTFS_INFO * ntfs, ntfs_idxrec * idxrec, uint32_t len)
{
    int i;
    uint16_t orig_seq;
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & ntfs->fs_info;
    ntfs_upd *upd;

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "ntfs_fix_idxrec: Fixing idxrec: %" PRIu64 "  Len: %"
            PRIu32 "\n", (uint64_t) ((uintptr_t) idxrec), len);

    /* sanity check so we don't run over in the next loop */
    if ((unsigned int) ((tsk_getu16(fs->endian, idxrec->upd_cnt) - 1) *
            ntfs->ssize_b) > len) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_INODE_COR);
        tsk_error_set_errstr
            ("fix_idxrec: More Update Sequence Entries than idx record size");
        return 1;
    }

    /* Apply the update sequence structure template */
    upd =
        (ntfs_upd *) ((uintptr_t) idxrec + tsk_getu16(fs->endian,
            idxrec->upd_off));

    /* Get the sequence value that each 16-bit value should be */
    orig_seq = tsk_getu16(fs->endian, upd->upd_val);

    /* cycle through each sector */
    for (i = 1; i < tsk_getu16(fs->endian, idxrec->upd_cnt); i++) {

        /* The offset into the buffer of the value to analyze */
        int offset = i * ntfs->ssize_b - 2;
        uint8_t *new_val, *old_val;

        /* get the current sequence value */
        uint16_t cur_seq =
            tsk_getu16(fs->endian, (uintptr_t) idxrec + offset);

        if (cur_seq != orig_seq) {
            /* get the replacement value */
            uint16_t cur_repl =
                tsk_getu16(fs->endian, &upd->upd_seq + (i - 1) * 2);

            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_INODE_COR);
            tsk_error_set_errstr
                ("fix_idxrec: Incorrect update sequence value in index buffer\nUpdate Value: 0x%"
                PRIx16 " Actual Value: 0x%" PRIx16
                " Replacement Value: 0x%" PRIx16
                "\nThis is typically because of a corrupted entry",
                orig_seq, cur_seq, cur_repl);
            return 1;
        }

        new_val = &upd->upd_seq + (i - 1) * 2;
        old_val = (uint8_t *) ((uintptr_t) idxrec + offset);

        if (tsk_verbose)
            tsk_fprintf(stderr,
                "ntfs_fix_idxrec: upd_seq %i   Replacing: %.4" PRIx16
                "   With: %.4" PRIx16 "\n", i, tsk_getu16(fs->endian,
                    old_val), tsk_getu16(fs->endian, new_val));

        *old_val++ = *new_val++;
        *old_val = *new_val;
    }

    return 0;
}





/** \internal
* Process a directory and load up FS_DIR with the entries. If a pointer to
* an already allocated FS_DIR struture is given, it will be cleared.  If no existing
* FS_DIR structure is passed (i.e. NULL), then a new one will be created. If the return
* value is error or corruption, then the FS_DIR structure could
* have entries (depending on when the error occured).
*
* @param a_fs File system to analyze
* @param a_fs_dir Pointer to FS_DIR pointer. Can contain an already allocated
* structure or a new structure.
* @param a_addr Address of directory to process.
* @returns error, corruption, ok etc.
*/
TSK_RETVAL_ENUM
ntfs_dir_open_meta(TSK_FS_INFO * a_fs, TSK_FS_DIR ** a_fs_dir,
    TSK_INUM_T a_addr)
{
    NTFS_INFO *ntfs = (NTFS_INFO *) a_fs;
    TSK_FS_DIR *fs_dir;
    const TSK_FS_ATTR *fs_attr_root = NULL;
    const TSK_FS_ATTR *fs_attr_idx;
    char *idxalloc;
    ntfs_idxentry *idxe;
    ntfs_idxroot *idxroot;
    ntfs_idxelist *idxelist;
    ntfs_idxrec *idxrec_p, *idxrec;
    int off;
    TSK_OFF_T idxalloc_len;
    TSK_FS_LOAD_FILE load_file;

    /* In this function, we will return immediately if we get an error.
     * If we get corruption though, we will record that in 'retval_final'
     * and continue processing.
     */
    TSK_RETVAL_ENUM retval_final = TSK_OK;
    TSK_RETVAL_ENUM retval_tmp;

    /* sanity check */
    if (a_addr < a_fs->first_inum || a_addr > a_fs->last_inum) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("ntfs_dir_open_meta: inode value: %" PRIuINUM
            "\n", a_addr);
        return TSK_ERR;
    }
    else if (a_fs_dir == NULL) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr
            ("ntfs_dir_open_meta: NULL fs_attr argument given");
        return TSK_ERR;
    }

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "ntfs_open_dir: Processing directory %" PRIuINUM "\n", a_addr);


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

    /* Get the inode and verify it has attributes */
    if ((fs_dir->fs_file =
            tsk_fs_file_open_meta(a_fs, NULL, a_addr)) == NULL) {
        tsk_error_errstr2_concat("- ntfs_dir_open_meta");
        return TSK_COR;
    }

    if (!(fs_dir->fs_file->meta->attr)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_INODE_COR);
        tsk_error_set_errstr("dent_walk: Error: Directory address %"
            PRIuINUM " has no attributes", a_addr);
        return TSK_COR;
    }

    // Update with the sequence number
    fs_dir->seq = fs_dir->fs_file->meta->seq;

    /*
     * Read the Index Root Attribute  -- we do some sanity checking here
     * to report errors before we start to make up data for the "." and ".."
     * entries
     */
    fs_attr_root =
        tsk_fs_attrlist_get(fs_dir->fs_file->meta->attr,
        TSK_FS_ATTR_TYPE_NTFS_IDXROOT);
    if (!fs_attr_root) {
        tsk_error_errstr2_concat(" - dent_walk: $IDX_ROOT not found");
        return TSK_COR;
    }

    if (fs_attr_root->flags & TSK_FS_ATTR_NONRES) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_INODE_COR);
        tsk_error_set_errstr
            ("dent_walk: $IDX_ROOT is not resident - it should be");
        return TSK_COR;
    }
    idxroot = (ntfs_idxroot *) fs_attr_root->rd.buf;

    /* Verify that the attribute type is $FILE_NAME */
    if (tsk_getu32(a_fs->endian, idxroot->type) == 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_INODE_COR);
        tsk_error_set_errstr
            ("dent_walk: Attribute type in index root is 0");
        return TSK_COR;
    }
    else if (tsk_getu32(a_fs->endian, idxroot->type) != NTFS_ATYPE_FNAME) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_INODE_COR);
        tsk_error_set_errstr("ERROR: Directory index is sorted by type: %"
            PRIu32 ".\nOnly $FNAME is currently supported",
            tsk_getu32(a_fs->endian, idxroot->type));
        return TSK_COR;
    }

    /* Get the header of the index entry list */
    idxelist = &idxroot->list;

    /* Get the offset to the start of the index entry list */
    idxe = (ntfs_idxentry *) ((uintptr_t) idxelist +
        tsk_getu32(a_fs->endian, idxelist->begin_off));

    /*
     * NTFS does not have "." and ".." entries in the index trees
     * (except for a "." entry in the root directory)
     *
     * So, we'll make 'em up by making a TSK_FS_NAME structure for
     * a '.' and '..' entry and call the action
     */
    if (a_addr != a_fs->root_inum) {    // && (flags & TSK_FS_NAME_FLAG_ALLOC)) {
        TSK_FS_NAME *fs_name;
        TSK_FS_META_NAME_LIST *fs_name_list;

        if (tsk_verbose)
            tsk_fprintf(stderr,
                "ntfs_dir_open_meta: Creating . and .. entries\n");

        if ((fs_name = tsk_fs_name_alloc(16, 0)) == NULL) {
            return TSK_ERR;
        }
        /*
         * "."
         */
        fs_name->meta_addr = a_addr;
        fs_name->meta_seq = fs_dir->fs_file->meta->seq;
        fs_name->type = TSK_FS_NAME_TYPE_DIR;
        strcpy(fs_name->name, ".");

        fs_name->flags = TSK_FS_NAME_FLAG_ALLOC;
        if (tsk_fs_dir_add(fs_dir, fs_name)) {
            tsk_fs_name_free(fs_name);
            return TSK_ERR;
        }


        /*
         * ".."
         */
        strcpy(fs_name->name, "..");
        fs_name->type = TSK_FS_NAME_TYPE_DIR;

        /* The fs_name structure holds the parent inode value, so we
         * just cycle using those
         */
        for (fs_name_list = fs_dir->fs_file->meta->name2;
            fs_name_list != NULL; fs_name_list = fs_name_list->next) {
            fs_name->meta_addr = fs_name_list->par_inode;
            fs_name->meta_seq = fs_name_list->par_seq;
            if (tsk_fs_dir_add(fs_dir, fs_name)) {
                tsk_fs_name_free(fs_name);
                return TSK_ERR;
            }
        }

        tsk_fs_name_free(fs_name);
        fs_name = NULL;
    }


    /* Now we return to processing the Index Root Attribute */
    if (tsk_verbose)
        tsk_fprintf(stderr,
            "ntfs_dir_open_meta: Processing $IDX_ROOT of inum %" PRIuINUM
            "\n", a_addr);

    /* Verify the offset pointers */
    if ((tsk_getu32(a_fs->endian, idxelist->seqend_off) <
            tsk_getu32(a_fs->endian, idxelist->begin_off)) ||
        (tsk_getu32(a_fs->endian, idxelist->bufend_off) <
            tsk_getu32(a_fs->endian, idxelist->seqend_off)) ||
        (((uintptr_t) idxe + tsk_getu32(a_fs->endian,
                    idxelist->bufend_off)) >
            ((uintptr_t) fs_attr_root->rd.buf +
                fs_attr_root->rd.buf_size))) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_INODE_COR);
        tsk_error_set_errstr
            ("Error: Index list offsets are invalid on entry: %" PRIuINUM,
            fs_dir->fs_file->meta->addr);
        return TSK_COR;
    }

    retval_tmp = ntfs_proc_idxentry(ntfs, fs_dir,
        (fs_dir->fs_file->meta->flags & TSK_FS_META_FLAG_UNALLOC) ? 1 : 0,
        idxe,
        tsk_getu32(a_fs->endian, idxelist->bufend_off) -
        tsk_getu32(a_fs->endian, idxelist->begin_off),
        tsk_getu32(a_fs->endian, idxelist->seqend_off) -
        tsk_getu32(a_fs->endian, idxelist->begin_off));

    // stop if we get an error, continue if we got corruption
    if (retval_tmp == TSK_ERR) {
        return TSK_ERR;
    }
    else if (retval_tmp == TSK_COR) {
        retval_final = TSK_COR;
    }

    /*
     * get the index allocation attribute if it exists (it doesn't for
     * small directories
     */
    fs_attr_idx =
        tsk_fs_attrlist_get(fs_dir->fs_file->meta->attr,
        TSK_FS_ATTR_TYPE_NTFS_IDXALLOC);


    /* if we don't have an index alloc then return, we have processed
     * all of the entries
     */
    if (!fs_attr_idx) {
        if (tsk_getu32(a_fs->endian,
                idxelist->flags) & NTFS_IDXELIST_CHILD) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_INODE_COR);
            tsk_error_set_errstr
                ("Error: $IDX_ROOT says there should be children, but there isn't");
            return TSK_COR;
        }
    }
    else {

        if (fs_attr_idx->flags & TSK_FS_ATTR_RES) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_INODE_COR);
            tsk_error_set_errstr
                ("$IDX_ALLOC is Resident - it shouldn't be");
            return TSK_COR;
        }

        /*
         * Copy the index allocation run into a big buffer
         */
        idxalloc_len = fs_attr_idx->nrd.allocsize;
        if ((idxalloc = (char *)tsk_malloc((size_t) idxalloc_len)) == NULL) {
            return TSK_ERR;
        }

        /* Fill in the loading data structure */
        load_file.total = load_file.left = (size_t) idxalloc_len;
        load_file.cur = load_file.base = idxalloc;

        if (tsk_verbose)
            tsk_fprintf(stderr,
                "ntfs_dir_open_meta: Copying $IDX_ALLOC into buffer\n");

        if (tsk_fs_attr_walk(fs_attr_idx,
                TSK_FS_FILE_WALK_FLAG_SLACK, tsk_fs_load_file_action,
                (void *) &load_file)) {
            free(idxalloc);
            tsk_error_errstr2_concat(" - ntfs_dir_open_meta");
            return TSK_COR;     // this could be an error though
        }

        /* Not all of the directory was copied, so we exit */
        if (load_file.left > 0) {
            free(idxalloc);

            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_FWALK);
            tsk_error_set_errstr("Error reading directory contents: %"
                PRIuINUM "\n", a_addr);
            return TSK_COR;
        }

        /*
         * The idxalloc is a big buffer that contains one or more
         * idx buffer structures.  Each idxrec is a node in the B-Tree.
         * We do not process the tree as a tree because then we could
         * not find the deleted file names.
         *
         * Therefore, we scan the big buffer looking for the index record
         * structures.  We save a pointer to the known beginning (idxrec_p).
         * Then we scan for the beginning of the next one (idxrec) and process
         * everything in the middle as an ntfs_idxrec.  We can't use the
         * size given because then we wouldn't see the deleted names
         */

        /* Set the previous pointer to NULL */
        idxrec_p = idxrec = NULL;

        /* Loop by cluster size */
        for (off = 0; off < idxalloc_len; off += ntfs->csize_b) {
            uint32_t list_len, rec_len;

            idxrec = (ntfs_idxrec *) & idxalloc[off];

            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "ntfs_dir_open_meta: Index Buffer Offset: %d  Magic: %"
                    PRIx32 "\n", off, tsk_getu32(a_fs->endian,
                        idxrec->magic));

            /* Is this the begining of an index record? */
            if (tsk_getu32(a_fs->endian,
                    idxrec->magic) != NTFS_IDXREC_MAGIC)
                continue;


            /* idxrec_p is only NULL for the first time
             * Set it and start again to find the next one */
            if (idxrec_p == NULL) {
                idxrec_p = idxrec;
                continue;
            }

            /* Process the previous structure */

            /* idxrec points to the next idxrec structure, idxrec_p
             * points to the one we are going to process
             */
            rec_len =
                (uint32_t) ((uintptr_t) idxrec - (uintptr_t) idxrec_p);

            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "ntfs_dir_open_meta: Processing previous index record (len: %"
                    PRIu32 ")\n", rec_len);

            /* remove the update sequence in the index record */
            if (ntfs_fix_idxrec(ntfs, idxrec_p, rec_len)) {
                free(idxalloc);
                return TSK_COR;
            }

            /* Locate the start of the index entry list */
            idxelist = &idxrec_p->list;
            idxe = (ntfs_idxentry *) ((uintptr_t) idxelist +
                tsk_getu32(a_fs->endian, idxelist->begin_off));

            /* the length from the start of the next record to where our
             * list starts.
             * This should be the same as bufend_off in idxelist, but we don't
             * trust it.
             */
            list_len = (uint32_t) ((uintptr_t) idxrec - (uintptr_t) idxe);

            /* Verify the offset pointers */
            if (((uintptr_t) idxe > (uintptr_t) idxrec) ||
                ((uintptr_t) idxelist +
                    tsk_getu32(a_fs->endian,
                        idxelist->seqend_off) > (uintptr_t) idxrec)) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_FS_INODE_COR);
                tsk_error_set_errstr
                    ("Error: Index list offsets are invalid on entry: %"
                    PRIuINUM, fs_dir->fs_file->meta->addr);
                free(idxalloc);
                return TSK_COR;
            }


            /* process the list of index entries */
            retval_tmp = ntfs_proc_idxentry(ntfs, fs_dir,
                (fs_dir->fs_file->meta->
                    flags & TSK_FS_META_FLAG_UNALLOC) ? 1 : 0, idxe,
                list_len, tsk_getu32(a_fs->endian,
                    idxelist->seqend_off) - tsk_getu32(a_fs->endian,
                    idxelist->begin_off));
            // stop if we get an error, record if we get corruption
            if (retval_tmp == TSK_ERR) {
                free(idxalloc);
                return TSK_ERR;
            }
            else if (retval_tmp == TSK_COR) {
                retval_final = TSK_COR;
            }

            /* reset the pointer to the next record */
            idxrec_p = idxrec;

        }                       /* end of cluster loop */


        /* Process the final record */
        if (idxrec_p) {
            uint32_t list_len, rec_len;

            /* Length from end of attribute to start of this */
            rec_len =
                (uint32_t) (idxalloc_len - (uintptr_t) idxrec_p -
                (uintptr_t) idxalloc);

            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "ntfs_dir_open_meta: Processing final index record (len: %"
                    PRIu32 ")\n", rec_len);

            /* remove the update sequence */
            if (ntfs_fix_idxrec(ntfs, idxrec_p, rec_len)) {
                free(idxalloc);
                return TSK_COR;
            }

            idxelist = &idxrec_p->list;
            idxe = (ntfs_idxentry *) ((uintptr_t) idxelist +
                tsk_getu32(a_fs->endian, idxelist->begin_off));

            /* This is the length of the idx entries */
            list_len =
                (uint32_t) ((uintptr_t) idxalloc + idxalloc_len) -
                (uintptr_t) idxe;

            /* Verify the offset pointers */
            if ((list_len > rec_len) ||
                ((uintptr_t) idxelist +
                    tsk_getu32(a_fs->endian, idxelist->seqend_off) >
                    (uintptr_t) idxalloc + idxalloc_len)) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_FS_INODE_COR);
                tsk_error_set_errstr
                    ("Error: Index list offsets are invalid on entry: %"
                    PRIuINUM, fs_dir->fs_file->meta->addr);
                free(idxalloc);
                return TSK_COR;
            }

            /* process the list of index entries */
            retval_tmp = ntfs_proc_idxentry(ntfs, fs_dir,
                (fs_dir->fs_file->meta->
                    flags & TSK_FS_META_FLAG_UNALLOC) ? 1 : 0, idxe,
                list_len, tsk_getu32(a_fs->endian,
                    idxelist->seqend_off) - tsk_getu32(a_fs->endian,
                    idxelist->begin_off));
            // stop if we get an error, record if we get corruption
            if (retval_tmp == TSK_ERR) {
                free(idxalloc);
                return TSK_ERR;
            }
            else if (retval_tmp == TSK_COR) {
                retval_final = TSK_COR;
            }
        }

        free(idxalloc);
    }


    // get the orphan files
    // load and cache the map if it has not already been done
    tsk_take_lock(&ntfs->orphan_map_lock);
    if (ntfs->orphan_map == NULL) {
        // we do this to make it non-NULL. WE had some images that
        // had no orphan files and it repeatedly did inode_walks
        // because orphan_map was always NULL
        getParentMap(ntfs);

        if (a_fs->inode_walk(a_fs, a_fs->first_inum, a_fs->last_inum,
                (TSK_FS_META_FLAG_ENUM)(TSK_FS_META_FLAG_UNALLOC | TSK_FS_META_FLAG_ALLOC), ntfs_parent_act, NULL)) {
            tsk_release_lock(&ntfs->orphan_map_lock);
            return TSK_ERR;
        }
    }

    
    /* see if there are any entries for this dir.
     * NTFS Updates the sequence when a directory is deleted and not when 
     * it is allocated.  So, if we have a deleted directory, then use
     * its previous sequence number to find the files that were in it when
     * it was allocated.
     */
    uint16_t seqToSrch = fs_dir->fs_file->meta->seq;
    if (fs_dir->fs_file->meta->flags & TSK_FS_META_FLAG_UNALLOC) {
        if (fs_dir->fs_file->meta->seq > 0)
            seqToSrch = fs_dir->fs_file->meta->seq - 1;
        else
            // I can't imagine how we get here or what we should do except maybe not do the search.
            seqToSrch = 0;
    }

    if (ntfs_parent_map_exists(ntfs, a_addr, seqToSrch)) {
        TSK_FS_NAME *fs_name;
        

        std::vector <TSK_INUM_T> &childFiles = ntfs_parent_map_get(ntfs, a_addr, seqToSrch);

        if ((fs_name = tsk_fs_name_alloc(256, 0)) == NULL)
            return TSK_ERR;

        fs_name->type = TSK_FS_NAME_TYPE_UNDEF;

        for (size_t a = 0; a < childFiles.size(); a++) {
            TSK_FS_FILE *fs_file_orp = NULL;
            /* Fill in the basics of the fs_name entry
             * so we can print in the fls formats */
            fs_name->meta_addr = childFiles[a];

            // lookup the file to get its name (we did not cache that)
            fs_file_orp =
                tsk_fs_file_open_meta(a_fs, fs_file_orp, fs_name->meta_addr);
            if (fs_file_orp) {
                if ((fs_file_orp->meta) && (fs_file_orp->meta->name2)) {
                    TSK_FS_META_NAME_LIST *n2 = fs_file_orp->meta->name2;
                    if (fs_file_orp->meta->flags & TSK_FS_META_FLAG_ALLOC)
                        fs_name->flags = TSK_FS_NAME_FLAG_ALLOC;
                    else
                        fs_name->flags = TSK_FS_NAME_FLAG_UNALLOC;

                    while (n2) {
                        if (n2->par_inode == a_addr) {
                            strncpy(fs_name->name, n2->name, fs_name->name_size);
                            tsk_fs_dir_add(fs_dir, fs_name);
                        }
                        n2 = n2->next;
                    }
                }
                //free
                tsk_fs_file_close(fs_file_orp);
            }
        }
        tsk_fs_name_free(fs_name);
    }
    tsk_release_lock(&ntfs->orphan_map_lock);

    // if we are listing the root directory, add the Orphan directory entry
    if (a_addr == a_fs->root_inum) {
        TSK_FS_NAME *fs_name;

        if ((fs_name = tsk_fs_name_alloc(256, 0)) == NULL)
            return TSK_ERR;

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


    return retval_final;
}



/****************************************************************************
 * FIND_FILE ROUTINES
 *
 */

#define MAX_DEPTH   128
#define DIR_STRSZ   4096

typedef struct {
    /* Recursive path stuff */

    /* how deep in the directory tree are we */
    unsigned int depth;

    /* pointer in dirs string to where '/' is for given depth */
    char *didx[MAX_DEPTH];

    /* The current directory name string */
    char dirs[DIR_STRSZ];

} NTFS_DINFO;


/*
 * Looks up the parent inode described in fs_name.
 *
 * fs_name was filled in by ntfs_find_file and will get the final path
 * added to it before action is called
 *
 * return 1 on error and 0 on success
 */
static uint8_t
ntfs_find_file_rec(TSK_FS_INFO * fs, NTFS_DINFO * dinfo,
    TSK_FS_FILE * fs_file, TSK_FS_META_NAME_LIST * fs_name_list,
    TSK_FS_DIR_WALK_CB action, void *ptr)
{
    TSK_FS_FILE *fs_file_par;
    TSK_FS_META_NAME_LIST *fs_name_list_par;
    uint8_t decrem = 0;
    size_t len = 0, i;
    char *begin = NULL;
    int retval;


    if (fs_name_list->par_inode < fs->first_inum ||
        fs_name_list->par_inode > fs->last_inum) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("invalid inode value: %" PRIuINUM "\n",
            fs_name_list->par_inode);
        return 1;
    }

    fs_file_par = tsk_fs_file_open_meta(fs, NULL, fs_name_list->par_inode);
    if (fs_file_par == NULL) {
        tsk_error_errstr2_concat(" - ntfs_find_file_rec");
        return 1;
    }

    /*
     * Orphan File
     * This occurs when the file is deleted and either:
     * - The parent is no longer a directory
     * - The sequence number of the parent is no longer correct
     */
    if ((fs_file_par->meta->type != TSK_FS_META_TYPE_DIR)
        || (fs_file_par->meta->seq != fs_name_list->par_seq)) {
        const char *str = TSK_FS_ORPHAN_STR;
        len = strlen(str);

        /* @@@ There should be a sanity check here to verify that the
         * previous name was unallocated ... but how do I get it again?
         */
        if ((((uintptr_t) dinfo->didx[dinfo->depth - 1] - len) >=
                (uintptr_t) & dinfo->dirs[0])
            && (dinfo->depth < MAX_DEPTH)) {
            begin = dinfo->didx[dinfo->depth] =
                (char *) ((uintptr_t) dinfo->didx[dinfo->depth - 1] - len);

            dinfo->depth++;
            decrem = 1;

            for (i = 0; i < len; i++)
                begin[i] = str[i];
        }

        retval = action(fs_file, begin, ptr);

        if (decrem)
            dinfo->depth--;

        tsk_fs_file_close(fs_file_par);
        return (retval == TSK_WALK_ERROR) ? 1 : 0;
    }

    for (fs_name_list_par = fs_file_par->meta->name2;
        fs_name_list_par != NULL;
        fs_name_list_par = fs_name_list_par->next) {

        len = strlen(fs_name_list_par->name);

        /* do some length checks on the dir structure
         * if we can't fit it then forget about it */
        if ((((uintptr_t) dinfo->didx[dinfo->depth - 1] - len - 1) >=
                (uintptr_t) & dinfo->dirs[0])
            && (dinfo->depth < MAX_DEPTH)) {
            begin = dinfo->didx[dinfo->depth] =
                (char *) ((uintptr_t) dinfo->didx[dinfo->depth - 1] - len -
                1);

            dinfo->depth++;
            decrem = 1;

            *begin = '/';
            for (i = 0; i < len; i++)
                begin[i + 1] = fs_name_list_par->name[i];
        }
        else {
            begin = dinfo->didx[dinfo->depth];
            decrem = 0;
        }


        /* if we are at the root, then fill out the rest of fs_name with
         * the full path and call the action
         */
        if (fs_name_list_par->par_inode == NTFS_ROOTINO) {
            /* increase the path by one so that we do not pass the '/'
             * if we do then the printed result will have '//' at
             * the beginning
             */
            if (TSK_WALK_ERROR == action(fs_file,
                    (const char *) ((uintptr_t) begin + 1), ptr)) {
                tsk_fs_file_close(fs_file_par);
                return 1;
            }
        }

        /* otherwise, recurse some more */
        else {
            if (ntfs_find_file_rec(fs, dinfo, fs_file, fs_name_list_par,
                    action, ptr)) {
                tsk_fs_file_close(fs_file_par);
                return 1;
            }
        }

        /* if we incremented before, then decrement the depth now */
        if (decrem)
            dinfo->depth--;
    }

    tsk_fs_file_close(fs_file_par);

    return 0;
}

/* \ingroup fslib
 * NTFS can map a meta address to its name much faster than in other file systems
 * because each entry stores the address of its parent.
 *
 * This can not be called with dent_walk because the path
 * structure will get messed up!
 *
 * @param fs File system being analyzed
 * @param inode_toid Address of file to find the name for.
 * @param type_toid Attribute type to find the more specific name for (if you want more than just the base file name)
 * @param type_used 1 if the type_toid value was passed a valid value.  0 otherwise.
 * @param id_toid Attribute id to find the more specific name for (if you want more than just the base file name)
 * @param id_used 1 if the id_toid value was passed a valid value. 0 otherwise.
 * @param dir_walk_flags Flags to use during search
 * @param action Callback that will be called for each name that uses the specified addresses.
 * @param ptr Pointer that will be passed into action when it is called (so that you can pass in other data)
 * @returns 1 on error, 0 on sucess
 */

uint8_t
ntfs_find_file(TSK_FS_INFO * fs, TSK_INUM_T inode_toid, uint32_t type_toid,
    uint8_t type_used, uint16_t id_toid, uint8_t id_used,
    TSK_FS_DIR_WALK_FLAG_ENUM dir_walk_flags, TSK_FS_DIR_WALK_CB action,
    void *ptr)
{
    TSK_FS_META_NAME_LIST *fs_name_list;
    char *attr = NULL;
    NTFS_DINFO dinfo;
    TSK_FS_FILE *fs_file;
    ntfs_mft *mft;
    TSK_RETVAL_ENUM r_enum;
    NTFS_INFO *ntfs = (NTFS_INFO *) fs;

    /* sanity check */
    if (inode_toid < fs->first_inum || inode_toid > fs->last_inum) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("ntfs_find_file: invalid inode value: %"
            PRIuINUM "\n", inode_toid);
        return 1;
    }
    if ((mft = (ntfs_mft *) tsk_malloc(ntfs->mft_rsize_b)) == NULL) {
        return 1;
    }
    r_enum = ntfs_dinode_lookup(ntfs, (char *) mft, inode_toid);
    if (r_enum == TSK_ERR) {
        free(mft);
        return 1;
    }
    // open the file to ID
    fs_file = tsk_fs_file_open_meta(fs, NULL, inode_toid);
    if (fs_file == NULL) {
        tsk_error_errstr2_concat("- ntfs_find_file");
        tsk_fs_file_close(fs_file);
        free(mft);
        return 1;
    }

    // see if its allocation status meets the callback needs
    if ((fs_file->meta->flags & TSK_FS_META_FLAG_ALLOC)
        && ((dir_walk_flags & TSK_FS_DIR_WALK_FLAG_ALLOC) == 0)) {
        tsk_fs_file_close(fs_file);
        free(mft);
        return 1;
    }
    else if ((fs_file->meta->flags & TSK_FS_META_FLAG_UNALLOC)
        && ((dir_walk_flags & TSK_FS_DIR_WALK_FLAG_UNALLOC) == 0)) {
        tsk_fs_file_close(fs_file);
        free(mft);
        return 1;
    }


    /* Allocate a name and fill in some details  */
    if ((fs_file->name =
            tsk_fs_name_alloc(NTFS_MAXNAMLEN_UTF8, 0)) == NULL) {
        free(mft);
        return 1;
    }
    fs_file->name->meta_addr = inode_toid;
    fs_file->name->meta_seq = 0;
    fs_file->name->flags =
        ((tsk_getu16(fs->endian,
                mft->flags) & NTFS_MFT_INUSE) ? TSK_FS_NAME_FLAG_ALLOC :
        TSK_FS_NAME_FLAG_UNALLOC);

    memset(&dinfo, 0, sizeof(NTFS_DINFO));

    /* in this function, we use the dinfo->dirs array in the opposite order.
     * we set the end of it to NULL and then prepend the
     * directories to it
     *
     * dinfo->didx[dinfo->depth] will point to where the current level started their
     * dir name
     */
    dinfo.dirs[DIR_STRSZ - 2] = '/';
    dinfo.dirs[DIR_STRSZ - 1] = '\0';
    dinfo.didx[0] = &dinfo.dirs[DIR_STRSZ - 2];
    dinfo.depth = 1;


    /* Get the name for the attribute - if specified */
    if (type_used) {
        const TSK_FS_ATTR *fs_attr;

        if (id_used)
            fs_attr =
                tsk_fs_attrlist_get_id(fs_file->meta->attr, (TSK_FS_ATTR_TYPE_ENUM)type_toid,
                id_toid);
        else
            fs_attr = tsk_fs_attrlist_get(fs_file->meta->attr, (TSK_FS_ATTR_TYPE_ENUM)type_toid);

        if (!fs_attr) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_INODE_COR);
            tsk_error_set_errstr("find_file: Type %" PRIu32 " Id %" PRIu16
                " not found in MFT %" PRIuINUM "", type_toid, id_toid,
                inode_toid);
            tsk_fs_file_close(fs_file);
            free(mft);
            return 1;
        }

        /* only add the attribute name if it is the non-default data stream */
        if (fs_attr->name != NULL)
            attr = fs_attr->name;
    }

    /* loop through all the names it may have */
    for (fs_name_list = fs_file->meta->name2; fs_name_list != NULL;
        fs_name_list = fs_name_list->next) {
        int retval;

        /* Append on the attribute name, if it exists */
        if (attr != NULL) {
            snprintf(fs_file->name->name, fs_file->name->name_size,
                "%s:%s", fs_name_list->name, attr);
        }
        else {
            strncpy(fs_file->name->name, fs_name_list->name,
                fs_file->name->name_size);
        }

        /* if this is in the root directory, then call back */
        if (fs_name_list->par_inode == NTFS_ROOTINO) {

            retval = action(fs_file, dinfo.didx[0], ptr);
            if (retval == TSK_WALK_STOP) {
                tsk_fs_file_close(fs_file);
                free(mft);
                return 0;
            }
            else if (retval == TSK_WALK_ERROR) {
                tsk_fs_file_close(fs_file);
                free(mft);
                return 1;
            }
        }
        /* call the recursive function on the parent to get the full path */
        else {
            if (ntfs_find_file_rec(fs, &dinfo, fs_file, fs_name_list,
                    action, ptr)) {
                tsk_fs_file_close(fs_file);
                free(mft);
                return 1;
            }
        }
    }                           /* end of name loop */

    tsk_fs_file_close(fs_file);
    free(mft);
    return 0;
}


int
ntfs_name_cmp(TSK_FS_INFO * a_fs_info, const char *s1, const char *s2)
{
    return strcasecmp(s1, s2);
}
