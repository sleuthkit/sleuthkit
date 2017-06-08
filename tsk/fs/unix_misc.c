/*
 * The Sleuth Kit 
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2008-2011 Brian Carrier.  All Rights reserved
 *
 * This software is distributed under the Common Public License 1.0
 */


/**
 * \file unix_misc.c
 * Contains code that is common to both UFS1/2 and Ext2/3 file systems. 
 */

#include "tsk_fs_i.h"
#include "tsk_ffs.h"
#include "tsk_ext2fs.h"


/*********** MAKE DATA RUNS ***************/

/** \internal
 * Process an array of addresses and turn them into runs
 *
 * @param fs File system to analyze
 * @param fs_attr Data attribute to add runs to
 * @param addrs Buffer of addresses to process and turn into runs
 * @param addr_len Number of addresses in buffer
 * @param length Length of file remaining
 *
 * @returns the number of bytes processed and -1 if an error occurred
 */
static TSK_OFF_T
unix_make_data_run_direct(TSK_FS_INFO * fs, TSK_FS_ATTR * fs_attr,
    TSK_DADDR_T * addrs, size_t addr_len, TSK_OFF_T length)
{
    TSK_DADDR_T run_start = 0;
    TSK_DADDR_T run_len = 0;
    TSK_DADDR_T blks_processed = 0;
    size_t i;
    size_t fs_blen;             // how big is each "block" (in fragments)

    if (addr_len == 0) {
        return 0;
    }

    // block_size is a fragment size in UFS, so we need to maintain length in fragments
    if (TSK_FS_TYPE_ISFFS(fs->ftype)) {
        FFS_INFO *ffs = (FFS_INFO *) fs;
        fs_blen = ffs->ffsbsize_f;
    }
    else {
        fs_blen = 1;
    }

    run_start = addrs[0];
    run_len = fs_blen;

    /* Note that we are lazy about length.  We stop only when a run is past length,
     * we do not end exactly at length -- although that should happen anyway.  
     */
    for (i = 0; i < addr_len; i++) {

        /* Make a new run if:
         * - This is the last addresss in the buffer
         * - The next address is not part of the current run
         * -- special case for sparse since they use 0 as an address
         */
        if ((i + 1 == addr_len) ||
            ((run_start + run_len != addrs[i + 1]) && (run_start != 0)) ||
            ((run_start == 0) && (addrs[i + 1] != 0))) {

            TSK_FS_ATTR_RUN *data_run;

            // make a non-resident run
            data_run = tsk_fs_attr_run_alloc();
            if (data_run == NULL)
                return -1;

            data_run->addr = run_start;
            data_run->len = run_len;

            if (run_start == 0)
                data_run->flags = TSK_FS_ATTR_RUN_FLAG_SPARSE;

            // save the run
            tsk_fs_attr_append_run(fs, fs_attr, data_run);

            // get ready for the next run
            if (i + 1 != addr_len)
                run_start = addrs[i + 1];
            run_len = 0;

            // stop if we are past the length requested
            if (blks_processed * fs->block_size > (TSK_DADDR_T) length)
                break;
        }
        run_len += fs_blen;
        blks_processed += fs_blen;
    }

    return blks_processed * fs->block_size;
}


/** \internal
 * Read an indirect block and process the contents to make a runlist from the pointers. 
 *
 * @param fs File system to analyze
 * @param fs_attr Structure to save run data into
 * @param fs_attr_indir Structure to save addresses of indirect block pointers in
 * @param buf Buffers to read block data into (0 is block sized, 1+ are DADDR_T arrays based on FS type)
 * @param level Indirection level that this will process at (1+)
 * @param addr Address of block to read
 * @param length Length of file remaining
 *
 * @returns the number of bytes processed during call and -1 if an error occurred
 */
static TSK_OFF_T
unix_make_data_run_indirect(TSK_FS_INFO * fs, TSK_FS_ATTR * fs_attr,
    TSK_FS_ATTR * fs_attr_indir, char *buf[], int level, TSK_DADDR_T addr,
    TSK_OFF_T length)
{
    char *myname = "unix_make_data_run_indirect";
    size_t addr_cnt = 0;
    TSK_DADDR_T *myaddrs = (TSK_DADDR_T *) buf[level];
    TSK_OFF_T length_remain = length;
    TSK_OFF_T retval;
    size_t fs_bufsize;
    size_t fs_blen;
    TSK_FS_ATTR_RUN *data_run;

    if (tsk_verbose)
        tsk_fprintf(stderr, "%s: level %d block %" PRIuDADDR "\n", myname,
            level, addr);

    // block_size is a fragment size in UFS, so we need to maintain length in fragments
    if (TSK_FS_TYPE_ISFFS(fs->ftype)) {
        FFS_INFO *ffs = (FFS_INFO *) fs;
        fs_blen = ffs->ffsbsize_f;
        fs_bufsize = ffs->ffsbsize_b;
    }
    else {
        fs_blen = 1;
        fs_bufsize = fs->block_size;
    }

    if (addr > fs->last_block) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_INODE_COR);
        tsk_error_set_errstr("unix: Indirect block address too large: %"
            PRIuDADDR "", addr);
        return -1;
    }

    // make a non-resident run
    data_run = tsk_fs_attr_run_alloc();
    if (data_run == NULL)
        return -1;

    data_run->addr = addr;
    data_run->len = fs_blen;

    /*
     * Read a block of disk addresses.
     */
    // sparse
    if (addr == 0) {
        memset(buf[0], 0, fs_bufsize);
        data_run->flags = TSK_FS_ATTR_RUN_FLAG_SPARSE;
    }
    else {
        ssize_t cnt;
        // read the data into the scratch buffer
        cnt = tsk_fs_read_block(fs, addr, buf[0], fs_bufsize);
        if (cnt != fs_bufsize) {
            if (cnt >= 0) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_FS_READ);
            }
            tsk_error_set_errstr2("unix_make_data_run_indir: Block %"
                PRIuDADDR, addr);
            return -1;
        }
    }

    // save the run
    tsk_fs_attr_append_run(fs, fs_attr_indir, data_run);

    // convert the raw addresses to the correct endian ordering
    if ((fs->ftype == TSK_FS_TYPE_FFS1)
        || (fs->ftype == TSK_FS_TYPE_FFS1B)
        || (TSK_FS_TYPE_ISEXT(fs->ftype))) {
        size_t n;
        uint32_t *iaddr = (uint32_t *) buf[0];
        addr_cnt = fs_bufsize / sizeof(*iaddr);
        for (n = 0; n < addr_cnt; n++) {
            myaddrs[n] = tsk_getu32(fs->endian, (uint8_t *) & iaddr[n]);
        }
    }
    else if (fs->ftype == TSK_FS_TYPE_FFS2) {
        size_t n;
        uint64_t *iaddr = (uint64_t *) buf[0];
        addr_cnt = fs_bufsize / sizeof(*iaddr);
        for (n = 0; n < addr_cnt; n++) {
            myaddrs[n] = tsk_getu64(fs->endian, (uint8_t *) & iaddr[n]);
        }
    }

    // pass the addresses to the next level
    if (level == 1) {
        retval =
            unix_make_data_run_direct(fs, fs_attr, myaddrs, addr_cnt,
            length_remain);
        if (retval != -1) {
            length_remain -= retval;
        }
    }
    else {
        size_t i;
        retval = 0;
        for (i = 0; i < addr_cnt && retval != -1; i++) {
            retval =
                unix_make_data_run_indirect(fs, fs_attr, fs_attr_indir,
                buf, level - 1, myaddrs[i], length_remain);
            if (retval == -1) {
                break;
            }
            else {
                length_remain -= retval;
            }
        }
    }

    if (retval == -1)
        return -1;
    else
        return length - length_remain;
}


/** \internal
 *
 * @returns 1 on error and 0 on success
 */
uint8_t
tsk_fs_unix_make_data_run(TSK_FS_FILE * fs_file)
{
    TSK_OFF_T length = 0;
    TSK_OFF_T read_b = 0;
    TSK_FS_ATTR *fs_attr;
    TSK_FS_ATTR *fs_attr_indir;
    TSK_FS_META *fs_meta = fs_file->meta;
    TSK_FS_INFO *fs = fs_file->fs_info;

    // clean up any error messages that are lying around
    tsk_error_reset();

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "unix_make_data_run: Processing file %" PRIuINUM "\n",
            fs_meta->addr);

    // see if we have already loaded the runs
    if ((fs_meta->attr != NULL)
        && (fs_meta->attr_state == TSK_FS_META_ATTR_STUDIED)) {
        return 0;
    }
    else if (fs_meta->attr_state == TSK_FS_META_ATTR_ERROR) {
        return 1;
    }
    // not sure why this would ever happen, but...
    else if (fs_meta->attr != NULL) {
        tsk_fs_attrlist_markunused(fs_meta->attr);
    }
    else if (fs_meta->attr == NULL) {
        fs_meta->attr = tsk_fs_attrlist_alloc();
    }

    if ((TSK_FS_TYPE_ISFFS(fs->ftype) == 0)
        && (TSK_FS_TYPE_ISEXT(fs->ftype) == 0)) {
        tsk_error_set_errno(TSK_ERR_FS_INODE_COR);
        tsk_error_set_errstr
            ("unix_make_run: Called with non-Unix file system: %x",
            fs->ftype);
        return 1;
    }

    length = roundup(fs_meta->size, fs->block_size);

    if ((fs_attr =
            tsk_fs_attrlist_getnew(fs_meta->attr,
                TSK_FS_ATTR_NONRES)) == NULL) {
        return 1;
    }

    // initialize the data run
    if (tsk_fs_attr_set_run(fs_file, fs_attr, NULL, NULL,
            TSK_FS_ATTR_TYPE_DEFAULT, TSK_FS_ATTR_ID_DEFAULT,
            fs_meta->size, fs_meta->size, roundup(fs_meta->size,
                fs->block_size), 0, 0)) {
        return 1;
    }

    read_b =
        unix_make_data_run_direct(fs, fs_attr,
        (TSK_DADDR_T *) fs_meta->content_ptr, 12, length);
    if (read_b == -1) {
        fs_meta->attr_state = TSK_FS_META_ATTR_ERROR;
        if (fs_meta->flags & TSK_FS_META_FLAG_UNALLOC)
            tsk_error_set_errno(TSK_ERR_FS_RECOVER);
        return 1;
    }
    length -= read_b;

    /* if there is still data left, read the indirect */
    if (length > 0) {
        int level;
        char *buf[4] = {NULL};
        size_t fs_bufsize0;
        size_t fs_bufsize1;
        size_t ptrsperblock;
        int numBlocks = 0;
        int numSingIndirect = 0;
        int numDblIndirect = 0;
        int numTripIndirect = 0;


        /* With FFS/UFS a full block contains the addresses, but block_size is
         * only a fragment.  Figure out the scratch buffer size and the buffers to 
         * store the cleaned addresses (endian converted) */
        if (TSK_FS_TYPE_ISFFS(fs->ftype)) {
            FFS_INFO *ffs = (FFS_INFO *) fs;

            fs_bufsize0 = ffs->ffsbsize_b;
            if ((fs->ftype == TSK_FS_TYPE_FFS1)
                || (fs->ftype == TSK_FS_TYPE_FFS1B)) {
                ptrsperblock = fs_bufsize0 / 4;
            }
            else {
                ptrsperblock = fs_bufsize0 / 8;
            }
        }
        else {
            fs_bufsize0 = fs->block_size;
            ptrsperblock = fs_bufsize0 / 4;
        }
        fs_bufsize1 = sizeof(TSK_DADDR_T) * ptrsperblock;

        /*
         * Initialize a buffer for the 3 levels of indirection that are supported by
         * this inode.  Each level of indirection will have a buffer to store
         * addresses in.  buf[0] is a special scratch buffer that is used to store
         * raw data from the image (before endian conversions are applied).  It is
         * equal to one block size.  The others will store TSK_DADDR_T structures
         * and will have a size depending on the FS type. 
         */
        if ((fs_attr_indir =
                tsk_fs_attrlist_getnew(fs_meta->attr,
                    TSK_FS_ATTR_NONRES)) == NULL) {
            return 1;
        }

        // determine number of indirect lbocks needed for file size...
        numBlocks =
            (int) (((fs_meta->size + fs_bufsize0 - 1) / fs_bufsize0) - 12);
        numSingIndirect =
            (int) ((numBlocks + ptrsperblock - 1) / ptrsperblock);
        numDblIndirect = 0;
        numTripIndirect = 0;

        // double block pointer?
        if (numSingIndirect > 1) {
            numDblIndirect = (int)
                ((numSingIndirect - 1 + ptrsperblock - 1) / ptrsperblock);
            if (numDblIndirect > 1) {
                numTripIndirect = (int)
                    ((numDblIndirect - 1 + ptrsperblock -
                        1) / ptrsperblock);
            }
        }

        // initialize the data run
        if (tsk_fs_attr_set_run(fs_file, fs_attr_indir, NULL, NULL,
                TSK_FS_ATTR_TYPE_UNIX_INDIR, TSK_FS_ATTR_ID_DEFAULT,
                fs_bufsize0 * (numSingIndirect + numDblIndirect +
                    numTripIndirect),
                fs_bufsize0 * (numSingIndirect + numDblIndirect +
                    numTripIndirect),
                fs_bufsize0 * (numSingIndirect + numDblIndirect +
                    numTripIndirect), 0, 0)) {
            return 1;
        }

        if ((buf[0] = (char *) tsk_malloc(fs_bufsize0)) == NULL) {
            return 1;
        }

        for (level = 1; length > 0 && level < 4; level++) {
            TSK_DADDR_T *addr_ptr = (TSK_DADDR_T *) fs_meta->content_ptr;

            if ((buf[level] = (char *) tsk_malloc(fs_bufsize1)) == NULL) {
                int f;
                for (f = 0; f < level; f++) {
                    free(buf[f]);
                }
                return 1;
            }

            /* the indirect addresses are stored in addr_ptr after the 12
             * direct addresses */
            read_b =
                unix_make_data_run_indirect(fs, fs_attr, fs_attr_indir,
                buf, level, addr_ptr[12 + level - 1], length);
            if (read_b == -1)
                break;
            length -= read_b;
        }

        /*
         * Cleanup.
         */
        for (level = 0; level < 4; ++level) {
            if (buf[level]) {
                free(buf[level]);
            }
        }
    }

    if (read_b == -1) {
        fs_meta->attr_state = TSK_FS_META_ATTR_ERROR;
        if (fs_meta->flags & TSK_FS_META_FLAG_UNALLOC)
            tsk_error_set_errno(TSK_ERR_FS_RECOVER);
        return 1;
    }

    fs_meta->attr_state = TSK_FS_META_ATTR_STUDIED;

    return 0;
}


TSK_FS_ATTR_TYPE_ENUM
tsk_fs_unix_get_default_attr_type(const TSK_FS_FILE * a_file)
{
    return TSK_FS_ATTR_TYPE_DEFAULT;
}

int
tsk_fs_unix_name_cmp(TSK_FS_INFO * a_fs_info, const char *s1,
    const char *s2)
{
    return strcmp(s1, s2);
}
