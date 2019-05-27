/**
*\file xfs.c
* Contains the internal TSK XFS file system functions.
*/

/* TCT
* LICENSE
*	This software is distributed under the Eclipse Public License.
* AUTHOR(S)
*	Andrey Labunets,
*	Andrey Lab Research
*
--*/

#include "tsk_fs_i.h"
#include "tsk_xfs.h"
#include "tsk_fs.h"

xfs_alloc_key_t recs[0x10000];
xfs_alloc_ptr_t ptrs[0x10000];

xfs_inobt_key_t ikeys[0x10000];
xfs_inobt_ptr_t iptrs[0x10000];
xfs_inobt_rec_t irecs[0x10000];

/*
 * Calculate number of records in an inobt btree block.
 */
uint32_t
xfs_inobt_maxrecs(xfs_sb_t *sb, int leaf)
{
    uint32_t blocklen = sb->sb_blocksize;
	blocklen -= XFS_INOBT_BLOCK_LEN(sb);

	if (leaf)
		return blocklen / sizeof(xfs_inobt_rec_t);
	return blocklen / (sizeof(xfs_inobt_key_t) + sizeof(xfs_inobt_ptr_t));
}

/* xfs_inode_getallocflag - get an allocation state of the inode
 * @param xfsfs A xfsfs file system information structure
 * @param dino_inum Metadata address
 * @param dino_buf (optional) The buffer with the inode contents (must be size of xfsfs->inode_size or larger). 
                              If null is passed, the inode magic is not checked
 *
 * return TSK_FS_META_FLAG_ALLOC or TSK_FS_META_FLAG_ALLOC on success and 0 on error
 * */

TSK_FS_META_FLAG_ENUM xfs_inode_getallocflag(
    XFSFS_INFO * xfsfs,
    TSK_INUM_T dino_inum,
    const xfs_dinode_t * dino_buf)
{
    char *myname = "xfs_inode_getallocflag";
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & xfsfs->fs_info;
    xfs_sb_t *sb = xfsfs->fs;
    xfs_agnumber_t ag_num = 0;
    uint64_t rel_inum_neg = 0;
    xfs_inobt_block_t *cur_inobt_block = NULL;
    TSK_DADDR_T cur_block_num;
    xfs_agino_t dino_aginum = 0;
    ssize_t len = 0;
    uint32_t cur_key = 0;
    bool found_key = false;
    ssize_t cnt;
    uint16_t bb_depth = 0;

  /*
   * Sanity check.
   */
   if (dino_inum < fs->first_inum || dino_inum > fs->last_inum) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("%s: start inode: %" PRIuINUM "", myname,
            dino_inum);
        return (TSK_FS_META_FLAG_ENUM) NULL;
    }

    len = XFS_INOBT_BLOCK_LEN(sb);
    if ((cur_inobt_block = (xfs_inobt_block_t*) tsk_malloc(len)) == NULL)
    {
        return (TSK_FS_META_FLAG_ENUM) NULL;
    }

    ag_num = dino_inum >> sb->sb_agblklog >> sb->sb_inopblog;
    rel_inum_neg = 1 << (sb->sb_agblklog + sb->sb_inopblog);
    rel_inum_neg -= 1;
    dino_aginum = dino_inum & rel_inum_neg;

    // take inode agi b+tree
    cur_block_num = (TSK_DADDR_T) ag_num * (TSK_DADDR_T) sb->sb_agblocks 
        + (TSK_DADDR_T) xfsfs->agi[ag_num].agi_root;

    cnt = tsk_fs_read(fs,
        (TSK_OFF_T) sb->sb_blocksize * cur_block_num,
        (char *) cur_inobt_block,
        len);
    if (cnt != len) {
        if (cnt >= 0) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_READ);
        }
        tsk_error_set_errstr2("xfs_inode_getallocflag: Inode %" PRIuINUM
            ", AGI from block %" PRIuOFF, dino_inum, cur_block_num);
        free(cur_inobt_block);
        return (TSK_FS_META_FLAG_ENUM) NULL;
    }

    cur_inobt_block->bb_level = bb_depth = 
        tsk_getu16(TSK_BIG_ENDIAN, &cur_inobt_block->bb_level);
    cur_inobt_block->bb_numrecs = 
        tsk_getu16(TSK_BIG_ENDIAN, &cur_inobt_block->bb_numrecs);

    // initialize the tree
    memset(ikeys, 0, sizeof(ikeys));
    memset(iptrs, 0, sizeof(iptrs));
    memset(irecs, 0, sizeof(irecs));

    // while not leaf node
    while(cur_inobt_block->bb_level > 0)
    {
        if(cur_inobt_block->bb_numrecs == 0)
        {
            if (tsk_verbose)
            {
                tsk_fprintf(stderr, "xfs_inode_getallocflag: empty node in AGI tree");
            }

            return (TSK_FS_META_FLAG_ENUM) NULL;
        }

        // read all the keys
        len = cur_inobt_block->bb_numrecs * sizeof(xfs_inobt_key_t);
        cnt = tsk_fs_read(fs, 
            (TSK_OFF_T) sb->sb_blocksize * cur_block_num + XFS_INOBT_BLOCK_LEN(sb),
            (char *) ikeys,
            len);
        if (cnt != len) {
            if (cnt >= 0) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_FS_READ);
            }
            tsk_error_set_errstr2("%s: Inode %" PRIuINUM, myname,
                dino_inum);
            free(cur_inobt_block);
            return (TSK_FS_META_FLAG_ENUM) NULL;
        }

        uint32_t maxrecs = xfs_inobt_maxrecs(sb, 0 /* not leaf */);

        // read all the node pointers
        len = cur_inobt_block->bb_numrecs * sizeof(xfs_inobt_ptr_t);
        cnt = tsk_fs_read(fs,
            (TSK_OFF_T) sb->sb_blocksize * cur_block_num 
                + (TSK_OFF_T) XFS_INOBT_BLOCK_LEN(sb)
                + (TSK_OFF_T) (maxrecs * sizeof(xfs_inobt_key_t)),
                (char *) iptrs,
                len);
        if (cnt != len) {
            if (cnt >= 0) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_FS_READ);
            }
            tsk_error_set_errstr2("%s: Inode %" PRIuINUM, myname,
                dino_inum);
            free(cur_inobt_block);
            return (TSK_FS_META_FLAG_ENUM) NULL;
        }

        // iterate over the keys (in linear time for now, todo binary search)
        // XFS should guarantee that keys/ptrs are sorted from lo to hi
        found_key = false;
        for(cur_key = 0; cur_key < cur_inobt_block->bb_numrecs; cur_key++)
        {
            ikeys[cur_key].ir_startino = 
                tsk_getu32(TSK_BIG_ENDIAN, &ikeys[cur_key].ir_startino);

            if(dino_aginum == ikeys[cur_key].ir_startino)
            {
                // exact match found, increment the cur_key, terminate the loop
                found_key = true;
                cur_key++;
                break;
            }
            else if(dino_aginum > ikeys[cur_key].ir_startino)
            {
                // inode can be in the range, but we aren't sure
                // just take note, continue search
                found_key = true;
            }
            else
            {
                // current key's startino is larger than the inode we look for
                // terminate the loop
                break;
            }
        }

        if(found_key)
        {
            // if exact match was found, cur_key is artificially incremented
            // otherwise cur_key also one value more than the valid one
            cur_key--;

            cur_block_num = (TSK_DADDR_T) ag_num * (TSK_DADDR_T) sb->sb_agblocks
                    + (TSK_DADDR_T) tsk_getu32(TSK_BIG_ENDIAN, &iptrs[cur_key]);

            if (tsk_verbose) { tsk_fprintf(stderr, "go one level down in b+tree, cur_block_num = %u at bb_level = %" PRIu64 "\n", cur_block_num, cur_inobt_block->bb_level); }

            len = XFS_INOBT_BLOCK_LEN(sb);
            cnt = tsk_fs_read(fs,
                (TSK_OFF_T) sb->sb_blocksize * cur_block_num,
                (char *) cur_inobt_block,
                len);
            if (cnt != len) {
                if (cnt >= 0) {
                    tsk_error_reset();
                    tsk_error_set_errno(TSK_ERR_FS_READ);
                }
                tsk_error_set_errstr2("%s: Inode %" PRIuINUM, myname,
                    dino_inum);
                free(cur_inobt_block);
                return (TSK_FS_META_FLAG_ENUM) NULL;
            }

            cur_inobt_block->bb_level =
                tsk_getu16(TSK_BIG_ENDIAN, &cur_inobt_block->bb_level);
            cur_inobt_block->bb_numrecs =
                tsk_getu16(TSK_BIG_ENDIAN, &cur_inobt_block->bb_numrecs);
        }
        else
        {
            // The inode is not in a Inode B+tree, that means it's not tracked
            if (tsk_verbose) { tsk_fprintf(stderr, "xfs_inode_getallocflag: Inode %" PRIuINUM " not found in AGI tree, it's not tracked \n", dino_inum); }

            free(cur_inobt_block);
            return (TSK_FS_META_FLAG_ENUM) NULL;
        }
    }

    // Now we are at the leaf node

    if(cur_inobt_block->bb_numrecs == 0)
    {
        if (tsk_verbose)
        {
            tsk_fprintf(stderr, "xfs_inode_getallocflag: empty leaf in AGI tree");
        }

        return (TSK_FS_META_FLAG_ENUM) NULL;
    }

    // read all the records
    len = cur_inobt_block->bb_numrecs * sizeof(xfs_inobt_rec_t);
    cnt = tsk_fs_read(fs,
        (TSK_OFF_T) sb->sb_blocksize * cur_block_num + XFS_INOBT_BLOCK_LEN(sb),
        (char *) irecs,
        len);
    if (cnt != len) {
        if (cnt >= 0) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_READ);
        }
        tsk_error_set_errstr2("%s: Inode %" PRIuINUM, myname,
            dino_inum);
        free(cur_inobt_block);
        return (TSK_FS_META_FLAG_ENUM) NULL;
    }

    // iterate over the records
    for(cur_key = 0; cur_key < cur_inobt_block->bb_numrecs; cur_key++)
    {
        irecs[cur_key].ir_startino =
            tsk_getu32(TSK_BIG_ENDIAN, &irecs[cur_key].ir_startino);
        irecs[cur_key].ir_freecount =
            tsk_getu32(TSK_BIG_ENDIAN, &irecs[cur_key].ir_freecount);
        irecs[cur_key].ir_free =
            tsk_getu64(TSK_BIG_ENDIAN, &irecs[cur_key].ir_free);

        if (tsk_verbose) { tsk_fprintf(stderr, "checking cur_key = %u, irecs[cur_key].ir_startino = %d, irecs[cur_key].ir_free = %" PRIx64 " \n",
            cur_key, irecs[cur_key].ir_startino, irecs[cur_key].ir_free); }

        if(dino_aginum >= irecs[cur_key].ir_startino
            && dino_aginum - irecs[cur_key].ir_startino < 64)
        {
            uint8_t rel_inum = dino_aginum - irecs[cur_key].ir_startino;

            if (tsk_verbose) { tsk_fprintf(stderr, "found at cur_inobt_block->bb_level = %u, cur_key = %u, irecs[cur_key].ir_startino = %u, irecs[cur_key].ir_free = %" PRIx64 ", rel_inum = %u \n",
                cur_inobt_block->bb_level, cur_key, irecs[cur_key].ir_startino, irecs[cur_key].ir_free, rel_inum); }

            free(cur_inobt_block);

            if (irecs[cur_key].ir_free & ((uint64_t) 1 << rel_inum))
                return TSK_FS_META_FLAG_UNALLOC;
            else
                return TSK_FS_META_FLAG_ALLOC;
        }
    }

    // tautology here: found_key must be false if bb_depth > 0
    if (bb_depth > 0 || !found_key)
    {
        // The inode was listed in the node, but not found in the leaf: that should never happen.
        // Report loudly, the world must know
        tsk_error_set_errstr2("%s: Inode %" PRIuINUM " found in B+Tree node range, but not in the leaf", myname,
            dino_inum);
    }
    else
    {
        // The inode is not in the B+tree of zero depth, that means it's not tracked
        if (tsk_verbose) { tsk_fprintf(stderr, "Inode is not tracked? didn't find dino_aginum = %d at level cur_inobt_block->bb_level = %u \n", dino_aginum, cur_inobt_block->bb_level); }
    }

    free(cur_inobt_block);

    return (TSK_FS_META_FLAG_ENUM) NULL;
}

/* xfs_dinode_load - look up disk inode & load into xfs_dinode_t structure
 * @param xfsfs A xfsfs file system information structure
 * @param dino_inum Metadata address
 * @param dino_buf The buffer to store the block in (must be size of xfsfs->inode_size or larger)
 *
 * return 1 on error and 0 on success
 * */

static uint8_t
xfs_dinode_load(XFSFS_INFO * xfsfs, TSK_INUM_T dino_inum,
    xfs_dinode_t * dino_buf)
{
    char *myname = "xfs_dinode_load";
    TSK_FS_INFO *fs = &(xfsfs->fs_info);
    xfs_sb_t *sb = xfsfs->fs;
    xfs_agnumber_t ag_num = 0;
    uint64_t rel_inum_neg = 0;
    xfs_agino_t dino_aginum = 0;
    uint64_t offset_neg = 0;
    TSK_DADDR_T ag_block = 0;
    xfs_off_t offset = 0;
    TSK_OFF_T addr = 0;
    ssize_t cnt;

    /*
     * Sanity check.
     */
    if ((dino_inum < fs->first_inum) || (dino_inum > fs->last_inum)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_INODE_NUM);
        tsk_error_set_errstr("ext2fs_dinode_load: address: %" PRIuINUM,
            dino_inum);
        return 1;
    }

    if (dino_buf == NULL) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("%s: dino_buf is NULL", myname);
        return 1;
    }

    ag_num = dino_inum >> sb->sb_agblklog >> sb->sb_inopblog;
    rel_inum_neg = 1 << (sb->sb_agblklog + sb->sb_inopblog);
    rel_inum_neg -= 1;
    dino_aginum = dino_inum & rel_inum_neg;
    ag_block = dino_aginum >> sb->sb_inopblog;
    offset_neg = 1 << sb->sb_inopblog;
    offset_neg -= 1;
    offset = dino_aginum & offset_neg;

    addr = 
     (TSK_OFF_T) ag_num * (TSK_OFF_T) sb->sb_agblocks * (TSK_OFF_T) sb->sb_blocksize
     + (TSK_OFF_T) ag_block * (TSK_OFF_T) sb->sb_blocksize
     + (TSK_OFF_T) offset * (TSK_OFF_T) sb->sb_inodesize;

    if (tsk_verbose) { tsk_fprintf(stderr, "ag_num = %" PRId64 " ag_block = %" PRId64 " offset  = %" PRId64 ", addr = %" PRId64 " \n", ag_num, ag_block, offset, addr); }

    cnt = tsk_fs_read(fs, addr, (char *) dino_buf, xfsfs->inode_size);
    if (cnt != sb->sb_inodesize) {
        if (cnt >= 0) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_READ);
        }
        tsk_error_set_errstr2("%s: Inode %" PRIuINUM
            " from %" PRIuOFF, myname, dino_inum, addr);
        return 1;
    }

    dino_buf->di_core.di_mode =
        tsk_getu16(TSK_BIG_ENDIAN, &dino_buf->di_core.di_mode);
    dino_buf->di_core.di_onlink =
        tsk_getu16(TSK_BIG_ENDIAN, &dino_buf->di_core.di_onlink);
    dino_buf->di_core.di_onlink =
        tsk_getu16(TSK_BIG_ENDIAN, &dino_buf->di_core.di_onlink);
    dino_buf->di_core.di_uid =
        tsk_getu32(TSK_BIG_ENDIAN, &dino_buf->di_core.di_uid);
    dino_buf->di_core.di_gid =
        tsk_getu32(TSK_BIG_ENDIAN, &dino_buf->di_core.di_gid);
    dino_buf->di_core.di_nlink =
        tsk_getu32(TSK_BIG_ENDIAN, &dino_buf->di_core.di_nlink);
    dino_buf->di_core.di_projid =
        tsk_getu16(TSK_BIG_ENDIAN, &dino_buf->di_core.di_projid);
    dino_buf->di_core.di_flushiter =
        tsk_getu16(TSK_BIG_ENDIAN, &dino_buf->di_core.di_flushiter);
    dino_buf->di_core.di_atime.t_sec =
        tsk_getu32(TSK_BIG_ENDIAN, &dino_buf->di_core.di_atime.t_sec);
    dino_buf->di_core.di_atime.t_nsec =
        tsk_getu32(TSK_BIG_ENDIAN, &dino_buf->di_core.di_atime.t_nsec);
    dino_buf->di_core.di_mtime.t_sec =
        tsk_getu32(TSK_BIG_ENDIAN, &dino_buf->di_core.di_mtime.t_sec);
    dino_buf->di_core.di_mtime.t_nsec =
        tsk_getu32(TSK_BIG_ENDIAN, &dino_buf->di_core.di_mtime.t_nsec);
    dino_buf->di_core.di_ctime.t_sec =
        tsk_getu32(TSK_BIG_ENDIAN, &dino_buf->di_core.di_ctime.t_sec);
    dino_buf->di_core.di_ctime.t_nsec =
        tsk_getu32(TSK_BIG_ENDIAN, &dino_buf->di_core.di_ctime.t_nsec);

    if (dino_buf->di_core.di_version == 3)
    {
        // only for inode v3 those fields mean what they say, otherwise don't try to initialize
        dino_buf->di_crtime.t_sec =
            tsk_getu32(TSK_BIG_ENDIAN, &dino_buf->di_crtime.t_sec);
        dino_buf->di_crtime.t_nsec =
            tsk_getu32(TSK_BIG_ENDIAN, &dino_buf->di_crtime.t_nsec);
    }

    dino_buf->di_core.di_size =
        tsk_getu64(TSK_BIG_ENDIAN, &dino_buf->di_core.di_size);
    dino_buf->di_core.di_nblocks =
        tsk_getu64(TSK_BIG_ENDIAN, &dino_buf->di_core.di_nblocks);
    dino_buf->di_core.di_extsize =
        tsk_getu32(TSK_BIG_ENDIAN, &dino_buf->di_core.di_extsize);
    dino_buf->di_core.di_nextents =
        tsk_getu32(TSK_BIG_ENDIAN, &dino_buf->di_core.di_nextents);
    dino_buf->di_core.di_anextents =
        tsk_getu16(TSK_BIG_ENDIAN, &dino_buf->di_core.di_anextents);
    dino_buf->di_core.di_dmevmask =
        tsk_getu32(TSK_BIG_ENDIAN, &dino_buf->di_core.di_dmevmask);
    dino_buf->di_core.di_flags =
        tsk_getu16(TSK_BIG_ENDIAN, &dino_buf->di_core.di_flags);
    dino_buf->di_core.di_gen =
        tsk_getu32(TSK_BIG_ENDIAN, &dino_buf->di_core.di_gen);
    dino_buf->di_next_unlinked =
        tsk_getu32(TSK_BIG_ENDIAN, &dino_buf->di_next_unlinked);

    return 0;
}

static TSK_FS_META_TYPE_ENUM
get_file_type(uint16_t xfs_ftype)
{
    switch (xfs_ftype) {
        case XFS_IN_REG:
            return TSK_FS_META_TYPE_REG;
        case XFS_IN_DIR:
            return TSK_FS_META_TYPE_DIR;
        case XFS_IN_SOCK:
            return TSK_FS_META_TYPE_SOCK;
        case XFS_IN_LNK:
            return TSK_FS_META_TYPE_LNK;
        case XFS_IN_BLK:
            return TSK_FS_META_TYPE_BLK;
        case XFS_IN_CHR:
            return TSK_FS_META_TYPE_CHR;
        case XFS_IN_FIFO:
            return TSK_FS_META_TYPE_FIFO;
        default:
            return TSK_FS_META_TYPE_UNDEF;
    }
}

static TSK_RETVAL_ENUM
get_inode_file_type(XFSFS_INFO *xfs, TSK_INUM_T meta_addr, uint16_t *xfs_ftype)
{
    xfs_dinode_t *dino_buf = NULL;
    xfs_sb_t *sb = xfs->fs;

    ssize_t dinodesize = sb->sb_inodesize > sizeof(xfs_dinode)
        ? sb->sb_inodesize
        : sizeof(xfs_dinode);

    if ((dino_buf = static_cast<xfs_dinode_t *>(tsk_malloc(dinodesize))) == NULL)
        return TSK_ERR;

    if (xfs_dinode_load(xfs, meta_addr, dino_buf)) {
        free(dino_buf);
        return TSK_ERR;
    }

    *xfs_ftype = dino_buf->di_core.di_mode & XFS_IN_FMT;
    free(dino_buf);

    return TSK_OK;
}

static inline uint64_t xfs_mask64lo(int n)
{
    return ((uint64_t)1 << (n)) - 1;
}

void
xfs_bmbt_disk_get_all(
    xfs_bmbt_rec_t    *rec,
    xfs_bmbt_irec_t    *irec)
{
    uint64_t l0 = tsk_getu64(TSK_BIG_ENDIAN, &rec->l0);
    uint64_t l1 = tsk_getu64(TSK_BIG_ENDIAN, &rec->l1);

    irec->br_startoff = (l0 & xfs_mask64lo(64 - BMBT_EXNTFLAG_BITLEN)) >> 9;
    irec->br_startblock = ((l0 & xfs_mask64lo(9)) << 43) | (l1 >> 21);
    irec->br_blockcount = l1 & xfs_mask64lo(21);

    if (l0 >> (64 - BMBT_EXNTFLAG_BITLEN))
        irec->br_state = XFS_EXT_UNWRITTEN;
    else
        irec->br_state = XFS_EXT_NORM;
}

/* xfs_dinode_copy - copy cached disk inode into generic inode
 *
 * returns 1 on error and 0 on success
 * */
static uint8_t
xfs_dinode_copy(XFSFS_INFO * xfsfs, TSK_FS_META * fs_meta,
    TSK_INUM_T inum, const xfs_dinode_t * dino_buf)
{
    char *myname = "xfs_dinode_copy";
    xfs_bmbt_rec_t *extent_data_offset = 0;
    xfs_dinode_core_t* di_core_ptr = NULL;
    void *data_offset = NULL;
    size_t content_len = 0;

    if (dino_buf == NULL) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("x2fs_dinode_copy: dino_buf is NULL");
        return 1;
    }

    // if inode doesn't start with "IN", report loudly, the world should know
    if (dino_buf->di_core.di_magic != 0x4e49) {
        tsk_error_set_errno(TSK_ERR_FS_INODE_NUM);
        tsk_error_set_errstr("%s: inode header magic incorrect", myname);
        return 1;
    }

    fs_meta->attr_state = TSK_FS_META_ATTR_EMPTY;
    if (fs_meta->attr) {
        tsk_fs_attrlist_markunused(fs_meta->attr);
    }

    // set the type
    fs_meta->type = get_file_type(dino_buf->di_core.di_mode & XFS_IN_FMT);

    // set the mode
    fs_meta->mode = (TSK_FS_META_MODE_ENUM) 0;
    if (dino_buf->di_core.di_mode & XFS_IN_ISUID)
        fs_meta->mode = (TSK_FS_META_MODE_ENUM) (fs_meta->mode | TSK_FS_META_MODE_ISUID);
    if (dino_buf->di_core.di_mode & XFS_IN_ISGID)
        fs_meta->mode = (TSK_FS_META_MODE_ENUM) (fs_meta->mode | TSK_FS_META_MODE_ISGID);
    if (dino_buf->di_core.di_mode & XFS_IN_ISVTX)
        fs_meta->mode = (TSK_FS_META_MODE_ENUM) (fs_meta->mode | TSK_FS_META_MODE_ISVTX);

    if (dino_buf->di_core.di_mode & XFS_IN_IRUSR)
        fs_meta->mode = (TSK_FS_META_MODE_ENUM) (fs_meta->mode | TSK_FS_META_MODE_IRUSR);
    if (dino_buf->di_core.di_mode & XFS_IN_IWUSR)
        fs_meta->mode = (TSK_FS_META_MODE_ENUM) (fs_meta->mode | TSK_FS_META_MODE_IWUSR);
    if (dino_buf->di_core.di_mode & XFS_IN_IXUSR)
        fs_meta->mode = (TSK_FS_META_MODE_ENUM) (fs_meta->mode | TSK_FS_META_MODE_IXUSR);

    if (dino_buf->di_core.di_mode & XFS_IN_IRGRP)
        fs_meta->mode = (TSK_FS_META_MODE_ENUM) (fs_meta->mode | TSK_FS_META_MODE_IRGRP);
    if (dino_buf->di_core.di_mode & XFS_IN_IWGRP)
        fs_meta->mode = (TSK_FS_META_MODE_ENUM) (fs_meta->mode | TSK_FS_META_MODE_IWGRP);
    if (dino_buf->di_core.di_mode & XFS_IN_IXGRP)
        fs_meta->mode = (TSK_FS_META_MODE_ENUM) (fs_meta->mode | TSK_FS_META_MODE_IXGRP);

    if (dino_buf->di_core.di_mode & XFS_IN_IROTH)
        fs_meta->mode = (TSK_FS_META_MODE_ENUM) (fs_meta->mode | TSK_FS_META_MODE_IROTH);
    if (dino_buf->di_core.di_mode & XFS_IN_IWOTH)
        fs_meta->mode = (TSK_FS_META_MODE_ENUM) (fs_meta->mode | TSK_FS_META_MODE_IWOTH);
    if (dino_buf->di_core.di_mode & XFS_IN_IXOTH)
        fs_meta->mode = (TSK_FS_META_MODE_ENUM) (fs_meta->mode | TSK_FS_META_MODE_IXOTH);

    /* di_onlink
        In v1 inodes, this specifies the number of links to the inode from directories. When the number exceeds 65535,
        the inode is converted to v2 and the link count is stored in di_nlink.
      ...
     di_nlink
        Specifies the number of links to the inode from directories. This is maintained for both inode versions for
        current versions of XFS. Prior to v2 inodes, this field was part of di_pad.
    */

    fs_meta->nlink = dino_buf->di_core.di_nlink;

    fs_meta->size = dino_buf->di_core.di_size;

    fs_meta->addr = inum;

    fs_meta->uid = dino_buf->di_core.di_uid;
    fs_meta->gid = dino_buf->di_core.di_gid;

    fs_meta->mtime = dino_buf->di_core.di_mtime.t_sec;
    fs_meta->mtime_nano = dino_buf->di_core.di_mtime.t_nsec;

    fs_meta->atime = dino_buf->di_core.di_atime.t_sec;
    fs_meta->atime_nano = dino_buf->di_core.di_atime.t_nsec;

    fs_meta->ctime = dino_buf->di_core.di_ctime.t_sec;
    fs_meta->ctime_nano = dino_buf->di_core.di_ctime.t_nsec;

    if (dino_buf->di_core.di_version == 3)
    {
        fs_meta->crtime = dino_buf->di_crtime.t_sec;
        fs_meta->crtime_nano = dino_buf->di_crtime.t_nsec;
    }

    fs_meta->seq = 0;

    if (fs_meta->link) {
        free(fs_meta->link);
        fs_meta->link = NULL;
    }

    // The inode size itself is the minimum size for fs_meta->content
    if (fs_meta->content_len != xfsfs->inode_size) {
        if ((fs_meta =
                tsk_fs_meta_realloc(fs_meta,
                    xfsfs->inode_size)) == NULL) {
            return 1;
        }
    }

    if (tsk_verbose) { tsk_fprintf(stderr, "inode %" PRId64 " ", inum); }

    if (dino_buf->di_core.di_format == XFS_DINODE_FMT_LOCAL)
    {
        if (tsk_verbose) { tsk_fprintf(stderr, "dino_buf->di_format == XFS_DINODE_FMT_LOCAL \n"); }

        fs_meta->content_type = TSK_FS_META_CONTENT_TYPE_XFS_LOCAL;

        di_core_ptr = (xfs_dinode_core_t*) &dino_buf->di_core;
        data_offset = XFS_DFORK_PTR(di_core_ptr, XFS_DATA_FORK);

        if(fs_meta->type == TSK_FS_META_TYPE_LNK)
        {
            if ((fs_meta->link = (char *)
                    tsk_malloc((size_t) (fs_meta->size + 1))) == NULL)
                return 1;

            memset(fs_meta->link, 0, fs_meta->size + 1);
            memcpy(fs_meta->link, data_offset, fs_meta->size);
        }
        else if (fs_meta->type == TSK_FS_META_TYPE_DIR)
        {
            if (fs_meta->content_len < fs_meta->size) {
                if ((fs_meta =
                        tsk_fs_meta_realloc(fs_meta,
                            fs_meta->size)) == NULL) {
                    return 1;
                }
            }

            memset(fs_meta->content_ptr, 0, fs_meta->size);
            memcpy(fs_meta->content_ptr, data_offset, fs_meta->size);
        }
        else
        {
            if (tsk_verbose) { tsk_fprintf(stderr, "unknown type = %d \n", fs_meta->type); }
        }
    }
    else if (dino_buf->di_core.di_format == XFS_DINODE_FMT_EXTENTS)
    {
        // if inode stores extents with pointers to the blocks with data,
        // just copy all the extents to the meta->content_ptr

        if (tsk_verbose) { tsk_fprintf(stderr, "dino_buf->di_format & XFS_DINODE_FMT_EXTENTS == true \n"); }

        fs_meta->content_type = TSK_FS_META_CONTENT_TYPE_XFS_EXTENTS;

        // has to be exactly of that size because extent count calculation will rely on this size
        content_len = sizeof(xfs_bmbt_rec_t) * dino_buf->di_core.di_nextents;

        if (fs_meta->content_len != content_len && content_len != 0) {
            if ((fs_meta =
                    tsk_fs_meta_realloc(fs_meta,
                        content_len)) == NULL) {
                return 1;
            }
        }

        fs_meta->content_len = content_len;

        if (tsk_verbose) { tsk_fprintf(stderr, "dino_buf->di_core.di_nextents = %d \n", dino_buf->di_core.di_nextents); }

        di_core_ptr = (xfs_dinode_core_t*) &dino_buf->di_core;
        extent_data_offset = (xfs_bmbt_rec_t*) XFS_DFORK_PTR(di_core_ptr, XFS_DATA_FORK);

        memcpy(fs_meta->content_ptr, extent_data_offset, content_len);
    }
    else if (dino_buf->di_core.di_format == XFS_DINODE_FMT_BTREE)
    {
        if (tsk_verbose) { tsk_fprintf(stderr, "dino_buf->di_format == XFS_DINODE_FMT_BTREE \n"); }

        fs_meta->content_type = TSK_FS_META_CONTENT_TYPE_XFS_FMT_BTREE;

        fs_meta->content_len = sizeof(TSK_OFF_T);

        di_core_ptr = (xfs_dinode_core_t*) &dino_buf->di_core;
        char *dfork_ptr = XFS_DFORK_PTR(di_core_ptr, XFS_DATA_FORK);
        TSK_OFF_T dfork_off = dfork_ptr - (char*) di_core_ptr;

        xfs_sb_t *sb = xfsfs->fs;
        xfs_agnumber_t ag_num = inum >> sb->sb_agblklog >> sb->sb_inopblog;
        uint64_t rel_inum_neg = 1 << (sb->sb_agblklog + sb->sb_inopblog);
        rel_inum_neg -= 1;
        xfs_agino_t dino_aginum = inum & rel_inum_neg;
        TSK_DADDR_T ag_block = dino_aginum >> sb->sb_inopblog;
        uint64_t offset_neg = 1 << sb->sb_inopblog;
        offset_neg -= 1;
        TSK_OFF_T offset = inum & offset_neg;

        TSK_OFF_T inode_offset =
         (TSK_OFF_T) ag_num * (TSK_OFF_T) sb->sb_agblocks * (TSK_OFF_T) sb->sb_blocksize
         + (TSK_OFF_T) ag_block * (TSK_OFF_T) sb->sb_blocksize
         + (TSK_OFF_T) offset * (TSK_OFF_T) sb->sb_inodesize;

        TSK_OFF_T bmap_root_offset = inode_offset + dfork_off;

        memcpy(fs_meta->content_ptr, &bmap_root_offset, sizeof(TSK_OFF_T));
    }
    else if (dino_buf->di_core.di_format == XFS_DINODE_FMT_UUID)
    {
        // not used
        if (tsk_verbose) { tsk_fprintf(stderr, "dino_buf->di_format == XFS_DINODE_FMT_UUID, which is not used \n"); }

        // a stub
        fs_meta->content_type = TSK_FS_META_CONTENT_TYPE_DEFAULT;
    }
    else if (dino_buf->di_core.di_format == XFS_DINODE_FMT_RMAP)
    {
        if (tsk_verbose) { tsk_fprintf(stderr, "dino_buf->di_format == XFS_DINODE_FMT_RMAP \n"); }

        fs_meta->content_type = TSK_FS_META_CONTENT_TYPE_XFS_FMT_RMAP;
    }
    else
    {
        // shouldn't reach this state
        if (tsk_verbose) { tsk_fprintf(stderr, "dino_buf->di_format == %d, which is an unexpected value \n"); }

        // a stub
        fs_meta->content_type = TSK_FS_META_CONTENT_TYPE_DEFAULT;
    }

    if (tsk_verbose) { tsk_fprintf(stderr, "xfs_dinode_copy: fs_meta->content_len = %d, fs_meta->content_ptr = 0x %x, fs_meta->content_type = %d \n", fs_meta->content_len, fs_meta->content_ptr, fs_meta->content_type); }

    fs_meta->flags = xfs_inode_getallocflag(xfsfs, inum, dino_buf);

    if(fs_meta->flags == 0)
    {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_INODE_COR);
        tsk_error_set_errstr2("%s: Inode %" PRIuINUM " is not found in the B+Tree",
            myname, inum);
        return 1;
    }

    /*
     * Apply the used/unused restriction.
     */
    fs_meta->flags = (TSK_FS_META_FLAG_ENUM) (fs_meta->flags | (fs_meta->ctime ?
        TSK_FS_META_FLAG_USED : TSK_FS_META_FLAG_UNUSED));

    return 0;
}

/* xfs_inode_lookup - lookup inode, external interface
 *
 * Returns 1 on error and 0 on success
 *
 */

static uint8_t
xfs_inode_lookup(TSK_FS_INFO * fs, TSK_FS_FILE * a_fs_file,
    TSK_INUM_T inum)
{
    XFSFS_INFO *xfsfs = (XFSFS_INFO *) fs;
    xfs_dinode_t *dino_buf = NULL;
    ssize_t size = 0;

    if (a_fs_file == NULL) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("xfs_inode_lookup: fs_file is NULL");
        return 1;
    }

    if (a_fs_file->meta == NULL) {
        if ((a_fs_file->meta =
                tsk_fs_meta_alloc(xfsfs->inode_size)) == NULL)
            return 1;
    }
    else {
        tsk_fs_meta_reset(a_fs_file->meta);
    }

    size =
        xfsfs->inode_size >
        sizeof(xfs_dinode) ? xfsfs->fs->sb_inodesize : sizeof(xfs_dinode);
    if ((dino_buf = static_cast<xfs_dinode_t *>(tsk_malloc(size))) == NULL) {
        return 1;
    }

    if (xfs_dinode_load(xfsfs, inum, dino_buf)) {
        free(dino_buf);
        return 1;
    }

    if (xfs_dinode_copy(xfsfs, a_fs_file->meta, inum, dino_buf)) {
        free(dino_buf);
        return 1;
    }

    free(dino_buf);
    return 0;
}

/* xfs_inode_walk - inode iterator
 *
 * flags used: TSK_FS_META_FLAG_USED, TSK_FS_META_FLAG_UNUSED,
 *  TSK_FS_META_FLAG_ALLOC, TSK_FS_META_FLAG_UNALLOC, TSK_FS_META_FLAG_ORPHAN
 *
 *  Return 1 on error and 0 on success
*/

uint8_t
xfs_inode_walk(TSK_FS_INFO * fs, TSK_INUM_T start_inum,
    TSK_INUM_T end_inum, TSK_FS_META_FLAG_ENUM flags,
    TSK_FS_META_WALK_CB a_action, void *a_ptr)
{
    char *myname = "xfsfs_inode_walk";
    XFSFS_INFO *xfsfs = (XFSFS_INFO *) fs;
    TSK_FS_FILE *fs_file;
    unsigned int size = 0;
    xfs_dinode_t *dino_buf = NULL;
    TSK_INUM_T inum;
    unsigned int myflags = 0;

    // clean up any error messages that are lying around
    tsk_error_reset();

    /*
     * Sanity checks.
     */
    if (start_inum < fs->first_inum || start_inum > fs->last_inum) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("%s: start inode: %" PRIuINUM "", myname,
            start_inum);
        return 1;
    }

    if (end_inum < fs->first_inum || end_inum > fs->last_inum
        || end_inum < start_inum) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("%s: end inode: %" PRIuINUM "", myname,
            end_inum);
        return 1;
    }

    if (((flags & TSK_FS_META_FLAG_ALLOC) == 0) &&
        ((flags & TSK_FS_META_FLAG_UNALLOC) == 0)) {
        flags = (TSK_FS_META_FLAG_ENUM) (flags | (TSK_FS_META_FLAG_ALLOC | TSK_FS_META_FLAG_UNALLOC));
    }

    /* If neither of the USED or UNUSED flags are set, then set them
     * both
     */
    if (((flags & TSK_FS_META_FLAG_USED) == 0) &&
        ((flags & TSK_FS_META_FLAG_UNUSED) == 0)) {
        flags = (TSK_FS_META_FLAG_ENUM) (flags | (TSK_FS_META_FLAG_USED | TSK_FS_META_FLAG_UNUSED));
    }

    if ((fs_file = tsk_fs_file_alloc(fs)) == NULL)
        return 1;
    if ((fs_file->meta =
            tsk_fs_meta_alloc(xfsfs->inode_size)) == NULL)
    {
        tsk_fs_file_close(fs_file);
        return 1;
    }

    /*
     * Iterate.
     */
    size =
        xfsfs->fs->sb_inodesize >
        sizeof(xfs_dinode) ? xfsfs->fs->sb_inodesize : sizeof(xfs_dinode);
    if ((dino_buf = static_cast<xfs_dinode_t *>(tsk_malloc(size))) == NULL) {
        tsk_fs_file_close(fs_file);
        tsk_fs_meta_close(fs_file->meta);
        return 1;
    }

    // The proper way to iterate through all inodes is to traverse each AGI tree,
    // but this will only discover what an OS can discover (also would need an optimization)
    // We "brute-force" inodes instead by sequentially "walking" all inodes 
    // until the end of the image, silently skipping those where magic doesn't 
    // match an expected "IN".
    // A good idea would be to cross check this with AGI trees
    for (inum = start_inum; inum <= end_inum; inum++) {
        int retval;

        if (xfs_dinode_load(xfsfs, inum, dino_buf)) {
            tsk_fs_file_close(fs_file);
            tsk_fs_meta_close(fs_file->meta);
            free(dino_buf);
            return 1;
        }

        if (dino_buf->di_core.di_magic != 0x4e49) {
            continue;
        }

        myflags = xfs_inode_getallocflag(xfsfs, inum, dino_buf);

        if (myflags == 0)
        {
            // skip a non-tracked inode
            continue;
        }

        /*
         * Apply the used/unused restriction.
         */
        myflags |= 
            (dino_buf->di_core.di_ctime.t_sec || dino_buf->di_core.di_ctime.t_nsec)
                ? TSK_FS_META_FLAG_USED
                : TSK_FS_META_FLAG_UNUSED;

        if (tsk_verbose) { tsk_fprintf(stderr, "flags = %d, myflags = %d \n", flags, myflags); }

        if ((flags & myflags) != myflags)
            continue;

        /*
         * Fill in a file system-independent inode structure and pass control
         * to the application.
         */
        if (xfs_dinode_copy(xfsfs, fs_file->meta, inum, dino_buf)) {
            tsk_fs_meta_close(fs_file->meta);
            tsk_fs_meta_close(fs_file->meta);
            free(dino_buf);
            return 1;
        }

        retval = a_action(fs_file, a_ptr);
        if (retval == TSK_WALK_STOP) {
            tsk_fs_file_close(fs_file);
            tsk_fs_meta_close(fs_file->meta);
            free(dino_buf);
            return 0;
        }
        else if (retval == TSK_WALK_ERROR) {
            tsk_fs_file_close(fs_file);
            tsk_fs_meta_close(fs_file->meta);
            free(dino_buf);
            return 1;
        }
    }

    /*
     * Cleanup.
     */
    tsk_fs_file_close(fs_file);
    tsk_fs_meta_close(fs_file->meta);
    free(dino_buf);

    return 0;
}

TSK_FS_BLOCK_FLAG_ENUM
xfs_block_getflags(TSK_FS_INFO * a_fs, TSK_DADDR_T a_addr)
{
    XFSFS_INFO *xfsfs = (XFSFS_INFO *) a_fs;
    xfs_sb_t *sb = xfsfs->fs;
    TSK_OFF_T ag_start_off = 0;
    TSK_OFF_T offset = 0;
    uint32_t len = 0;
    xfs_agf *agf = NULL;
    xfs_agblock_t *agfl = NULL;
    unsigned int agfl_cur_len = 0;
    TSK_FS_META_FLAG_ENUM inode_flag = (TSK_FS_META_FLAG_ENUM) 0;
    xfs_alloc_ptr_t cur_sblock_num = 0;
    xfs_btree_sblock_t *cur_btree_sblock = NULL;
    uint32_t cur_key = 0;
    ssize_t cnt;
    bool found;

    // Actually, determining the status of a block in a general case,
    // without the reverse-mapping B+tree is difficult, or at least nonoptimal
    // But let's try

    xfs_agnumber_t ag_num = a_addr >> sb->sb_agblklog;
    uint64_t rel_blk_neg = 1 << (sb->sb_agblklog);
    rel_blk_neg -= 1;
    uint64_t rel_blk = a_addr & rel_blk_neg;

    // Sanity check
    if (rel_blk >= sb->sb_agblocks)
    {
        // TODO: error msg
        return (TSK_FS_BLOCK_FLAG_ENUM) NULL;
    }

    /* 0 -   superblock, agf, agi, agfl
    *  1 -    inobt
    *  2 -    free space b+tree (key is block num)
    *  3 -    free space b+tree (key is block count)
    *  4 -7 - free list, 
    *        "With a freshly made filesystem, 4 blocks are reserved immediately
    *        after the free space B+tree root blocks (blocks 4 to 7).
    *        As they are used up as the free space fragments, additional blocks 
    *        will be reserved from the AG and added to the free list array.
    *        This size may increase as features are added."
    *        (c) http://ftp.ntu.edu.tw/linux/utils/fs/xfs/docs/xfs_filesystem_structure.pdf
    */

    if (rel_blk <= 7)
        return (TSK_FS_BLOCK_FLAG_ENUM) (TSK_FS_BLOCK_FLAG_META | TSK_FS_BLOCK_FLAG_ALLOC);

    ag_start_off = (TSK_OFF_T) ag_num * (TSK_OFF_T) sb->sb_agblocks * (TSK_OFF_T) sb->sb_blocksize;

    // Check agfl

    len = sizeof(xfs_agf);
    if ((agf = static_cast<xfs_agf *>(tsk_malloc(len))) == NULL)
        return (TSK_FS_BLOCK_FLAG_ENUM) NULL;

    if (tsk_verbose) { tsk_fprintf(stderr, "reading xfs AG Free Space Block, ag_start_off = %" PRId64 ", sect_size = %" PRId64 ", len = %" PRId64 " \n", ag_start_off, sb->sb_sectsize, len); }
    cnt = tsk_fs_read(&xfsfs->fs_info, ag_start_off + (TSK_OFF_T) sb->sb_sectsize, (char *) agf, len);
    if (cnt != len) {
        if (cnt >= 0) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_READ);
        }
        tsk_error_set_errstr2("xfs_block_getflags: xfs_agf, cnt = %" PRId64 ", len = %" PRId64 "", cnt, len);
        free(agf);
        return (TSK_FS_BLOCK_FLAG_ENUM) NULL;
    }

    agf->agf_versionnum = tsk_getu32(TSK_BIG_ENDIAN, &agf->agf_versionnum);
    agf->agf_seqno = tsk_getu32(TSK_BIG_ENDIAN, &agf->agf_seqno);
    agf->agf_length = tsk_getu32(TSK_BIG_ENDIAN, &agf->agf_length);
    agf->agf_roots[0] = tsk_getu32(TSK_BIG_ENDIAN, &agf->agf_roots[0]);
    agf->agf_roots[1] = tsk_getu32(TSK_BIG_ENDIAN, &agf->agf_roots[1]);
    agf->agf_spare0 = tsk_getu32(TSK_BIG_ENDIAN, &agf->agf_spare0);
    agf->agf_levels[0] = tsk_getu32(TSK_BIG_ENDIAN, &agf->agf_levels[0]);
    agf->agf_levels[1] = tsk_getu32(TSK_BIG_ENDIAN, &agf->agf_levels[1]);
    agf->agf_spare1 = tsk_getu32(TSK_BIG_ENDIAN, &agf->agf_spare1);
    agf->agf_flfirst = tsk_getu32(TSK_BIG_ENDIAN, &agf->agf_flfirst);
    agf->agf_fllast = tsk_getu32(TSK_BIG_ENDIAN, &agf->agf_fllast);
    agf->agf_flcount = tsk_getu32(TSK_BIG_ENDIAN, &agf->agf_flcount);
    agf->agf_freeblks = tsk_getu32(TSK_BIG_ENDIAN, &agf->agf_freeblks);
    agf->agf_longest = tsk_getu32(TSK_BIG_ENDIAN, &agf->agf_longest);
    agf->agf_btreeblks = tsk_getu32(TSK_BIG_ENDIAN, &agf->agf_btreeblks);

    if (tsk_verbose) { tsk_fprintf(stderr, "agf->agf_magicnum = %.4s \n", &agf->agf_magicnum); }
    if (tsk_verbose) { tsk_fprintf(stderr, "agf->agf_length = %" PRId64 " \n", agf->agf_length); }
    if (tsk_verbose) { tsk_fprintf(stderr, "agf->agf_flfirst = %" PRId64 " \n", agf->agf_flfirst); }
    if (tsk_verbose) { tsk_fprintf(stderr, "agf->agf_fllast = %" PRId64 " \n", agf->agf_fllast); }

    // agfl is one sector and 4 blocks
    len = (sb->sb_blocksize * 4 + sb->sb_sectsize) * sizeof(xfs_agblock_t);
    if ((agfl = static_cast<xfs_agblock_t *>(tsk_malloc(len))) == NULL)
    {
        free(agf);
        return (TSK_FS_BLOCK_FLAG_ENUM) NULL;
    }

    offset = ag_start_off + (TSK_OFF_T) sb->sb_sectsize * 3;
    len = sb->sb_sectsize;
    if (XFS_SB_VERSION_NUM(sb) == 5)
    {
        if(sb->sb_sectsize < XFS_AGFL_SIZE)
        {
            // free other structures
            tsk_error_set_errstr2("xfs_block_getflags: sb_sectsize = %" PRId64 " < XFS_AGFL_SIZE = %" PRId64 "", sb->sb_sectsize, XFS_AGFL_SIZE);
            free(agf);
            free(agfl);
            return (TSK_FS_BLOCK_FLAG_ENUM) NULL;
        }

        offset += XFS_AGFL_SIZE;
        len -= XFS_AGFL_SIZE;
    }
    agfl_cur_len = len;

    cnt = tsk_fs_read(&xfsfs->fs_info, offset, (char *) agfl, len);
    if (cnt != len) {
        if (cnt >= 0) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_READ);
        }
        tsk_error_set_errstr2("xfs_block_getflags: xfs_agf, cnt = %" PRId64 ", len = %" PRId64 "", cnt, len);
        free(agf);
        free(agfl);
        return (TSK_FS_BLOCK_FLAG_ENUM) NULL;
    }

    // "As they are used up as the free space fragments, additional blocks will
    // be reserved from the AG and added to the free list array. This size may
    // increase as features are added." 
    // (c) http://ftp.ntu.edu.tw/linux/utils/fs/xfs/docs/xfs_filesystem_structure.pdf
    // Q: will they be reserved right after the 7th block?

    offset = ag_start_off + (TSK_OFF_T) sb->sb_blocksize * 4;
    len = sb->sb_blocksize * 4;
    cnt = tsk_fs_read(&xfsfs->fs_info, (TSK_OFF_T) offset, ((char *) agfl) + agfl_cur_len, len);
    if (cnt != len) {
        if (cnt >= 0) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_READ);
        }
        tsk_error_set_errstr2("xfs_block_getflags: xfs_agf, cnt = %" PRId64 ", len = %" PRId64 "", cnt, len);
        free(agf);
        free(agfl);
        return (TSK_FS_BLOCK_FLAG_ENUM) NULL;
    }

    for (cur_key = agf->agf_flfirst; cur_key <= agf->agf_fllast; cur_key++)
    {
        if (rel_blk == tsk_getu32(TSK_BIG_ENDIAN, &agfl[cur_key]))
        {
            free(agf);
            free(agfl);
            return (TSK_FS_BLOCK_FLAG_ENUM) (TSK_FS_BLOCK_FLAG_META | TSK_FS_BLOCK_FLAG_UNALLOC);
        }
    }

    uint64_t aginode_num = rel_blk * (uint64_t) sb->sb_inopblock;
    uint64_t inode_num = (uint64_t) ag_num << (sb->sb_agblklog + aginode_num);

    // Pet trick here: if the block possibly stores inodes, try to read the corresponding inode flags
    if (tsk_verbose) { tsk_fprintf(stderr, "trying to treat rel_block %" PRId64 " in ag %" PRId64 " as rel inode %" PRId64 " (abs inode %" PRId64 ") \n", rel_blk, ag_num, aginode_num, inode_num); }

    inode_flag =
        xfs_inode_getallocflag(xfsfs, inode_num, NULL);
    if (inode_flag)
    {
        free(agf);
        free(agfl);

        if (inode_flag == TSK_FS_META_FLAG_ALLOC)
            return (TSK_FS_BLOCK_FLAG_ENUM) (TSK_FS_BLOCK_FLAG_META | TSK_FS_BLOCK_FLAG_ALLOC);
        else if (inode_flag == TSK_FS_META_FLAG_UNALLOC)
            return (TSK_FS_BLOCK_FLAG_ENUM) (TSK_FS_BLOCK_FLAG_META | TSK_FS_META_FLAG_UNALLOC);
    }

    // Completed checking all meta blocks, now checking content blocks

    // Checking the free space B+tree

    memset(recs, 0, sizeof(recs));
    memset(ptrs, 0, sizeof(ptrs));

    if ((cur_btree_sblock = static_cast<xfs_btree_sblock_t *>(tsk_malloc(sizeof(xfs_btree_sblock_t)))) == NULL)
    {
        free(agf);
        free(agfl);
        return (TSK_FS_BLOCK_FLAG_ENUM) NULL;
    }

    // take b+tree sorted by block offset
    cur_sblock_num = agf->agf_roots[0];
    if (tsk_verbose) { tsk_fprintf(stderr, "cur_sblock_num = %" PRId64 " \n", cur_sblock_num); }
    len = sizeof(xfs_btree_sblock_t);
    cnt = tsk_fs_read(&xfsfs->fs_info,
        (TSK_OFF_T) sb->sb_blocksize * cur_sblock_num,
        (char *) cur_btree_sblock,
        len);
    if (cnt != len) {
        if (cnt >= 0) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_READ);
        }
        tsk_error_set_errstr2("xfs_block_getflags: xfs_agf, cnt = %" PRId64 ", len = %" PRId64 "", cnt, len);
        free(agf);
        free(agfl);
        free(cur_btree_sblock);
        return (TSK_FS_BLOCK_FLAG_ENUM) NULL;
    }

    cur_btree_sblock->bb_level = 
        tsk_getu16(TSK_BIG_ENDIAN, &cur_btree_sblock->bb_level);
    cur_btree_sblock->bb_numrecs = 
        tsk_getu16(TSK_BIG_ENDIAN, &cur_btree_sblock->bb_numrecs);
    cur_btree_sblock->bb_leftsib =
        tsk_getu32(TSK_BIG_ENDIAN, &cur_btree_sblock->bb_leftsib);
    cur_btree_sblock->bb_rightsib =
        tsk_getu32(TSK_BIG_ENDIAN, &cur_btree_sblock->bb_rightsib);

    if (tsk_verbose) { tsk_fprintf(stderr, "cur_btree_sblock = %x, cur_btree_sblock->bb_magic = %.4s \n", cur_btree_sblock, &cur_btree_sblock->bb_magic); }

    // while not leaf node
    while(cur_btree_sblock->bb_level > 0)
    {
        // read all the keys
        len = cur_btree_sblock->bb_numrecs * sizeof(xfs_alloc_key_t);
        cnt = tsk_fs_read(&xfsfs->fs_info,
            (TSK_OFF_T) sb->sb_blocksize * (TSK_OFF_T) cur_sblock_num
                + (TSK_OFF_T) sizeof(xfs_btree_sblock_t),
            (char *) recs, 
            len);
        if (cnt != len) {
            if (cnt >= 0) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_FS_READ);
            }
            tsk_error_set_errstr2("xfs_block_getflags: xfs_agf, cnt = %" PRId64 ", len = %" PRId64 "", cnt, len);
            free(agf);
            free(agfl);
            free(cur_btree_sblock);
            return (TSK_FS_BLOCK_FLAG_ENUM) NULL;
        }

        // read all the node pointers
        len = cur_btree_sblock->bb_numrecs * sizeof(xfs_alloc_ptr_t);
        cnt = tsk_fs_read(&xfsfs->fs_info,
            (TSK_OFF_T) sb->sb_blocksize * (TSK_OFF_T) cur_sblock_num
                + (TSK_OFF_T) sizeof(xfs_btree_sblock_t)
                + (TSK_OFF_T) (cur_btree_sblock->bb_numrecs * sizeof(xfs_alloc_key_t)),
            (char *) ptrs,
            len);
        if (cnt != len) {
            if (cnt >= 0) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_FS_READ);
            }
            tsk_error_set_errstr2("xfs_block_getflags: xfs_agf, cnt = %" PRId64 ", len = %" PRId64 "", cnt, len);
            free(agf);
            free(agfl);
            free(cur_btree_sblock);
            return (TSK_FS_BLOCK_FLAG_ENUM) NULL;
        }

        // iterate over the keys
        found = false;
        for(cur_key = 0; !found && cur_key < cur_btree_sblock->bb_numrecs; cur_key++)
        {
            recs[cur_key].ar_startblock =
                tsk_getu32(TSK_BIG_ENDIAN, &recs[cur_key].ar_startblock);
            recs[cur_key].ar_blockcount =
                tsk_getu32(TSK_BIG_ENDIAN, &recs[cur_key].ar_blockcount);

            if(rel_blk >= recs[cur_key].ar_startblock
                && rel_blk - recs[cur_key].ar_startblock < recs[cur_key].ar_blockcount)
            {
                // go one level down in b+tree
                found = true;
                cur_sblock_num = tsk_getu32(TSK_BIG_ENDIAN, &ptrs[cur_key]);

                if (tsk_verbose) { tsk_fprintf(stderr, "go one level down in b+tree, cur_sblock_num = %" PRId64 " \n", cur_sblock_num); }

                cnt = tsk_fs_read(&xfsfs->fs_info,
                    (TSK_OFF_T) sb->sb_blocksize * cur_sblock_num,
                    (char *) cur_btree_sblock,
                    len);
                if (cnt != len) {
                    if (cnt >= 0) {
                        tsk_error_reset();
                        tsk_error_set_errno(TSK_ERR_FS_READ);
                    }
                    tsk_error_set_errstr2("xfs_block_getflags: xfs_agf, cnt = %" PRId64 ", len = %" PRId64 "", cnt, len);
                    free(agf);
                    free(agfl);
                    free(cur_btree_sblock);
                    return (TSK_FS_BLOCK_FLAG_ENUM) NULL;
                }

                cur_btree_sblock->bb_level =
                    tsk_getu16(TSK_BIG_ENDIAN, &cur_btree_sblock->bb_level);
                cur_btree_sblock->bb_numrecs =
                    tsk_getu16(TSK_BIG_ENDIAN, &cur_btree_sblock->bb_numrecs);
                cur_btree_sblock->bb_leftsib =
                    tsk_getu32(TSK_BIG_ENDIAN, &cur_btree_sblock->bb_leftsib);
                cur_btree_sblock->bb_rightsib =
                    tsk_getu32(TSK_BIG_ENDIAN, &cur_btree_sblock->bb_rightsib);
            }
        }

        if(!found)
        {
            // The block is not in a free list, means it's allocated
            if (tsk_verbose) { tsk_fprintf(stderr, "didn't find a_addr at level cur_btree_sblock->bb_level = %" PRId64 " \n", cur_btree_sblock->bb_level); }
            free(agf);
            free(agfl);
            free(cur_btree_sblock);
            return (TSK_FS_BLOCK_FLAG_ENUM) (TSK_FS_BLOCK_FLAG_CONT | TSK_FS_BLOCK_FLAG_ALLOC);
        }
    }

    // read all the records
    len = cur_btree_sblock->bb_numrecs * sizeof(xfs_alloc_rec_t);
    cnt = tsk_fs_read(&xfsfs->fs_info,
        (TSK_OFF_T) sb->sb_blocksize * cur_sblock_num + sizeof(xfs_btree_sblock_t),
        (char *) recs,
        len);

    // iterate over the keys
    found = false;
    for(cur_key = 0; cur_key < cur_btree_sblock->bb_numrecs; cur_key++)
    {
        recs[cur_key].ar_startblock = 
            tsk_getu32(TSK_BIG_ENDIAN, &recs[cur_key].ar_startblock);
        recs[cur_key].ar_blockcount =
            tsk_getu32(TSK_BIG_ENDIAN, &recs[cur_key].ar_blockcount);

        if (tsk_verbose) { tsk_fprintf(stderr, "checking cur_key = %" PRId64 ", recs[cur_key].ar_startblock = %" PRId64 ", recs[cur_key].ar_blockcount = %" PRId64 " \n",
            cur_key, recs[cur_key].ar_startblock, recs[cur_key].ar_blockcount); }

        if(rel_blk >= recs[cur_key].ar_startblock
            && rel_blk - recs[cur_key].ar_startblock < recs[cur_key].ar_blockcount)
        {
            if (tsk_verbose) { tsk_fprintf(stderr, "found at cur_btree_sblock->bb_level = %" PRId64 ", cur_key = %" PRId64 ", recs[cur_key].ar_startblock = %" PRId64 ", recs[cur_key].ar_blockcount = %" PRId64 " \n",
                cur_btree_sblock->bb_level, cur_key, recs[cur_key].ar_startblock, recs[cur_key].ar_blockcount); }
            free(agf);
            free(agfl);
            free(cur_btree_sblock);
            return (TSK_FS_BLOCK_FLAG_ENUM) (TSK_FS_BLOCK_FLAG_CONT | TSK_FS_BLOCK_FLAG_UNALLOC);
        }
    }

    free(agf);
    free(agfl);
    free(cur_btree_sblock);

    // The block is neither metadata, nor in a free list, therefore it's allocated
    return (TSK_FS_BLOCK_FLAG_ENUM) (TSK_FS_BLOCK_FLAG_CONT | TSK_FS_BLOCK_FLAG_ALLOC);
}


/* xfs_block_walk - block iterator
 *
 * flags: TSK_FS_BLOCK_FLAG_ALLOC, TSK_FS_BLOCK_FLAG_UNALLOC, TSK_FS_BLOCK_FLAG_CONT,
 *  TSK_FS_BLOCK_FLAG_META
 *
 *  Return 1 on error and 0 on success
*/

uint8_t
xfs_block_walk(TSK_FS_INFO * a_fs, TSK_DADDR_T a_start_blk,
    TSK_DADDR_T a_end_blk, TSK_FS_BLOCK_WALK_FLAG_ENUM a_flags,
    TSK_FS_BLOCK_WALK_CB a_action, void *a_ptr)

{
    char *myname = "xfs_block_walk";
    TSK_FS_BLOCK *fs_block;
    TSK_DADDR_T addr;

    // clean up any error messages that are lying around
    tsk_error_reset();

    /*
     * Sanity checks.
     */
    if (a_start_blk < a_fs->first_block || a_start_blk > a_fs->last_block) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("%s: start block: %" PRIuDADDR, myname,
            a_start_blk);
        return 1;
    }
    if (a_end_blk < a_fs->first_block || a_end_blk > a_fs->last_block
        || a_end_blk < a_start_blk) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("%s: end block: %" PRIuDADDR, myname,
            a_end_blk);
        return 1;
    }

    /* Sanity check on a_flags -- make sure at least one ALLOC is set */
    if (((a_flags & TSK_FS_BLOCK_WALK_FLAG_ALLOC) == 0) &&
        ((a_flags & TSK_FS_BLOCK_WALK_FLAG_UNALLOC) == 0)) {
        a_flags = (TSK_FS_BLOCK_WALK_FLAG_ENUM) (a_flags |
            (TSK_FS_BLOCK_WALK_FLAG_ALLOC |
            TSK_FS_BLOCK_WALK_FLAG_UNALLOC));
    }
    if (((a_flags & TSK_FS_BLOCK_WALK_FLAG_META) == 0) &&
        ((a_flags & TSK_FS_BLOCK_WALK_FLAG_CONT) == 0)) {
        a_flags = (TSK_FS_BLOCK_WALK_FLAG_ENUM) (a_flags |
            (TSK_FS_BLOCK_WALK_FLAG_CONT |
            TSK_FS_BLOCK_WALK_FLAG_META));
    }

    if ((fs_block = tsk_fs_block_alloc(a_fs)) == NULL) {
        return 1;
    }

    /*
     * Iterate
     */

    // TODO: iterate AGs and iterate block numbers until sb_agblocks
    for (addr = a_start_blk; addr <= a_end_blk; addr++) {
        int retval;
        int myflags;

        myflags = xfs_block_getflags(a_fs, addr);

        // test if we should call the callback with this one
        if ((myflags & TSK_FS_BLOCK_FLAG_ALLOC)
            && (!(a_flags & TSK_FS_BLOCK_WALK_FLAG_ALLOC)))
            continue;
        else if ((myflags & TSK_FS_BLOCK_FLAG_UNALLOC)
            && (!(a_flags & TSK_FS_BLOCK_WALK_FLAG_UNALLOC)))
            continue;

        if (a_flags & TSK_FS_BLOCK_WALK_FLAG_AONLY)
            myflags |= TSK_FS_BLOCK_FLAG_AONLY;

        if (tsk_fs_block_get_flag(a_fs, fs_block, addr,
            (TSK_FS_BLOCK_FLAG_ENUM) myflags) == NULL) {
            tsk_error_set_errstr2("%s: block %" PRIuDADDR,
                myname, addr);
            tsk_fs_block_free(fs_block);
            return 1;
        }

        retval = a_action(fs_block, a_ptr);
        if (retval == TSK_WALK_STOP) {
            break;
        }
        else if (retval == TSK_WALK_ERROR) {
            tsk_fs_block_free(fs_block);
            return 1;
        }
    }

    /*
     * Cleanup.
     */
    tsk_fs_block_free(fs_block);
    return 0;
}

/** \internal
 * Add the data runs and extents to the file attributes.
 *
 * @param fs_file File system to analyze
 * @returns 0 on success, 1 otherwise
 */
static uint8_t
xfs_load_attrs(TSK_FS_FILE * fs_file)
{
    TSK_FS_META *fs_meta = fs_file->meta;
    TSK_FS_INFO *fs_info = fs_file->fs_info;
    XFSFS_INFO *xfs = (XFSFS_INFO *) fs_info;
    TSK_FS_ATTR *fs_attr;
    TSK_OFF_T length = 0;
    xfs_bmbt_irec_t irec;

    if (fs_meta->attr != NULL) {
        tsk_fs_attrlist_markunused(fs_meta->attr);
    }
    else {
        fs_meta->attr = tsk_fs_attrlist_alloc();
    }

    if ((fs_attr =
         tsk_fs_attrlist_getnew(fs_meta->attr,
                                TSK_FS_ATTR_NONRES)) == NULL) {
        return 1;
    }

    length = roundup(fs_meta->size, fs_info->block_size);

    if (tsk_fs_attr_set_run(fs_file, fs_attr, NULL, NULL,
                            TSK_FS_ATTR_TYPE_DEFAULT, TSK_FS_ATTR_ID_DEFAULT,
                            fs_meta->size, fs_meta->size, length, 
                            (TSK_FS_ATTR_FLAG_ENUM) 0, 0)) {
        return 1;
    }

    if (fs_meta->content_type == TSK_FS_META_CONTENT_TYPE_XFS_LOCAL)
    {
        // don't add data runs here
    }
    else if (fs_meta->content_type == TSK_FS_META_CONTENT_TYPE_XFS_EXTENTS)
    {
        xfs_bmbt_rec_t* addr_ptr = (xfs_bmbt_rec_t *) fs_meta->content_ptr;
        uint16_t extent_count = fs_meta->content_len / sizeof(xfs_bmbt_rec_t);
        for (uint16_t extent_num = 0; extent_num < extent_count; extent_num++)
        {
            if (tsk_verbose) { tsk_fprintf(stderr, "extent_num = %d, sizeof(xfs_bmbt_rec_t) = %d, fs_meta->content_len = %d \n", extent_num, sizeof(xfs_bmbt_rec_t), fs_meta->content_len); }

            xfs_bmbt_disk_get_all(&addr_ptr[extent_num], &irec);

            if (tsk_verbose) {
                tsk_fprintf(stderr, "extent_num = %d, adding br_startblock = %" PRIu64 " / br_blockcount = %d \n", extent_num, irec.br_startblock, irec.br_blockcount);
            }

            TSK_FS_ATTR_RUN *data_run = tsk_fs_attr_run_alloc();
            if (data_run == NULL) {
                return 1;
            }

            // converting xfs block numbers to disk addr
            xfs_agnumber_t ag_num = irec.br_startblock >> xfs->fs->sb_agblklog;
            uint64_t rel_blk_neg = 1 << (xfs->fs->sb_agblklog);
            rel_blk_neg -= 1;
            uint64_t rel_blk = (uint64_t) irec.br_startblock & rel_blk_neg;
            TSK_OFF_T offset = ((TSK_OFF_T) ag_num
                * (TSK_OFF_T) xfs->fs->sb_agblocks + rel_blk) 
                * (TSK_OFF_T) fs_info->block_size;

            data_run->offset = irec.br_startoff;
            data_run->addr = offset / fs_info->block_size;
            data_run->len = irec.br_blockcount;

            if (tsk_fs_attr_add_run(fs_info, fs_attr, data_run)) {
                tsk_fs_attr_run_free(data_run);
                return 1;
            }
        }
    }

    fs_meta->attr_state = TSK_FS_META_ATTR_STUDIED;

    return 0;
}

/**
* Print details about the file system to a file handle.
*
* @param fs File system to print details on
* @param hFile File handle to print text to
*
* @returns 1 on error and 0 on success
*/
static uint8_t
    xfsfs_fsstat(TSK_FS_INFO * fs, FILE * hFile)
{
    XFSFS_INFO *xfs = (XFSFS_INFO *) fs;
    xfs_sb_t *sb = xfs->fs;

    // clean up any error messages that are lying around
    tsk_error_reset();

    tsk_fprintf(hFile, "FILE SYSTEM INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");
    tsk_fprintf(hFile, "File System Type: %s\n", "XFS");
    tsk_fprintf(hFile, "Volume Name: %s\n", sb->sb_fname);
    tsk_fprintf(hFile, "Volume ID: %" PRIx32 "-%" PRIx16 "-%" PRIx16 "-%" PRIx16 "-%" PRIx32 "%" PRIx16  "\n",
        tsk_getu32(fs->endian, &sb->sb_uuid.b[0]),
            tsk_getu16(fs->endian, &sb->sb_uuid.b[4]),
            tsk_getu16(fs->endian, &sb->sb_uuid.b[6]),
            tsk_getu16(fs->endian, &sb->sb_uuid.b[8]),
            tsk_getu32(fs->endian, &sb->sb_uuid.b[10]),
            tsk_getu16(fs->endian, &sb->sb_uuid.b[14]));

    tsk_fprintf(hFile, "Version: %");
    if (XFS_SB_VERSION_NUM(sb) == XFS_SB_VERSION_1)
        tsk_fprintf(hFile, "V1");
    else if (XFS_SB_VERSION_NUM(sb) == XFS_SB_VERSION_2)
        tsk_fprintf(hFile, "V2");
    else if (XFS_SB_VERSION_NUM(sb) == XFS_SB_VERSION_3)
        tsk_fprintf(hFile, "V3");
    else if (XFS_SB_VERSION_NUM(sb) == XFS_SB_VERSION_4)
        tsk_fprintf(hFile, "V4");
    else if (XFS_SB_VERSION_NUM(sb) == XFS_SB_VERSION_5)
        tsk_fprintf(hFile, "V5");
    if (xfs_sb_version_hasattr(sb))
        tsk_fprintf(hFile, ",ATTR");
    if (xfs_sb_version_hasnlink(sb))
        tsk_fprintf(hFile, ",NLINK");
    if (xfs_sb_version_hasquota(sb))
        tsk_fprintf(hFile, ",QUOTA");
    if (xfs_sb_version_hasalign(sb))
        tsk_fprintf(hFile, ",ALIGN");
    if (xfs_sb_version_hasdalign(sb))
        tsk_fprintf(hFile, ",DALIGN");
    if (xfs_sb_version_hasshared(sb))
        tsk_fprintf(hFile, ",SHARED");
    if (xfs_sb_version_hasdirv2(sb))
        tsk_fprintf(hFile, ",DIRV2");
    if (xfs_sb_version_haslogv2(sb))
        tsk_fprintf(hFile, ",LOGV2");
    if (xfs_sb_version_hasextflgbit(sb))
        tsk_fprintf(hFile, ",EXTFLG");
    if (xfs_sb_version_hassector(sb))
        tsk_fprintf(hFile, ",SECTOR");
    if (xfs_sb_version_hasasciici(sb))
        tsk_fprintf(hFile, ",ASCII_CI");
    if (xfs_sb_version_hasmorebits(sb))
        tsk_fprintf(hFile, ",MOREBITS");
    if (xfs_sb_version_hasattr2(sb))
        tsk_fprintf(hFile, ",ATTR2");
    if (xfs_sb_version_haslazysbcount(sb))
        tsk_fprintf(hFile, ",LAZYSBCOUNT");
    if (xfs_sb_version_hasprojid32bit(sb))
        tsk_fprintf(hFile, ",PROJID32BIT");
    if (xfs_sb_version_hascrc(sb))
        tsk_fprintf(hFile, ",CRC");
    if (xfs_sb_version_hasftype(sb))
        tsk_fprintf(hFile, ",FTYPE");
    tsk_fprintf(hFile, "\n");

    tsk_fprintf(hFile, "Features Compat: %" PRIu32 "\n", sb->sb_features_compat);
    tsk_fprintf(hFile, "Features Read-Only Compat: %" PRIu32 "\n", sb->sb_features_ro_compat);
    if (sb->sb_features_ro_compat) {
        tsk_fprintf(hFile, "Read Only Compat Features: ");
        if (sb->sb_features_ro_compat & XFS_SB_FEAT_RO_COMPAT_FINOBT)
            tsk_fprintf(hFile, "Free inode B+tree, ");
        if (sb->sb_features_ro_compat & XFS_SB_FEAT_RO_COMPAT_RMAPBT)
            tsk_fprintf(hFile, "Reverse mapping B+tree, ");
        if (sb->sb_features_ro_compat & XFS_SB_FEAT_RO_COMPAT_REFLINK)
            tsk_fprintf(hFile, "Reference count B+tree, ");
        tsk_fprintf(hFile, "\n");
    }

    // todo: sb_versionnum feature flags
    // todo: sb_qflags

    tsk_fprintf(hFile, "Features Incompat: %" PRIu32 "\n", sb->sb_features_incompat);
    if (sb->sb_features_incompat) {
        tsk_fprintf(hFile, "InCompat Features: ");

        if (sb->sb_features_incompat & XFS_SB_FEAT_INCOMPAT_FTYPE)
            tsk_fprintf(hFile, "Directory file type, ");
        if (sb->sb_features_incompat & XFS_SB_FEAT_INCOMPAT_SPINODES)
            tsk_fprintf(hFile, "Sparse inodes, ");
        if (sb->sb_features_incompat & XFS_SB_FEAT_INCOMPAT_META_UUID)
            tsk_fprintf(hFile, "Metadata UUID, ");

        tsk_fprintf(hFile, "\n");
    }

    tsk_fprintf(hFile, "CRC: %" PRIu32 "\n", sb->sb_crc);

    /* Print journal information */
    // TODO

    tsk_fprintf(hFile, "\nMETADATA INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");
    tsk_fprintf(hFile, "Allocated inode count : %" PRIuINUM "\n", sb->sb_icount);
    tsk_fprintf(hFile, "Root Directory: %" PRIuINUM "\n", fs->root_inum);
    tsk_fprintf(hFile, "Free Inodes: %" PRIuINUM "\n", sb->sb_ifree);
    tsk_fprintf(hFile, "Inode Size: %" PRIu16 "\n", sb->sb_inodesize);
    tsk_fprintf(hFile, "Extent Size: %" PRIu32 "\n", sb->sb_rextsize);
    tsk_fprintf(hFile, "Free Extent Count: %" PRIu64 "\n", sb->sb_frextents);

    tsk_fprintf(hFile, "\nCONTENT INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");
    tsk_fprintf(hFile, "Block Range: %" PRIuDADDR " - %" PRIuDADDR "\n",
        fs->first_block, fs->last_block);
    if (fs->last_block != fs->last_block_act)
        tsk_fprintf(hFile,
            "Total Range in Image: %" PRIuDADDR " - %" PRIuDADDR "\n",
            fs->first_block, fs->last_block_act);
    tsk_fprintf(hFile, "Block Size: %" PRId64 "\n", fs->block_size);
    tsk_fprintf(hFile, "Free Blocks: %" PRIu64 "\n", sb->sb_fdblocks);
    tsk_fprintf(hFile, "Sector Size: %" PRIu16 "\n", sb->sb_sectsize);

    tsk_fprintf(hFile, "\nALLOCATION GROUP INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");
    tsk_fprintf(hFile, "Number of Allocation Groups: %" PRIu32 "\n", sb->sb_agcount);
    tsk_fprintf(hFile, "Blocks per allocation group: %" PRIu32 "\n", sb->sb_agblocks);

    // TODO: print per-AG statss
    // for (i = 0; i < sb->sb_agcount; i++) {
        // TODO: print per-AG statss

        // such as
        // agf_length

    // }

    return 0;
}


typedef struct {
    FILE *hFile;
    int idx;
} XFS_PRINT_ADDR;


/* Callback for istat to print the block addresses */
static TSK_WALK_RET_ENUM
print_addr_act(TSK_FS_FILE * fs_file, TSK_OFF_T a_off, TSK_DADDR_T addr,
    char *buf, size_t size, TSK_FS_BLOCK_FLAG_ENUM flags, void *a_ptr)
{
    XFSFS_INFO *xfs = (XFSFS_INFO *) fs_file->fs_info;
    XFS_PRINT_ADDR *print = (XFS_PRINT_ADDR *) a_ptr;

    // addr -> xfs fsblock
    xfs_agnumber_t ag_num = addr >> xfs->fs->sb_agblklog;
    uint64_t rel_blk = addr -(TSK_DADDR_T) ag_num * (TSK_DADDR_T) xfs->fs->sb_agblocks;
    TSK_DADDR_T fsblock_addr = (ag_num << xfs->fs->sb_agblklog) | rel_blk;

    if (flags & TSK_FS_BLOCK_FLAG_CONT) {
        int i, s;
        /* cycle through the blocks if they exist */
        for (i = 0, s = (int) size; s > 0; s -= xfs->fs_info.block_size, i++) {

            /* sparse file */
            if (fsblock_addr)
                tsk_fprintf(print->hFile, "%" PRIuDADDR " ", fsblock_addr + i);
            else
                tsk_fprintf(print->hFile, "0 ");

            if (++(print->idx) == 8) {
                tsk_fprintf(print->hFile, "\n");
                print->idx = 0;
            }
        }
    }

    return TSK_WALK_CONT;
}


/**
 * Parse extended attributes
 *
 * @param a_fs File system file is located in
 * @param a_dino_buf Inode buffer
 * @param a_hFile File handle to print text to
 *
 * @returns 1 on error and 0 on success
 */
static uint8_t
parse_extended_attrs(XFSFS_INFO *a_xfsfs, xfs_dinode_t *a_dino_buf, FILE *a_hFile)
{
    if (a_dino_buf->di_core.di_forkoff == 0)
    {
        return 0;
    }

    tsk_fprintf(a_hFile, "\nExtended Attributes: \n");

    uint8_t *in_base = (uint8_t*) &a_dino_buf->di_core;
    uint64_t in_offset = a_xfsfs->inode_size -
        XFS_DFORK_ASIZE(&a_dino_buf->di_core, a_xfsfs);

    if (a_dino_buf->di_core.di_aformat == XFS_DINODE_FMT_LOCAL)
    {
        uint16_t attr_fork_size = XFS_DFORK_ASIZE(&a_dino_buf->di_core, a_xfsfs);

        xfs_attr_sf_hdr *attr_hdr = (xfs_attr_sf_hdr*) (in_base + in_offset);
        uint16_t totsize = tsk_getu16(TSK_BIG_ENDIAN, &attr_hdr->totsize);

        if (attr_fork_size < ATTR_SF_HDR_SIZE ||
            attr_fork_size - ATTR_SF_HDR_SIZE < totsize)
        {
            tsk_fprintf(a_hFile, "incorrect attribute header");
            return 1;
        }

        in_offset = roundup(in_offset + ATTR_SF_HDR_SIZE, sizeof(uint64_t));
        xfs_attr_sf_entry *sf_entry = (xfs_attr_sf_entry*) (in_base + in_offset);
        uint64_t limit = a_xfsfs->inode_size;

        // we intentionally attempt to go beyond entry_num and not
        // beyond inode end if more (hidden) attributes are allocated
        for (uint8_t entry_num = 0; in_offset < limit; entry_num++)
        {
            uint64_t sf_entry_size = ATTR_SF_ENTRY_SIZE + sf_entry->namelen
                + sf_entry->valuelen;
            if (sf_entry_size >= limit)
            {
                tsk_fprintf(a_hFile, "sf_entry goes past the inode literal area");
                return 1;
            }

            if(sf_entry->flags & XFS_ATTR_ROOT)
            {
                tsk_fprintf(a_hFile, "root,");
            }
            else
            {
                tsk_fprintf(a_hFile, "user,");
            }
            if(sf_entry->flags & XFS_ATTR_SECURE)
            {
                tsk_fprintf(a_hFile, "secure,");
            }
            if(sf_entry->flags & XFS_ATTR_LOCAL)
            {
                tsk_fprintf(a_hFile, "local,");
            }
            if(sf_entry->flags & XFS_ATTR_INCOMPLETE)
            {
                tsk_fprintf(a_hFile, "incomplete,");
            }

            char name[sf_entry->namelen + 1];
            memcpy(&name, &sf_entry->nameval, sf_entry->namelen);
            name[sf_entry->namelen + 1] = '\0';
            char val[sf_entry->valuelen + 1];
            memcpy(&val, &sf_entry->nameval + sf_entry->namelen,
                sf_entry->valuelen);
            val[sf_entry->valuelen + 1] = '\0';

            tsk_fprintf(a_hFile, ".%s=%s\n", &name, &val);

            in_offset = roundup(in_offset + sf_entry_size, sizeof(uint64_t));
            sf_entry = (xfs_attr_sf_entry*) (in_base + in_offset);
        }
    }
    else
    {
        tsk_fprintf(a_hFile, "xfs_istat: parsing non-XFS_DINODE_FMT_LOCAL"
            "long-form attributes (%d) is not supported yet \n",
            a_dino_buf->di_core.di_aformat);
    }
}

/**
 * Print details on a specific file to a file handle.
 *
 * @param fs File system file is located in
 * @param hFile File handle to print text to
 * @param inum Address of file in file system
 * @param numblock The number of blocks in file to force print (can go beyond file size)
 * @param sec_skew Clock skew in seconds to also print times in
 *
 * @returns 1 on error and 0 on success
 */
static uint8_t
xfs_istat(TSK_FS_INFO * fs, TSK_FS_ISTAT_FLAG_ENUM istat_flags, FILE * hFile, TSK_INUM_T inum,
    TSK_DADDR_T numblock, int32_t sec_skew)
{
    XFSFS_INFO *xfsfs = (XFSFS_INFO *) fs;
    xfs_dinode_t *dino_buf = NULL;
    TSK_FS_FILE *fs_file;
    TSK_FS_META *fs_meta;
    XFS_PRINT_ADDR print;
    char ls[12];
    unsigned int size = 0;
    char timeBuf[128];

    if ((fs_file = tsk_fs_file_alloc(fs)) == NULL)
        return 1;
    if ((fs_file->meta =
            tsk_fs_meta_alloc(xfsfs->inode_size)) == NULL)
        {
            return 1;
        }

    // clean up any error messages that are lying around
    tsk_error_reset();

    size =
        xfsfs->fs->sb_inodesize >
        sizeof(xfs_dinode) ? xfsfs->fs->sb_inodesize : sizeof(xfs_dinode);
    if ((dino_buf = static_cast<xfs_dinode_t *>(tsk_malloc(size))) == NULL) {
        return 1;
    }

    if (xfs_dinode_load(xfsfs, inum, dino_buf)) {
        free(dino_buf);
        return 1;
    }

    if ((fs_file = tsk_fs_file_open_meta(fs, NULL, inum)) == NULL) {
        free(dino_buf);
        return 1;
    }
    fs_meta = fs_file->meta;

    tsk_fprintf(hFile, "Inode: %" PRIuINUM "\n", inum);

    tsk_fprintf(hFile, "%sAllocated\n",
        (fs_meta->flags & TSK_FS_META_FLAG_ALLOC) ? "" : "Not ");

    if (fs_meta->link)
        tsk_fprintf(hFile, "symbolic link to: %s\n", fs_meta->link);

    tsk_fprintf(hFile, "uid / gid: %" PRIuUID " / %" PRIuGID "\n",
        fs_meta->uid, fs_meta->gid);

    tsk_fs_meta_make_ls(fs_meta, ls, sizeof(ls));
    tsk_fprintf(hFile, "mode: %s\n", ls);

    tsk_fprintf(hFile, "Flags: ");
    if (dino_buf->di_core.di_flags & XFS_DIFLAG_REALTIME)
            tsk_fprintf(hFile, "Realtime, ");
    if (dino_buf->di_core.di_flags & XFS_DIFLAG_PREALLOC)
            tsk_fprintf(hFile, "Preallocated, ");
    if (dino_buf->di_core.di_flags & XFS_DIFLAG_NEWRTBM)
            tsk_fprintf(hFile, "NEWRTBM, ");
    if (dino_buf->di_core.di_flags & XFS_DIFLAG_IMMUTABLE)
            tsk_fprintf(hFile, "Immutable, ");
    if (dino_buf->di_core.di_flags & XFS_DIFLAG_APPEND)
            tsk_fprintf(hFile, "Append-only, ");
    if (dino_buf->di_core.di_flags & XFS_DIFLAG_SYNC)
            tsk_fprintf(hFile, "Sync, ");
    if (dino_buf->di_core.di_flags & XFS_DIFLAG_NOATIME)
            tsk_fprintf(hFile, "No A-Time, ");
    if (dino_buf->di_core.di_flags & XFS_DIFLAG_NODUMP)
            tsk_fprintf(hFile, "Do Not Dump, ");
    if (dino_buf->di_core.di_flags & XFS_DIFLAG_RTINHERIT)
            tsk_fprintf(hFile, "Inherit realtime, ");
    if (dino_buf->di_core.di_flags & XFS_DIFLAG_PROJINHERIT)
            tsk_fprintf(hFile, "Inheit di_projid, ");
    if (dino_buf->di_core.di_flags & XFS_DIFLAG_NOSYMLINKS)
            tsk_fprintf(hFile, "No symlinks, ");
    if (dino_buf->di_core.di_flags & XFS_DIFLAG_EXTSIZE)
            tsk_fprintf(hFile, "XFS_DIFLAG_EXTSIZE, ");
    if (dino_buf->di_core.di_flags & XFS_DIFLAG_EXTSZINHERIT)
            tsk_fprintf(hFile, "Inherit di_extsize, ");
    if (dino_buf->di_core.di_flags & XFS_DIFLAG_NODEFRAG)
            tsk_fprintf(hFile, "No defragmentation, ");
    if (dino_buf->di_core.di_flags & XFS_DIFLAG_FILESTREAM)
            tsk_fprintf(hFile, "Filestream allocator, ");

    tsk_fprintf(hFile, "\n");

    tsk_fprintf(hFile, "size: %" PRIuOFF "\n", fs_meta->size);
    tsk_fprintf(hFile, "num of links: %d\n", fs_meta->nlink);

    parse_extended_attrs(xfsfs, dino_buf, hFile);

    if (sec_skew != 0) {
        tsk_fprintf(hFile, "\nAdjusted Inode Times:\n");
        if (fs_meta->mtime)
            fs_meta->mtime -= sec_skew;
        if (fs_meta->atime)
            fs_meta->atime -= sec_skew;
        if (fs_meta->ctime)
            fs_meta->ctime -= sec_skew;
        if (fs_meta->crtime)
            fs_meta->crtime -= sec_skew;

        tsk_fprintf(hFile, "Accessed:\t%s\n",
            tsk_fs_time_to_str_subsecs(fs_meta->atime,
                fs_meta->atime_nano, timeBuf));
        tsk_fprintf(hFile, "File Modified:\t%s\n",
            tsk_fs_time_to_str_subsecs(fs_meta->mtime,
                fs_meta->mtime_nano, timeBuf));
        tsk_fprintf(hFile, "Inode Modified:\t%s\n",
            tsk_fs_time_to_str_subsecs(fs_meta->ctime,
                fs_meta->ctime_nano, timeBuf));


        if (fs_meta->mtime)
            fs_meta->mtime += sec_skew;
        if (fs_meta->atime)
            fs_meta->atime += sec_skew;
        if (fs_meta->ctime)
            fs_meta->ctime += sec_skew;
        if (fs_meta->crtime)
            fs_meta->crtime += sec_skew;

        tsk_fprintf(hFile, "\nOriginal Inode Times:\n");
    }
    else {
        tsk_fprintf(hFile, "\nInode Times:\n");
    }

    tsk_fprintf(hFile, "Accessed:\t%s\n",
            tsk_fs_time_to_str_subsecs(fs_meta->atime,
                fs_meta->atime_nano, timeBuf));
    tsk_fprintf(hFile, "File Modified:\t%s\n",
        tsk_fs_time_to_str_subsecs(fs_meta->mtime,
            fs_meta->mtime_nano, timeBuf));
    tsk_fprintf(hFile, "Inode Modified:\t%s\n",
        tsk_fs_time_to_str_subsecs(fs_meta->ctime,
            fs_meta->ctime_nano, timeBuf));

    if (dino_buf->di_core.di_version == 3)
    {
        // fs_meta->crtime only valid on v3 inodes (v5 filsystem)
        tsk_fprintf(hFile, "File Created:\t%s\n",
            tsk_fs_time_to_str_subsecs(fs_meta->crtime,
                fs_meta->crtime_nano, timeBuf));
    }

    if (numblock > 0)
        fs_meta->size = numblock * fs->block_size;

    tsk_fprintf(hFile, "\nDirect Blocks:\n");

    if (istat_flags & TSK_FS_ISTAT_RUNLIST) {
        const TSK_FS_ATTR *fs_attr_default =
            tsk_fs_file_attr_get_type(fs_file,
                TSK_FS_ATTR_TYPE_DEFAULT, 0, 0);

        if (tsk_verbose) { tsk_fprintf(hFile, "\n istat_flags & TSK_FS_ISTAT_RUNLIST = true, fs_attr_default = 0x %x\n", fs_attr_default);    }
        if (fs_attr_default && (fs_attr_default->flags & TSK_FS_ATTR_NONRES)) {
            if (tsk_fs_attr_print(fs_attr_default, hFile)) {
                tsk_fprintf(hFile, "\nError creating run lists\n");
                tsk_error_print(hFile);
                tsk_error_reset();
            }
        }
    }
    else {
        print.idx = 0;
        print.hFile = hFile;

        if (tsk_fs_file_walk(fs_file, TSK_FS_FILE_WALK_FLAG_AONLY,
            print_addr_act, (void *)&print)) {
            tsk_fprintf(hFile, "\nError reading file:  ");
            tsk_error_print(hFile);
            tsk_error_reset();
        }
        else if (print.idx != 0) {
            tsk_fprintf(hFile, "\n");
        }
    }

    tsk_fs_file_close(fs_file);
    free(dino_buf);
    return 0;
}


/* Directories */

/*
 * Calculate number of records in a bmap btree inode root.
 */
uint32_t
xfs_bmdr_maxrecs(uint32_t blocklen, bool leaf)
{
	blocklen -= sizeof(xfs_bmdr_block_t);

	if (leaf)
		return blocklen / sizeof(xfs_bmdr_rec_t);
	return blocklen / (sizeof(xfs_bmdr_key_t) + sizeof(xfs_bmdr_ptr_t));
}

static TSK_RETVAL_ENUM
parse_dir_block(
    TSK_FS_INFO *a_fs,
    TSK_FS_DIR *fs_dir,
    TSK_FS_META *fs_meta,
    xfs_bmbt_irec_t *irec,
    TSK_FS_NAME *fs_name)
{
    TSK_OFF_T size = 0;
    char *dirbuf = NULL;
    XFSFS_INFO *xfs = (XFSFS_INFO *) a_fs;
    xfs_sb_t *sb = xfs->fs;
    TSK_RETVAL_ENUM ret;

    uint8_t ftype_size = xfs_sb_version_hasftype(sb) ? sizeof(uint8_t) : 0;

    // skip ft if that's not a data block
    if (irec->br_startoff >= XFS_DIR2_LEAF_OFFSET / a_fs->block_size 
        || irec->br_startoff >= XFS_DIR2_FREE_OFFSET / a_fs->block_size)
    {
        return TSK_COR;
    }

    if (tsk_verbose) {
        tsk_fprintf(stderr, "adding irec->br_startoff = %" PRId64 " br_startblock = %" PRId64 " / br_blockcount = %" PRId64 ", XFS_DIR2_LEAF_OFFSET = %" PRId64 ",  XFS_DIR2_FREE_OFFSET = %" PRId64 "\n", irec->br_startoff, irec->br_startblock, irec->br_blockcount, XFS_DIR2_LEAF_OFFSET, XFS_DIR2_FREE_OFFSET);
    }

    size = (TSK_OFF_T) irec->br_blockcount * (TSK_OFF_T) a_fs->block_size;

    if ((dirbuf = (char*) tsk_malloc(size)) == NULL) {
        return TSK_ERR;
    }

    xfs_agnumber_t ag_num = (TSK_OFF_T) irec->br_startblock >> sb->sb_agblklog;
    uint64_t rel_blk_neg = 1 << (sb->sb_agblklog);
    rel_blk_neg -= 1;
    uint64_t rel_blk = (TSK_OFF_T) irec->br_startblock & rel_blk_neg;
    TSK_OFF_T offset = 
        ((TSK_OFF_T) ag_num * (TSK_OFF_T) sb->sb_agblocks + rel_blk) 
        * (TSK_OFF_T) a_fs->block_size;

    // read xfs_dir2_data_hdr (on a v5 filesystem this is xfs_dir3_data_hdr_t)

    // let's read the whole extent, but parse it block-by-block
    ssize_t len = size;
    ssize_t cnt = tsk_fs_read(a_fs, offset, dirbuf, len);
    if (cnt != len) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_FWALK);
        tsk_error_set_errstr
        ("xfs_dir_open_meta: Error reading directory contents: %"
            PRIuINUM "\n", fs_meta->addr);
        free(dirbuf);
        return TSK_COR;
    }

    for (uint16_t block_num = 0; block_num < irec->br_blockcount; block_num++)
    {
        TSK_OFF_T offset_in_block =
            (TSK_OFF_T) block_num * (TSK_OFF_T) a_fs->block_size;
        TSK_OFF_T limit = 
            (TSK_OFF_T) (block_num + 1) * (TSK_OFF_T) a_fs->block_size;

        xfs_dir2_data_hdr data_hdr;
        memcpy(&data_hdr, dirbuf + offset_in_block, sizeof(data_hdr));

        offset_in_block += XFS_SB_VERSION_NUM(sb) == XFS_SB_VERSION_5 ?
                XFS_DIR3_HDR_LEN : XFS_DIR2_HDR_LEN;

        xfs_dir2_data_entry_t data_entry;

        while (offset_in_block < limit)
        {
            if (tsk_verbose) { tsk_fprintf(stderr, "offset_in_block = %d \n", offset_in_block); }

            uint16_t *xfs_dir2_data_unused_freetag = 
                (uint16_t*) (dirbuf + offset_in_block);

            if (*xfs_dir2_data_unused_freetag == 0xffff)
            {
                xfs_dir2_data_unused *data_unused = 
                    static_cast<xfs_dir2_data_unused *>((void*) (dirbuf + offset_in_block));

                if (tsk_verbose) { tsk_fprintf(stderr, "offset_in_block = % is a free space, shifting forward by tsk_getu32(TSK_BIG_ENDIAN, &data_unused->length)) = %d \n", offset_in_block, tsk_getu32(TSK_BIG_ENDIAN, &data_unused->length)); }
                offset_in_block += tsk_getu16(TSK_BIG_ENDIAN, &data_unused->length);
            }
            else
            {
                if (offset_in_block + sizeof(uint64_t) + sizeof(uint8_t) >= limit)
                {
                    tsk_error_set_errno(TSK_ERR_FS_FWALK);
                    tsk_error_set_errstr
                    ("xfs_dir_open_meta: Error reading directory contents: %"
                        PRIuINUM "\n", fs_meta->addr);
                    free(dirbuf);
                    return TSK_COR;
                }

                memcpy(&data_entry, dirbuf + offset_in_block, sizeof(uint64_t) + sizeof(uint8_t));
                offset_in_block += sizeof(uint64_t) + sizeof(uint8_t);

                data_entry.inumber = tsk_getu64(TSK_BIG_ENDIAN, &data_entry.inumber);
                fs_name->meta_addr = data_entry.inumber;


                if (offset_in_block + data_entry.namelen + ftype_size >= limit)
                {
                    tsk_error_set_errno(TSK_ERR_FS_FWALK);
                    tsk_error_set_errstr
                    ("xfs_dir_open_meta: Error reading directory contents: %"
                        PRIuINUM "\n", fs_meta->addr);
                    free(dirbuf);
                    return TSK_COR;
                }

                char *name = (char *) dirbuf + offset_in_block;
                memcpy(fs_name->name, name, data_entry.namelen);
                offset_in_block += data_entry.namelen;
                fs_name->name[data_entry.namelen] = '\0';

                uint16_t ftype = 0;
                if (ftype_size > 0)
                {
                    ftype = * (uint8_t *) (name + data_entry.namelen);
                    ftype = ftype << 12;
                }
                else
                {
                    ret = get_inode_file_type(xfs, fs_name->meta_addr, &ftype);
                    if (ret) {
                        free(dirbuf);
                        return ret;
                    }
                }
                fs_meta->type = get_file_type(ftype);

                // we iterate over allocated directories
                fs_name->flags = TSK_FS_NAME_FLAG_ALLOC;

                if (tsk_verbose) { tsk_fprintf(stderr, "namelen = %d, fs_name->name = %s, fs_meta->type = %d, fs_name->meta_addr = %" PRId64  " fs_name->flags = \n", data_entry.namelen, fs_name->name, fs_meta->type, fs_name->meta_addr, fs_name->flags); }

                if (tsk_fs_dir_add(fs_dir, fs_name)) {
                    free(dirbuf);
                    return TSK_ERR;
                }

                // skipping xfs_dir2_data_off_t tag (and ftype, if present)
                offset_in_block += sizeof(xfs_dir2_data_off_t) + ftype_size;

                // x64 alignment
                offset_in_block = roundup(offset_in_block, sizeof(uint64_t));
            }
        }
    }

    return TSK_OK;
}

/* visit the btree node (or leaf) */
static TSK_RETVAL_ENUM
visit_btree_node(
    TSK_FS_INFO *a_fs,
        TSK_FS_DIR *fs_dir,
        TSK_FS_META *fs_meta,
        xfs_off_t cur_node_offset,
        xfs_dinode_t *dino_buf,
        TSK_FS_NAME *fs_name,
        bool is_root)
{
    XFSFS_INFO *xfs = (XFSFS_INFO *) a_fs;

    // xfs_bmdr_block and xfs_bmbt_block_t share those two fields
    uint16_t bb_numrecs = 0;
    uint16_t bb_level = 0;

    uint16_t header_offset = 0;
    ssize_t len = 0;
    ssize_t cnt = 0;

    if(is_root)
    {
        xfs_bmdr_block *cur_bmdr_block = NULL;

        if ((cur_bmdr_block =
            static_cast<xfs_bmdr_block *>(tsk_malloc(sizeof(xfs_bmdr_block)))) == NULL)
        {
            return TSK_ERR;
        }

        len = header_offset = sizeof(xfs_bmdr_block);
        cnt = tsk_fs_read(&xfs->fs_info, cur_node_offset, (char *) cur_bmdr_block, len);
        if (cnt != len) {
            if (cnt >= 0) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_FS_READ);
            }
            tsk_error_set_errstr2("xfs_dir_open_meta: cnt = %" PRId64 ", len = %" PRId64 "", cnt, len);
            free(cur_bmdr_block);
            return TSK_ERR;
        }

        bb_level = tsk_getu16(TSK_BIG_ENDIAN, &cur_bmdr_block->bb_level);
        bb_numrecs = tsk_getu16(TSK_BIG_ENDIAN, &cur_bmdr_block->bb_numrecs);

        free(cur_bmdr_block);
    }
    else
    {
        xfs_bmbt_block_t *cur_bmbt_block;

        if ((cur_bmbt_block =
            static_cast<xfs_bmbt_block_t *>(tsk_malloc(sizeof(xfs_bmbt_block_t)))) == NULL)
        {
            return TSK_ERR;
        }

        len = header_offset = sizeof(xfs_bmbt_block_t);
        cnt = tsk_fs_read(&xfs->fs_info,
            cur_node_offset,
            (char *) cur_bmbt_block,
            len);
        if (cnt != len) {
            if (cnt >= 0) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_FS_READ);
            }
            tsk_error_set_errstr2("xfs_dir_open_meta: cnt = %" PRId64 ", len = %" PRId64 "", cnt, len);
            free(cur_bmbt_block);
            return TSK_ERR;
        }

        bb_level = tsk_getu16(TSK_BIG_ENDIAN, &cur_bmbt_block->bb_level);
        bb_numrecs = tsk_getu16(TSK_BIG_ENDIAN, &cur_bmbt_block->bb_numrecs);

        free(cur_bmbt_block);
    }

    uint32_t dblocksize = XFS_DFORK_SIZE(&dino_buf->di_core, xfs, XFS_DATA_FORK);

    // if not a leaf node
    if(bb_level > 0)
    {
        uint32_t maxrecs = xfs_bmdr_maxrecs(dblocksize, 0 /* not leaf */);

        xfs_bmbt_rec_t *node_recs = NULL;
        size_t len = (size_t) bb_numrecs * sizeof(xfs_bmbt_rec_t);

        if ((node_recs = static_cast<xfs_bmbt_rec_t *>(tsk_malloc(len))) == NULL)
        {
            return TSK_ERR;
        }

        // read all the keys
        cnt = tsk_fs_read(&xfs->fs_info,
            cur_node_offset + (TSK_OFF_T) header_offset,
            (char *) node_recs,
            len);
        if (cnt != len) {
            if (cnt >= 0) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_FS_READ);
            }
            tsk_error_set_errstr2("xfs_dir_open_meta: cnt = %" PRId64 ", len = %" PRId64 "", cnt, len);
            free(node_recs);
            return TSK_ERR;
        }

        xfs_bmbt_ptr_t *node_ptrs = NULL;
        len = bb_numrecs * sizeof(xfs_bmbt_ptr_t);
        if ((node_ptrs = static_cast<xfs_bmbt_ptr_t *>(tsk_malloc(len))) == NULL)
        {
            free(node_recs);
            return TSK_ERR;
        }

        // read all the node pointers
        cnt = tsk_fs_read(&xfs->fs_info,
            cur_node_offset + (TSK_OFF_T) header_offset + 
                (TSK_OFF_T) maxrecs * (TSK_OFF_T) sizeof(xfs_bmbt_key),
            (char *) node_ptrs,
            len);
        if (cnt != len) {
            if (cnt >= 0) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_FS_READ);
            }
            tsk_error_set_errstr2("xfs_dir_open_meta: cnt = %" PRId64 ", len = %" PRId64 "", cnt, len);
            free(node_recs);
            free(node_ptrs);
            return TSK_ERR;
        }

        // traverse all the pointers
        for(uint32_t cur_key = 0; cur_key < bb_numrecs; cur_key++)
        {
            xfs_fsblock_t next_node_block =
                tsk_getu64(TSK_BIG_ENDIAN, &node_ptrs[cur_key]);

            // block -> offset
            xfs_agnumber_t ag_num = next_node_block >> xfs->fs->sb_agblklog;
            uint64_t rel_blk_neg = 1 << (xfs->fs->sb_agblklog);
            rel_blk_neg -= 1;
            uint64_t rel_blk = (uint64_t) next_node_block & rel_blk_neg;
            TSK_OFF_T next_node_offset = 
                ((TSK_OFF_T) ag_num * (TSK_OFF_T) xfs->fs->sb_agblocks + rel_blk) 
                * (TSK_OFF_T) xfs->fs_info.block_size;

            if (tsk_verbose) { tsk_fprintf(stderr, "visiting next_node (block %" PRId64", offset %" PRId64 " \n", next_node_block, next_node_offset); }

            visit_btree_node(a_fs,fs_dir, fs_meta, next_node_offset, dino_buf,
                fs_name, 0);
        }

        free(node_recs);
        free(node_ptrs);

        return TSK_OK;
    }
    else
    {
        // at the leaf node now
        xfs_bmbt_rec_t *node_recs = NULL;

        size_t len = bb_numrecs * sizeof(xfs_bmbt_rec_t);

        if ((node_recs = static_cast<xfs_bmbt_rec_t *>(tsk_malloc(len))) == NULL)
        {
            return TSK_ERR;
        }

        // read all the records
        cnt = tsk_fs_read(&xfs->fs_info, 
            cur_node_offset + (TSK_OFF_T) header_offset, (char *) node_recs, len);
        if (cnt != len) {
            if (cnt >= 0) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_FS_READ);
            }
            tsk_error_set_errstr2("xfs_dir_open_meta: cnt = %" PRId64 ", len = %" PRId64 "", cnt, len);
            free(node_recs);
            return TSK_ERR;
        }

        // iterate over the keys
        for(uint32_t cur_key = 0; cur_key < bb_numrecs; cur_key++)
        {
            // unpack extent
            xfs_bmbt_irec_t irec;
            memset(&irec, 0, sizeof(irec));
            xfs_bmbt_disk_get_all(&node_recs[cur_key], &irec);

            if (tsk_verbose) { tsk_fprintf(stderr, "now at cur_key = %" PRId64 ", &irec = %" PRIx64" \n",
                cur_key, &irec); }

            parse_dir_block(a_fs, fs_dir, fs_meta, &irec, fs_name);
            // parse the directory entry in this extent
        }

        free(node_recs);

        return TSK_OK;
    }
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
xfs_dir_open_meta(TSK_FS_INFO * a_fs, TSK_FS_DIR ** a_fs_dir,
    TSK_INUM_T a_addr)
{
    XFSFS_INFO *xfs = (XFSFS_INFO *) a_fs;
    xfs_sb_t *sb = xfs->fs;
    TSK_FS_META *fs_meta;
    uint8_t ftype_size = 0;
    char *dirbuf = NULL;
    TSK_OFF_T size;
    TSK_FS_DIR *fs_dir;
    TSK_RETVAL_ENUM retval = TSK_OK;
    TSK_FS_NAME *fs_name;
    TSK_RETVAL_ENUM ret;

    // Assuming fs_meta->type == TSK_FS_META_TYPE_DIR

    if (tsk_verbose) { tsk_fprintf(stderr, "a_fs->first_inum = %d, a_fs->last_inum = %d \n", a_fs->first_inum, a_fs->last_inum); }

    if (a_addr < a_fs->first_inum || a_addr > a_fs->last_inum) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("xfs_dir_open_meta: inode value: %"
            PRIuINUM "\n", a_addr);
        return TSK_ERR;
    }
    else if (a_fs_dir == NULL) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr
            ("xfs_dir_open_meta: NULL fs_attr argument given");
        return TSK_ERR;
    }

    if (tsk_verbose) {
        tsk_fprintf(stderr,
            "xfs_dir_open_meta: Processing directory %" PRIuINUM
            "\n", a_addr);
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

    if ((fs_dir->fs_file =
            tsk_fs_file_open_meta(a_fs, NULL, a_addr)) == NULL) {
        tsk_error_reset();
        tsk_error_errstr2_concat("- xfs_dir_open_meta");
        return TSK_COR;
    }

    fs_meta = fs_dir->fs_file->meta;

    if ((fs_name = tsk_fs_name_alloc(XFS_MAXNAMELEN, 0)) == NULL)
        return TSK_ERR;

    ftype_size = xfs_sb_version_hasftype(sb) ? sizeof(uint8_t) : 0;

    if (fs_meta->content_type == TSK_FS_META_CONTENT_TYPE_XFS_LOCAL)
    {
        xfs_dir2_sf_t *dir_sf = (xfs_dir2_sf_t*) fs_meta->content_ptr;

        if (tsk_verbose) { tsk_fprintf(stderr, "dir_sf = 0x %" PRIx64  " \n", dir_sf); }

        bool i8 = dir_sf->hdr.i8count != 0;
        uint8_t count = i8 ? dir_sf->hdr.i8count : dir_sf->hdr.count;

        /*
        *    sf_entry goes after xfs_dir2_sf_hdr, which is defined as:
        *
        *    typedef struct xfs_dir2_sf_hdr {
        *         uint8_t count;
        *         uint8_t i8count;
        *         xfs_dir2_inou_t parent; <-- uint32_t (uint64_t if i8count > 0)
        *    } xfs_dir2_sf_hdr_t;
        */

        xfs_dir2_sf_entry *sf_entry = 0;
        sf_entry = (xfs_dir2_sf_entry*) ((char *) dir_sf + sizeof(uint8_t)
            + sizeof(uint8_t) + (i8 ? sizeof(uint64_t) : sizeof(uint32_t)));

        if (tsk_verbose) { tsk_fprintf(stderr, "sf_entry = 0x %" PRIx64  " \n", sf_entry); }

        for(uint8_t dir_ent_num = 0; dir_ent_num < count; dir_ent_num++)
        {
            /*
            *    typedef struct   {
            *         uint8_t namelen;
            *         xfs_dir2_sf_off_t offset;
            *         uint8_t name[1];
            *         uint8_t ftype;
            *         xfs_dir2_inou_t inumber;
            *    } xfs_dir2_sf_entry_t;
            */

            uint8_t namelen = sf_entry->namelen;
            char *name = (char *) sf_entry + sizeof(uint8_t)
                + sizeof(xfs_dir2_sf_off_t);
            memcpy(fs_name->name, name, namelen);
            fs_name->name[namelen] = '\0';

            xfs_dir2_inou_t *inum_p = (xfs_dir2_inou_t*) (name + namelen + 
                ftype_size);
            fs_name->meta_addr = i8
                ? tsk_getu64(TSK_BIG_ENDIAN, &inum_p->i8)
                : tsk_getu32(TSK_BIG_ENDIAN, &inum_p->i4);

            uint16_t ftype = 0;
            if (ftype_size > 0)
            {
                ftype = * (uint8_t *) (name + namelen);
                ftype = ftype << 12;
            }
            else
            {
                ret = get_inode_file_type(xfs, fs_name->meta_addr, &ftype);
                if (ret) {
                    free(dirbuf);
                    return ret;
                }
            }
            fs_meta->type = get_file_type(ftype);

            fs_name->flags = (TSK_FS_NAME_FLAG_ENUM) 0;

            /* Do we have a deleted entry? */
            bool is_del = fs_dir->fs_file->meta->flags & TSK_FS_META_FLAG_UNALLOC;
            if ((fs_name->meta_addr == 0) || (is_del)) {
                fs_name->flags = TSK_FS_NAME_FLAG_UNALLOC;
            }
            /* We have a non-deleted entry */
            else {
                fs_name->flags = TSK_FS_NAME_FLAG_ALLOC;
            }

            if (tsk_verbose) { tsk_fprintf(stderr, "namelen = %d, fs_name->name = %s, fs_name->meta_addr = %" PRId64  " fs_name->flags = \n", namelen, fs_name->name, fs_name->meta_addr, fs_name->flags); }

            if (tsk_fs_dir_add(fs_dir, fs_name)) {
                tsk_fs_name_free(fs_name);
                return TSK_ERR;
            }

            sf_entry = (xfs_dir2_sf_entry*) ((char *) sf_entry + sizeof(uint8_t)
                + sizeof(xfs_dir2_sf_off_t) + namelen + ftype_size
                + (i8 ? sizeof(uint64_t) : sizeof(uint32_t)));
        }
    }
    else if (fs_meta->content_type == TSK_FS_META_CONTENT_TYPE_XFS_EXTENTS)
    {
        xfs_bmbt_rec_t *extent_data_offset =
            (xfs_bmbt_rec_t *) fs_meta->content_ptr;
        uint32_t nextents =
            fs_meta->content_len / sizeof(xfs_bmbt_rec_t);

        if (tsk_verbose) { tsk_fprintf(stderr, "nextents == %" PRId64 ", fs_meta->size = %" PRId64 " \n", nextents, fs_meta->size); }

        if (nextents == 0)
        {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_ARG);
            tsk_error_set_errstr
                ("xfs_dir_open_meta: fs_meta->nextents is 0 for TSK_FS_META_CONTENT_TYPE_XFS_EXTENTS type");
            return TSK_ERR;
        } else if (nextents == 1)
        {
            // parsing "block directory" format

            // unpack extent
            xfs_bmbt_irec_t irec;
            memset(&irec, 0, sizeof(irec));
            xfs_bmbt_disk_get_all(extent_data_offset, &irec);

            if (tsk_verbose) {
                tsk_fprintf(stderr, "extent_num = %d, adding br_startblock = %d / br_blockcount = %d \n", /* extent_num */ 0, irec.br_startblock, irec.br_blockcount);
            }

            if ((dirbuf = (char*) tsk_malloc((size_t)a_fs->block_size)) == NULL) {
                return TSK_ERR;
            }

            size = irec.br_blockcount * a_fs->block_size;

            xfs_agnumber_t ag_num = (TSK_OFF_T) irec.br_startblock >> sb->sb_agblklog;
            uint64_t rel_blk_neg = 1 << (sb->sb_agblklog);
            rel_blk_neg -= 1;
            uint64_t rel_blk = (TSK_OFF_T) irec.br_startblock & rel_blk_neg;
            TSK_OFF_T offset = ((TSK_OFF_T) ag_num * (TSK_OFF_T) sb->sb_agblocks + rel_blk) 
                * (TSK_OFF_T) a_fs->block_size;

            TSK_OFF_T offset_in_block = 0;

            // directory block starts with xfs_dir2_data_hdr
            // or (xfs_dir3_data_hdr_t on a v5 filesystem)

            ssize_t len = (size > a_fs->block_size) ? a_fs->block_size : size;
            ssize_t cnt = tsk_fs_read(a_fs, offset, dirbuf, len);
            if (cnt != len) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_FS_FWALK);
                tsk_error_set_errstr
                ("xfs_dir_open_meta: Error reading directory contents: %"
                    PRIuINUM "\n", a_addr);
                free(dirbuf);
                return TSK_COR;
            }

            offset_in_block += XFS_SB_VERSION_NUM(sb) == XFS_SB_VERSION_5 ?
                XFS_DIR3_HDR_LEN : XFS_DIR2_HDR_LEN;

            xfs_dir2_block_tail block_tail;
            memcpy(&block_tail, dirbuf + size - sizeof(xfs_dir2_block_tail),
                sizeof(xfs_dir2_block_tail));
            block_tail.count = tsk_getu32(TSK_BIG_ENDIAN, &block_tail.count);
            block_tail.stale = tsk_getu32(TSK_BIG_ENDIAN, &block_tail.stale);
            uint32_t leaf_offset = size - sizeof(xfs_dir2_block_tail)
                - block_tail.count * sizeof(xfs_dir2_leaf_entry_t);

            if (leaf_offset >= len) {
                tsk_fprintf(stderr, "leaf_offset = %d past len = %d \n", leaf_offset, len);
                tsk_error_set_errno(TSK_ERR_FS_FWALK);
                tsk_error_set_errstr
                ("xfs_dir_open_meta: Error reading directory contents: %"
                    PRIuINUM "\n", a_addr);
                free(dirbuf);
                return TSK_COR;
            }

            if (tsk_verbose) {
                tsk_fprintf(stderr, "block_tail.count = %d, leaf_offset = %d (out of len = %d) \n", block_tail.count, leaf_offset, len);
            }

            size -= len;
            offset += len;

            xfs_dir2_data_entry_t data_entry;

            while (offset_in_block < leaf_offset)
            {
                if (tsk_verbose) { tsk_fprintf(stderr, "offset_in_block = %d \n", offset_in_block); }

                uint16_t *xfs_dir2_data_unused_freetag = (uint16_t*) (dirbuf + offset_in_block);

                if (*xfs_dir2_data_unused_freetag == 0xffff)
                {
                    xfs_dir2_data_unused *data_unused = static_cast<xfs_dir2_data_unused *>((void *)(dirbuf + offset_in_block));

                    if (tsk_verbose) { tsk_fprintf(stderr, "offset_in_block = % is a free space, shifting forward by tsk_getu32(TSK_BIG_ENDIAN, &data_unused->length)) = %d \n", offset_in_block, tsk_getu32(TSK_BIG_ENDIAN, &data_unused->length)); }
                    offset_in_block +=
                        tsk_getu16(TSK_BIG_ENDIAN, &data_unused->length);
                }
                else
                {
                    if (offset_in_block + sizeof(uint64_t) + sizeof(uint8_t) >= leaf_offset)
                    {
                        tsk_error_set_errno(TSK_ERR_FS_FWALK);
                        tsk_error_set_errstr
                        ("xfs_dir_open_meta: Error reading directory contents: %"
                            PRIuINUM "\n", a_addr);
                        free(dirbuf);
                        return TSK_COR;
                    }

                    memcpy(&data_entry, dirbuf + offset_in_block, sizeof(uint64_t) + sizeof(uint8_t));
                    offset_in_block += sizeof(uint64_t) + sizeof(uint8_t);

                    data_entry.inumber = tsk_getu64(TSK_BIG_ENDIAN, &data_entry.inumber);
                    fs_name->meta_addr = data_entry.inumber;


                    if (offset_in_block + data_entry.namelen + ftype_size >= leaf_offset)
                    {
                        tsk_error_set_errno(TSK_ERR_FS_FWALK);
                        tsk_error_set_errstr
                        ("xfs_dir_open_meta: Error reading directory contents: %"
                            PRIuINUM "\n", a_addr);
                        free(dirbuf);
                        return TSK_COR;
                    }

                    char *name = (char *) dirbuf + offset_in_block;
                    memcpy(fs_name->name, name, data_entry.namelen);
                    offset_in_block += data_entry.namelen;
                    fs_name->name[data_entry.namelen] = '\0';

                    uint16_t ftype = 0;
                    if (ftype_size > 0)
                    {
                        ftype = * (uint8_t *) (name + data_entry.namelen);
                        ftype = ftype << 12;
                    }
                    else
                    {
                        ret = get_inode_file_type(xfs, fs_name->meta_addr, &ftype);
                        if (ret) {
                            free(dirbuf);
                            return ret;
                        }
                    }
                    fs_meta->type = get_file_type(ftype);

                    // we iterate over allocated directories
                    fs_name->flags = TSK_FS_NAME_FLAG_ALLOC;

                    if (tsk_verbose) { tsk_fprintf(stderr, "namelen = %d, fs_name->name = %s, fs_meta->type = %d, fs_name->meta_addr = %" PRId64  " fs_name->flags = \n", data_entry.namelen, fs_name->name, fs_meta->type, fs_name->meta_addr, fs_name->flags); }

                    if (tsk_fs_dir_add(fs_dir, fs_name)) {
                        free(dirbuf);
                        tsk_fs_name_free(fs_name);
                        return TSK_ERR;
                    }

                    // skipping xfs_dir2_data_off_t tag (and ftype, if present)
                    offset_in_block += sizeof(xfs_dir2_data_off_t) + ftype_size;

                    // x64 alignment
                    offset_in_block = roundup(offset_in_block, sizeof(uint64_t));
                }
            }
        }
        else
        {
            // parsing "leaf direcory" and "node directory" formats

            for(uint32_t extent_num = 0; extent_num < nextents; extent_num++)
            {
                // unpack extent
                xfs_bmbt_irec_t irec;
                memset(&irec, 0, sizeof(irec));
                xfs_bmbt_disk_get_all(&extent_data_offset[extent_num], &irec);

                parse_dir_block(a_fs, fs_dir, fs_meta, &irec, fs_name);
            }
        }

        free(dirbuf);
    }
    else if (fs_meta->content_type == TSK_FS_META_CONTENT_TYPE_XFS_FMT_BTREE)
    {
        TSK_OFF_T *cur_node_offset = (TSK_OFF_T*) fs_meta->content_ptr;

        if (tsk_verbose) { tsk_fprintf(stderr, "starting TSK_FS_META_CONTENT_TYPE_XFS_FMT_BTREE btree traversal, cur_node_offset = %" PRId64 "  \n", *cur_node_offset); }

        // have to load the dinode again for proper data fork size calculation
        xfs_dinode_t *dino_buf = NULL;
        ssize_t dinode_size =
            sb->sb_inodesize >
            sizeof(xfs_dinode) ? sb->sb_inodesize : sizeof(xfs_dinode);
        if ((dino_buf =
            static_cast<xfs_dinode_t *>(tsk_malloc(dinode_size))) == NULL) {
            return TSK_ERR;
        }

        if (xfs_dinode_load(xfs, a_addr, dino_buf)) {
            free(dino_buf);
            return TSK_ERR;
        }

        retval = visit_btree_node(a_fs, fs_dir, fs_meta, *cur_node_offset, dino_buf, fs_name, 1 /* root node */);

        free(dino_buf);

        if (tsk_verbose) { tsk_fprintf(stderr, "finished TSK_FS_META_CONTENT_TYPE_XFS_FMT_BTREE btree traversal \n"); }
    }

    return retval;
}



/* xfsfs_close - close an xfsfs file system */
static void
    xfsfs_close(TSK_FS_INFO *fs)
{
    if(fs != NULL){
        XFSFS_INFO *xfsfs = (XFSFS_INFO *)fs;
        free(xfsfs->fs);
        free(xfsfs->agi);
        tsk_fs_free(fs);
    }
}

/**
* \internal
* Open part of a disk image as a XFS file system.
*
* @param img_info Disk image to analyze
* @param offset Byte offset where file system starts
* @param ftype Specific type of file system
* @param test Going to use this - 1 if we're doing auto-detect, 0 if not (display more verbose messages if the user specified XFS)
* @returns NULL on error or if data is not an XFS file system
*/
TSK_FS_INFO *
    xfs_open(TSK_IMG_INFO * img_info, TSK_OFF_T offset,
    TSK_FS_TYPE_ENUM ftype, uint8_t test)
{
    XFSFS_INFO *xfsfs = NULL;
    TSK_FS_INFO *fs = NULL;
    xfs_sb_t *sb = NULL;
    xfs_agi *agi = NULL;
    unsigned int len = 0;
    ssize_t cnt;

    // temporary sanity check
    if (xfs_dinode_size(2) != 100) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("Invalid FS Type in xfsfs_open");
        return NULL;
    }

    // clean up any error messages that are lying around
    tsk_error_reset();

    if (TSK_FS_TYPE_ISXFS(ftype) == 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("Invalid FS Type in xfsfs_open");
        return NULL;
    }

    if (img_info->sector_size == 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("xfs_open: sector size is 0");
        return NULL;
    }

    if ((xfsfs = (XFSFS_INFO *) tsk_fs_malloc(sizeof(XFSFS_INFO))) == NULL)
        return NULL;


    fs = &(xfsfs->fs_info);

    fs->ftype = ftype;
    fs->flags = TSK_FS_INFO_FLAG_NONE;
    fs->img_info = img_info;
    fs->offset = offset;
    fs->tag = TSK_FS_INFO_TAG;

    /*
     * Read the superblock.
    */

    len = sizeof(xfs_sb_t);
    if ((xfsfs->fs = static_cast<xfs_sb_t *>(tsk_malloc(len))) == NULL) {
        tsk_fs_free(&xfsfs->fs_info);
        return NULL;
    }
    if (tsk_verbose) { tsk_fprintf(stderr, "reading xfs superblock, len = %" PRId64 " \n", len); }
    cnt = tsk_fs_read(fs, (TSK_OFF_T) 0, (char *) xfsfs->fs, len);
    if (tsk_verbose) { tsk_fprintf(stderr, "read the xfs superblock, cnt =%" PRId64 " \n", cnt); }
    if (cnt != len) {
        if (cnt >= 0) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_READ);
        }
        tsk_error_set_errstr2("xfs_open: superblock");
        free(xfsfs->fs);
        tsk_fs_free(&xfsfs->fs_info);
        return NULL;
    }

    sb = xfsfs->fs;

    sb->sb_magicnum = tsk_getu32(TSK_BIG_ENDIAN, &sb->sb_magicnum);
    sb->sb_blocksize = tsk_getu32(TSK_BIG_ENDIAN, &sb->sb_blocksize);
    sb->sb_dblocks = tsk_getu64(TSK_BIG_ENDIAN, &sb->sb_dblocks);
    sb->sb_rblocks = tsk_getu64(TSK_BIG_ENDIAN, &sb->sb_rblocks);
    sb->sb_rextents = tsk_getu64(TSK_BIG_ENDIAN, &sb->sb_rextents);
    sb->sb_logstart = tsk_getu64(TSK_BIG_ENDIAN, &sb->sb_logstart);
    sb->sb_rootino = tsk_getu64(TSK_BIG_ENDIAN, &sb->sb_rootino);
    sb->sb_rbmino = tsk_getu64(TSK_BIG_ENDIAN, &sb->sb_rbmino);
    sb->sb_rsumino = tsk_getu64(TSK_BIG_ENDIAN, &sb->sb_rsumino);
    sb->sb_rextsize = tsk_getu32(TSK_BIG_ENDIAN, &sb->sb_rextsize);
    sb->sb_agblocks = tsk_getu32(TSK_BIG_ENDIAN, &sb->sb_agblocks);
    sb->sb_agcount = tsk_getu32(TSK_BIG_ENDIAN, &sb->sb_agcount);
    sb->sb_rbmblocks = tsk_getu32(TSK_BIG_ENDIAN, &sb->sb_rbmblocks);
    sb->sb_logblocks = tsk_getu32(TSK_BIG_ENDIAN, &sb->sb_logblocks);
    sb->sb_versionnum = tsk_getu16(TSK_BIG_ENDIAN, &sb->sb_versionnum);
    sb->sb_sectsize = tsk_getu16(TSK_BIG_ENDIAN, &sb->sb_sectsize);
    sb->sb_inodesize = tsk_getu16(TSK_BIG_ENDIAN, &sb->sb_inodesize);
    sb->sb_inopblock = tsk_getu16(TSK_BIG_ENDIAN, &sb->sb_inopblock);
    sb->sb_icount = tsk_getu64(TSK_BIG_ENDIAN, &sb->sb_icount);
    sb->sb_ifree = tsk_getu64(TSK_BIG_ENDIAN, &sb->sb_ifree);
    sb->sb_fdblocks = tsk_getu64(TSK_BIG_ENDIAN, &sb->sb_fdblocks);
    sb->sb_frextents = tsk_getu64(TSK_BIG_ENDIAN, &sb->sb_frextents);
    sb->sb_uquotino = tsk_getu64(TSK_BIG_ENDIAN, &sb->sb_uquotino);
    sb->sb_qflags = tsk_getu16(TSK_BIG_ENDIAN, &sb->sb_qflags);
    sb->sb_inoalignmt = tsk_getu32(TSK_BIG_ENDIAN, &sb->sb_inoalignmt);
    sb->sb_unit = tsk_getu32(TSK_BIG_ENDIAN, &sb->sb_unit);
    sb->sb_width = tsk_getu32(TSK_BIG_ENDIAN, &sb->sb_width);
    sb->sb_logsectsize = tsk_getu16(TSK_BIG_ENDIAN, &sb->sb_logsectsize);
    sb->sb_logsunit = tsk_getu32(TSK_BIG_ENDIAN, &sb->sb_logsunit);
    sb->sb_features2 = tsk_getu32(TSK_BIG_ENDIAN, &sb->sb_features2);

    /* version 5 superblock fields start here */
    sb->sb_features_compat = tsk_getu32(TSK_BIG_ENDIAN, &sb->sb_features_compat);
    sb->sb_features_ro_compat = tsk_getu32(TSK_BIG_ENDIAN, &sb->sb_features_ro_compat);
    sb->sb_features_incompat = tsk_getu32(TSK_BIG_ENDIAN, &sb->sb_features_incompat);
    sb->sb_features_log_incompat = tsk_getu32(TSK_BIG_ENDIAN, &sb->sb_features_log_incompat);
    sb->sb_crc = tsk_getu32(TSK_BIG_ENDIAN, &sb->sb_crc);
    sb->sb_spino_align = tsk_getu32(TSK_BIG_ENDIAN, &sb->sb_spino_align);
    sb->sb_pquotino = tsk_getu64(TSK_BIG_ENDIAN, &sb->sb_pquotino);
    sb->sb_lsn = tsk_getu64(TSK_BIG_ENDIAN, &sb->sb_lsn);
    // uuid_t sb_meta_uuid;
    sb->sb_rrmapino = tsk_getu64(TSK_BIG_ENDIAN, &sb->sb_rrmapino);

    if (xfsfs->fs->sb_magicnum != 0x58465342) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_READ);
        tsk_error_set_errstr2("xfs_open: magic number doesn't match XFSB");
        free(xfsfs->fs);
        tsk_fs_free(&xfsfs->fs_info);
        return NULL;
    }

    if(XFS_SB_VERSION_NUM(sb) > 4)
    {
        tsk_fprintf(stderr, "Version 5 and newer are not fully supported yet, be careful (current version: %d) \n", XFS_SB_VERSION_NUM(sb));
    }

    len = sizeof(xfs_agi) * xfsfs->fs->sb_agcount;
    if ((agi = static_cast<xfs_agi *>(tsk_malloc(len))) == NULL)
        return NULL;

    for (xfs_agnumber_t current_ag = 0; current_ag < sb->sb_agcount; current_ag++)
    {
        TSK_OFF_T agi_offset =  (TSK_OFF_T) current_ag 
            * (TSK_OFF_T) sb->sb_agblocks * (TSK_OFF_T) sb->sb_blocksize
            + (TSK_OFF_T) (sb->sb_sectsize * 2);
        len = sizeof(xfs_agi);

        xfs_agi *cur_agi = &agi[current_ag];
        if (tsk_verbose) { tsk_fprintf(stderr, "reading xfs AGI[%d/%d] from agi_offset = %" PRId64 " \n", current_ag, sb->sb_agcount, agi_offset); }
        cnt = tsk_fs_read(&xfsfs->fs_info, agi_offset, (char *) cur_agi, len);
        if (cnt != len) {
            if (cnt >= 0) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_FS_READ);
            }
            tsk_error_set_errstr2("xfs_block_getflags: xfs_agf, cnt = %" PRId64 ", len = %" PRId64 "", cnt, len);
            free(agi);
            tsk_fs_free(&xfsfs->fs_info);
            return NULL;
        }

        cur_agi->agi_magicnum = tsk_getu32(TSK_BIG_ENDIAN, &cur_agi->agi_magicnum);
        cur_agi->agi_versionnum = tsk_getu32(TSK_BIG_ENDIAN, &cur_agi->agi_versionnum);
        cur_agi->agi_seqno = tsk_getu32(TSK_BIG_ENDIAN, &cur_agi->agi_seqno);
        cur_agi->agi_length = tsk_getu32(TSK_BIG_ENDIAN, &cur_agi->agi_length);
        cur_agi->agi_count = tsk_getu32(TSK_BIG_ENDIAN, &cur_agi->agi_count);
        cur_agi->agi_root = tsk_getu32(TSK_BIG_ENDIAN, &cur_agi->agi_root);
        cur_agi->agi_level = tsk_getu32(TSK_BIG_ENDIAN, &cur_agi->agi_level);
        cur_agi->agi_freecount = tsk_getu32(TSK_BIG_ENDIAN, &cur_agi->agi_freecount);
        cur_agi->agi_newino = tsk_getu32(TSK_BIG_ENDIAN, &cur_agi->agi_newino);
        cur_agi->agi_dirino = tsk_getu32(TSK_BIG_ENDIAN, &cur_agi->agi_dirino);

        if (tsk_verbose) { tsk_fprintf(stderr, "agi->agi_magicnum = %.4s \n", &cur_agi->agi_magicnum); }
        if (tsk_verbose) { tsk_fprintf(stderr, "agi->agi_length = %" PRId64 " \n", cur_agi->agi_length); }
        if (tsk_verbose) { tsk_fprintf(stderr, "agi->agi_count = %" PRId64 " \n", cur_agi->agi_count); }
    }

    xfsfs->agi = agi;

    /* Set the size of the inode, but default to our data structure
     * size if it is larger */
    xfsfs->inode_size = sb->sb_inodesize;

    if (xfsfs->inode_size < sizeof(xfs_dinode_core)) {
        if (tsk_verbose)
            tsk_fprintf(stderr, "SB inode size is small");
    }

    /*
     * Calculate the block info
     */
    fs->dev_bsize = img_info->sector_size;
    fs->block_count = sb->sb_dblocks;
    fs->first_block = 0;

    if (xfsfs->fs->sb_agcount < 1)
    {
        tsk_fprintf(stderr, "xfsfs->fs->sb_agcount is <1");
    }

    fs->last_block = (TSK_DADDR_T) (sb->sb_agcount - 1) << sb->sb_agblklog;
    fs->last_block += (TSK_DADDR_T) agi[sb->sb_agcount - 1].agi_length;
    fs->last_block_act = fs->last_block;
    fs->block_size = sb->sb_blocksize;

    /*
     * Calculate the meta data info
     */
    fs->root_inum = fs->first_inum = sb->sb_rootino; // usually 128
    fs->inum_count = sb->sb_icount;
    fs->last_inum = 
        (uint64_t) (sb->sb_agcount - 1) << (sb->sb_agblklog + sb->sb_inopblog);
    fs->last_inum +=
        (uint64_t) agi[sb->sb_agcount - 1].agi_length * (uint64_t) sb->sb_inopblock;
    fs->last_inum -= 1;
    // right now, 0xffff prefix signifies the start of unused space in directory
    // entry, so theoretical last inode num is 0xffff000000000000

    fs->get_default_attr_type = tsk_fs_unix_get_default_attr_type;
    fs->load_attrs = xfs_load_attrs;

    fs->dir_open_meta = xfs_dir_open_meta;

    fs->fsstat = xfsfs_fsstat;

    fs->inode_walk = xfs_inode_walk;

    fs->block_walk = xfs_block_walk;
    fs->block_getflags = xfs_block_getflags;

    fs->file_add_meta = xfs_inode_lookup;
    fs->istat = xfs_istat;

    fs->close = xfsfs_close;

    return fs;
}
