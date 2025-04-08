/*
** The Sleuth Kit
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2003-2011 Brian Carrier.  All rights reserved
**
** ICS Laboratory [515lab.ics <at> gmail [dot] com]
** Copyright (c) 2019 ICS Laboratory.  All rights reserved.
**
** This software is distributed under the Common Public License 1.0
*/

#include "tsk_fs_i.h"
#include "tsk_xfs.h"

/*
 * Inode numbers in short-form directories can come in two versions,
 * either 4 bytes or 8 bytes wide.  These helpers deal with the
 * two forms transparently by looking at the headers i8count field.
 *
 * For 64-bit inode number the most significant byte must be zero.
 */
static xfs_ino_t
xfs_dir2_sf_get_ino(
    struct xfs_dir2_sf_hdr  *hdr,
    uint8_t         *from)
{
    if (hdr->i8count)
        return get_unaligned_be64(from) & 0x00ffffffffffffffULL;
    else
        return get_unaligned_be32(from);
}

static xfs_ino_t
xfs_dir3_sfe_get_ino(
    struct xfs_dir2_sf_hdr  *hdr,
    struct xfs_dir2_sf_entry *sfep)
{
    return xfs_dir2_sf_get_ino(hdr, &sfep->name[sfep->namelen + 1]);
}

static uint8_t
xfs_dir3_sfe_get_ftype(
	struct xfs_dir2_sf_entry *sfep)
{
    uint8_t	ftype;
	ftype = sfep->name[sfep->namelen];
	if (ftype >= XFS_DIR3_FT_MAX)
		return XFS_DIR3_FT_UNKNOWN;
	return ftype;
}

static uint8_t
xfs_dir3_blockentry_get_ftype(
    struct xfs_dir2_data_entry *daen) // inumber namelen name ftype tag
{
    uint8_t ftype;
    ftype = daen->name[daen->namelen];
    if (ftype >= XFS_DIR3_FT_MAX)
        return XFS_DIR3_FT_UNKNOWN;
    return ftype;
}

static uint8_t
xfs_dent_copy(XFS_INFO * xfs,
    char *xfs_dent, TSK_FS_NAME *fs_name, TSK_FS_FILE *fs_file)
{
    if (fs_file->meta->content_type == 
        TSK_FS_META_CONTENT_TYPE_XFS_DATA_FORK_SHORTFORM)
    {
        xfs_dir2_sf_t *dir2_sf = (xfs_dir2_sf_t*)xfs_dent;
        xfs_dir2_sf_hdr_t *hdr = (xfs_dir2_sf_hdr_t*)dir2_sf->hdr;
        xfs_dir2_sf_entry_t *ent = (xfs_dir2_sf_entry_t*)dir2_sf->entry;

        strncpy(fs_name->name, (char*)ent->name, ent->namelen);
        fs_name->name[ent->namelen] = '\0';
        fs_name->type = TSK_FS_NAME_TYPE_UNDEF;
        fs_name->meta_addr = (TSK_INUM_T)xfs_dir3_sfe_get_ino(hdr, ent);

        if (ent->namelen >= fs_name->name_size){
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_ARG);
            tsk_error_set_errstr
                ("xfs_dent_copy: Name Space too Small %d %" PRIuSIZE "",
               ent->namelen, fs_name->name_size);
            return 1;
        }

        switch (xfs_dir3_sfe_get_ftype(ent)) {
            case XFS_DE_REG:
                fs_name->type = TSK_FS_NAME_TYPE_REG;
                break;
            case XFS_DE_DIR:
                fs_name->type = TSK_FS_NAME_TYPE_DIR;
                break;
            case XFS_DE_CHR:
                fs_name->type = TSK_FS_NAME_TYPE_CHR;
                break;
            case XFS_DE_BLK:
                fs_name->type = TSK_FS_NAME_TYPE_BLK;
                break;
            case XFS_DE_FIFO:
                fs_name->type = TSK_FS_NAME_TYPE_FIFO;
                break;
            case XFS_DE_SOCK:
                fs_name->type = TSK_FS_NAME_TYPE_SOCK;
                break;
            case XFS_DE_LNK:
                fs_name->type = TSK_FS_NAME_TYPE_LNK;
                break;
            case XFS_DE_UNKNOWN:
            default:
                fs_name->type = TSK_FS_NAME_TYPE_UNDEF;
                break;
        }
    }
    else if (fs_file->meta->content_type ==
        TSK_FS_META_CONTENT_TYPE_XFS_DATA_FORK_EXTENTS)
    {
        xfs_dir2_data_entry_t *ent = (xfs_dir2_data_entry_t*)xfs_dent;

        strncpy(fs_name->name, (char*)ent->name, ent->namelen);
        fs_name->name[ent->namelen] = '\0';
        fs_name->meta_addr = tsk_getu64(xfs->fs_info.endian, ent->inumber);
        fs_name->type = TSK_FS_NAME_TYPE_UNDEF;

        if (ent->namelen >= fs_name->name_size){
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_ARG);
            tsk_error_set_errstr
                ("xfs_dent_copy: Name Space too Small %d %" PRIuSIZE "",
               ent->namelen, fs_name->name_size);
            return 1;
        }

        switch (xfs_dir3_blockentry_get_ftype(ent)) {
            case XFS_DE_REG:
                fs_name->type = TSK_FS_NAME_TYPE_REG;
                break;
            case XFS_DE_DIR:
                fs_name->type = TSK_FS_NAME_TYPE_DIR;
                break;
            case XFS_DE_CHR:
                fs_name->type = TSK_FS_NAME_TYPE_CHR;
                break;
            case XFS_DE_BLK:
                fs_name->type = TSK_FS_NAME_TYPE_BLK;
                break;
            case XFS_DE_FIFO:
                fs_name->type = TSK_FS_NAME_TYPE_FIFO;
                break;
            case XFS_DE_SOCK:
                fs_name->type = TSK_FS_NAME_TYPE_SOCK;
                break;
            case XFS_DE_LNK:
                fs_name->type = TSK_FS_NAME_TYPE_LNK;
                break;
            case XFS_DE_UNKNOWN:
            default:
                fs_name->type = TSK_FS_NAME_TYPE_UNDEF;
                break;
        }
    }
    else fprintf(stderr, "[i] xfs_dent_copy: xfs.cpp: %d - unsupported metadata type detected\n", __LINE__);

    fs_name->flags = TSK_FS_NAME_FLAG_ALLOC;

    return 0;
}

/*
 * Shortform directory ops
 */
static int
xfs_dir2_sf_entsize(
	struct xfs_dir2_sf_hdr	*hdr,
	int			len)
{
	int count = sizeof(struct xfs_dir2_sf_entry);	/* namelen + offset */

	count += len;					/* name */
	count += hdr->i8count ? XFS_INO64_SIZE : XFS_INO32_SIZE; /* ino # */
	return count;
}

static int
xfs_dir3_sf_entsize(
	struct xfs_dir2_sf_hdr	*hdr,
	int			len)
{
	return xfs_dir2_sf_entsize(hdr, len) + sizeof(uint8_t);
}

static struct xfs_dir2_sf_entry *
xfs_dir3_sf_nextentry(
	struct xfs_dir2_sf_hdr	*hdr,
	struct xfs_dir2_sf_entry *sfep)
{
	return (struct xfs_dir2_sf_entry *)
		((char *)sfep + xfs_dir3_sf_entsize(hdr, sfep->namelen));
}

static TSK_RETVAL_ENUM
xfs_dent_parse_shortform(XFS_INFO * xfs, TSK_FS_DIR * a_fs_dir, char *buf)
{
    TSK_FS_INFO *fs = &(xfs->fs_info);
    
    TSK_FS_NAME *fs_name;
    TSK_FS_FILE *fs_file = a_fs_dir->fs_file;
    xfs_dir2_sf_hdr_t *hdr;
    xfs_dir2_sf_entry_t *ent; 
    
    xfs_dir2_sf_t * dir2_sf = (xfs_dir2_sf_t *)tsk_malloc(sizeof(xfs_dir2_sf_t));
    hdr = (xfs_dir2_sf_hdr_t*)buf;
    dir2_sf->hdr = hdr;

    if ((fs_name = tsk_fs_name_alloc(XFS_MAXNAMELEN + 1, 0)) == NULL)
        return TSK_ERR;

    ent = (xfs_dir2_sf_entry_t*)((char*)(hdr + 1) - (hdr->i8count == 0) * 4); // code of miracle
    
    while (1)
    {
        uint8_t namelen;
        uint64_t inode;
        
        dir2_sf->entry = ent;
        namelen = ent->namelen;
        inode = xfs_dir2_sf_get_ino(hdr, (uint8_t*)ent);
        
        if (inode > fs->last_inum || namelen == 0) {
            break;
        }

        if (xfs_dent_copy(xfs, (char*)dir2_sf, fs_name, fs_file)) {
            tsk_fs_name_free(fs_name);
            return TSK_ERR;
        }

        fs_name->flags = TSK_FS_NAME_FLAG_ALLOC;

        if (tsk_fs_dir_add(a_fs_dir, fs_name)) {
            tsk_fs_name_free(fs_name);
            return TSK_ERR;
        }

        ent = xfs_dir3_sf_nextentry(hdr, ent);
    }
    free(dir2_sf);
    tsk_fs_name_free(fs_name);
    return TSK_OK;
}

/*
 * @param a_is_del Set to 1 if block is from a deleted directory
 * a_fs_dir = 채워야 할 것, 나머지는 채워져 있는 것
 * parse_block = 최종목표: a_fs_dir 채우기
 * inode format = local -> shortform
 *              = block -> block
 *                      or leaf
 */
static TSK_RETVAL_ENUM
xfs_dent_parse_block(XFS_INFO * xfs, TSK_FS_DIR * a_fs_dir, [[maybe_unused]]uint8_t a_is_del, [[maybe_unused]]TSK_LIST ** list_seen, char *buf,[[maybe_unused]] TSK_OFF_T offset)
{
    TSK_FS_NAME *fs_name;

    if ((fs_name = tsk_fs_name_alloc(XFS_MAXNAMELEN + 1, 0)) == NULL)
        return TSK_ERR;

    xfs_bmbt_rec_t *rec;
    xfs_bmbt_irec_t *irec;

    rec = (xfs_bmbt_rec_t*)buf;
    irec = (xfs_bmbt_irec_t*)tsk_malloc(sizeof(xfs_bmbt_irec_t));

    xfs_bmbt_disk_get_all(xfs, rec, irec);

    ssize_t len = irec->br_blockcount * tsk_getu32(xfs->fs_info.endian, xfs->fs->sb_blocksize);

    char *fbuf = (char*)tsk_malloc(sizeof(char) * len);

    struct xfs_dir3_data_hdr *hdr = (struct xfs_dir3_data_hdr*)fbuf;

    // sanity check
    if (hdr->hdr.magic != 0x33424458) { // XDB3
        // Trick to explore unalloc dent
        a_fs_dir->fs_file->meta->content_type = TSK_FS_META_CONTENT_TYPE_XFS_DATA_FORK_SHORTFORM;
        if (xfs_dent_parse_shortform(xfs, a_fs_dir, buf) == TSK_OK){
            return TSK_OK;
        }else{
            fprintf(stderr, "[i] xfs_dent_parse_block: xfs_dent.cpp: %d - not a dir2_data_hdr: %8x\n",
            __LINE__, hdr->hdr.magic);            
            return TSK_ERR;
        }
    }

    xfs_dir2_data_entry_t *ent = (xfs_dir2_data_entry_t*)((char*)(hdr + 1) + 32); // magically should be happened

    while (true)
    {
        if (ent->namelen == 0)
            break;
  
        if (xfs_dent_copy(xfs, (char*)ent, fs_name, a_fs_dir->fs_file)) {
            tsk_fs_name_free(fs_name);
            return TSK_ERR;
        }

        fs_name->flags = TSK_FS_NAME_FLAG_ALLOC;

        if (tsk_fs_dir_add(a_fs_dir, fs_name)) {
            tsk_fs_name_free(fs_name);
            return TSK_ERR;
        }

        ent = xfs_dir2_data_nextentry(ent);
    }

    return TSK_OK;
}

static TSK_RETVAL_ENUM
xfs_dent_parse(XFS_INFO * xfs, TSK_FS_DIR * a_fs_dir, uint8_t a_is_del, TSK_LIST ** list_seen, char *buf, TSK_OFF_T offset)
{
    switch(a_fs_dir->fs_file->meta->content_type){
        case TSK_FS_META_CONTENT_TYPE_XFS_DATA_FORK_SHORTFORM:
            xfs_dent_parse_shortform(xfs, a_fs_dir, buf);
            break;

        case TSK_FS_META_CONTENT_TYPE_XFS_DATA_FORK_EXTENTS:
            xfs_dent_parse_block(xfs, a_fs_dir, a_is_del, list_seen, buf, offset);
            break;
        default:
            return TSK_ERR;
    }
    return TSK_OK;
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
    TSK_INUM_T a_addr,[[maybe_unused]] int recursion_depth)
{
    XFS_INFO * xfs = (XFS_INFO *) a_fs;
    TSK_FS_DIR * fs_dir;
    TSK_LIST *list_seen = NULL;

    char *dirbuf;
    
    TSK_RETVAL_ENUM retval_tmp;
    TSK_RETVAL_ENUM retval_final = TSK_OK;

    if (a_addr < a_fs->first_inum || a_addr > a_fs->last_inum) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("xfs_dir_open_meta: inode value: %" PRIuINUM
            "\n", a_addr);
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
        if((*a_fs_dir = fs_dir =
                tsk_fs_dir_alloc(a_fs, a_addr, 128)) == NULL) {
            return TSK_ERR;
        }
    }

    if ((fs_dir->fs_file =
        tsk_fs_file_open_meta(a_fs, NULL, a_addr)) == NULL) { // inode_lookup -> content_ptr 채움
        fprintf(stderr, "xfs_fs_dir_open_meta: failed to obtain fs_file meta info\n");
        tsk_error_errstr2_concat("- xfs_dir_open_meta");
        return TSK_COR;
    }

    // We only read in and process a single block at a time
    if ((dirbuf = (char*)tsk_malloc((size_t)a_fs->block_size)) == NULL) {
        fprintf(stderr, "[i] xfs_load_attr_block: xfs.cpp: %d - failed to malloc\n", __LINE__);
        return TSK_ERR;
    }

    memcpy(dirbuf, fs_dir->fs_file->meta->content_ptr, XFS_CONTENT_LEN_V5(xfs));

    retval_tmp =
        xfs_dent_parse(xfs, fs_dir, (fs_dir->fs_file->meta->
            flags & TSK_FS_META_FLAG_UNALLOC) ? 1 : 0, &list_seen,
        dirbuf, XFS_CONTENT_LEN_V5(xfs));
 
    if (retval_tmp == TSK_ERR)
        retval_final = TSK_ERR;
    else if (retval_tmp == TSK_COR)
        retval_final = TSK_COR;

    free(dirbuf);

    return retval_final;
}

uint8_t xfs_jentry_walk([[maybe_unused]]TSK_FS_INFO *info, [[maybe_unused]]int a,
        [[maybe_unused]]TSK_FS_JENTRY_WALK_CB c, [[maybe_unused]]void *b)
{
    return -1;
}

uint8_t xfs_jblk_walk([[maybe_unused]]TSK_FS_INFO *a, [[maybe_unused]]TSK_DADDR_T b,
        [[maybe_unused]]TSK_DADDR_T c, [[maybe_unused]]int d, [[maybe_unused]]TSK_FS_JBLK_WALK_CB e, [[maybe_unused]]void *f)
{
    return -1;
}

uint8_t xfs_jopen([[maybe_unused]]TSK_FS_INFO *a, [[maybe_unused]]TSK_INUM_T b)
{
    return -1;
}