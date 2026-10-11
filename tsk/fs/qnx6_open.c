/* Experimental QNX6 TSK entry point.
 * Explicit -f qnx6 only. Inode/dir operations intentionally report
 * unsupported until the full TSK_FS_INFO callbacks are implemented.
 */
#include "tsk_fs_i.h"
#include "qnx6_probe.h"
#include "qnx6_inode.h"
#include "qnx6_bitmap.h"
#include <limits.h>
#include <stdint.h>

typedef struct {
    TSK_IMG_INFO *image;
    TSK_OFF_T fs_offset;
    TSK_QNX6_PROBE_INFO probe;
} QNX6_READ_CONTEXT;

static int qnx6_read_block(void *opaque, uint64_t block,
                           uint8_t *dst, size_t length) {
    QNX6_READ_CONTEXT *ctx=(QNX6_READ_CONTEXT *)opaque;
    uint64_t image_offset;
    if (!ctx || !dst || length!=ctx->probe.block_size ||
        block > UINT64_MAX / length) return 0;
    image_offset=block*length;
    if ((uint64_t)ctx->fs_offset > UINT64_MAX-image_offset) return 0;
    image_offset+=(uint64_t)ctx->fs_offset;
    if (image_offset>(uint64_t)INT64_MAX ||
        image_offset>(uint64_t)ctx->image->size ||
        length>(uint64_t)ctx->image->size-image_offset) return 0;
    return tsk_img_read(ctx->image,(TSK_OFF_T)image_offset,
                        (char *)dst,length)==(ssize_t)length;
}

typedef struct {
    TSK_FS_INFO fs;
    QNX6_READ_CONTEXT io;
    TSK_QNX6_ROOT inode_tree;
    TSK_QNX6_ROOT bitmap_tree;
    int free_bit;
    uint64_t data_base;
} QNX6_FS_INFO;

static uint8_t qnx6_file_add_meta(TSK_FS_INFO *fs, TSK_FS_FILE *file,
                                   TSK_INUM_T addr) {
    QNX6_FS_INFO *qfs=(QNX6_FS_INFO *)fs;
    TSK_QNX6_INODE inode;
    TSK_FS_META *meta;
    uint16_t kind;
    if (!file || addr<1 || addr>fs->last_inum ||
        !tsk_qnx6_read_inode(&qfs->io.probe,&qfs->inode_tree,(uint32_t)addr,
                            qnx6_read_block,&qfs->io,&inode)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_INODE_NUM);
        tsk_error_set_errstr("qnx6_file_add_meta: invalid or unreadable inode");
        return 1;
    }
    if (!file->meta) {
        file->meta=tsk_fs_meta_alloc(0);
        if (!file->meta) return 1;
    }
    meta=file->meta;
    tsk_fs_meta_reset(meta);
    kind=inode.mode & 0170000;
    switch(kind) {
    case 0040000: meta->type=TSK_FS_META_TYPE_DIR; break;
    case 0100000: meta->type=TSK_FS_META_TYPE_REG; break;
    case 0120000: meta->type=TSK_FS_META_TYPE_LNK; break;
    default: meta->type=TSK_FS_META_TYPE_UNDEF; break;
    }
    meta->addr=addr;
    meta->flags=(TSK_FS_META_FLAG_ENUM)(TSK_FS_META_FLAG_ALLOC|TSK_FS_META_FLAG_USED);
    meta->mode=(TSK_FS_META_MODE_ENUM)(inode.mode & 07777);
    meta->size=(TSK_OFF_T)inode.size;
    meta->mtime=(time_t)inode.mtime;
    meta->nlink=1;
    return 0;
}

typedef struct {
    TSK_FS_DIR *dir;
    TSK_FS_INFO *fs;
} QNX6_DIRENT_CONTEXT;

static int qnx6_add_dirent(void *opaque, uint32_t inum,
                           const char *name, size_t length) {
    QNX6_DIRENT_CONTEXT *ctx=(QNX6_DIRENT_CONTEXT *)opaque;
    TSK_FS_NAME *entry;
    int result;
    if (!ctx || !name || !length || length>27) return 0;
    entry=tsk_fs_name_alloc(length+1,0);
    if (!entry) return 0;
    memcpy(entry->name,name,length);
    entry->name[length]=0;
    entry->meta_addr=inum;
    entry->flags=TSK_FS_NAME_FLAG_ALLOC;
    entry->type=TSK_FS_NAME_TYPE_UNDEF;
    result=tsk_fs_dir_add(ctx->dir,entry);
    tsk_fs_name_free(entry);
    return result==0;
}

static TSK_RETVAL_ENUM qnx6_dir_open_meta(TSK_FS_INFO *fs,
                    TSK_FS_DIR **out, TSK_INUM_T inum, int depth) {
    QNX6_FS_INFO *qfs=(QNX6_FS_INFO *)fs;
    TSK_QNX6_INODE inode;
    QNX6_DIRENT_CONTEXT ctx;
    TSK_FS_DIR *dir;
    (void)depth;
    if (!fs || !out || inum<fs->first_inum || inum>fs->last_inum ||
        !tsk_qnx6_read_inode(&qfs->io.probe,&qfs->inode_tree,(uint32_t)inum,
                            qnx6_read_block,&qfs->io,&inode) ||
        (inode.mode & 0170000)!=0040000) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_INODE_NUM);
        tsk_error_set_errstr("qnx6_dir_open_meta: invalid directory inode");
        return TSK_ERR;
    }
    dir=tsk_fs_dir_alloc(fs,inum,16);
    if (!dir) return TSK_ERR;
    ctx.dir=dir;
    ctx.fs=fs;
    if (!tsk_qnx6_walk_directory(&qfs->io.probe,&inode,qnx6_read_block,
                                 &qfs->io,qnx6_add_dirent,&ctx)) {
        tsk_fs_dir_close(dir);
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_READ);
        tsk_error_set_errstr("qnx6_dir_open_meta: unreadable directory");
        return TSK_ERR;
    }
    *out=dir;
    return TSK_OK;
}

static uint8_t qnx6_inode_walk(TSK_FS_INFO *fs, TSK_INUM_T start,
                               TSK_INUM_T end, TSK_FS_META_FLAG_ENUM flags,
                               TSK_FS_META_WALK_CB callback, void *opaque) {
    TSK_INUM_T inum;
    TSK_FS_FILE *file;
    if (!fs || !callback || start < fs->first_inum ||
        end > fs->last_inum || start > end) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("qnx6_inode_walk: invalid inode range");
        return 1;
    }
    file = tsk_fs_file_alloc(fs);
    if (!file) return 1;
    for (inum = start; ; ++inum) {
        TSK_WALK_RET_ENUM result;
        if (qnx6_file_add_meta(fs, file, inum)) {
            tsk_error_reset();
        } else if (file->meta && file->meta->type != TSK_FS_META_TYPE_UNDEF &&
                   (!(flags & TSK_FS_META_FLAG_UNALLOC) ||
                    (flags & TSK_FS_META_FLAG_ALLOC))) {
            result = callback(file, opaque);
            if (result == TSK_WALK_STOP) break;
            if (result == TSK_WALK_ERROR) {
                tsk_fs_file_close(file);
                return 1;
            }
        }
        if (inum == end) break;
    }
    tsk_fs_file_close(file);
    return 0;
}

static uint8_t qnx6_load_attrs(TSK_FS_FILE *file) {
    TSK_FS_META *meta;
    QNX6_FS_INFO *qfs;
    TSK_QNX6_INODE inode;
    TSK_FS_ATTR *attr;
    TSK_FS_ATTR_RUN *first=NULL, *last=NULL, *run;
    uint64_t logical, blocks, physical;
    if (!file || !file->fs_info || !file->meta) return 1;
    meta=file->meta;
    qfs=(QNX6_FS_INFO *)file->fs_info;
    if (meta->attr_state==TSK_FS_META_ATTR_STUDIED) return 0;
    if (!tsk_qnx6_read_inode(&qfs->io.probe,&qfs->inode_tree,
                            (uint32_t)meta->addr,qnx6_read_block,&qfs->io,&inode))
        goto error;
    if (!meta->attr) {
        meta->attr=tsk_fs_attrlist_alloc();
        if (!meta->attr) goto error;
    }
    attr=tsk_fs_attrlist_getnew(meta->attr,TSK_FS_ATTR_NONRES);
    if (!attr) goto error;
    blocks=inode.size/qfs->io.probe.block_size+
           (inode.size%qfs->io.probe.block_size!=0);
    if (blocks>qfs->io.probe.block_count) goto error;
    for (logical=0;logical<blocks;logical++) {
        if (!tsk_qnx6_map_block(&qfs->io.probe,&inode.data,logical,
                               qnx6_read_block,&qfs->io,&physical)) goto error;
        if (last && last->addr+last->len==physical) {
            last->len++;
            continue;
        }
        run=tsk_fs_attr_run_alloc();
        if (!run) goto error;
        run->offset=logical;
        run->addr=physical;
        run->len=1;
        if (last) last->next=run;
        else first=run;
        last=run;
    }
    if (tsk_fs_attr_set_run(file,attr,first,NULL,TSK_FS_ATTR_TYPE_DEFAULT,
                            TSK_FS_ATTR_ID_DEFAULT,(TSK_OFF_T)inode.size,
                            (TSK_OFF_T)inode.size,
                            (TSK_OFF_T)(blocks*qfs->io.probe.block_size),
                            TSK_FS_ATTR_FLAG_NONE,0)) goto error;
    meta->attr_state=TSK_FS_META_ATTR_STUDIED;
    return 0;
error:
    meta->attr_state=TSK_FS_META_ATTR_ERROR;
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_READ);
    tsk_error_set_errstr("qnx6_load_attrs: cannot map file data blocks");
    return 1;
}

/* Data-block addresses are physical filesystem-relative block numbers.
 * Bitmap indices are relative to the data region, not the boot area. */
static TSK_FS_BLOCK_FLAG_ENUM qnx6_block_getflags(TSK_FS_INFO *fs,
                                                    TSK_DADDR_T addr) {
    QNX6_FS_INFO *qfs=(QNX6_FS_INFO *)fs;
    int bit;
    if (!fs || addr<qfs->data_base ||
        (uint64_t)addr-qfs->data_base>=qfs->io.probe.block_count) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_BLK_NUM);
        tsk_error_set_errstr("qnx6_block_getflags: block outside QNX6 data region");
        return TSK_FS_BLOCK_FLAG_UNUSED;
    }
    if (qfs->free_bit<0 ||
        !tsk_qnx6_bitmap_raw_bit(&qfs->io.probe,&qfs->bitmap_tree,
                                  (uint64_t)addr-qfs->data_base,
                                  qnx6_read_block,&qfs->io,&bit)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_READ);
        tsk_error_set_errstr("qnx6_block_getflags: allocation bitmap unavailable");
        return TSK_FS_BLOCK_FLAG_UNUSED;
    }
    return (TSK_FS_BLOCK_FLAG_ENUM)(
        (bit==qfs->free_bit ? TSK_FS_BLOCK_FLAG_UNALLOC :
                              TSK_FS_BLOCK_FLAG_ALLOC) |
        TSK_FS_BLOCK_FLAG_CONT);
}

static uint8_t qnx6_block_walk(TSK_FS_INFO *fs, TSK_DADDR_T start,
                                TSK_DADDR_T end,
                                TSK_FS_BLOCK_WALK_FLAG_ENUM flags,
                                TSK_FS_BLOCK_WALK_CB callback, void *opaque) {
    QNX6_FS_INFO *qfs=(QNX6_FS_INFO *)fs;
    TSK_FS_BLOCK *block;
    TSK_DADDR_T addr;
    if (!fs || !callback || start<qfs->data_base ||
        end>fs->last_block || start>end || qfs->free_bit<0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("qnx6_block_walk: invalid range or unvalidated bitmap");
        return 1;
    }
    block=tsk_fs_block_alloc(fs);
    if (!block) return 1;
    for(addr=start;;addr++) {
        TSK_FS_BLOCK_FLAG_ENUM status=qnx6_block_getflags(fs,addr);
        TSK_WALK_RET_ENUM result;
        if (status==TSK_FS_BLOCK_FLAG_UNUSED) {
            tsk_fs_block_free(block);
            return 1;
        }
        if (((status & TSK_FS_BLOCK_FLAG_ALLOC) &&
             (flags & TSK_FS_BLOCK_WALK_FLAG_ALLOC)) ||
            ((status & TSK_FS_BLOCK_FLAG_UNALLOC) &&
             (flags & TSK_FS_BLOCK_WALK_FLAG_UNALLOC))) {
            if (flags & TSK_FS_BLOCK_WALK_FLAG_AONLY)
                status=(TSK_FS_BLOCK_FLAG_ENUM)(status|TSK_FS_BLOCK_FLAG_AONLY);
            if (!tsk_fs_block_get_flag(fs,block,addr,status)) {
                tsk_fs_block_free(block);
                return 1;
            }
            result=callback(block,opaque);
            if (result==TSK_WALK_ERROR) {
                tsk_fs_block_free(block);
                return 1;
            }
            if (result==TSK_WALK_STOP) break;
        }
        if (addr==end) break;
    }
    tsk_fs_block_free(block);
    return 0;
}

static uint8_t qnx6_fsstat(TSK_FS_INFO *fs, FILE *out) {
    if (!fs || !out) return 1;
    tsk_fprintf(out, "FILE SYSTEM INFORMATION\\n");
    tsk_fprintf(out, "--------------------------------------------\\n");
    tsk_fprintf(out, "File System Type: QNX6 (experimental)\\n");
    tsk_fprintf(out, "Root Inode: %llu\\n", (unsigned long long)fs->root_inum);
    tsk_fprintf(out, "Inode Count: %llu\\n", (unsigned long long)fs->inum_count);
    tsk_fprintf(out, "Block Size: %u\\n", fs->block_size);
    tsk_fprintf(out, "Block Count: %llu\\n", (unsigned long long)fs->block_count);
    tsk_fprintf(out, "NOTE: File and directory traversal not implemented in TSK.\\n");
    return 0;
}
TSK_FS_INFO *qnx6_open(TSK_IMG_INFO *img, TSK_OFF_T offset,
                       TSK_FS_TYPE_ENUM type, const char *password,
                       uint8_t test) {
    uint8_t sb[512];
    TSK_QNX6_PROBE_INFO probe;
    TSK_FS_INFO *fs;
    QNX6_FS_INFO *qfs;
    TSK_OFF_T sb_offset;
    TSK_QNX6_ROOT inode_tree;
    TSK_QNX6_ROOT bitmap_tree;
    TSK_QNX6_INODE root_inode;
    QNX6_READ_CONTEXT ctx;
    (void)password;
    (void)test;
    tsk_error_reset();
    if (!img || type != TSK_FS_TYPE_QNX6 || offset < 0 ||
        offset > img->size || img->size - offset < 0x2000 + (TSK_OFF_T)sizeof(sb)) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("qnx6_open: invalid image, type, or offset");
        return NULL;
    }
    sb_offset = offset + 0x2000;
    if (tsk_img_read(img, sb_offset, (char *)sb, sizeof(sb)) != (ssize_t)sizeof(sb) ||
        !tsk_qnx6_probe_superblock(sb, sizeof(sb), &probe)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_MAGIC);
        tsk_error_set_errstr("qnx6_open: no valid QNX6 superblock at 0x2000");
        return NULL;
    }
    /* Validate the inode tree and root directory before accepting the image.
     * This is still not a complete TSK inode/dir driver. */
    if (!tsk_qnx6_parse_root(sb,sizeof(sb),72,&inode_tree) ||
        !tsk_qnx6_parse_root(sb,sizeof(sb),152,&bitmap_tree)) {
        tsk_error_set_errno(TSK_ERR_FS_MAGIC);
        tsk_error_set_errstr("qnx6_open: invalid inode-tree root");
        return NULL;
    }
    ctx.image=img;
    ctx.fs_offset=offset;
    ctx.probe=probe;
    if (!tsk_qnx6_read_inode(&probe,&inode_tree,1,qnx6_read_block,&ctx,
                             &root_inode) ||
        (root_inode.mode & 0170000) != 0040000) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_MAGIC);
        tsk_error_set_errstr("qnx6_open: root inode is not a readable directory");
        return NULL;
    }
    fs = tsk_fs_malloc(sizeof(QNX6_FS_INFO));
    if (!fs) return NULL;
    qfs=(QNX6_FS_INFO *)fs;
    qfs->io=ctx;
    qfs->inode_tree=inode_tree;
    qfs->bitmap_tree=bitmap_tree;
    qfs->data_base=(0x2000U/probe.block_size)+(0x1000U/probe.block_size);
    qfs->free_bit=-1;
    if (!tsk_qnx6_bitmap_free_bit(&probe,&bitmap_tree,qnx6_read_block,
                                  &qfs->io,&qfs->free_bit)) qfs->free_bit=-1;
    fs->img_info = img;
    fs->offset = offset;
    fs->ftype = TSK_FS_TYPE_QNX6;
    fs->duname = "Block";
    fs->tag = TSK_FS_INFO_TAG;
    fs->block_size = probe.block_size;
    fs->block_count = probe.block_count + qfs->data_base;
    fs->first_block = 0;
    fs->last_block = fs->last_block_act = fs->block_count - 1;
    fs->dev_bsize = img->sector_size;
    fs->root_inum = 1;
    fs->first_inum = 1;
    fs->last_inum = probe.inode_count;
    fs->inum_count = probe.inode_count;
    fs->close = tsk_fs_nofs_close;
    fs->fsstat = qnx6_fsstat;
    fs->block_walk = qnx6_block_walk;
    fs->block_getflags = qnx6_block_getflags;
    fs->inode_walk = qnx6_inode_walk;
    fs->file_add_meta = qnx6_file_add_meta;
    fs->istat = tsk_fs_nofs_istat;
    fs->get_default_attr_type = tsk_fs_nofs_get_default_attr_type;
    fs->load_attrs = qnx6_load_attrs;
    fs->dir_open_meta = qnx6_dir_open_meta;
    fs->name_cmp = tsk_fs_nofs_name_cmp;
    fs->jblk_walk = tsk_fs_nofs_jblk_walk;
    fs->jentry_walk = tsk_fs_nofs_jentry_walk;
    fs->jopen = tsk_fs_nofs_jopen;
    return fs;
}
