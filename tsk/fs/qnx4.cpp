/* Native read-only TSK QNX4 adapter. Reader provenance: qnx4_reader.h. */
#include "tsk_fs_i.h"
#include "qnx4_reader.h"
#include <memory>
using namespace tsk_qnx4;
struct QNX4_INFO {TSK_FS_INFO fs; Reader *reader;};
static Reader &reader(TSK_FS_INFO *fs){return *reinterpret_cast<QNX4_INFO *>(fs)->reader;}
static uint8_t failure(const std::exception &e){tsk_error_reset();tsk_error_set_errno(TSK_ERR_FS_READ);tsk_error_set_errstr("qnx4: %s",e.what());return 1;}
static void close_fs(TSK_FS_INFO *fs){delete reinterpret_cast<QNX4_INFO *>(fs)->reader;fs->tag=0;tsk_fs_free(fs);}
static uint8_t meta(TSK_FS_INFO *fs,TSK_FS_FILE *file,TSK_INUM_T addr){
    try {
        Reader &r=reader(fs);
        if(!file||!r.live.count(addr))throw std::runtime_error("inode is not active filesystem metadata");
        Inode i=r.inode(addr);
        if(!file->meta)file->meta=tsk_fs_meta_alloc(0);
        if(!file->meta)return 1;
        TSK_FS_META *m=file->meta;tsk_fs_meta_reset(m);m->addr=addr;
        uint16_t kind=i.mode&0170000;
        switch(kind){
        case 0040000:m->type=TSK_FS_META_TYPE_DIR;break;
        case 0100000:m->type=TSK_FS_META_TYPE_REG;break;
        case 0120000:m->type=TSK_FS_META_TYPE_LNK;break;
        case 0020000:m->type=TSK_FS_META_TYPE_CHR;break;
        case 0060000:m->type=TSK_FS_META_TYPE_BLK;break;
        case 0010000:m->type=TSK_FS_META_TYPE_FIFO;break;
        default:m->type=TSK_FS_META_TYPE_UNDEF;break;
        }
        m->flags=TSK_FS_META_FLAG_ENUM(TSK_FS_META_FLAG_ALLOC|TSK_FS_META_FLAG_USED);
        m->mode=TSK_FS_META_MODE_ENUM(i.mode&07777);m->size=i.size;
        m->uid=uint32_t(le(i.raw,52,2));m->gid=uint32_t(le(i.raw,54,2));m->nlink=int(le(i.raw,56,2));
        m->atime=time_t(le(i.raw,40));m->ctime=time_t(le(i.raw,44));m->mtime=time_t(le(i.raw,36));
        // di_ftime's precise semantics are not established; do not guess crtime.
        if(m->type==TSK_FS_META_TYPE_LNK&&i.size<=4096){
            std::vector<uint8_t> target;uint64_t left=i.size;
            for(const auto &e:r.extents(i))for(uint64_t j=0;j<e.count&&left;j++){
                Bytes b=r.block(e.block+j);size_t take=size_t(left<512?left:512);
                target.insert(target.end(),b.begin(),b.begin()+take);left-=take;
            }
            free(m->link);m->link=(char *)tsk_malloc(target.size()+1);if(!m->link)return 1;
            memcpy(m->link,target.data(),target.size());m->link[target.size()]=0;
        }
        return 0;
    }catch(const std::exception &e){return failure(e);}
}
static uint8_t attrs(TSK_FS_FILE *file){
    TSK_FS_ATTR_RUN *first=nullptr,*last=nullptr;
    try {
        if(!file||!file->meta)throw std::runtime_error("missing metadata");
        TSK_FS_META *m=file->meta;if(m->attr_state==TSK_FS_META_ATTR_STUDIED)return 0;
        Reader &r=reader(file->fs_info);Inode i=r.inode(m->addr);
        if(!m->attr)m->attr=tsk_fs_attrlist_alloc();
        if(!m->attr)return 1;
        TSK_FS_ATTR *a=tsk_fs_attrlist_getnew(m->attr,TSK_FS_ATTR_NONRES);if(!a)return 1;
        uint64_t logical=0;
        for(const auto &e:r.extents(i)){
            auto *run=tsk_fs_attr_run_alloc();if(!run)throw std::runtime_error("run allocation failed");
            run->addr=e.block;run->offset=logical;run->len=e.count;logical+=e.count;
            if(last)last->next=run;else first=run;last=run;
        }
        if(tsk_fs_attr_set_run(file,a,first,nullptr,TSK_FS_ATTR_TYPE_DEFAULT,TSK_FS_ATTR_ID_DEFAULT,i.size,i.size,
                               TSK_OFF_T(logical*512),TSK_FS_ATTR_FLAG_NONE,0))throw std::runtime_error("attribute initialization failed");
        first=nullptr;m->attr_state=TSK_FS_META_ATTR_STUDIED;return 0;
    }catch(const std::exception &e){if(first)tsk_fs_attr_run_free(first);if(file&&file->meta)file->meta->attr_state=TSK_FS_META_ATTR_ERROR;return failure(e);}
}
static TSK_RETVAL_ENUM directory(TSK_FS_INFO *fs,TSK_FS_DIR **out,TSK_INUM_T addr,int depth){
    (void)depth;
    try {
        if(!out||!reader(fs).live.count(addr))throw std::runtime_error("invalid directory argument");
        auto entries=reader(fs).directory(reader(fs).inode(addr));
        if(*out)tsk_fs_dir_reset(*out);else *out=tsk_fs_dir_alloc(fs,addr,entries.size()+2);
        if(!*out)return TSK_ERR;
        (*out)->addr=addr;(*out)->fs_file=tsk_fs_file_open_meta(fs,nullptr,addr);if(!(*out)->fs_file)return TSK_ERR;
        for(const auto &e:entries){
            auto *name=tsk_fs_name_alloc(e.name.size()+1,0);if(!name)return TSK_ERR;
            memcpy(name->name,e.name.c_str(),e.name.size()+1);name->meta_addr=e.number;name->flags=TSK_FS_NAME_FLAG_ALLOC;
            uint16_t kind=reader(fs).inode(e.number).mode&0170000;
            name->type=kind==0040000?TSK_FS_NAME_TYPE_DIR:kind==0100000?TSK_FS_NAME_TYPE_REG:kind==0120000?TSK_FS_NAME_TYPE_LNK:TSK_FS_NAME_TYPE_UNDEF;
            int status=tsk_fs_dir_add(*out,name);tsk_fs_name_free(name);if(status)return TSK_ERR;
        }return TSK_OK;
    }catch(const std::exception &e){failure(e);return TSK_ERR;}
}
static uint8_t inode_walk(TSK_FS_INFO *fs,TSK_INUM_T start,TSK_INUM_T end,TSK_FS_META_FLAG_ENUM flags,TSK_FS_META_WALK_CB cb,void *ctx){
    if(!cb||start<fs->first_inum||end>fs->last_inum||start>end){tsk_error_set_errno(TSK_ERR_FS_ARG);return 1;}
    if(!(flags&TSK_FS_META_FLAG_ALLOC))return 0;
    TSK_FS_FILE *f=tsk_fs_file_alloc(fs);if(!f)return 1;
    const auto &live=reader(fs).live;
    for(auto it=live.lower_bound(start);it!=live.end()&&*it<=end;++it){
        TSK_INUM_T n=*it;
        if(meta(fs,f,n)){tsk_fs_file_close(f);return 1;}
        auto result=cb(f,ctx);if(result!=TSK_WALK_CONT){tsk_fs_file_close(f);return result==TSK_WALK_ERROR?1:0;}
    }tsk_fs_file_close(f);return 0;
}
static TSK_FS_BLOCK_FLAG_ENUM block_flags(TSK_FS_INFO *fs,TSK_DADDR_T a){
    try{return TSK_FS_BLOCK_FLAG_ENUM((reader(fs).allocated(a)?TSK_FS_BLOCK_FLAG_ALLOC:TSK_FS_BLOCK_FLAG_UNALLOC)|(reader(fs).is_metadata(a)?TSK_FS_BLOCK_FLAG_META:TSK_FS_BLOCK_FLAG_CONT));}
    catch(const std::exception &e){failure(e);return TSK_FS_BLOCK_FLAG_UNUSED;}
}
static uint8_t block_walk(TSK_FS_INFO *fs,TSK_DADDR_T start,TSK_DADDR_T end,TSK_FS_BLOCK_WALK_FLAG_ENUM flags,TSK_FS_BLOCK_WALK_CB cb,void *ctx){
    if(!cb||start>end||end>fs->last_block_act){tsk_error_set_errno(TSK_ERR_FS_ARG);return 1;}
    auto *b=tsk_fs_block_alloc(fs);if(!b)return 1;
    for(TSK_DADDR_T a=start;a<=end;a++){
        auto f=block_flags(fs,a);if(f==TSK_FS_BLOCK_FLAG_UNUSED){tsk_fs_block_free(b);return 1;}
        if((f&TSK_FS_BLOCK_FLAG_ALLOC)&&!(flags&TSK_FS_BLOCK_WALK_FLAG_ALLOC))continue;
        if((f&TSK_FS_BLOCK_FLAG_UNALLOC)&&!(flags&TSK_FS_BLOCK_WALK_FLAG_UNALLOC))continue;
        if((f&TSK_FS_BLOCK_FLAG_META)&&!(flags&TSK_FS_BLOCK_WALK_FLAG_META))continue;
        if((f&TSK_FS_BLOCK_FLAG_CONT)&&!(flags&TSK_FS_BLOCK_WALK_FLAG_CONT))continue;
        if(!tsk_fs_block_get_flag(fs,b,a,TSK_FS_BLOCK_FLAG_ENUM(f|((flags&TSK_FS_BLOCK_WALK_FLAG_AONLY)?TSK_FS_BLOCK_FLAG_AONLY:0)))){tsk_fs_block_free(b);return 1;}
        auto result=cb(b,ctx);if(result!=TSK_WALK_CONT){tsk_fs_block_free(b);return result==TSK_WALK_ERROR?1:0;}
    }tsk_fs_block_free(b);return 0;
}
static uint8_t istat(TSK_FS_INFO *fs,TSK_FS_ISTAT_FLAG_ENUM flags,FILE *out,
                     TSK_INUM_T addr,TSK_DADDR_T numblock,int32_t skew){
    (void)flags;(void)numblock;
    TSK_FS_FILE *file=tsk_fs_file_open_meta(fs,nullptr,addr);
    if(!file)return 1;
    TSK_FS_META *m=file->meta;
    tsk_fprintf(out,"Inode: %llu\nAllocated\nSize: %lld\nUID: %u\nGID: %u\nLinks: %d\nMode: %o\n",
                (unsigned long long)addr,(long long)m->size,(unsigned)m->uid,
                (unsigned)m->gid,m->nlink,(unsigned)m->mode);
    // Print numeric seconds/nanoseconds without timezone-dependent conversion.
    tsk_fprintf(out,"Access: %lld.%09u\nModified: %lld.%09u\nChanged: %lld.%09u\n",
                (long long)m->atime-skew,m->atime_nano,
                (long long)m->mtime-skew,m->mtime_nano,
                (long long)m->ctime-skew,m->ctime_nano);
    if(m->crtime)tsk_fprintf(out,"Created: %lld.%09u\n",(long long)m->crtime-skew,m->crtime_nano);
    tsk_fs_file_close(file);return 0;
}
static uint8_t fsstat(TSK_FS_INFO *fs,FILE *out){
    tsk_fprintf(out,"FILE SYSTEM INFORMATION\nFile System Type: QNX4\nBlock Size: %u\nBlock Count: %llu\nRoot Inode: %llu\n",fs->block_size,(unsigned long long)fs->block_count,(unsigned long long)fs->root_inum);return 0;
}
extern "C" TSK_FS_INFO *qnx4_open(TSK_IMG_INFO *img,TSK_OFF_T offset,TSK_FS_TYPE_ENUM type,const char *password,uint8_t test){
    (void)password;(void)test;
    try {
        if(!img||offset<0||offset>img->size||type!=TSK_FS_TYPE_QNX4)throw std::runtime_error("invalid image or offset");
        auto io=[=](uint64_t pos,size_t len)->Bytes {
            uint64_t size=uint64_t(img->size-offset);if(pos>size||len>size-pos)return {};
            Bytes b(len);if(tsk_img_read(img,offset+TSK_OFF_T(pos),reinterpret_cast<char *>(b.data()),len)!=ssize_t(len))return {};return b;
        };
        std::unique_ptr<Reader> r(new Reader(io,uint64_t(img->size-offset)));
        auto *info=reinterpret_cast<QNX4_INFO *>(tsk_fs_malloc(sizeof(QNX4_INFO)));if(!info)return nullptr;
        info->reader=r.release();auto *fs=&info->fs;Reader &v=*info->reader;
        fs->img_info=img;fs->offset=offset;fs->ftype=TSK_FS_TYPE_QNX4;fs->duname="Block";fs->tag=TSK_FS_INFO_TAG;
        fs->endian=TSK_LIT_ENDIAN;fs->block_size=512;fs->dev_bsize=img->sector_size;fs->block_count=v.blocks;
        fs->first_block=0;fs->last_block=v.blocks-1;fs->last_block_act=v.readable_blocks()-1;
        fs->root_inum=v.root;fs->first_inum=v.root;fs->last_inum=v.blocks*8-1;fs->inum_count=v.blocks*8-v.root;
        fs->close=close_fs;fs->fsstat=fsstat;fs->file_add_meta=meta;fs->load_attrs=attrs;fs->dir_open_meta=directory;
        fs->inode_walk=inode_walk;fs->block_walk=block_walk;fs->block_getflags=block_flags;
        fs->istat=istat;fs->get_default_attr_type=tsk_fs_nofs_get_default_attr_type;fs->name_cmp=tsk_fs_nofs_name_cmp;
        fs->jblk_walk=tsk_fs_nofs_jblk_walk;fs->jentry_walk=tsk_fs_nofs_jentry_walk;fs->jopen=tsk_fs_nofs_jopen;
        tsk_error_reset();return fs;
    }catch(const std::exception &e){failure(e);tsk_error_set_errno(TSK_ERR_FS_MAGIC);return nullptr;}
}
