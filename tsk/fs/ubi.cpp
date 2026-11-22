/* Native read-only TSK UBI adapter. Reader provenance: ubi_reader.h. */
#include "tsk_fs_i.h"
#include "ubi_reader.h"
#include <memory>
using namespace tsk_ubi;
struct UBI_INFO {TSK_FS_INFO fs; Reader *reader;};
static Reader &reader(TSK_FS_INFO *fs){return *reinterpret_cast<UBI_INFO *>(fs)->reader;}
static uint8_t failure(const std::exception &e){tsk_error_reset();tsk_error_set_errno(TSK_ERR_FS_READ);tsk_error_set_errstr("ubi: %s",e.what());return 1;}
static void close_fs(TSK_FS_INFO *fs){delete reinterpret_cast<UBI_INFO *>(fs)->reader;fs->tag=0;tsk_fs_free(fs);}
static uint8_t meta(TSK_FS_INFO *fs,TSK_FS_FILE *file,TSK_INUM_T addr){
    try{
        const Node &n=reader(fs).node(addr);
        if(!file->meta)file->meta=tsk_fs_meta_alloc(0);
        if(!file->meta)return 1;
        auto *m=file->meta;tsk_fs_meta_reset(m);m->addr=addr;
        switch(n.mode&0170000){
        case 0040000:m->type=TSK_FS_META_TYPE_DIR;break;
        case 0100000:m->type=TSK_FS_META_TYPE_REG;break;
        case 0120000:m->type=TSK_FS_META_TYPE_LNK;break;
        case 0010000:m->type=TSK_FS_META_TYPE_FIFO;break;
        case 0020000:m->type=TSK_FS_META_TYPE_CHR;break;
        case 0060000:m->type=TSK_FS_META_TYPE_BLK;break;
        default:m->type=TSK_FS_META_TYPE_UNDEF;break;
        }
        m->flags=TSK_FS_META_FLAG_ENUM(TSK_FS_META_FLAG_ALLOC|TSK_FS_META_FLAG_USED);
        m->mode=TSK_FS_META_MODE_ENUM(n.mode&07777);m->size=TSK_OFF_T(n.size);
        m->uid=n.uid;m->gid=n.gid;m->nlink=n.nlink;m->mtime=time_t(n.mtime);m->ctime=time_t(n.ctime);m->atime=time_t(n.atime);m->mtime_nano=n.mtime_nano;m->ctime_nano=n.ctime_nano;m->atime_nano=n.atime_nano;
        if(m->type==TSK_FS_META_TYPE_LNK&&n.size<=4096){
            Bytes data=reader(fs).content(n,0,size_t(n.size));
            free(m->link);m->link=(char *)tsk_malloc(data.size()+1);if(!m->link)return 1;
            if(!data.empty())memcpy(m->link,data.data(),data.size());
            m->link[data.size()]=0;
        }return 0;
    }catch(const std::exception &e){return failure(e);}
}
// Byte-addressed physical runs are exact; these callbacks read/walk them in
// batches rather than issuing one image read and callback per flash byte.
static ssize_t read_attr(const TSK_FS_ATTR *a,TSK_OFF_T off,char *buf,size_t len){
    try{if(off<0||(!buf&&len))throw std::runtime_error("invalid read");Reader&r=reader(a->fs_file->fs_info);Bytes b=r.content(r.node(a->fs_file->meta->addr),uint64_t(off),len);if(!b.empty())memcpy(buf,b.data(),b.size());return ssize_t(b.size());}catch(const std::exception&e){failure(e);return -1;}
}
static uint8_t walk_attr(const TSK_FS_ATTR *a,int flags,TSK_FS_FILE_WALK_CB cb,void *ctx){
    try{Reader&r=reader(a->fs_file->fs_info);const Node&n=r.node(a->fs_file->meta->addr);
        if(flags&TSK_FS_FILE_WALK_FLAG_AONLY)throw std::runtime_error("logical content has no contiguous physical block mapping; use UBI volume map");
        for(uint64_t off=0;off<n.size;){Bytes b=r.content(n,off,size_t(std::min<uint64_t>(65536,n.size-off)));auto result=cb(a->fs_file,TSK_OFF_T(off),0,reinterpret_cast<char*>(b.data()),b.size(),TSK_FS_BLOCK_FLAG_ENUM(TSK_FS_BLOCK_FLAG_ALLOC|TSK_FS_BLOCK_FLAG_CONT|TSK_FS_BLOCK_FLAG_COMP),ctx);if(result!=TSK_WALK_CONT)return result==TSK_WALK_ERROR?1:0;off+=b.size();}return 0;
    }catch(const std::exception&e){return failure(e);}
}
static uint8_t attrs(TSK_FS_FILE *file){
    try{if(!file||!file->meta)throw std::runtime_error("missing metadata");auto*m=file->meta;if(m->attr_state==TSK_FS_META_ATTR_STUDIED)return 0;const Node&n=reader(file->fs_info).node(m->addr);
        if(!m->attr)m->attr=tsk_fs_attrlist_alloc();if(!m->attr)return 1;auto*a=tsk_fs_attrlist_getnew(m->attr,TSK_FS_ATTR_NONRES);if(!a)return 1;
        if(tsk_fs_attr_set_run(file,a,nullptr,nullptr,TSK_FS_ATTR_TYPE_DEFAULT,TSK_FS_ATTR_ID_DEFAULT,TSK_OFF_T(n.size),TSK_OFF_T(n.size),TSK_OFF_T(n.size),TSK_FS_ATTR_COMP,0))throw std::runtime_error("attribute initialization failed");a->r=read_attr;a->w=walk_attr;m->attr_state=TSK_FS_META_ATTR_STUDIED;return 0;
    }catch(const std::exception&e){if(file&&file->meta)file->meta->attr_state=TSK_FS_META_ATTR_ERROR;return failure(e);}
}
static TSK_RETVAL_ENUM directory(TSK_FS_INFO *fs,TSK_FS_DIR **out,TSK_INUM_T addr,int depth){
    (void)depth;
    try{
        const Node &n=reader(fs).node(addr);if(!out||(n.mode&0170000)!=0040000)throw std::runtime_error("not a directory");
        if(*out)tsk_fs_dir_reset(*out);else *out=tsk_fs_dir_alloc(fs,addr,n.children.size()+2);if(!*out)return TSK_ERR;
        (*out)->addr=addr;(*out)->fs_file=tsk_fs_file_open_meta(fs,nullptr,addr);if(!(*out)->fs_file)return TSK_ERR;
        for(const auto &e:n.children){auto *name=tsk_fs_name_alloc(e.name.size()+1,0);if(!name)return TSK_ERR;
            memcpy(name->name,e.name.c_str(),e.name.size()+1);name->meta_addr=e.number;name->flags=TSK_FS_NAME_FLAG_ALLOC;
            auto kind=reader(fs).node(e.number).mode&0170000;
            name->type=kind==0040000?TSK_FS_NAME_TYPE_DIR:kind==0100000?TSK_FS_NAME_TYPE_REG:kind==0120000?TSK_FS_NAME_TYPE_LNK:kind==0010000?TSK_FS_NAME_TYPE_FIFO:TSK_FS_NAME_TYPE_UNDEF;
            int status=tsk_fs_dir_add(*out,name);tsk_fs_name_free(name);if(status)return TSK_ERR;
        }return TSK_OK;
    }catch(const std::exception &e){failure(e);return TSK_ERR;}
}
static uint8_t inode_walk(TSK_FS_INFO *fs,TSK_INUM_T start,TSK_INUM_T end,TSK_FS_META_FLAG_ENUM flags,TSK_FS_META_WALK_CB cb,void *ctx){
    if(!cb||start<1||end>fs->last_inum||start>end){tsk_error_set_errno(TSK_ERR_FS_ARG);return 1;}
    if(!(flags&TSK_FS_META_FLAG_ALLOC))return 0;
    auto *file=tsk_fs_file_alloc(fs);if(!file)return 1;
    for(TSK_INUM_T id=start;id<=end;id++){
        if(meta(fs,file,id)){tsk_fs_file_close(file);return 1;}
        auto result=cb(file,ctx);if(result!=TSK_WALK_CONT){tsk_fs_file_close(file);return result==TSK_WALK_ERROR?1:0;}
    }tsk_fs_file_close(file);return 0;
}
static TSK_FS_BLOCK_FLAG_ENUM region_flags(const Region &r){
    return TSK_FS_BLOCK_FLAG_ENUM((r.allocated?TSK_FS_BLOCK_FLAG_ALLOC:TSK_FS_BLOCK_FLAG_UNALLOC)|(r.metadata?TSK_FS_BLOCK_FLAG_META:TSK_FS_BLOCK_FLAG_CONT));
}
static TSK_FS_BLOCK_FLAG_ENUM block_flags(TSK_FS_INFO *fs,TSK_DADDR_T addr){
    try{return region_flags(reader(fs).flags(addr));}catch(const std::exception &e){failure(e);return TSK_FS_BLOCK_FLAG_UNUSED;}
}
static uint8_t block_walk(TSK_FS_INFO *fs,TSK_DADDR_T start,TSK_DADDR_T end,TSK_FS_BLOCK_WALK_FLAG_ENUM flags,TSK_FS_BLOCK_WALK_CB cb,void *ctx){
    if(!cb||start>end||end>fs->last_block){tsk_error_set_errno(TSK_ERR_FS_ARG);return 1;}
    auto *block=tsk_fs_block_alloc(fs);if(!block)return 1;
    try{
        Reader &r=reader(fs);
        for(const auto &region:r.allocation){
            if(region.end<=start||region.start>end)continue;
            if(region.allocated?!(flags&TSK_FS_BLOCK_WALK_FLAG_ALLOC):!(flags&TSK_FS_BLOCK_WALK_FLAG_UNALLOC))continue;
            if(region.metadata?!(flags&TSK_FS_BLOCK_WALK_FLAG_META):!(flags&TSK_FS_BLOCK_WALK_FLAG_CONT))continue;
            uint64_t at=std::max<uint64_t>(start,region.start),limit=std::min<uint64_t>(end+1,region.end);
            auto f=TSK_FS_BLOCK_FLAG_ENUM(region_flags(region)|TSK_FS_BLOCK_FLAG_RAW);
            bool only=(flags&TSK_FS_BLOCK_WALK_FLAG_AONLY)!=0;if(only)f=TSK_FS_BLOCK_FLAG_ENUM(f|TSK_FS_BLOCK_FLAG_AONLY);
            while(at<limit){size_t length=size_t(std::min<uint64_t>(65536,limit-at));Bytes b;if(!only)b=r.read(at,length);
                for(size_t k=0;k<length;k++){
                    block->addr=at+k;block->flags=f;if(!only)block->buf[0]=char(b[k]);
                    auto result=cb(block,ctx);if(result!=TSK_WALK_CONT){tsk_fs_block_free(block);return result==TSK_WALK_ERROR?1:0;}
                }at+=length;
            }
        }tsk_fs_block_free(block);return 0;
    }catch(const std::exception &e){tsk_fs_block_free(block);return failure(e);}
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
    Reader&r=reader(fs);tsk_fprintf(out,"FILE SYSTEM INFORMATION\nFile System Type: UBI / UBIFS\nAddress Unit: Byte\nVolume Count: %u\nPEB Size: %llu\nAllocation: conservative selected-PEB map, not UBIFS LPT free-space accounting\n",unsigned(r.volumes.size()),(unsigned long long)r.peb_size);
    for(const auto&v:r.volumes)tsk_fprintf(out,"Volume %u: %s, %s, usable LEB %u, logical size %llu\n",v.id,v.name.c_str(),v.ubifs?"UBIFS":"raw",v.leb_size,(unsigned long long)v.size);return 0;
}
extern "C" TSK_FS_INFO *ubi_open(TSK_IMG_INFO *img,TSK_OFF_T offset,TSK_FS_TYPE_ENUM type,const char *password,uint8_t test){
    (void)password;(void)test;
    try {
        if(!img||offset<0||offset>img->size||type!=TSK_FS_TYPE_UBI)throw std::runtime_error("invalid image or offset");
        auto io=[=](uint64_t pos,size_t len)->Bytes {
            uint64_t size=uint64_t(img->size-offset);if(pos>size||len>size-pos)return {};
            Bytes b(len);if(tsk_img_read(img,offset+TSK_OFF_T(pos),reinterpret_cast<char *>(b.data()),len)!=ssize_t(len))return {};return b;
        };
        std::unique_ptr<Reader> r(new Reader(io,uint64_t(img->size-offset)));
        auto *info=reinterpret_cast<UBI_INFO *>(tsk_fs_malloc(sizeof(UBI_INFO)));if(!info)return nullptr;
        info->reader=r.release();auto *fs=&info->fs;Reader &v=*info->reader;
        fs->img_info=img;fs->offset=offset;fs->ftype=TSK_FS_TYPE_UBI;fs->duname="Byte";fs->tag=TSK_FS_INFO_TAG;
        fs->endian=TSK_LIT_ENDIAN;fs->block_size=1;fs->dev_bsize=img->sector_size;fs->block_count=v.size;
        fs->first_block=0;fs->last_block=fs->last_block_act=v.size-1;
        fs->root_inum=v.root;fs->first_inum=1;fs->last_inum=v.nodes.size()-1;fs->inum_count=fs->last_inum;
        fs->close=close_fs;fs->fsstat=fsstat;fs->file_add_meta=meta;fs->load_attrs=attrs;fs->dir_open_meta=directory;
        fs->inode_walk=inode_walk;fs->block_walk=block_walk;fs->block_getflags=block_flags;
        fs->istat=istat;fs->get_default_attr_type=tsk_fs_nofs_get_default_attr_type;fs->name_cmp=tsk_fs_nofs_name_cmp;
        fs->jblk_walk=tsk_fs_nofs_jblk_walk;fs->jentry_walk=tsk_fs_nofs_jentry_walk;fs->jopen=tsk_fs_nofs_jopen;
        tsk_error_reset();return fs;
    }catch(const std::exception &e){failure(e);tsk_error_set_errno(TSK_ERR_FS_MAGIC);return nullptr;}
}
