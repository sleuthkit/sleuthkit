/* Native FTL100 image backend. See ftl100_reader.h and ftl100_LICENSE.txt. */
#include "ftl100.h"
#include "ftl100_reader.h"
#include <memory>
using namespace tsk_ftl100;
struct FTL_INFO{TSK_IMG_INFO img;TSK_IMG_INFO *physical;Reader *reader;};
static ssize_t logical_read(TSK_IMG_INFO*img,TSK_OFF_T offset,char*buf,size_t len){
    try{if(offset<0||(!buf&&len))throw std::runtime_error("invalid logical read");Bytes b=reinterpret_cast<FTL_INFO*>(img)->reader->read(uint64_t(offset),len);if(!b.empty())memcpy(buf,b.data(),b.size());return ssize_t(b.size());}
    catch(const std::exception&e){tsk_error_reset();tsk_error_set_errno(TSK_ERR_IMG_READ);tsk_error_set_errstr("FTL100: %s",e.what());return -1;}
}
static void close_ftl(TSK_IMG_INFO*img){auto*p=reinterpret_cast<FTL_INFO*>(img);delete p->reader;tsk_img_close(p->physical);tsk_img_free(p);}
static void stat_ftl(TSK_IMG_INFO*img,FILE*out){
    const Reader&r=*reinterpret_cast<FTL_INFO*>(img)->reader;
    tsk_fprintf(out,"IMAGE FILE INFORMATION\nImage Type: FTL100 NOR logical view\nSize in bytes: %llu\nPhysical dump bytes: %llu\nSector size: 512\nErase-unit bytes: %llu\nHeaders: %u\nSelected data units: %u\nTransfer units: %u\nMapped sectors: %llu\nUnmapped sectors: %llu (zero-filled recovery holes)\nDuplicate erase units: %u\nDuplicate logical sectors: %u\nIgnored foreign headers: %u\nRecovery policy: higher erase-count duplicate EUN; last BAM entry in first-seen EUN order\nAddresses below this layer are LOGICAL, not physical NOR offsets\n",
        (unsigned long long)r.logical_size,(unsigned long long)r.physical_size,(unsigned long long)r.erase_size,r.headers,unsigned(r.units.size()),r.transfer_units,(unsigned long long)r.sectors.size(),(unsigned long long)(r.logical_size/512-r.sectors.size()),r.duplicate_units,r.duplicate_sectors,r.ignored_headers);
}
TSK_IMG_INFO*ftl100_open(int count,const TSK_TCHAR * const paths[],unsigned int ssize,int*matched){
    if(matched)*matched=0;
    std::unique_ptr<TSK_IMG_INFO,decltype(&tsk_img_close)> physical(tsk_img_open(count,paths,TSK_IMG_TYPE_RAW,512),tsk_img_close);
    if(!physical)return nullptr;
    try{
        if(ssize&&ssize!=512)throw std::runtime_error("FTL100 logical sector size must be 512");
        auto io=[&](uint64_t at,size_t length){Bytes b(length);ssize_t got=tsk_img_read(physical.get(),TSK_OFF_T(at),reinterpret_cast<char*>(b.data()),length);if(got<0)throw std::runtime_error("physical dump read failed");b.resize(size_t(got));return b;};
        if(matched){Bytes b=io(0,size_t(std::min<TSK_OFF_T>(physical->size,1048576)));bool found=false;for(size_t k=0;k+14<=b.size();k++)if(signature(b,k)){found=true;break;}if(!found){tsk_error_reset();return nullptr;}*matched=1;}
        // Reader keeps a backend pointer, not the local owning smart pointer.
        TSK_IMG_INFO*backend=physical.get();auto read_backend=[backend](uint64_t at,size_t length){Bytes b(length);ssize_t got=tsk_img_read(backend,TSK_OFF_T(at),reinterpret_cast<char*>(b.data()),length);if(got<0)throw std::runtime_error("physical dump read failed");b.resize(size_t(got));return b;};
        std::unique_ptr<Reader> reader(new Reader(read_backend,uint64_t(physical->size)));
        auto*p=reinterpret_cast<FTL_INFO*>(tsk_img_malloc(sizeof(FTL_INFO)));if(!p)return nullptr;
        p->physical=physical.release();p->reader=reader.release();p->img.itype=TSK_IMG_TYPE_FTL100;p->img.size=TSK_OFF_T(p->reader->logical_size);p->img.sector_size=512;p->img.num_img=p->physical->num_img;p->img.images=p->physical->images;
        p->img.read=logical_read;p->img.close=close_ftl;p->img.imgstat=stat_ftl;tsk_error_reset();return &p->img;
    }catch(const std::exception&e){tsk_error_reset();tsk_error_set_errno(TSK_ERR_IMG_READ);tsk_error_set_errstr("FTL100: %s",e.what());return nullptr;}
}
