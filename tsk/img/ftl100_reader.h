/* Read-only FTL100 NOR translation, adapted from Gerd1986/qnxprobe ftl100.py.
 * MIT attribution: ftl100_LICENSE.txt. Recovery policy follows that reader,
 * not a claim to fully emulate a writable TrueFFS implementation. */
#ifndef TSK_FTL100_READER_H
#define TSK_FTL100_READER_H
#include <algorithm>
#include <cstdint>
#include <functional>
#include <map>
#include <stdexcept>
#include <vector>
namespace tsk_ftl100 {
using Bytes=std::vector<uint8_t>;
inline uint32_t le(const Bytes&b,size_t p,size_t n){
    if(p>b.size()||n>b.size()-p)throw std::runtime_error("truncated header/BAM");
    uint32_t v=0;for(size_t k=0;k<n;k++)v|=uint32_t(b[p+k])<<(k*8);return v;
}
inline bool signature(const Bytes&b,size_t p){
    const uint8_t a[]={0x13,0x03,'C','I','S'},c[]={'F','T','L','1','0','0'};
    return p<=b.size()&&14<=b.size()-p&&std::equal(a,a+5,b.begin()+p)&&std::equal(c,c+6,b.begin()+p+8);
}
// Search every byte, including signatures crossing a read boundary. Keep
// memory bounded independently of dump size; stop at the first candidate.
inline bool probe(const std::function<Bytes(uint64_t,size_t)>& io,uint64_t size){
    for(uint64_t p=0;p<size;){
        size_t n=size_t(std::min<uint64_t>(1048576,size-p));
        Bytes b=io(p,n);
        if(b.size()!=n)throw std::runtime_error("short physical probe read");
        for(size_t k=0;k+14<=b.size();k++)if(signature(b,k))return true;
        if(p+n==size)break;
        p+=n-13;
    }
    return false;
}
struct Unit{uint64_t physical=0;uint32_t count=0;};
class Reader{
    std::function<Bytes(uint64_t,size_t)> io;
    Bytes fetch(uint64_t p,size_t n)const{if(p>physical_size||n>physical_size-p)throw std::runtime_error("read outside physical dump");Bytes b=io(p,n);if(b.size()!=n)throw std::runtime_error("short physical read");return b;}
public:
    uint64_t physical_size=0,logical_size=0,erase_size=0;
    uint32_t block_size=512,bam_offset=0,headers=0,transfer_units=0,duplicate_units=0,duplicate_sectors=0,ignored_headers=0,ignored_bam_sectors=0;
    uint16_t first_unit=0,total_units=0,data_units=0;
    std::map<uint16_t,Unit> units;
    std::map<uint32_t,uint64_t> sectors;
    Reader(std::function<Bytes(uint64_t,size_t)> fn,uint64_t size):io(fn),physical_size(size){
        std::vector<std::pair<uint64_t,Bytes>> found;
        // A 67-byte overlap keeps a header spanning chunk boundaries visible.
        for(uint64_t p=0;p<physical_size;){size_t n=size_t(std::min<uint64_t>(1048576,physical_size-p));Bytes b=fetch(p,n);
            for(size_t k=0;k+68<=b.size();k++)if(signature(b,k)){found.push_back({p+k,Bytes(b.begin()+k,b.begin()+k+68)});k+=13;}
            if(p+n==physical_size)break;p+=n-67;
        }
        if(found.empty())throw std::runtime_error("no FTL100 header");
        const Bytes&h=found.front().second;
        if(h[22]!=9||h[23]<12||h[23]>24)throw std::runtime_error("unsupported FTL100 block/erase geometry");
        erase_size=uint64_t(1)<<h[23];first_unit=uint16_t(le(h,24,2));total_units=uint16_t(le(h,26,2));
        if(!total_units||h[15]>=total_units)throw std::runtime_error("invalid data/transfer unit count");
        data_units=uint16_t(total_units-h[15]);logical_size=le(h,28,4);bam_offset=le(h,48,4);
        uint64_t bam_bytes=4*(erase_size/block_size);
        if(!logical_size||logical_size%block_size||logical_size>uint64_t(data_units)*erase_size||logical_size>physical_size||bam_offset<68||bam_offset>erase_size||bam_bytes>erase_size-bam_offset)throw std::runtime_error("invalid logical size or BAM bounds");
        uint64_t alignment=found.front().first%erase_size;
        std::vector<uint16_t> order;
        for(const auto&hit:found){uint64_t base=hit.first;const Bytes&b=hit.second;
            if(le(b,28,4)!=logical_size||le(b,26,2)!=total_units){ignored_headers++;continue;}
            if(b[22]!=h[22]||b[23]!=h[23]||le(b,24,2)!=first_unit||b[15]!=h[15]||le(b,48,4)!=bam_offset||base%erase_size!=alignment||base>physical_size||erase_size>physical_size-base)throw std::runtime_error("inconsistent or truncated FTL100 erase unit");
            headers++;uint16_t lun=uint16_t(le(b,20,2));if(lun==0xffff){transfer_units++;continue;}
            // Same absolute-EUN normalization as the tested BMW preprocessor.
            uint32_t normalized=(lun>=first_unit&&uint32_t(lun)<uint32_t(first_unit)+data_units)?uint32_t(lun-first_unit):lun;
            if(normalized>=data_units)throw std::runtime_error("logical erase unit outside data-unit range");
            uint16_t id=uint16_t(normalized);uint32_t ec=le(b,16,4);auto it=units.find(id);
            if(it==units.end()){units[id]={base,ec};order.push_back(id);}else{duplicate_units++;if(ec>it->second.count)it->second={base,ec};}
        }
        if(units.empty())throw std::runtime_error("no active FTL100 data units");
        for(uint16_t id:order){const Unit&u=units.at(id);Bytes bam=fetch(u.physical+bam_offset,size_t(bam_bytes));
            for(uint32_t k=0;k<erase_size/block_size;k++){uint32_t ent=le(bam,size_t(k)*4,4);if((ent&0x7f)!=0x40)continue;
                uint32_t sector=ent>>9;uint64_t relative=uint64_t(k)*block_size;
                // Linux ftl.c builds VirtualBlockMap only for BLOCK_NUMBER <
                // FormattedSize / block_size. The BMW ASK-II also has high
                // BAM addresses (0xffffec40..0xfffffe40) outside that range.
                // Like the reference recovery, ignore them without reading
                // their payload or extending the formatted logical image.
                if(uint64_t(sector)*block_size>=logical_size){ignored_bam_sectors++;continue;}
                if(relative<68||(relative<bam_offset+bam_bytes&&relative+block_size>bam_offset))throw std::runtime_error("BAM data points into translation metadata");
                if(sectors.count(sector))duplicate_sectors++;sectors[sector]=u.physical+relative;
            }
        }
        if(sectors.empty())throw std::runtime_error("no mapped FTL100 data sectors");
    }
    Bytes read(uint64_t offset,size_t length)const{
        if(offset>logical_size)throw std::runtime_error("logical offset beyond end");length=size_t(std::min<uint64_t>(length,logical_size-offset));Bytes out(length,0);size_t written=0;
        while(written<length){uint32_t sector=uint32_t(offset/block_size);size_t skip=size_t(offset%block_size),take=std::min<size_t>(length-written,block_size-skip);auto it=sectors.find(sector);
            if(it!=sectors.end()){Bytes b=fetch(it->second+skip,take);std::copy(b.begin(),b.end(),out.begin()+written);}offset+=take;written+=take;
        }return out;
    }
};
}
#endif
