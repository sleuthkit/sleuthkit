/* Read-only QNX4 reader adapted from abrignoni/qnxprobe (MIT).
 * Copyright (c) 2026 Alexis Brignoni. See qnx4_LICENSE.txt.
 * Disk structures also checked against Linux qnx4 headers and driver.
 */
#ifndef TSK_QNX4_READER_H
#define TSK_QNX4_READER_H
#include <cstdint>
#include <vector>
#include <set>
#include <map>
#include <string>
#include <stdexcept>
#include <functional>
#include <mutex>
namespace tsk_qnx4 {
using Bytes = std::vector<uint8_t>;
inline uint64_t le(const Bytes &b,size_t p,size_t n=4) {
    if(p>b.size()||n>b.size()-p)throw std::runtime_error("QNX4 truncated structure");
    uint64_t v=0;for(size_t i=0;i<n;i++)v|=uint64_t(b[p+i])<<(i*8);return v;
}
struct Extent {uint64_t block, count;}; // physical, zero-based
struct Inode {Bytes raw;uint64_t number;uint32_t size;uint16_t mode;};
struct Entry {std::string name;uint64_t number;};
class Reader {
    std::function<Bytes(uint64_t,size_t)> read;
    uint64_t available;
    Inode bitmap_inode;
    std::map<uint64_t,Bytes> cache;
    std::mutex cache_lock;
    std::vector<Extent> metadata;
    std::vector<Extent> bitmap_runs;
    void range(uint64_t start,uint64_t length) {
        if(!length||start>=blocks||length>blocks-start||start>=available/512||length>available/512-start)
            throw std::runtime_error("QNX4 extent outside readable volume");
    }
    std::string name(const Bytes &b,size_t width) {
        size_t n=0;while(n<width&&b[n])n++;
        std::string s(reinterpret_cast<const char *>(b.data()),n);
        if(s.find('/')!=std::string::npos)throw std::runtime_error("QNX4 invalid filename");
        return s;
    }
    std::vector<Extent> map(const Inode &i,std::vector<uint64_t> *xblocks=nullptr) {
        uint32_t n=uint32_t(le(i.raw,48,2));std::vector<Extent> out;
        if(!n){if(i.size)throw std::runtime_error("QNX4 missing file extents");return out;}
        auto add=[&](uint64_t disk,uint64_t count){
            if(!disk)throw std::runtime_error("QNX4 zero extent address");
            range(disk-1,count);out.push_back({disk-1,count});
        };
        add(le(i.raw,20),le(i.raw,24));uint32_t left=n-1;
        uint64_t next=le(i.raw,28);std::set<uint64_t> seen;
        while(left){
            if(!next||!seen.insert(next).second)throw std::runtime_error("QNX4 missing or cyclic xblk chain");
            range(next-1,1);Bytes b=block(next-1);
            if(std::string(reinterpret_cast<const char *>(b.data()+496),7)!="IamXblk")
                throw std::runtime_error("QNX4 invalid IamXblk signature");
            uint32_t count=b[8];if(!count||count>60||count>left)throw std::runtime_error("QNX4 invalid xblk extent count");
            if(xblocks)xblocks->push_back(next-1);
            for(uint32_t k=0;k<count;k++)add(le(b,16+k*8),le(b,20+k*8));
            left-=count;next=le(b,0);
        }
        uint64_t total=0;for(const auto &e:out)total+=e.count;
        if(total<(uint64_t(i.size)+511)/512)throw std::runtime_error("QNX4 extents do not cover file size");
        return out;
    }
public:
    uint64_t blocks=0, root=8;
    std::set<uint64_t> live;
    Reader(std::function<Bytes(uint64_t,size_t)> io,uint64_t size):read(io),available(size) {
        if(size<1536)throw std::runtime_error("QNX4 image too short");
        blocks=size/512;
        Inode r=inode(root);
        if(r.raw[0]!='/'||r.raw[1]||(r.mode&0170000)!=0040000)
            throw std::runtime_error("QNX4 no valid root superblock at 512");
        auto initial=directory(r);bool found=false;
        for(const auto &e:initial)if(e.name==".bitmap"){
            bitmap_inode=inode(e.number);found=true;break;
        }
        if(!found||(bitmap_inode.mode&0170000)!=0100000||!bitmap_inode.size)
            throw std::runtime_error("QNX4 no valid .bitmap");
        blocks=uint64_t(bitmap_inode.size)*8;
        if(blocks<3)throw std::runtime_error("QNX4 invalid volume geometry");
        bitmap_runs=map(bitmap_inode);
        metadata.push_back({0,2});
        metadata.insert(metadata.end(),bitmap_runs.begin(),bitmap_runs.end());
        // Reachable inode indexing avoids interpreting arbitrary file bytes as
        // allocated inodes. Work is bounded by the volume and visited IDs.
        std::vector<uint64_t> pending={root};live.insert(root);
        for(uint64_t n=9;n<=11;n++){
            try{Inode sys=inode(n);if((sys.raw[63]&(1|0x10))&&sys.mode){live.insert(n);
                auto spans=map(sys);metadata.insert(metadata.end(),spans.begin(),spans.end());}}
            catch(const std::runtime_error &){/* unused optional system entry */}
        }
        std::set<uint64_t> visited;
        while(!pending.empty()){
            uint64_t number=pending.back();pending.pop_back();
            if(!visited.insert(number).second)continue;
            Inode dir=inode(number);auto spans=map(dir);
            metadata.insert(metadata.end(),spans.begin(),spans.end());
            for(const auto &e:directory(dir)){
                Inode child=inode(e.number);live.insert(e.number);
                if(e.name!="."&&e.name!=".."&&(child.mode&0170000)==0040000)pending.push_back(e.number);
            }
        }
        // Validate active extent chains and identify their xblk metadata.
        for(uint64_t n:live){std::vector<uint64_t> xb;map(inode(n),&xb);
            metadata.push_back({n/8,1});for(uint64_t a:xb)metadata.push_back({a,1});}
        // Allocation bit 0 is the low bit, and addresses are zero-based.
        if(!allocated(0)||!allocated(1))throw std::runtime_error("QNX4 reserved blocks marked free");
    }
    Bytes block(uint64_t a){
        range(a,1);
        {std::lock_guard<std::mutex> lock(cache_lock);auto c=cache.find(a);if(c!=cache.end())return c->second;}
        Bytes b=read(a*512,512);if(b.size()!=512)throw std::runtime_error("QNX4 short block read");
        {std::lock_guard<std::mutex> lock(cache_lock);if(cache.size()>=256)cache.clear();cache[a]=b;}
        return b;
    }
    Inode inode(uint64_t n){
        if(n<8||n/8>=blocks)throw std::runtime_error("QNX4 inode outside volume");
        Bytes b=block(n/8);size_t p=size_t(n%8)*64;
        Bytes raw(b.begin()+p,b.begin()+p+64);uint16_t mode=uint16_t(le(raw,50,2));
        if(!(raw[63]&(1|0x10))||(raw[63]&8)||!(mode&0170000))throw std::runtime_error("QNX4 not an allocated inode");
        return {raw,n,uint32_t(le(raw,16)),mode};
    }
    std::vector<Extent> extents(const Inode &i){return map(i);}
    std::vector<Entry> directory(const Inode &dir){
        if((dir.mode&0170000)!=0040000||dir.size%64)throw std::runtime_error("QNX4 invalid directory size or mode");
        std::vector<Entry> out;uint64_t done=0;
        for(const auto &e:map(dir))for(uint64_t j=0;j<e.count&&done<dir.size;j++){
            Bytes b=block(e.block+j);size_t take=size_t((dir.size-done)<512?(dir.size-done):512);
            for(size_t p=0;p<take;p+=64){
                Bytes raw(b.begin()+p,b.begin()+p+64);if(!raw[0]||!(raw[63]&(1|8)))continue;
                bool link=(raw[63]&8)!=0;std::string nm=name(raw,link?48:16);
                uint64_t child=(e.block+j)*8+p/64;
                if(link){uint64_t disk=le(raw,48);if(!disk||raw[52]>=8)throw std::runtime_error("QNX4 invalid linked inode reference");child=(disk-1)*8+raw[52];}
                if(child/8>=blocks)throw std::runtime_error("QNX4 linked inode outside volume");
                out.push_back({nm,child});
            }done+=512;
        }return out;
    }
    bool allocated(uint64_t a){
        if(a>=blocks)throw std::runtime_error("QNX4 allocation address outside volume");
        uint64_t byte=a/8,logical=byte/512,offset=byte%512;
        for(const auto &e:bitmap_runs){if(logical<e.count){Bytes b=block(e.block+logical);return (b[size_t(offset)]&(1U<<(a%8)))!=0;}logical-=e.count;}
        throw std::runtime_error("QNX4 unreadable allocation bitmap");
    }
    bool is_metadata(uint64_t a)const{
        for(const auto &e:metadata)if(a>=e.block&&a-e.block<e.count)return true;
        return false;
    }
    uint64_t readable_blocks()const{return available/512<blocks?available/512:blocks;}
};
}
#endif
