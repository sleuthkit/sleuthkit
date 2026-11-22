/* Read-only F2FS reader adapted from abrignoni/qnxprobe, qnxprobe.py.
 * Copyright (c) 2026 Alexis Brignoni. MIT license: see f2fs_LICENSE.txt.
 * Native port uses bounded reads and rejects unsupported content features. */
#ifndef TSK_F2FS_READER_H
#define TSK_F2FS_READER_H
#include <cstdint>
#include <vector>
#include <map>
#include <string>
#include <stdexcept>
#include <functional>
#include <algorithm>
#include <mutex>
namespace tsk_f2fs {
using Bytes = std::vector<uint8_t>;
inline uint64_t le(const Bytes &b, size_t p, size_t n=4) {
    if (p>b.size() || n>b.size()-p) throw std::runtime_error("F2FS truncated structure");
    uint64_t v=0; for(size_t i=0;i<n;i++) v|=uint64_t(b[p+i])<<(i*8); return v;
}
inline bool bit(const Bytes &b, uint64_t i) {
    if(i/8>=b.size()) throw std::runtime_error("F2FS bitmap too short");
    return (b[size_t(i/8)] & (0x80U>>(i%8)))!=0;
}
struct Inode { Bytes raw; uint32_t nid, base, count; uint64_t size; uint16_t mode; };
struct Entry { std::string name; uint32_t nid; uint8_t type; };
class Reader {
    std::function<Bytes(uint64_t,size_t)> read;
    uint64_t image_size;
    std::map<uint64_t,Bytes> cache;
    std::mutex cache_lock;
    Bytes cp, nat_bitmap, sit_bitmap;
    std::map<uint32_t,uint32_t> nat_j;
    std::map<uint32_t,Bytes> sit_j;
    uint32_t cp_start=0, cp_total=0, cp_flags=0, payload=0, sit_segs=0;
    Bytes slice(const Bytes &b,size_t p,size_t n) {
        if(p>b.size()||n>b.size()-p) throw std::runtime_error("F2FS invalid bitmap placement");
        return Bytes(b.begin()+p,b.begin()+p+n);
    }
    bool valid_sb(const Bytes &b) {
        return b.size()==3072 && le(b,0)==0xf2f52010 &&
            (le(b,16)==12||le(b,16)==14) && le(b,20)==9 &&
            le(b,96)==3 && le(b,100)==1 && le(b,104)==2;
    }
    uint32_t word(uint32_t nid,uint32_t i) {
        if(!nid) return 0;
        Bytes b=node(nid); if(b.empty()) return 0;
        if(i>=(bs-24)/4) throw std::runtime_error("F2FS node index out of range");
        return uint32_t(le(b,i*4));
    }
    void journals() {
        uint32_t sum_bs=(feature&0x10000)?4096:bs, entries=7*(sum_bs/8);
        uint32_t addr, noff, soff, saddr;
        if(cp_flags&4) {
            addr=cp_start+uint32_t(le(cp,140)); noff=0;
            saddr=addr; soff=sum_bs-5-entries;
        } else {
            uint32_t back=(cp_flags&(1|0x20))?7:4;
            if(cp_total<back) throw std::runtime_error("F2FS invalid summary pack");
            addr=cp_start+cp_total-back; noff=entries; saddr=addr+2; soff=entries;
        }
        if(addr<cp_start || addr>=cp_start+cp_total-1 || saddr>=cp_start+cp_total-1)
            throw std::runtime_error("F2FS summary outside checkpoint");
        Bytes b=block(addr); uint32_t n=uint32_t(le(b,noff,2));
        if(n>(sum_bs-5-entries-2)/13) throw std::runtime_error("F2FS invalid NAT journal count");
        for(uint32_t i=0;i<n;i++) { size_t p=noff+2+i*13; nat_j[uint32_t(le(b,p))]=uint32_t(le(b,p+9)); }
        b=block(saddr); n=uint32_t(le(b,soff,2));
        if(n>(sum_bs-5-entries-2)/78) throw std::runtime_error("F2FS invalid SIT journal count");
        for(uint32_t i=0;i<n;i++) {size_t p=soff+2+i*78; sit_j[uint32_t(le(b,p))]=slice(b,p+4,74);}
    }
public:
    uint32_t bs=0, root=3, nat=0, sit=0, main=0, main_segs=0, feature=0;
    uint64_t blocks=0, version=0, max_nid=0;
    Reader(std::function<Bytes(uint64_t,size_t)> io,uint64_t size):read(io),image_size(size) {
        Bytes sb;
        for(uint64_t off: {uint64_t(1024),uint64_t(5120),uint64_t(17408)}) {
            if(off<=size && 3072<=size-off) {Bytes b=read(off,3072); if(valid_sb(b)){sb=b;break;}}
        }
        if(sb.empty()) throw std::runtime_error("F2FS no valid superblock");
        bs=1U<<le(sb,16); blocks=le(sb,36,8); uint32_t cpaddr=uint32_t(le(sb,76));
        sit=uint32_t(le(sb,80)); nat=uint32_t(le(sb,84)); main=uint32_t(le(sb,92));
        main_segs=uint32_t(le(sb,68)); sit_segs=uint32_t(le(sb,56));
        payload=uint32_t(le(sb,1664)); feature=uint32_t(le(sb,2180));
        uint32_t nat_segs=uint32_t(le(sb,60));
        if(!blocks||blocks>size/bs||cpaddr>=sit||sit>=nat||nat>=main||
           !sit_segs||(sit_segs&1)||!nat_segs||(nat_segs&1)||
           uint64_t(main)+uint64_t(main_segs)*512>blocks)
            throw std::runtime_error("F2FS invalid or truncated geometry");
        // Additional devices require an address translator that is not implemented.
        if(le(sb,2201+68,1))throw std::runtime_error("F2FS multi-device volume unsupported");
        max_nid=uint64_t(nat_segs/2)*512*(bs/9)-1;
        if(max_nid>UINT32_MAX) throw std::runtime_error("F2FS unsupported NAT size");
        bool found=false;
        for(uint32_t a: {cpaddr,cpaddr+512}) {
            try { Bytes h=block(a); uint32_t total=uint32_t(le(h,136));
                if(total<3||total>512||uint64_t(a)+total>sit) continue;
                uint64_t v=le(h,0,8); Bytes tail=block(a+total-1);
                // Validate both checkpoint CRCs and their matching versions.
                if(!checkpoint_crc(h)||!checkpoint_crc(tail)||le(tail,0,8)!=v) continue;
                if(!found||int64_t(v-version)>0) {found=true; version=v;cp=h;cp_total=total;cp_start=a;}
            } catch(const std::runtime_error &) {}
        }
        if(!found) throw std::runtime_error("F2FS no complete valid checkpoint");
        cp_flags=uint32_t(le(cp,132)); if(cp_flags&8) throw std::runtime_error("F2FS checkpoint error flag");
        size_t sn=size_t(le(cp,156)), nn=size_t(le(cp,160));
        if(cp_flags&0x400) {nat_bitmap=slice(cp,196,nn);sit_bitmap=slice(cp,196+nn,sn);}
        else if(payload) {
            if(payload>=cp_total-1) throw std::runtime_error("F2FS invalid checkpoint payload");
            nat_bitmap=slice(cp,192,nn); Bytes p;
            for(uint32_t i=0;i<payload;i++){Bytes b=block(cp_start+1+i);p.insert(p.end(),b.begin(),b.end());}
            sit_bitmap=slice(p,0,sn);
        } else {sit_bitmap=slice(cp,192,sn);nat_bitmap=slice(cp,192+sn,nn);}
        if(nn*8<uint64_t(nat_segs/2)*512 || sn*8<uint64_t(sit_segs/2)*512)
            throw std::runtime_error("F2FS version bitmap geometry mismatch");
        journals(); Inode r=inode(root); if((r.mode&0170000)!=0040000) throw std::runtime_error("F2FS invalid root");
    }
    static bool checkpoint_crc(const Bytes &b) {
        size_t off=size_t(le(b,164)); if(off<192||off>b.size()-4) return false;
        uint32_t crc=0xf2f52010;
        for(size_t i=0;i<off;i++) {crc^=b[i];for(unsigned j=0;j<8;j++)crc=(crc>>1)^((crc&1)?0xedb88320:0);}
        return crc==le(b,off);
    }
    Bytes block(uint64_t a) {
        if(a>=blocks || a>image_size/bs) throw std::runtime_error("F2FS block outside volume");
        {
            std::lock_guard<std::mutex> lock(cache_lock);
            auto cached=cache.find(a);if(cached!=cache.end())return cached->second;
        }
        Bytes b=read(a*bs,bs);
        if(b.size()!=bs)throw std::runtime_error("F2FS short block read");
        {
            std::lock_guard<std::mutex> lock(cache_lock);
            // Bound memory; retaining recent metadata avoids rereading NAT/SIT
            // blocks for every inode/block during forensic walks.
            if(cache.size()>=256)cache.clear();
            cache[a]=b;
        }
        return b;
    }
    uint32_t resolve(uint32_t nid) {
        if(nid>max_nid) throw std::runtime_error("F2FS invalid node id");
        auto j=nat_j.find(nid); if(j!=nat_j.end()) return j->second;
        uint64_t index=nid/(bs/9), a=uint64_t(nat)+index*2-(index&511);
        if(bit(nat_bitmap,index))a+=512;
        if(a>=main)throw std::runtime_error("F2FS NAT outside metadata");
        return uint32_t(le(block(a),(nid%(bs/9))*9+5));
    }
    Bytes node(uint32_t nid) {
        uint32_t a=resolve(nid); if(!a||a==UINT32_MAX)return {};
        if(a<main)throw std::runtime_error("F2FS node outside main area");
        Bytes b=block(a);if(le(b,bs-24)!=nid)throw std::runtime_error("F2FS node footer mismatch");return b;
    }
    Inode inode(uint32_t nid) {
        Bytes b=node(nid); if(b.empty()||le(b,bs-20)!=nid)throw std::runtime_error("F2FS not an allocated inode");
        uint32_t extra=(b[3]&0x20)?uint32_t(le(b,360,2)):0;
        uint32_t ix=(feature&0x40)?uint32_t(le(b,362,2)):((b[3]&(1|4))?50:0);
        uint32_t def=(bs-404)/4;
        if(extra%4||extra/4>=def||ix>=def-extra/4)throw std::runtime_error("F2FS invalid inode address layout");
        uint64_t size=le(b,16,8); if(size>INT64_MAX)throw std::runtime_error("F2FS invalid inode size");
        return {b,nid,360+extra,def-extra/4-ix,size,uint16_t(le(b,0,2))};
    }
    uint32_t data(const Inode &ino,uint64_t l) {
        uint64_t apb=(bs-24)/4;
        if(l<ino.count)return uint32_t(le(ino.raw,ino.base+size_t(l)*4));
        l-=ino.count;
        auto slot=[&](uint32_t i){return uint32_t(le(ino.raw,bs-44+i*4));};
        for(uint32_t i=0;i<2;i++){if(l<apb)return word(slot(i),uint32_t(l));l-=apb;}
        for(uint32_t i=2;i<4;i++){if(l<apb*apb)return word(word(slot(i),uint32_t(l/apb)),uint32_t(l%apb));l-=apb*apb;}
        if(l>=apb*apb*apb)throw std::runtime_error("F2FS file exceeds node capacity");
        return word(word(word(slot(4),uint32_t(l/(apb*apb))),uint32_t((l/apb)%apb)),uint32_t(l%apb));
    }
    bool unreadable(const Inode &i) {return ((feature&1)&&(i.raw[2]&4))||((feature&0x2000)&&(le(i.raw,80)&4));}
    Bytes inline_data(const Inode &i) {
        if(i.size>uint64_t(i.count-1)*4)throw std::runtime_error("F2FS inline size out of range");
        return slice(i.raw,i.base+4,size_t(i.size));
    }
    std::vector<Entry> directory(const Inode &i) {
        if((i.mode&0170000)!=0040000||unreadable(i))throw std::runtime_error("F2FS unreadable directory");
        std::vector<Entry> out;
        auto parse=[&](const Bytes &b,size_t off,size_t span) {
            size_t nr=8*span/153, bm=(nr+7)/8, de=span-19*nr, names=de+11*nr;
            if(off>b.size()||span>b.size()-off)throw std::runtime_error("F2FS dentry bounds");
            for(size_t k=0;k<nr;) {
                if(!(b[off+k/8]&(1U<<(k%8)))){k++;continue;}
                size_t p=off+de+k*11, n=size_t(le(b,p+8,2)), slots=(n+7)/8;
                if(!n||n>255||slots>nr-k)throw std::runtime_error("F2FS invalid directory entry");
                std::string name(reinterpret_cast<const char *>(&b[off+names+k*8]),n);
                if(name.find('\0')!=std::string::npos||name.find('/')!=std::string::npos)throw std::runtime_error("F2FS invalid filename");
                out.push_back({name,uint32_t(le(b,p+4)),b[p+10]}); k+=slots;
            }
            (void)bm;
        };
        if(i.raw[3]&4)parse(i.raw,i.base+4,4*(i.count-1));
        else {uint64_t count=(i.size+bs-1)/bs; if(count>blocks)throw std::runtime_error("F2FS excessive directory size");
            for(uint64_t l=0;l<count;l++){uint32_t a=data(i,l);if(!a||a==UINT32_MAX)continue;if(a==UINT32_MAX-1)throw std::runtime_error("F2FS compressed directory");parse(block(a),0,bs);}}
        return out;
    }
    bool allocated(uint64_t a) {
        if(a>=blocks)throw std::runtime_error("F2FS block out of bounds");
        if(a<main)return true;
        uint64_t seg=(a-main)/512, pos=(a-main)%512;
        if(seg>=main_segs)return true; // reserved trailing area
        Bytes e;auto j=sit_j.find(uint32_t(seg));
        if(j!=sit_j.end())e=j->second;
        else {uint64_t index=seg/(bs/74), addr=uint64_t(sit)+index;
            if(bit(sit_bitmap,index))addr+=uint64_t(sit_segs/2)*512;
            if(addr>=nat)throw std::runtime_error("F2FS SIT outside metadata");
            e=slice(block(addr),size_t(seg%(bs/74))*74,74);}
        return (e[2+size_t(pos/8)]&(0x80U>>(pos%8)))!=0;
    }
};
}
#endif
