/* Native read-only QNX EFS/F3S reader adapted from abrignoni/qnxprobe.
 * Copyright (c) 2026 Alexis Brignoni. MIT: see efs_LICENSE.txt.
 * Byte-addressed extents retain exact provenance across partition folders. */
#ifndef TSK_EFS_READER_H
#define TSK_EFS_READER_H
#include <cstdint>
#include <vector>
#include <map>
#include <set>
#include <string>
#include <stdexcept>
#include <functional>
#include <mutex>
#include <algorithm>
#include <cstdio>
namespace tsk_efs {
using Bytes=std::vector<uint8_t>;
using Ptr=std::pair<uint16_t,uint16_t>;
inline uint64_t integer(const Bytes &b,size_t p,size_t n,bool big){
    if(p>b.size()||n>b.size()-p)throw std::runtime_error("EFS truncated structure");
    uint64_t v=0;for(size_t i=0;i<n;i++)v|=uint64_t(b[p+i])<<(8*(big?n-1-i:i));return v;
}
struct Span{uint64_t start,length;};
struct Extent{uint32_t status,status1,physical,index;uint64_t offset;uint16_t length;Ptr next,super;};
struct Unit{std::vector<Extent> extents;};
struct Part{uint64_t base,size,unit;uint16_t index,total,spare,align;bool big;Ptr root;std::vector<Unit> units;std::map<uint16_t,uint32_t> logical;};
struct Entry{std::string name;uint64_t number;};
struct Node{uint64_t number=0,parent=0,size=0;uint16_t mode=0;uint32_t uid=0,gid=0,mtime=0,ctime=0,nlink=1;std::vector<Span> spans;std::vector<Entry> children;};
struct Region{uint64_t start,end;bool allocated,metadata;};
class Reader{
    std::function<Bytes(uint64_t,size_t)> io;
    std::map<uint64_t,Bytes> cache;
    std::mutex cache_lock;
    std::vector<Span> occupied,metadata;
    static bool null(Ptr p){return p.first==0xffff&&p.second==0xffff;}
    Ptr pointer(const Bytes &b,size_t at,bool big){return {uint16_t(integer(b,at,2,big)),uint16_t(integer(b,at+2,2,big))};}
    bool info(const Bytes &b,bool big,uint64_t &unit){
        if(b.size()<16||b[3]!=0xff||b[6]!=0xff||b[7]!=0xff||integer(b,0,2,big)!=16)return false;
        uint64_t pow=integer(b,4,2,big);if(pow<9||pow>30)return false;unit=uint64_t(1)<<pow;return true;
    }
    bool candidate(uint64_t sig,Part &p){
        if(sig<4||sig-4>size||24>size-(sig-4))return false;
        Bytes b=read(sig-4,24);bool big;
        if(integer(b,0,2,false)==24)big=false;else if(integer(b,0,2,true)==24)big=true;else return false;
        if(b[2]!=3||b[3]!=0)return false;
        p.index=uint16_t(integer(b,12,2,big));p.total=uint16_t(integer(b,14,2,big));
        p.spare=uint16_t(integer(b,16,2,big));p.align=uint16_t(integer(b,18,2,big));p.root=pointer(b,20,big);p.big=big;
        if(!p.total||p.index>=p.total||p.spare>=p.total||p.align>16)return false;
        // Boot text is normally in the first 512 bytes. Also try the
        // reference's power-of-two unit boundaries, supporting larger heads.
        std::set<uint64_t> starts;
        for(uint64_t a=sig-4>512?sig-4-512:0;a<=sig-4;a++)starts.insert(a);
        for(unsigned pow=9;pow<=30;pow++)starts.insert(sig&~((uint64_t(1)<<pow)-1));
        for(uint64_t a:starts){
            if(a>size||16>size-a)continue;
            uint64_t unit=0;if(!info(read(a,16),big,unit)||unit>size-a||sig-4-a>=unit)continue;
            if(uint64_t(p.index)*unit>a)continue;
            uint64_t base=a-uint64_t(p.index)*unit,length=uint64_t(p.total)*unit;
            if(base>size||length>size-base)continue;
            Bytes h=read(a+unit-96,32);
            uint64_t off=((uint64_t(h[19])<<16)+integer(h,20,2,big))<<p.align;
            uint32_t status=uint32_t(integer(h,0,4,big));
            if(off!=sig-4-a||integer(h,22,2,big)<24||(status&0x300)!=0x100||(status&0x70)!=0x30)continue;
            p.base=base;p.size=length;p.unit=unit;return true;
        }return false;
    }
    Span span(const Part &p,const Extent &e){return {p.base+uint64_t(e.physical)*p.unit+e.offset,e.length};}
    const Extent &raw(const Part &p,Ptr ptr){
        auto it=p.logical.find(ptr.first);if(it==p.logical.end())throw std::runtime_error("EFS unresolved logical unit");
        const auto &exts=p.units[it->second].extents;
        if(ptr.second>=exts.size())throw std::runtime_error("EFS extent index outside unit");
        return exts[ptr.second];
    }
    const Extent &current(const Part &p,Ptr ptr){
        std::set<std::pair<uint32_t,uint32_t>> seen;
        const Extent *e=&raw(p,ptr);
        while(!(e->status&4)){
            if(!seen.insert({e->physical,e->index}).second)throw std::runtime_error("EFS cyclic supersede chain");
            e=&raw(p,e->super);
        }return *e;
    }
    std::vector<const Extent *> chain(const Part &p,Ptr ptr){
        std::vector<const Extent *> out;if(null(ptr))return out;
        std::set<std::pair<uint32_t,uint32_t>> seen;
        while(true){const Extent &e=current(p,ptr);
            if(!seen.insert({e.physical,e.index}).second)throw std::runtime_error("EFS cyclic next chain");
            out.push_back(&e);if(e.status&2)break;ptr=e.next;
        }return out;
    }
    struct Dirent{std::string name;Node node;Ptr first;};
    Dirent dirent(const Part &p,const Extent &e,bool root=false){
        if((e.status&0x300)!=0x200||(e.status&0x70)!=0x30)throw std::runtime_error("EFS invalid live directory entry");
        Span s=span(p,e);Bytes b=read(s.start,size_t(s.length));
        if(b.size()<8||integer(b,0,2,p.big)!=8)throw std::runtime_error("EFS invalid directory record");
        size_t n=b[3],stat=8+((n+3)&~size_t(3));
        if(!n||stat>b.size()||20>b.size()-stat||integer(b,stat,2,p.big)<20)throw std::runtime_error("EFS truncated stat or filename");
        size_t len=0;while(len<n&&b[8+len])len++;
        std::string name(reinterpret_cast<const char *>(b.data()+8),len);
        if(!root&&(name.empty()||name.find('/')!=std::string::npos||name=="."||name==".."))throw std::runtime_error("EFS unsafe filename");
        Node node;node.mode=uint16_t(integer(b,stat+2,2,p.big));node.uid=uint32_t(integer(b,stat+4,4,p.big));
        node.gid=uint32_t(integer(b,stat+8,4,p.big));node.mtime=uint32_t(integer(b,stat+12,4,p.big));node.ctime=uint32_t(integer(b,stat+16,4,p.big));
        return {name,node,pointer(b,4,p.big)};
    }
    void parse(Part &p){
        p.units.resize(p.total);
        for(uint32_t u=0;u<p.total;u++){
            auto &exts=p.units[u].extents;uint64_t at=p.base+uint64_t(u)*p.unit;
            bool ended=false;
            for(uint32_t i=0;i<std::min<uint64_t>(p.unit/32,65536);i++){
                Bytes b=read(at+p.unit-32*(uint64_t(i)+1),32);
                Extent e={uint32_t(integer(b,0,4,p.big)),uint32_t(integer(b,4,4,p.big)),u,i,
                    ((uint64_t(b[19])<<16)+integer(b,20,2,p.big))<<p.align,uint16_t(integer(b,22,2,p.big)),pointer(b,24,p.big),pointer(b,28,p.big)};
                exts.push_back(e);if(e.status&0x80){ended=true;break;}
            }
            if(!ended)throw std::runtime_error("EFS unit has no terminating extent header");
            uint64_t end=p.unit-32*exts.size();
            metadata.push_back({at+end,p.unit-end});
            for(const auto &e:exts){
                if((e.status&0x70)==0x70)continue; // erased/free sentinel has undefined text fields
                if(e.offset>end||e.length>end-e.offset)throw std::runtime_error("EFS extent overlaps its header array");
                if((e.status&0x300)!=0x300||(e.status&0x70)==0)metadata.push_back(span(p,e));
            }
            bool spare=exts.size()==1||(exts.size()==2&&exts[1].status1==0xffffffff);
            if(!spare&&exts.size()>=2){const Extent &e=exts[1];Span s=span(p,e);Bytes logi=read(s.start,size_t(s.length));
                if(logi.size()<8||integer(logi,0,2,p.big)<8)throw std::runtime_error("EFS invalid logical-unit record");
                p.logical[uint16_t(integer(logi,2,2,p.big))]=u;
            }
        }
    }
    uint64_t add(Node node,uint64_t parent){node.number=nodes.size();node.parent=parent;nodes.push_back(node);return node.number;}
    void tree(Part &p,uint64_t rootid,Ptr first){
        std::vector<std::pair<uint64_t,Ptr>> todo={{rootid,first}};
        std::set<Ptr> dirs;dirs.insert(first);
        for(size_t index=0;index<todo.size();index++){
            uint64_t parent=todo[index].first;
            for(const Extent *e:chain(p,todo[index].second)){
                if(!e->length)break;
                if((e->status&0x70)!=0x30)continue; // deleted records are traversed but not live names
                Dirent d=dirent(p,*e);uint16_t kind=d.node.mode&0170000;
                if(kind==0100000||kind==0120000){
                    for(const Extent *data:chain(p,d.first)){
                        if((data->status&0x300)!=0x300||(data->status&0x70)!=0x30)throw std::runtime_error("EFS invalid live file extent");
                        Span s=span(p,*data);if(s.length){d.node.spans.push_back(s);d.node.size+=s.length;occupied.push_back(s);}
                    }
                }
                uint64_t id=add(d.node,parent);nodes[parent].children.push_back({d.name,id});
                if(kind==0040000){
                    if(!null(d.first)&&!dirs.insert(d.first).second)throw std::runtime_error("EFS cyclic or shared directory chain");
                    todo.push_back({id,d.first});
                }
            }
        }
    }
    void regions(){
        occupied.insert(occupied.end(),metadata.begin(),metadata.end());
        std::map<uint64_t,std::pair<int64_t,int64_t>> events;
        events[0];events[size];
        auto add_events=[&](const std::vector<Span>&spans,bool meta){for(const auto&s:spans){if(!s.length)continue;
            if(s.start>size||s.length>size-s.start)throw std::runtime_error("EFS allocation span out of bounds");
            if(meta){events[s.start].second++;events[s.start+s.length].second--;}
            else {events[s.start].first++;events[s.start+s.length].first--;}}};
        add_events(occupied,false);add_events(metadata,true);
        int64_t alloc=0,meta=0;uint64_t prev=0;
        for(const auto &entry:events){uint64_t at=entry.first;
            if(at>prev){Region r={prev,at,alloc>0,meta>0};
                if(!allocation.empty()&&allocation.back().allocated==r.allocated&&allocation.back().metadata==r.metadata)allocation.back().end=at;
                else allocation.push_back(r);
            }alloc+=entry.second.first;meta+=entry.second.second;prev=at;
        }
    }
public:
    uint64_t size,root=1;
    std::vector<Part> partitions;
    std::vector<Node> nodes;
    std::vector<Region> allocation;
    Reader(std::function<Bytes(uint64_t,size_t)> reader,uint64_t bytes):io(reader),size(bytes){
        if(size<512)throw std::runtime_error("EFS image too short");
        std::map<uint64_t,Part> found;const std::string signature="QSSL_F3S";
        for(uint64_t pos=0;pos<size;){size_t length=size_t((size-pos)<1048584?(size-pos):1048584);
            Bytes b=read(pos,length);auto it=b.begin();
            while((it=std::search(it,b.end(),signature.begin(),signature.end()))!=b.end()){
                uint64_t local=uint64_t(it-b.begin());if(local>=1048576)break;
                Part p;if(candidate(pos+local,p))found.emplace(p.base,p);++it;
            }if(size-pos<=1048576)break;pos+=1048576;
        }
        uint64_t end=0;for(auto &entry:found){Part p=entry.second;if(p.base<end)continue;
            if(p.base>end)metadata.push_back({end,p.base-end});
            end=p.base+p.size;partitions.push_back(p);
        }
        if(partitions.empty())throw std::runtime_error("EFS no structurally valid F3S partition");
        if(end<size)metadata.push_back({end,size-end});
        nodes.push_back(Node());Node container;container.mode=0040755;add(container,1);
        for(size_t i=0;i<partitions.size();i++){
            Part &p=partitions[i];parse(p);Dirent d=dirent(p,current(p,p.root),true);
            if((d.node.mode&0170000)!=0040000)throw std::runtime_error("EFS root is not a directory");
            uint64_t id=add(d.node,root);char label[80];
            std::snprintf(label,sizeof(label),"Partition_%02u_0x%08llx",unsigned(i+1),(unsigned long long)p.base);
            nodes[root].children.push_back({label,id});tree(p,id,d.first);
        }regions();
    }
    Bytes read(uint64_t at,size_t length){
        if(at>size||length>size-at)throw std::runtime_error("EFS read outside image");
        Bytes out;out.reserve(length);
        while(length){uint64_t key=at/65536*65536;Bytes b;
            {std::lock_guard<std::mutex> lock(cache_lock);auto it=cache.find(key);if(it!=cache.end())b=it->second;}
            if(b.empty()){size_t n=size_t((size-key)<65536?(size-key):65536);b=io(key,n);
                if(b.size()!=n)throw std::runtime_error("EFS short image read");
                std::lock_guard<std::mutex> lock(cache_lock);if(cache.size()>=64)cache.clear();cache[key]=b;
            }
            size_t off=size_t(at-key),take=std::min(length,b.size()-off);
            out.insert(out.end(),b.begin()+off,b.begin()+off+take);at+=take;length-=take;
        }return out;
    }
    const Node &node(uint64_t id)const{if(id<1||id>=nodes.size())throw std::runtime_error("EFS invalid inode number");return nodes[size_t(id)];}
    Region flags(uint64_t byte)const{
        if(byte>=size)throw std::runtime_error("EFS address outside image");
        auto it=std::upper_bound(allocation.begin(),allocation.end(),byte,[](uint64_t n,const Region&r){return n<r.start;});
        if(it==allocation.begin())throw std::runtime_error("EFS allocation map unavailable");
        return *--it;
    }
};
}
#endif
