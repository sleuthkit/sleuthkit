/* Read-only QNX ETFS transaction reader.
 * Layout and replay reference: Gerd1986/qnxprobe (MIT), EtfsWalker;
 * NFI/qnxmount qnxmount/etfs/parser.ksy (Apache-2.0). See etfs_LICENSE.txt.
 */
#ifndef TSK_ETFS_READER_H
#define TSK_ETFS_READER_H
#include <algorithm>
#include <cstdint>
#include <functional>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>
namespace tsk_etfs {
using Bytes = std::vector<uint8_t>;
inline uint32_t le(const Bytes &b, size_t p, size_t n) {
    if (p > b.size() || n > b.size()-p) throw std::runtime_error("truncated ETFS structure");
    uint32_t v=0; for(size_t i=0;i<n;i++) v|=uint32_t(b[p+i])<<(8*i); return v;
}
struct Span { uint64_t start,length; bool hole=false; };
struct Entry { std::string name; uint64_t number; };
struct Node {
    uint64_t number=0,parent=0,size=0;
    uint32_t mode=0,uid=0,gid=0,atime=0,mtime=0,ctime=0,nlink=1;
    std::string name;
    std::vector<Span> spans;
    std::vector<Entry> children;
};
struct Region { uint64_t start,end; bool allocated,metadata; };
struct Transaction { uint32_t sequence; uint64_t page; };
class Reader {
    std::function<Bytes(uint64_t,size_t)> io;
    using Pages=std::map<uint32_t,Transaction>;
    std::map<uint32_t,Pages> current;
    static std::string text(const Bytes &b,size_t pos,size_t length) {
        size_t end=pos; while(end<pos+length && b.at(end)) ++end;
        return std::string(reinterpret_cast<const char *>(b.data()+pos),end-pos);
    }
    template<class F> void scan(uint32_t pageSize,uint64_t limit,F consume) {
        uint64_t stride=uint64_t(pageSize)+16;
        size_t batch=std::max<size_t>(1,1048576/stride);
        for(uint64_t first=0;first<limit;) {
            size_t count=size_t(std::min<uint64_t>(batch,limit-first));
            Bytes b=read(first*stride,count*size_t(stride));
            for(size_t k=0;k<count;k++) {
                size_t at=k*size_t(stride)+pageSize;
                uint32_t fid=le(b,at,4),cluster=le(b,at+4,4);
                if(fid>=65535 || (b[at+10]&15)>1) continue;
                if(consume(first+k,fid,cluster,le(b,at+12,4))) return;
            }
            first+=count;
        }
    }
    bool probe(uint32_t p) {
        uint64_t stride=uint64_t(p)+16;
        if(size<stride || size%stride) return false;
        bool found=false;
        scan(p,std::min<uint64_t>(size/stride,200000),[&](uint64_t page,uint32_t fid,uint32_t cluster,uint32_t) {
            if(fid!=1 || cluster!=0) return false;
            Bytes b=read(page*stride,p);
            if(le(b,0,2)==0xffff || le(b,2,2)==0xffff || (le(b,4,4)&0170000)!=0040000) return false;
            const char *reserved[]={".filetable",".badblks",".counts",".lost+found",".reserved"};
            unsigned hits=0;
            for(unsigned id=1;id<=5;id++) if(le(b,id*64,2)!=0xffff && le(b,id*64+2,2)!=0xffff && text(b,id*64+32,32)==reserved[id-1]) ++hits;
            found=hits>=3; return found;
        });
        return found;
    }
    void build() {
        auto ft=current.find(1);
        if(ft==current.end()) throw std::runtime_error("ETFS file table missing");
        std::map<uint32_t,Bytes> records;
        uint32_t per=page_size/64;
        for(const auto &item:ft->second) {
            if(item.first>=65536/per) throw std::runtime_error("ETFS file table exceeds file-id space");
            Bytes b=read(item.second.page*unit,page_size);
            for(uint32_t j=0;j<per;j++) records.emplace(item.first*per+j,Bytes(b.begin()+j*64,b.begin()+(j+1)*64));
        }
        for(const auto &item:records) {
            uint32_t fid=item.first; const Bytes &b=item.second;
            uint32_t ext=le(b,0,2),parent=le(b,2,2),mode=le(b,4,4),kind=mode&0170000;
            if(ext==0xffff || ext==0x8000 || parent==0xffff) continue;
            if(kind!=0040000 && kind!=0100000 && kind!=0120000 && kind!=0010000 && kind!=0020000 && kind!=0060000 && kind!=0140000) continue;
            Node n; n.number=uint64_t(fid)+1; n.parent=uint64_t(parent)+1; n.mode=mode;
            n.uid=le(b,8,4);n.gid=le(b,12,4);n.atime=le(b,16,4);n.mtime=le(b,20,4);n.ctime=le(b,24,4);n.size=le(b,28,4);
            n.name=text(b,32,32);
            if(ext) {
                auto e=records.find(ext);
                if(e!=records.end() && le(e->second,0,2)==0x8000 && le(e->second,2,2)==fid && e->second[63]==0)
                    n.name+=text(e->second,4,59);
            }
            if(fid && (n.name.empty() || n.name=="." || n.name==".." || n.name.find('/')!=std::string::npos)) continue;
            if(kind==0040000) n.size=0;
            const auto data=current.find(fid);
            uint64_t logical=0;
            if(data!=current.end()) for(const auto &page:data->second) {
                uint64_t start=uint64_t(page.first)*page_size;
                if(start>=n.size) break;
                if(logical<start) n.spans.push_back({0,start-logical,true});
                uint64_t length=std::min<uint64_t>(page_size,n.size-start);
                n.spans.push_back({page.second.page*unit,length,false});logical=start+length;
            }
            if(logical<n.size) n.spans.push_back({0,n.size-logical,true});
            nodes.emplace(n.number,std::move(n));
        }
        if(!nodes.count(root) || (nodes.at(root).mode&0170000)!=0040000) throw std::runtime_error("ETFS active root missing");
        // Keep malformed/missing parent chains visible without allowing recursive loops.
        const uint64_t recovered=65537;
        bool needRecovered=false;
        for(auto &item:nodes) {
            Node &n=item.second; if(n.number==root) continue;
            std::set<uint64_t> seen{n.number}; uint64_t parent=n.parent;bool valid=true;
            while(parent!=root && parent!=recovered) {
                auto p=nodes.find(parent);
                if(p==nodes.end() || (p->second.mode&0170000)!=0040000 || !seen.insert(parent).second) {valid=false;break;}
                parent=p->second.parent;
            }
            if(!valid) {n.parent=recovered;needRecovered=true;}
        }
        if(needRecovered) {
            Node n;n.number=recovered;n.parent=root;n.mode=0040755;n.name="$ETFS_Orphans";
            while(std::any_of(nodes.begin(),nodes.end(),[&](const auto &v){return v.second.parent==root && v.second.name==n.name;})) n.name+="_";
            nodes.emplace(recovered,std::move(n));
        }
        for(const auto &item:nodes) if(item.first!=root) nodes.at(item.second.parent).children.push_back({item.second.name,item.first});
        // Physical byte allocation: obsolete transactions remain unallocated evidence.
        std::map<uint64_t,bool> active;
        for(const auto &file:current) if(nodes.count(uint64_t(file.first)+1)) {
            for(const auto &page:file.second) {
                if(file.first!=1 && uint64_t(page.first)*page_size>=nodes.at(uint64_t(file.first)+1).size) continue;
                active[page.second.page]=(file.first==1);
            }
        }
        uint64_t at=0;
        for(const auto &page:active) {
            uint64_t begin=page.first*unit;
            if(at<begin) allocation.push_back({at,begin,false,false});
            allocation.push_back({begin,begin+page_size,true,page.second});
            allocation.push_back({begin+page_size,begin+unit,true,true});at=begin+unit;
        }
        if(at<size) allocation.push_back({at,size,false,false});
    }
public:
    uint64_t size,unit=0,root=1;
    uint32_t page_size=0;
    std::map<uint64_t,Node> nodes;
    std::vector<Region> allocation;
    Reader(std::function<Bytes(uint64_t,size_t)> source,uint64_t length):io(std::move(source)),size(length) {
        for(uint32_t p:{512,1024,2048,4096,8192,16384}) if(probe(p)) {page_size=p;break;}
        if(!page_size) throw std::runtime_error("no ETFS file table / transaction geometry");
        unit=uint64_t(page_size)+16;
        scan(page_size,size/unit,[&](uint64_t page,uint32_t fid,uint32_t cluster,uint32_t seq) {
            auto &pages=current[fid];auto it=pages.find(cluster);
            if(it==pages.end() || seq>=it->second.sequence) pages[cluster]={seq,page};
            return false;
        });
        build();
    }
    Bytes read(uint64_t pos,size_t length) const {
        if(pos>size || length>size-pos) throw std::runtime_error("ETFS read outside image");
        Bytes b=io(pos,length);if(b.size()!=length) throw std::runtime_error("ETFS short image read");return b;
    }
    const Node &node(uint64_t id) const {
        auto it=nodes.find(id);if(it==nodes.end()) throw std::runtime_error("ETFS inode is not live");return it->second;
    }
    const Region &flags(uint64_t addr) const {
        auto it=std::upper_bound(allocation.begin(),allocation.end(),addr,[](uint64_t a,const Region &r){return a<r.start;});
        if(it==allocation.begin() || addr>=(--it)->end) throw std::runtime_error("ETFS block outside image");
        return *it;
    }
};
}
#endif
