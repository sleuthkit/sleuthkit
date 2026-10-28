/* Observed FlashFX/VBF + Reliance Nitro 2.7.1 layout from Gerd1986/qnxprobe.
 * MIT attribution in reliance_LICENSE.txt. Fixed observed NAND geometry. */
#ifndef TSK_RELIANCE_READER_H
#define TSK_RELIANCE_READER_H
#include <algorithm>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <set>
#include <stdexcept>
#include <string>
#include <tuple>
#include <vector>
namespace tsk_reliance {
using Bytes=std::vector<uint8_t>;
inline uint64_t val(const Bytes&b,size_t p,size_t n,bool big=false){if(p>b.size()||n>b.size()-p)throw std::runtime_error("truncated Reliance structure");uint64_t v=0;for(size_t k=0;k<n;k++)v|=uint64_t(b[p+k])<<(8*(big?n-1-k:k));return v;}
inline bool magic(const Bytes&b,size_t p,const char*s,size_t n=4){if(p>b.size()||n>b.size()-p)return false;for(size_t k=0;k<n;k++)if(b[p+k]!=uint8_t(s[k]))return false;return true;}
struct Span{uint64_t start,length;};
struct Entry{std::string name;uint64_t number;};
struct Node{uint64_t number=0,parent=0,size=0;uint32_t mode=0,uid=0,gid=0,nlink=1;int64_t atime=0,mtime=0,ctime=0;uint32_t atime_nano=0,mtime_nano=0,ctime_nano=0;std::vector<Span> spans;std::vector<Entry> children;};
struct Region{uint64_t start,end;bool allocated,metadata;};
struct Header{uint32_t client,sequence,serial,total;uint16_t clients,blocks,region;uint64_t unit;};
struct Device{bool raw=false;uint64_t size=0;uint32_t serial=0;std::map<uint32_t,std::pair<uint32_t,uint64_t>> mapping;};
struct Volume{size_t device;uint64_t start;uint32_t blocks,transaction;};
struct Record{uint32_t oid,parent;std::string name;};
struct Allocation{uint32_t first,index,leaf,slot;uint64_t value;};
class Reader{
    std::function<Bytes(uint64_t,size_t)> io;
    std::map<uint64_t,Bytes> cache;std::mutex lock;
    std::vector<Device> devices;std::set<uint64_t> candidates,selected;
    Bytes mainpage(uint64_t physical){Bytes raw=read(physical*4320,4320),b;for(size_t k=0;k<8;k++)b.insert(b.end(),raw.begin()+10+k*538,raw.begin()+10+k*538+512);return b;}
    Bytes page(const Device&d,uint32_t lp){if(!d.raw)return read(uint64_t(lp)*4096,4096);auto it=d.mapping.find(lp);if(it==d.mapping.end())return Bytes(4096,255);return mainpage(it->second.second);}
    Bytes logical(const Device&d,uint64_t at,size_t len){if(at>d.size||len>d.size-at)throw std::runtime_error("Reliance read outside logical device");Bytes out;while(len){size_t skip=size_t(at%4096),take=std::min<size_t>(len,4096-skip);Bytes b=page(d,uint32_t(at/4096));out.insert(out.end(),b.begin()+skip,b.begin()+skip+take);at+=take;len-=take;}return out;}
    Bytes block(const Volume&v,uint32_t n){if(n>=v.blocks)throw std::runtime_error("Reliance block outside volume");return logical(devices.at(v.device),v.start+uint64_t(n)*4096,4096);}
    std::vector<uint32_t> leaves(const Volume&v,uint32_t root,const char*inner,const char*leaf){
        std::vector<uint32_t> pending={root},out;std::set<uint32_t> seen;
        while(!pending.empty()){uint32_t n=pending.back();pending.pop_back();if(!seen.insert(n).second||seen.size()>v.blocks)throw std::runtime_error("cyclic/shared Reliance metadata tree");Bytes b=block(v,n);
            if(magic(b,0,leaf)){out.push_back(n);continue;}if(!magic(b,0,inner))throw std::runtime_error("unexpected Reliance tree block");uint32_t count=uint32_t(val(b,16,4)&0x7fffffff);if(count>(4096-0xab0)/4)throw std::runtime_error("Reliance child array overflow");for(uint32_t k=count;k;k--)pending.push_back(uint32_t(val(b,0xab0+4*(k-1),4)));
        }return out;
    }
    void spans(Node&n,const Volume&v,uint32_t start,uint32_t count){
        const Device&d=devices.at(v.device);uint64_t left=n.size;for(const auto&s:n.spans){if(s.length>left)throw std::runtime_error("extent coverage overflow");left-=s.length;}
        for(uint32_t j=0;j<count&&left;j++){uint64_t logical_page=(v.start/4096)+start+j;size_t take=size_t(std::min<uint64_t>(left,4096));
            if(!d.raw)n.spans.push_back({logical_page*4096,take});else{auto it=d.mapping.find(uint32_t(logical_page));if(it==d.mapping.end())throw std::runtime_error("live file extent has no FlashFX mapping");uint64_t physical=it->second.second*4320;for(size_t k=0;k<8&&take;k++){size_t part=std::min<size_t>(take,512);n.spans.push_back({physical+10+k*538,part});take-=part;}}
            left-=std::min<uint64_t>(left,4096);
        }
    }
    void volume(Volume v,uint64_t folder){
        Bytes mast=logical(devices.at(v.device),v.start+64,128);uint32_t a=uint32_t(val(mast,40,4)),b=uint32_t(val(mast,44,4));Bytes ma,mb;
        if(a<v.blocks)ma=block(v,a);if(b<v.blocks)mb=block(v,b);bool va=magic(ma,0,"META"),vb=magic(mb,0,"META");if(!va&&!vb)throw std::runtime_error("no current Reliance META");Bytes meta=va&&(!vb||val(ma,8,4)>=val(mb,8,4))?ma:mb;v.transaction=uint32_t(val(meta,8,4));
        std::vector<Record> records;std::set<std::tuple<uint32_t,uint32_t,std::string>> unique;
        for(uint32_t leaf:leaves(v,uint32_t(val(meta,16,4)),"IDIR","LDIR")){Bytes blockdata=block(v,leaf);uint32_t count=uint32_t(val(blockdata,16,4)&0x7fffffff);if(count>(0x4a0-24)/8||count>(4096-0x4a0)/20)throw std::runtime_error("Reliance LDIR count overflow");
            for(uint32_t k=0;k<count;){size_t key=24+k*8,slot=0x4a0+k*20;if(blockdata[key+7]!=1){k++;continue;}Record rec;rec.parent=uint32_t(val(blockdata,key,4,true)>>2);rec.oid=uint32_t(val(blockdata,slot+16,4));Bytes base(blockdata.begin()+key,blockdata.begin()+key+7);unsigned fragment=1;
                do{size_t p=0x4a0+k*20;for(size_t c=0;c<16&&blockdata[p+c];c++)rec.name+=char(blockdata[p+c]);k++;fragment++;key=24+k*8;}while(k<count&&std::equal(base.begin(),base.end(),blockdata.begin()+key)&&blockdata[key+7]==fragment);
                if(!rec.oid||rec.name.empty()||rec.name=="."||rec.name==".."||rec.name.find('/')!=std::string::npos)throw std::runtime_error("invalid Reliance name/object");if(unique.insert({rec.parent,rec.oid,rec.name}).second)records.push_back(rec);
            }
        }
        if(records.empty())throw std::runtime_error("no decoded Reliance namespace records");
        std::map<uint32_t,std::vector<Allocation>> allocation_records;
        for(uint32_t leaf:leaves(v,uint32_t(val(meta,20,4)),"IALC","LALC")){Bytes bdata=block(v,leaf);uint32_t count=uint32_t(val(bdata,16,4)&0x7fffffff);if(count>254)throw std::runtime_error("Reliance LALC count overflow");for(uint32_t k=0;k<count;k++){uint32_t first=uint32_t(val(bdata,24+k*8,4,true));allocation_records[first>>2].push_back({first,uint32_t(val(bdata,28+k*8,4,true)),leaf,k,val(bdata,0x808+k*8,8)});}}
        for(auto&kv:allocation_records)std::sort(kv.second.begin(),kv.second.end(),[](const Allocation&a,const Allocation&b){return std::tie(a.first,a.index,a.leaf,a.slot)<std::tie(b.first,b.index,b.leaf,b.slot);});
        std::map<uint32_t,uint32_t> parent_counts;std::set<uint32_t> object_ids,dirs;for(const auto&r:records){parent_counts[r.parent]++;object_ids.insert(r.oid);dirs.insert(r.parent);}
        uint32_t rootid=2;if(!parent_counts.count(2)){std::pair<uint32_t,uint32_t> best={0,0};for(const auto&kv:parent_counts)if(!object_ids.count(kv.first))best=std::max(best,{kv.second,kv.first});if(!best.first)throw std::runtime_error("cannot establish Reliance root");rootid=best.second;}
        std::map<uint32_t,uint64_t> ids;ids[rootid]=folder;for(const auto&r:records)if(!ids.count(r.oid)){ids[r.oid]=nodes.size();Node n;n.number=nodes.size();nodes.push_back(n);}
        std::set<std::pair<uint64_t,std::string>> names;std::set<uint32_t> populated;
        for(const auto&r:records){if(r.oid==rootid||!ids.count(r.parent))throw std::runtime_error("orphaned/cyclic Reliance parent");uint64_t id=ids.at(r.oid),parent=ids.at(r.parent);if(!names.insert({parent,r.name}).second)throw std::runtime_error("duplicate Reliance child name");nodes[parent].children.push_back({r.name,id});
            if(!populated.insert(r.oid).second){nodes[id].nlink++;continue;}Node&n=nodes[id];n.number=id;n.parent=parent;n.mode=dirs.count(r.oid)?0040755:0100644;bool have_size=false;
            for(const auto&ar:allocation_records[r.oid])if((ar.first&3)==1){if(ar.index==2&&!have_size){n.size=(ar.value&0x10)?0:ar.value>>16;have_size=true;}if(ar.index>=3&&ar.index<=5){int64_t seconds=int64_t(ar.value/1000);uint32_t nano=uint32_t(ar.value%1000)*1000000;switch(ar.index){case 3:n.atime=seconds;n.atime_nano=nano;break;case 4:n.mtime=seconds;n.mtime_nano=nano;break;case 5:n.ctime=seconds;n.ctime_nano=nano;break;}}}
            if((n.mode&0170000)==0040000)n.size=0;else{if(!have_size)throw std::runtime_error("file size record not decoded");for(const auto&ar:allocation_records[r.oid])if((ar.first&3)==0){uint32_t start=uint32_t(ar.value),count=uint32_t(ar.value>>32);if(!start||start>=v.blocks||!count||count>v.blocks-start||count>4096)throw std::runtime_error("invalid Reliance file extent");spans(n,v,start,count);}uint64_t covered=0;for(const auto&s:n.spans)covered+=s.length;if(covered!=n.size)throw std::runtime_error("Reliance file extents do not cover declared size");}
        }
        // Reachability proves the decoded parent relation has no hidden cycles.
        std::set<uint64_t> reached;std::vector<uint64_t> pending={folder};while(!pending.empty()){uint64_t id=pending.back();pending.pop_back();if(!reached.insert(id).second)continue;for(const auto&e:nodes[id].children){if((nodes[e.number].mode&0170000)==0040000&&reached.count(e.number))throw std::runtime_error("Reliance directory cycle");pending.push_back(e.number);}}
        if(reached.size()!=ids.size())throw std::runtime_error("unreachable Reliance objects");volumes.push_back(v);
    }
public:
    uint64_t size=0,root=1;std::vector<Node> nodes;std::vector<Volume> volumes;std::vector<Region> allocation;bool raw=false;
    Bytes read(uint64_t at,size_t length){if(at>size||length>size-at)throw std::runtime_error("Reliance read outside source");Bytes out;while(length){uint64_t key=(at/65536)*65536;Bytes b;{std::lock_guard<std::mutex>g(lock);auto it=cache.find(key);if(it!=cache.end())b=it->second;}if(b.empty()){size_t take=size_t(std::min<uint64_t>(65536,size-key));b=io(key,take);if(b.size()!=take)throw std::runtime_error("short Reliance read");std::lock_guard<std::mutex>g(lock);if(cache.size()>=64)cache.clear();cache[key]=b;}size_t skip=size_t(at-key),take=std::min<size_t>(length,b.size()-skip);out.insert(out.end(),b.begin()+skip,b.begin()+skip+take);at+=take;length-=take;}return out;}
    const Node&node(uint64_t id)const{if(!id||id>=nodes.size())throw std::runtime_error("invalid Reliance inode");return nodes[size_t(id)];}
    Region flags(uint64_t at)const{if(at>=size)throw std::runtime_error("address outside source");auto it=std::upper_bound(allocation.begin(),allocation.end(),at,[](uint64_t a,const Region&r){return a<r.start;});return *--it;}
    Reader(std::function<Bytes(uint64_t,size_t)>fn,uint64_t length):io(fn),size(length){
        if(size<4096)throw std::runtime_error("Reliance source too short");nodes.resize(2);nodes[1].number=1;nodes[1].mode=0040755;Bytes first=read(0,size_t(std::min<uint64_t>(4320,size)));
        Bytes main;if(first.size()==4320)for(size_t k=0;k<8;k++)main.insert(main.end(),first.begin()+10+k*538,first.begin()+10+k*538+512);
        const char sig[]={'\xcc','\xdd','D','L','_','F','S','4','.','0','0'};
        raw=magic(main,0,sig,11);
        if(!raw&&!magic(first,64,"MAST")&&size%(uint64_t(4320)*128)==0){for(uint64_t unit=1;unit<size/(uint64_t(4320)*128);unit++)if(magic(mainpage(unit*128),0,sig,11)){raw=true;break;}}
        if(raw){const uint64_t unit_size=uint64_t(4320)*128;if(size%unit_size)throw std::runtime_error("raw FlashFX dump must contain complete 4320-byte x 128-page units");
            using Key=std::tuple<uint32_t,uint32_t,uint16_t,uint16_t,uint16_t,uint16_t>;std::map<Key,std::vector<Header>> groups;
            for(uint64_t unit=0;unit<size/unit_size;unit++){Bytes b=mainpage(unit*128);if(!magic(b,0,sig,11))continue;uint32_t sum=0;for(size_t k=0;k<54;k++)sum+=b[k];if((sum&65535)!=val(b,54,2))throw std::runtime_error("FlashFX header checksum mismatch");
                if(val(b,42,2)!=4096||!val(b,32,4)||!val(b,50,2)||val(b,48,2)<2||val(b,48,2)>128||val(b,16,4)%4096)throw std::runtime_error("unsupported FlashFX geometry");Header h={uint32_t(val(b,16,4)),uint32_t(val(b,28,4)),uint32_t(val(b,24,4)),uint32_t(val(b,32,4)),uint16_t(val(b,50,2)),uint16_t(val(b,48,2)),uint16_t(val(b,44,2)),unit};groups[{h.serial,h.total,4096,h.clients,h.blocks,h.region}].push_back(h);
            }
            std::vector<std::vector<Header>> ordered;for(const auto&kv:groups)if(kv.second.size()>=2)ordered.push_back(kv.second);
            std::sort(ordered.begin(),ordered.end(),[](const std::vector<Header>&a,const std::vector<Header>&b){return a.front().unit<b.front().unit;});
            for(const auto&units:ordered){const Header&h=units.front();Device d;d.raw=true;d.serial=h.serial;d.size=uint64_t(h.clients)*h.total*4096;if(!d.size||d.size>size||d.size/4096>0xffffffff)throw std::runtime_error("invalid FlashFX logical size");for(const Header&u:units)for(uint32_t p=1;p<u.blocks;p++){uint64_t physical=u.unit*128+p;Bytes tag=read(physical*4320+2,2);uint16_t word=uint16_t(val(tag,0,2));if((word>>12)!=4)continue;uint64_t lp=uint64_t(u.client/4096)+(word&4095);if(lp>=d.size/4096)throw std::runtime_error("FlashFX allocation outside device");candidates.insert(physical);auto candidate=std::make_pair(u.sequence,physical);auto old=d.mapping.find(uint32_t(lp));if(old==d.mapping.end()||candidate>old->second)d.mapping[uint32_t(lp)]=candidate;}for(const auto&mp:d.mapping)selected.insert(mp.second.second);devices.push_back(d);}
            if(devices.empty())throw std::runtime_error("no validated FlashFX device group");
        }else{if(size%4096)throw std::runtime_error("logical Reliance image not block aligned");Device d;d.size=size;devices.push_back(d);}
        for(size_t di=0;di<devices.size();di++){const Device&d=devices[di];uint64_t group=1;if(raw){group=nodes.size();Node n;n.number=group;n.parent=1;n.mode=0040755;nodes.push_back(n);nodes[1].children.push_back({"FlashFX_"+std::to_string(di+1),group});}
            for(uint64_t lp=0;lp<d.size/4096;lp++){if(d.raw&&!d.mapping.count(uint32_t(lp)))continue;Bytes b=page(d,uint32_t(lp));if(!magic(b,64,"MAST"))continue;uint32_t bs=uint32_t(val(b,72,4)),count=uint32_t(val(b,76,4));if(bs!=4096||!count||uint64_t(count)*4096>d.size-lp*4096)throw std::runtime_error("invalid Reliance MAST geometry");Volume v={di,lp*4096,count,0};uint64_t folder=nodes.size();Node n;n.number=folder;n.parent=group;n.mode=0040755;nodes.push_back(n);nodes[group].children.push_back({"Reliance_"+std::to_string(volumes.size()+1)+"_0x"+std::to_string(v.start),folder});volume(v,folder);lp+=count-1;}
        }
        if(volumes.empty())throw std::runtime_error("no Reliance Nitro volume found");
        if(!raw)allocation.push_back({0,size,true,false});else for(uint64_t p=0;p<size/4320;p++){bool live=!candidates.count(p)||selected.count(p);uint64_t at=p*4320;allocation.push_back({at,at+10,true,true});for(size_t k=0;k<8;k++){uint64_t part=at+10+k*538;allocation.push_back({part,part+512,live,false});allocation.push_back({part+512,part+538,true,true});}allocation.push_back({at+4314,at+4320,true,true});}
    }
};
}
#endif
