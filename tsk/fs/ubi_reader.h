/* Native read-only UBI/UBIFS, adapted from abrignoni/qnxprobe (MIT).
 * See ubi_LICENSE.txt. CRC failures are never silently repaired. */
#ifndef TSK_UBI_READER_H
#define TSK_UBI_READER_H
#include <algorithm>
#include <cstdint>
#include <functional>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>
#ifdef HAVE_LIBZ
#include <zlib.h>
#endif
namespace tsk_ubi {
using Bytes=std::vector<uint8_t>;
inline uint64_t num(const Bytes&b,size_t p,size_t n,bool big=false){
    if(p>b.size()||n>b.size()-p)throw std::runtime_error("truncated structure");
    uint64_t v=0;for(size_t i=0;i<n;i++)v|=uint64_t(b[p+i])<<(8*(big?n-i-1:i));return v;
}
inline uint32_t crc(const Bytes&b,size_t start,size_t length){
    if(start>b.size()||length>b.size()-start)throw std::runtime_error("CRC range");
    uint32_t c=0xffffffff;for(size_t k=start;k<start+length;k++){c^=b[k];for(int j=0;j<8;j++)c=(c>>1)^(0xedb88320U&uint32_t(-int(c&1)));}return c;
}
inline Bytes lzo(const Bytes&s){
    Bytes out;size_t ip=0;unsigned state=0;
    auto get=[&](){if(ip>=s.size())throw std::runtime_error("truncated LZO");return unsigned(s[ip++]);};
    auto literal=[&](size_t n){if(n>s.size()-ip||n>4096-out.size())throw std::runtime_error("LZO literal overflow");out.insert(out.end(),s.begin()+ip,s.begin()+ip+n);ip+=n;};
    auto match=[&](size_t d,size_t n){if(!d||d>out.size()||n>4096-out.size())throw std::runtime_error("LZO match overflow");while(n--)out.push_back(out[out.size()-d]);};
    auto extend=[&](unsigned base){unsigned n=0,c;while((c=get())==0){n+=255;if(n>4096)throw std::runtime_error("LZO length overflow");}return n+base+c;};
    if(s.size()<3||(s.size()>=5&&s[0]==17))throw std::runtime_error("unsupported LZO stream");
    if(s[0]>17){unsigned t=get()-17;literal(t);state=t<4?t:4;}
    for(;;){unsigned t=get(),next=0;size_t dist,len;
        if(t<16){if(!state){len=t?t:extend(15);literal(len+3);state=4;continue;}next=t&3;dist=(t>>2)+(get()<<2)+(state==4?2049:1);match(dist,state==4?3:2);}
        else if(t>=64){next=t&3;dist=((t>>2)&7)+(get()<<3)+1;match(dist,(t>>5)+1);}
        else if(t>=32){len=t&31;if(!len)len=extend(31);unsigned a=get(),b=get(),v=a|(b<<8);next=v&3;match((v>>2)+1,len+2);}
        else{len=t&7;if(!len)len=extend(7);unsigned a=get(),b=get(),v=a|(b<<8);next=v&3;dist=((t&8)<<11)+(v>>2);if(!dist){if(len!=1||ip!=s.size())throw std::runtime_error("bad LZO end");break;}match(dist+0x4000,len+2);}
        state=next;literal(next);
    }return out;
}
struct Location{uint32_t leb=0,off=0,len=0;};
struct Mapping{uint64_t physical=0,sq=0;uint32_t data_size=0,used=0,pad=0,data_crc=0;uint8_t type=0,copy=0;};
struct Entry{std::string name;uint64_t number;};
struct Region{uint64_t start,end;bool allocated,metadata;};
struct Node{uint64_t number=0,parent=0,size=0,source=0;uint32_t mode=0,uid=0,gid=0,nlink=1,flags=0;int64_t atime=0,mtime=0,ctime=0;uint32_t atime_nano=0,mtime_nano=0,ctime_nano=0;size_t volume=0;bool raw=false;Bytes inline_data;std::map<uint32_t,Location> data;std::vector<Entry> children;};
struct Volume{uint32_t id=0,leb_size=0,reserved=0;uint64_t size=0;std::string name;std::map<uint32_t,Mapping> map;bool ubifs=false;};
class Reader{
    std::function<Bytes(uint64_t,size_t)> io;
    std::set<uint64_t> active_pebs,known_pebs;
    Bytes view(const Volume&v,uint64_t at,size_t length)const{
        if(at>v.size||length>v.size-at)throw std::runtime_error("volume read outside bounds");Bytes out;
        while(length){uint32_t l=uint32_t(at/v.leb_size),off=uint32_t(at%v.leb_size);size_t take=std::min<size_t>(length,v.leb_size-off);auto it=v.map.find(l);
            if(it==v.map.end())out.insert(out.end(),take,255);else{Bytes b=read(it->second.physical+off,take);out.insert(out.end(),b.begin(),b.end());}at+=take;length-=take;
        }return out;
    }
    Bytes ubnode(const Volume&v,Location loc,int type=-1)const{
        if(loc.leb>=v.size/v.leb_size||loc.off>v.leb_size-24)throw std::runtime_error("UBIFS node outside LEB");
        uint64_t at=uint64_t(loc.leb)*v.leb_size+loc.off;Bytes h=view(v,at,24);
        if(num(h,0,4)!=0x06101831)throw std::runtime_error("invalid UBIFS node magic");
        uint32_t length=uint32_t(num(h,16,4));if(length<24||length>1048576||length>v.leb_size-loc.off||(loc.len&&length!=loc.len))throw std::runtime_error("invalid UBIFS node length");
        Bytes b=view(v,at,length);if(crc(b,8,length-8)!=num(b,4,4))throw std::runtime_error("UBIFS node CRC mismatch");
        if(type>=0&&b[20]!=type)throw std::runtime_error("unexpected UBIFS node type");return b;
    }
    std::vector<std::pair<Location,Bytes>> scan(const Volume&v,uint32_t l,uint32_t off)const{
        std::vector<std::pair<Location,Bytes>> out;
        while(off+24<=v.leb_size){Bytes h=view(v,uint64_t(l)*v.leb_size+off,24);if(num(h,0,4)==0xffffffff)break;
            if(h[0]==0xce){unsigned n=0;while(n<24&&h[n]==0xce)n++;if(!n||n%8)throw std::runtime_error("bad UBIFS padding");off+=n;continue;}
            Bytes b=ubnode(v,{l,off,0});uint32_t step=uint32_t((b.size()+7)&~size_t(7));if(step>v.leb_size-off)throw std::runtime_error("UBIFS node alignment outside LEB");if(b[20]==5){uint64_t pad=num(b,24,4);if(pad>v.leb_size-off-step)throw std::runtime_error("bad UBIFS pad node");step+=uint32_t(pad);}
            else out.push_back({{l,off,uint32_t(b.size())},b});off+=step;
        }return out;
    }
    void filesystem(size_t vi,uint64_t folder){
        Volume&v=volumes[vi];Bytes sb=ubnode(v,{0,0,0},6);
        if(sb.size()<128||sb[27]||num(sb,36,4)!=v.leb_size||num(sb,40,4)>v.size/v.leb_size||num(sb,80,4)>5)throw std::runtime_error("unsupported UBIFS geometry, format or key format");
        if(num(sb,28,4)&0x30)throw std::runtime_error("encrypted/authenticated UBIFS unsupported");
        uint32_t loglebs=uint32_t(num(sb,56,4));if(!loglebs||3+loglebs>v.size/v.leb_size)throw std::runtime_error("invalid UBIFS log geometry");
        Bytes master;uint64_t best=0;
        for(uint32_t l:{1U,2U}){
            try{for(const auto&e:scan(v,l,0))if(e.second[20]==7&&e.second.size()>=168){uint64_t sq=num(e.second,8,8);if(master.empty()||sq>best){master=e.second;best=sq;}}}catch(const std::runtime_error&){/* Try redundant master. */}
        }if(master.empty())throw std::runtime_error("no valid UBIFS master");
        std::map<uint32_t,Location> inos;std::map<uint32_t,std::map<uint32_t,Location>> datas;std::map<uint32_t,std::map<std::string,uint64_t>> dents;
        auto apply=[&](Location loc,const Bytes&b){uint32_t ino=uint32_t(num(b,24,4)),key=uint32_t(num(b,28,4));
            if(b[20]==0){if(b.size()<160)throw std::runtime_error("short inode");if(num(b,92,4))inos[ino]=loc;else{inos.erase(ino);datas.erase(ino);}}
            else if(b[20]==1){if(b.size()<48||(key>>29)!=1)throw std::runtime_error("invalid data node");datas[ino][key&0x1fffffff]=loc;}
            else if(b[20]==2){if(b.size()<56)throw std::runtime_error("short dent");size_t n=size_t(num(b,50,2));if(n>255||n>b.size()-56)throw std::runtime_error("invalid dent length");std::string nm(b.begin()+56,b.begin()+56+n);if(nm.empty()||nm.find('/')!=std::string::npos||nm.find('\0')!=std::string::npos)throw std::runtime_error("invalid directory name");uint64_t target=num(b,40,8);if(target)dents[ino][nm]=target;else dents[ino].erase(nm);}
            else if(b[20]==4){uint64_t old=num(b,40,8),nw=num(b,48,8);if(nw>old)throw std::runtime_error("invalid truncation");auto&d=datas[ino];for(auto it=d.begin();it!=d.end();)if(it->first>=(nw+4095)/4096&&uint64_t(it->first)*4096<old)it=d.erase(it);else ++it;}
        };
        std::vector<Location> stack={{uint32_t(num(master,48,4)),uint32_t(num(master,52,4)),uint32_t(num(master,56,4))}};std::set<std::pair<uint32_t,uint32_t>> seen;
        while(!stack.empty()){Location loc=stack.back();stack.pop_back();if(!seen.insert({loc.leb,loc.off}).second||seen.size()>5000000)throw std::runtime_error("cyclic or excessive UBIFS index");Bytes b=ubnode(v,loc,9);uint32_t count=uint32_t(num(b,24,2)),level=uint32_t(num(b,26,2));if(!count||level>64||b.size()!=28+size_t(count)*20)throw std::runtime_error("invalid UBIFS index branches");
            for(uint32_t k=0;k<count;k++){size_t at=28+k*20;Location child={uint32_t(num(b,at,4)),uint32_t(num(b,at+4,4)),uint32_t(num(b,at+8,4))};if(level)stack.push_back(child);else{Bytes leaf=ubnode(v,child);if(leaf.size()<32||num(leaf,24,8)!=num(b,at+12,8))throw std::runtime_error("UBIFS index key mismatch");apply(child,leaf);}}
        }
        uint32_t log=uint32_t(num(master,44,4));if(log<3||log>=3+loglebs)throw std::runtime_error("invalid UBIFS log start");
        std::vector<std::pair<Location,Bytes>> journal;std::set<uint32_t> buds;uint64_t cs=0;
        for(uint32_t k=0;k<loglebs;k++){auto records=scan(v,log,0);if(records.empty())break;
            if(!k){if(records[0].second[20]!=10||num(records[0].second,24,8)!=num(master,32,8))break;cs=num(records[0].second,8,8);}else if(num(records[0].second,8,8)<cs)break;
            for(const auto&e:records)if(e.second[20]==8){uint32_t l=uint32_t(num(e.second,24,4)),off=uint32_t(num(e.second,28,4));if(buds.insert(l).second){auto entries=scan(v,l,off);journal.insert(journal.end(),entries.begin(),entries.end());}}
            log++;if(log==3+loglebs)log=3;
        }
        std::sort(journal.begin(),journal.end(),[](const std::pair<Location,Bytes>&a,const std::pair<Location,Bytes>&b){return num(a.second,8,8)<num(b.second,8,8);});
        std::vector<std::pair<Location,Bytes>> group;
        for(const auto&e:journal){uint8_t g=e.second[21];if(g>2)throw std::runtime_error("invalid journal group");
            if(g==0){if(!group.empty())throw std::runtime_error("incomplete journal group before standalone node");if(e.second[20]<=4)apply(e.first,e.second);}
            else{group.push_back(e);if(g==2){for(const auto&item:group)if(item.second[20]<=4)apply(item.first,item.second);group.clear();}}
        } // An incomplete final group is not replayed.
        if(!inos.count(1))throw std::runtime_error("UBIFS root inode missing");
        std::map<uint32_t,uint64_t> ids;ids[1]=folder;std::vector<uint32_t> pending={1};std::set<uint32_t> expanded;
        for(size_t k=0;k<pending.size();k++){uint32_t ino=pending[k];uint64_t id=ids.at(ino);Bytes b=ubnode(v,inos.at(ino),0);Node n;n.number=id;n.parent=nodes[id].parent;n.volume=vi;n.source=ino;n.size=num(b,48,8);n.atime=int64_t(num(b,56,8));n.ctime=int64_t(num(b,64,8));n.mtime=int64_t(num(b,72,8));n.atime_nano=uint32_t(num(b,80,4));n.ctime_nano=uint32_t(num(b,84,4));n.mtime_nano=uint32_t(num(b,88,4));n.nlink=uint32_t(num(b,92,4));n.uid=uint32_t(num(b,96,4));n.gid=uint32_t(num(b,100,4));n.mode=uint32_t(num(b,104,4));n.flags=uint32_t(num(b,108,4));size_t dlen=size_t(num(b,112,4));if(dlen>b.size()-160)throw std::runtime_error("invalid inline inode content");n.inline_data.assign(b.begin()+160,b.begin()+160+dlen);n.data=datas[ino];
            if((n.mode&0170000)==0040000){if(!expanded.insert(ino).second)throw std::runtime_error("directory cycle");for(const auto&e:dents[ino]){if(e.second>0xffffffff||!inos.count(uint32_t(e.second)))throw std::runtime_error("dangling UBIFS directory entry");uint32_t child=uint32_t(e.second);if(!ids.count(child)){ids[child]=nodes.size();Node placeholder;placeholder.parent=id;nodes.push_back(placeholder);pending.push_back(child);}else if((num(ubnode(v,inos.at(child),0),104,4)&0170000)==0040000)throw std::runtime_error("shared/cyclic directory");n.children.push_back({e.first,ids[child]});}}
            if(n.size>0x7fffffffffffffffULL)throw std::runtime_error("file size exceeds TSK range");nodes[id]=n;
        }v.ubifs=true;
    }
public:
    uint64_t size=0,root=1,peb_size=0;uint32_t data_offset=0;std::vector<Node> nodes;std::vector<Volume> volumes;std::vector<Region> allocation;
    Bytes read(uint64_t at,size_t n)const{if(at>size||n>size-at)throw std::runtime_error("read outside image");Bytes b=io(at,n);if(b.size()!=n)throw std::runtime_error("short image read");return b;}
    const Node&node(uint64_t id)const{if(!id||id>=nodes.size())throw std::runtime_error("invalid inode");return nodes[size_t(id)];}
    Region flags(uint64_t at)const{if(at>=size)throw std::runtime_error("invalid block");auto it=std::upper_bound(allocation.begin(),allocation.end(),at,[](uint64_t a,const Region&r){return a<r.start;});return *--it;}
    Bytes content(const Node&n,uint64_t off,size_t length)const{
        if(off>n.size)throw std::runtime_error("offset past file end");length=size_t(std::min<uint64_t>(length,n.size-off));if(n.flags&0x40)throw std::runtime_error("fscrypt content unsupported");const Volume&v=volumes.at(n.volume);
        if(n.raw)return view(v,off,length);if((n.mode&0170000)==0120000){if(n.size>n.inline_data.size())throw std::runtime_error("short symlink");return Bytes(n.inline_data.begin()+off,n.inline_data.begin()+off+length);}
        Bytes out;while(length){uint32_t block=uint32_t(off/4096);size_t skip=size_t(off%4096),take=std::min<size_t>(length,4096-skip);Bytes b(4096);auto it=n.data.find(block);
            if(it!=n.data.end()){Bytes raw=ubnode(v,it->second,1);uint32_t expected=uint32_t(num(raw,40,4));uint32_t compression=uint32_t(num(raw,44,2));if(expected>4096)throw std::runtime_error("invalid data block size");Bytes compressed(raw.begin()+48,raw.end()),decoded;
                if(!compression)decoded=compressed;else if(compression==1)decoded=lzo(compressed);
                else if(compression==2){
#ifdef HAVE_LIBZ
                    decoded.resize(4096);z_stream z={};z.next_in=compressed.data();z.avail_in=unsigned(compressed.size());z.next_out=decoded.data();z.avail_out=4096;if(inflateInit2(&z,-15)!=Z_OK)throw std::runtime_error("deflate initialization failed");int result=inflate(&z,Z_FINISH);size_t actual=z.total_out;bool consumed=z.avail_in==0;inflateEnd(&z);if(result!=Z_STREAM_END||!consumed)throw std::runtime_error("invalid deflate block");decoded.resize(actual);
#else
                    throw std::runtime_error("zlib support not compiled");
#endif
                }else throw std::runtime_error("unsupported UBIFS compression (Zstd not compiled)");
                if(decoded.size()!=expected)throw std::runtime_error("decompressed length mismatch");std::copy(decoded.begin(),decoded.end(),b.begin());
            }out.insert(out.end(),b.begin()+skip,b.begin()+skip+take);off+=take;length-=take;
        }return out;
    }
    Reader(std::function<Bytes(uint64_t,size_t)> readfn,uint64_t length):io(readfn),size(length){
        if(size<64)throw std::runtime_error("image too short");Bytes first=read(0,64);
        nodes.resize(2);nodes[1].number=1;nodes[1].mode=0040555;
        if(num(first,0,4)==0x06101831){Bytes sb=read(0,128);uint32_t leb=uint32_t(num(sb,36,4));if(leb<4096||leb>16*1024*1024||size%leb)throw std::runtime_error("invalid flat UBIFS geometry");Volume v;v.name="UBIFS";v.leb_size=leb;v.size=size;for(uint64_t l=0;l<size/leb;l++){Mapping m;m.physical=l*leb;v.map[uint32_t(l)]=m;}volumes.push_back(v);filesystem(0,1);allocation.push_back({0,size,true,false});return;}
        auto ecok=[](const Bytes&b){return b.size()==64&&num(b,0,4,true)==0x55424923&&b[4]==1&&crc(b,0,60)==num(b,60,4,true);};
        if(!ecok(first))throw std::runtime_error("invalid UBI EC header");uint32_t seq=uint32_t(num(first,24,4,true));
        for(uint64_t p=1024;p+64<=std::min<uint64_t>(size,8*1024*1024);p+=1024){Bytes b=read(p,64);if(ecok(b)&&num(b,24,4,true)==seq){peb_size=p;break;}}
        if(!peb_size||size%peb_size)throw std::runtime_error("cannot determine complete UBI eraseblock geometry");
        data_offset=uint32_t(num(first,20,4,true));uint32_t vid_off=uint32_t(num(first,16,4,true));if(vid_off<64||vid_off+64>data_offset||data_offset>=peb_size)throw std::runtime_error("invalid UBI header offsets");
        std::map<std::pair<uint32_t,uint32_t>,std::vector<Mapping>> candidates;
        for(uint64_t p=0;p<size;p+=peb_size){Bytes ec=read(p,64);if(!ecok(ec))continue;if(num(ec,24,4,true)!=seq)throw std::runtime_error("mixed UBI image sequences");if(num(ec,16,4,true)!=vid_off||num(ec,20,4,true)!=data_offset)throw std::runtime_error("inconsistent UBI geometry");known_pebs.insert(p/peb_size);Bytes b=read(p+vid_off,64);if(num(b,0,4,true)==0xffffffff)continue;
            if(num(b,0,4,true)!=0x55424921||b[4]!=1||crc(b,0,60)!=num(b,60,4,true))throw std::runtime_error("invalid UBI VID CRC");Mapping m;m.physical=p+data_offset;m.type=b[5];m.copy=b[6];m.data_size=uint32_t(num(b,20,4,true));m.used=uint32_t(num(b,24,4,true));m.pad=uint32_t(num(b,28,4,true));m.data_crc=uint32_t(num(b,32,4,true));m.sq=num(b,40,8,true);
            if((m.type!=1&&m.type!=2)||m.pad>=peb_size-data_offset||m.data_size>peb_size-data_offset-m.pad)throw std::runtime_error("invalid UBI VID geometry");candidates[{uint32_t(num(b,8,4,true)),uint32_t(num(b,12,4,true))}].push_back(m);
        }
        std::map<std::pair<uint32_t,uint32_t>,Mapping> selected;
        for(auto&kv:candidates){auto&a=kv.second;std::sort(a.begin(),a.end(),[](const Mapping&a,const Mapping&b){return a.sq>b.sq;});for(size_t k=0;k<a.size();k++){Mapping m=a[k];if(m.type==2||m.copy){Bytes data=read(m.physical,m.data_size);if(crc(data,0,data.size())!=m.data_crc){if(k+1<a.size())continue;throw std::runtime_error("no CRC-valid UBI static/copy data");}}selected[kv.first]=m;active_pebs.insert((m.physical-data_offset)/peb_size);break;}}
        std::map<uint32_t,Volume> table;bool tableok=false;
        for(uint32_t copy:{0U,1U}){auto it=selected.find({0x7fffefff,copy});if(it==selected.end())continue;Bytes raw=read(it->second.physical,size_t(peb_size-data_offset));std::map<uint32_t,Volume> trial;bool ok=true;
            for(uint32_t k=0;k<std::min<size_t>(128,raw.size()/172);k++){size_t at=k*172;if(crc(raw,at,168)!=num(raw,at+168,4,true)){ok=false;break;}uint32_t reserved=uint32_t(num(raw,at,4,true));if(!reserved)continue;size_t n=size_t(num(raw,at+14,2,true));uint32_t pad=uint32_t(num(raw,at+8,4,true));if(n>127||pad>=peb_size-data_offset||raw[at+13])throw std::runtime_error("invalid/incomplete UBI volume table");Volume v;v.id=k;v.reserved=reserved;v.name=std::string(raw.begin()+at+16,raw.begin()+at+16+n);v.leb_size=uint32_t(peb_size-data_offset-pad);trial[k]=v;}
            if(ok){table=trial;tableok=true;break;}
        }
        if(!tableok)throw std::runtime_error("no valid UBI volume table");
        for(auto&kv:table){Volume v=kv.second;for(const auto&m:selected)if(m.first.first==v.id){if(m.first.second>=v.reserved||peb_size-data_offset-m.second.pad!=v.leb_size)throw std::runtime_error("volume map out of bounds");v.map[m.first.second]=m.second;v.size=std::max<uint64_t>(v.size,uint64_t(m.first.second+1)*v.leb_size);}
            if(v.map.empty())continue;const Mapping&last=v.map.rbegin()->second;if(last.type==2){if(!last.used||last.used>v.reserved||v.map.size()!=last.used)throw std::runtime_error("incomplete static volume");v.size=uint64_t(last.used-1)*v.leb_size+last.data_size;}
            std::string nm=v.name;if(nm.empty())nm="vol"+std::to_string(v.id);if(nm.find('/')!=std::string::npos||nm.find('\0')!=std::string::npos||nm=="."||nm=="..")throw std::runtime_error("invalid volume name");nm="Volume_"+std::to_string(v.id)+"_"+nm;
            uint64_t folder=nodes.size();Node dir;dir.number=folder;dir.parent=1;dir.mode=0040555;nodes.push_back(dir);nodes[1].children.push_back({nm,folder});size_t vi=volumes.size();volumes.push_back(v);
            Bytes head=view(volumes[vi],0,size_t(std::min<uint64_t>(v.size,4)));if(head.size()==4&&num(head,0,4)==0x06101831)filesystem(vi,folder);else{Node n;n.number=nodes.size();n.parent=folder;n.volume=vi;n.raw=true;n.size=v.size;n.mode=0100444;nodes.push_back(n);nodes[folder].children.push_back({"volume.bin",n.number});}
        }if(volumes.empty())throw std::runtime_error("UBI contains no readable volumes");
        for(uint64_t p=0;p<size;p+=peb_size){bool live=active_pebs.count(p/peb_size)!=0||!known_pebs.count(p/peb_size);allocation.push_back({p,p+data_offset,true,true});allocation.push_back({p+data_offset,p+peb_size,live,false});}
    }
};
}
#endif
