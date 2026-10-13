/* Microware OS-9 classic RBF; adapted from Gerd1986/qnxprobe (MIT).
 * Attribution and license: os9_LICENSE.txt. No Apple macOS filesystem. */
#ifndef TSK_OS9_READER_H
#define TSK_OS9_READER_H
#include <cstdint>
#include <vector>
#include <set>
#include <map>
#include <string>
#include <functional>
#include <stdexcept>
#include <algorithm>
namespace tsk_os9 {
using Bytes=std::vector<uint8_t>;
inline uint64_t be(const Bytes&b,size_t p,size_t n){if(p>b.size()||n>b.size()-p)throw std::runtime_error("OS-9 truncated field");uint64_t v=0;for(size_t i=0;i<n;i++)v=(v<<8)|b[p+i];return v;}
inline std::string name(const Bytes&b,size_t at,size_t n){std::string s;for(size_t i=0;i<n;i++){uint8_t c=b[at+i];if(!c)break;s+=char(c&127);if(c&128)break;}return s;}
inline int64_t date(const Bytes&b,size_t at,bool minute){
    int y=1900+b[at],m=b[at+1],d=b[at+2],h=minute?b[at+3]:0,mi=minute?b[at+4]:0;
    const int days[]={0,31,28,31,30,31,30,31,31,30,31,30,31};bool leap=(y%4==0&&(y%100!=0||y%400==0));
    if(m<1||m>12||d<1||d>days[m]+(m==2&&leap)||h>23||mi>59)return 0;
    y-=m<=2;int era=y/400;unsigned yo=unsigned(y-era*400),mp=unsigned(m+(m>2?-3:9));
    unsigned doy=(153*mp+2)/5+unsigned(d)-1,doe=yo*365+yo/4-yo/100+doy;
    return (int64_t(era)*146097+doe-719468)*86400+h*3600+mi*60;
}
struct Extent{uint64_t block,count;};
struct Inode{Bytes raw;uint64_t number,size;uint8_t attributes;uint16_t mode;int64_t mtime,crtime;};
struct Entry{std::string name;uint64_t number;};
class Reader{
    std::function<Bytes(uint64_t,size_t)> io;
    uint64_t available;
    Bytes bitmap;
    std::set<uint64_t> metadata;
    bool probe(uint32_t bs){
        if(available<bs)return false;
        Bytes dd=io(0,bs);if(dd.size()!=bs)return false;
        uint64_t tot=be(dd,0,3),mb=be(dd,4,2),cluster=be(dd,6,2),r=be(dd,8,3);
        if(tot<4||!mb||!cluster||(cluster&(cluster-1))||r<1||r>=tot||tot>available/bs||mb<(tot+cluster*8-1)/(cluster*8))return false;
        sector_size=bs;total=tot;root=r;cluster_sectors=uint32_t(cluster);mapbytes=uint32_t(mb);map_lsn=1;volume=name(dd,31,32);
        if(dd.size()>=108&&std::string(reinterpret_cast<const char*>(dd.data()+96),4)=="Cruz"){
            uint64_t map=be(dd,100,4);if(map)map_lsn=map;
        }
        if(map_lsn>=total||(mapbytes+bs-1)/bs>total-map_lsn)return false;
        try{Inode ino=inode(root);if(!(ino.attributes&128)||!ino.size||ino.size%32)return false;
            bool dot=false,dotdot=false;for(const auto&e:directory(ino)){dot|=e.name=="."&&e.number==root;dotdot|=e.name==".."&&e.number>0;}
            if(!dot||!dotdot)return false;
        }catch(const std::runtime_error&){return false;}
        return true;
    }
public:
    uint32_t sector_size=0,cluster_sectors=0,mapbytes=0;
    uint64_t total=0,root=0,map_lsn=1;
    std::string volume;
    std::set<uint64_t> live;
    Reader(std::function<Bytes(uint64_t,size_t)> read,uint64_t size):io(read),available(size){
        bool found=false;for(uint32_t bs:{128U,256U,512U,1024U,2048U,4096U})if(probe(bs)){found=true;break;}
        if(!found)throw std::runtime_error("OS-9 no validated RBF volume at offset");
        bitmap=io(map_lsn*sector_size,mapbytes);if(bitmap.size()!=mapbytes)throw std::runtime_error("OS-9 short allocation map");
        metadata.insert(0);for(uint64_t a=map_lsn;a<map_lsn+(mapbytes+sector_size-1)/sector_size;a++)metadata.insert(a);
        live.insert(root);std::vector<uint64_t> todo={root};std::set<uint64_t> visited,dirs={root};
        for(size_t index=0;index<todo.size();index++){
            uint64_t n=todo[index];if(!visited.insert(n).second)continue;
            Inode dir=inode(n);for(const auto&span:extents(dir))for(uint64_t k=0;k<span.count;k++)metadata.insert(span.block+k);
            for(const auto&e:directory(dir)){
                if(e.name=="."||e.name=="..")continue;
                Inode child=inode(e.number);live.insert(e.number);if(child.attributes&128){if(!dirs.insert(e.number).second)throw std::runtime_error("OS-9 cyclic/shared directory");todo.push_back(e.number);}
            }
        }
        for(uint64_t n:live){metadata.insert(n);Inode i=inode(n);extents(i);
            if(!allocated(n))throw std::runtime_error("OS-9 active descriptor marked free");
            for(const auto&s:extents(i))for(uint64_t k=0;k<s.count;k++)if(!allocated(s.block+k))throw std::runtime_error("OS-9 live file segment marked free");
        }
        for(uint64_t n:metadata)if(!allocated(n))throw std::runtime_error("OS-9 filesystem metadata marked free");
    }
    Bytes block(uint64_t n){if(n>=total)throw std::runtime_error("OS-9 sector outside volume");Bytes b=io(n*sector_size,sector_size);if(b.size()!=sector_size)throw std::runtime_error("OS-9 short sector read");return b;}
    Inode inode(uint64_t n){
        if(!n||n>=total)throw std::runtime_error("OS-9 invalid FD LSN");
        Bytes b=block(n);uint8_t a=b[0];
        uint16_t mode=(a&128)?0040000:0100000;
        if(a&1)mode|=0400;
        if(a&2)mode|=0200;
        if(a&4)mode|=0100;
        if(a&8)mode|=0004;
        if(a&16)mode|=0002;
        if(a&32)mode|=0001;
        return {b,n,be(b,9,4),a,mode,date(b,3,true),date(b,13,false)};
    }
    std::vector<Extent> extents(const Inode&i){
        std::vector<Extent> out;uint64_t sum=0;
        // Classic FD records have at most 48 segment slots in 256 bytes.
        for(size_t p=16;p+5<=std::min<size_t>(i.raw.size(),256);p+=5){
            uint64_t start=be(i.raw,p,3),count=be(i.raw,p+3,2);if(!start||!count)break;
            if(start>=total||count>total-start)throw std::runtime_error("OS-9 segment outside volume");
            out.push_back({start,count});sum+=count;
        }
        if(i.size>sum*sector_size)throw std::runtime_error("OS-9 segments do not cover file size");
        return out;
    }
    std::vector<Entry> directory(const Inode&i){
        if(!(i.attributes&128)||i.size%32)throw std::runtime_error("OS-9 invalid directory");
        std::vector<Entry> out;uint64_t left=i.size;
        for(const auto&s:extents(i))for(uint64_t k=0;k<s.count&&left;k++){
            Bytes b=block(s.block+k);size_t take=size_t(std::min<uint64_t>(left,sector_size));
            for(size_t p=0;p<take;p+=32){std::string nm=name(b,p,29);uint64_t child=be(b,p+29,3);
                if(nm.empty()||!child)continue;
                if(child>=total||nm.find('/')!=std::string::npos)throw std::runtime_error("OS-9 invalid directory entry");
                out.push_back({nm,child});
            }left-=take;
        }return out;
    }
    bool allocated(uint64_t n)const{if(n>=total)throw std::runtime_error("OS-9 allocation sector out of range");uint64_t cluster=n/cluster_sectors;return (bitmap[size_t(cluster/8)]&(128U>>(cluster%8)))!=0;}
    bool is_metadata(uint64_t n)const{return metadata.count(n)!=0;}
};
}
#endif
