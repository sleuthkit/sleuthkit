/* Standalone native-reader checks, also used before the full TSK build. */
#include "tsk/fs/etfs_reader.h"
#include <fstream>
#include <iostream>
#include <cstdlib>
#include <cstdio>
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#endif
int main(int argc,char **argv) {
    if(argc<3)return 2;
#ifdef _WIN32
    _setmode(_fileno(stdout), _O_BINARY);
#endif
    try {
        std::ifstream image(argv[1],std::ios::binary);
        if(!image) return 2;
        image.seekg(0,std::ios::end);auto length=image.tellg();
        auto io=[&](uint64_t pos,size_t len) {
            tsk_etfs::Bytes b(len);image.clear();image.seekg(std::streamoff(pos));
            image.read(reinterpret_cast<char *>(b.data()),std::streamsize(len));b.resize(size_t(image.gcount()));return b;
        };
        tsk_etfs::Reader r(io,uint64_t(length));
        std::string command=argv[2];
        if(command=="list") {
            for(const auto &item:r.nodes) {
                const auto &n=item.second;
                std::cout<<n.number<<'\t'<<n.parent<<'\t'<<n.mode<<'\t'<<n.uid<<'\t'<<n.gid<<'\t'<<n.atime<<'\t'<<n.mtime<<'\t'<<n.ctime<<'\t'<<n.size<<'\t'<<n.name<<'\n';
            }
        } else if(command=="read" && argc==4) {
            const auto &n=r.node(std::strtoull(argv[3],nullptr,0));
            for(const auto &span:n.spans) for(uint64_t at=0;at<span.length;) {
                size_t take=size_t(std::min<uint64_t>(65536,span.length-at));
                auto b=span.hole?tsk_etfs::Bytes(take,0xff):r.read(span.start+at,take);
                std::cout.write(reinterpret_cast<const char *>(b.data()),b.size());at+=take;
            }
        } else if(command=="free") {
            for(const auto &region:r.allocation) if(!region.allocated) for(uint64_t at=region.start;at<region.end;) {
                size_t take=size_t(std::min<uint64_t>(65536,region.end-at));auto b=r.read(at,take);
                std::cout.write(reinterpret_cast<const char *>(b.data()),b.size());at+=take;
            }
        } else return 2;
    } catch(const std::exception &e) {std::cerr<<e.what()<<'\n';return 1;}
    return 0;
}
