#include "tsk/libtsk.h"
#include <cstdlib>
#include <cstdio>
#include <vector>
int main(int argc,char**argv){
    if(argc!=5)return 2;
    auto*img=tsk_img_open_utf8_sing(argv[1],argv[4][0]=='a'?TSK_IMG_TYPE_DETECT:TSK_IMG_TYPE_FTL100,0);if(!img)return 3;
    std::vector<char>b(size_t(std::strtoull(argv[3],nullptr,0)));
    ssize_t n=tsk_img_read(img,TSK_OFF_T(std::strtoll(argv[2],nullptr,0)),b.data(),b.size());
    if(n>0)fwrite(b.data(),1,size_t(n),stdout);tsk_img_close(img);return n<0?4:0;
}
