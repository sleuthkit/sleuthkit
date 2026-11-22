#include "tsk/libtsk.h"
#include <cstdlib>
#include <cstdio>
#include <vector>
int main(int argc,char**argv){
    if(argc!=5)return 2;auto*img=tsk_img_open_utf8_sing(argv[1],TSK_IMG_TYPE_DETECT,0);if(!img)return 3;
    auto*fs=tsk_fs_open_img(img,0,TSK_FS_TYPE_RELIANCE);if(!fs){tsk_img_close(img);return 4;}
    auto*file=tsk_fs_file_open_meta(fs,nullptr,std::strtoull(argv[2],nullptr,0));if(!file){tsk_fs_close(fs);tsk_img_close(img);return 5;}
    std::vector<char>b(size_t(std::strtoull(argv[4],nullptr,0)));ssize_t n=tsk_fs_file_read(file,TSK_OFF_T(std::strtoll(argv[3],nullptr,0)),b.data(),b.size(),TSK_FS_FILE_READ_FLAG_NONE);
    if(n>0)fwrite(b.data(),1,size_t(n),stdout);tsk_fs_file_close(file);tsk_fs_close(fs);tsk_img_close(img);return n<0?6:0;
}
