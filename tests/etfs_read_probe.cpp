/* Exercise buffered TSK reads independently of icat's file-walk callback. */
#include "tsk/libtsk.h"
#include <cstdlib>
#include <cstdio>
#include <vector>
int main(int argc,char **argv){
    if(argc!=5)return 2;
    TSK_IMG_INFO *img=tsk_img_open_utf8_sing(argv[1],TSK_IMG_TYPE_DETECT,0);if(!img)return 3;
    TSK_FS_INFO *fs=tsk_fs_open_img(img,0,TSK_FS_TYPE_ETFS);if(!fs){tsk_img_close(img);return 4;}
    auto *file=tsk_fs_file_open_meta(fs,nullptr,std::strtoull(argv[2],nullptr,0));
    if(!file){tsk_fs_close(fs);tsk_img_close(img);return 5;}
    std::vector<char> b(size_t(std::strtoull(argv[4],nullptr,0)));
    ssize_t got=tsk_fs_file_read(file,TSK_OFF_T(std::strtoll(argv[3],nullptr,0)),b.data(),b.size(),TSK_FS_FILE_READ_FLAG_NONE);
    if(got>0)fwrite(b.data(),1,size_t(got),stdout);
    tsk_fs_file_close(file);tsk_fs_close(fs);tsk_img_close(img);return got<0?6:0;
}

