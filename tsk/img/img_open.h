#ifndef _TSK_IMG_IMG_OPEN_H
#define _TSK_IMG_IMG_OPEN_H

#include "tsk_img_i.h"

#include <memory>
#include <string>

bool sector_size_ok(unsigned int sector_size);

template <class T>
bool images_ok(int num_img, const T* const images[]) {
    if (num_img < 0) {
        tsk_error_set_errno(TSK_ERR_IMG_ARG);
        tsk_error_set_errstr("number of images is negative (%d)", num_img);
        return false;
    }

    if (num_img == 0 || !images || !images[0]) {
        tsk_error_set_errno(TSK_ERR_IMG_NOFILE);
        tsk_error_set_errstr("tsk_img_open");
        return false;
    }

    return true;
}

void img_info_deleter(TSK_IMG_INFO* img_info);

std::unique_ptr<TSK_IMG_INFO, decltype(&img_info_deleter)>
img_open_by_type(
    int num_img,
    const TSK_TCHAR* const images[],
    TSK_IMG_TYPE_ENUM type,
    unsigned int a_ssize
);

const char* type_name(TSK_IMG_TYPE_ENUM t);

#endif
