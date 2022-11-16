/*
 * The Sleuth Kit - Add on for Linux LVM support
 *
 * Copyright (c) 2022 Joachim Metz <joachim.metz@gmail.com>
 *
 * This software is distributed under the Common Public License 1.0
 */

#include "tsk/base/tsk_base_i.h"

#if HAVE_LIBVSLVM

#include "lvm_pool_compat.hpp"

#include "tsk/img/pool.hpp"
#include "tsk/img/tsk_img_i.h"

#include <stdexcept>

/**
 * Get error string from libvslvm and make buffer empty if that didn't work. 
 * @returns 1 if error message was not set
 */
static uint8_t getError(libvslvm_error_t *vslvm_error, char error_string[512])
{
    error_string[0] = '\0';
    int retval = libvslvm_error_backtrace_sprint(vslvm_error, error_string, 512);
    return retval <= 0;
}

uint8_t LVMPoolCompat::poolstat(FILE *hFile) const noexcept try {

    tsk_fprintf(hFile, "POOL CONTAINER INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n\n");
    tsk_fprintf(hFile, "Volume group %s\n", identifier.c_str());
    tsk_fprintf(hFile, "==============================================\n");
    tsk_fprintf(hFile, "Type: LVM\n");

    int number_of_logical_volumes = 0;
    if (libvslvm_volume_group_get_number_of_logical_volumes(_lvm_volume_group, &number_of_logical_volumes, NULL) != 1 ) {
        return 1;
    }
    libvslvm_logical_volume_t *lvm_logical_volume = NULL;
    char volume_name[ 64 ];
    char volume_identifier[ 64 ];

    for (int volume_index = 0; volume_index < number_of_logical_volumes; volume_index++ ) {
        if (libvslvm_volume_group_get_logical_volume(_lvm_volume_group, volume_index, &lvm_logical_volume, NULL) != 1 ) {
            return 1;
        }
        if (libvslvm_logical_volume_get_identifier(lvm_logical_volume, volume_identifier, 64, NULL) != 1 ) {
            return 1;
        }
        if (libvslvm_logical_volume_get_name(lvm_logical_volume, volume_name, 64, NULL) != 1 ) {
            return 1;
        }
        if (libvslvm_logical_volume_free(&lvm_logical_volume, NULL) != 1 ) {
            return 1;
        }
        tsk_fprintf(hFile, "|\n");
        tsk_fprintf(hFile, "+-> Volume %s\n", volume_identifier);
        tsk_fprintf(hFile, "|   ===========================================\n");
        tsk_fprintf(hFile, "|   Name: %s\n", volume_name);
    }
    return 0;
} catch (const std::exception &e) {
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_POOL_GENPOOL);
    tsk_error_set_errstr("%s", e.what());
    return 1;
}

static void
lvm_logical_volume_img_close(TSK_IMG_INFO * img_info)
{
    if (img_info != NULL) {
        IMG_POOL_INFO *pool_img_info = (IMG_POOL_INFO *)img_info;
        libvslvm_logical_volume_free((libvslvm_logical_volume_t **) &( pool_img_info->impl ), NULL);

        tsk_deinit_lock(&(img_info->cache_lock));
        tsk_img_free(img_info);
    }
}

static void
lvm_logical_volume_img_imgstat(TSK_IMG_INFO * img_info, FILE *hFile)
{
    tsk_fprintf(hFile, "IMAGE FILE INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");
    tsk_fprintf(hFile, "Image Type:\t\tLVM logical volume\n");
    tsk_fprintf(hFile, "\nSize of data in bytes:\t%" PRIdOFF "\n",
        img_info->size);
}

static ssize_t
lvm_logical_volume_img_read(TSK_IMG_INFO * img_info, TSK_OFF_T offset, char *buf, size_t len)
{
    IMG_POOL_INFO *pool_img_info = (IMG_POOL_INFO *)img_info;
    libvslvm_error_t *vslvm_error = NULL;

    // correct the offset to be relative to the start of the logical volume
    offset -= pool_img_info->pool_info->img_offset;

    if (tsk_verbose) {
        tsk_fprintf(stderr, "lvm_logical_volume_img_read: offset: %" PRIdOFF " read len: %" PRIuSIZE ".\n",
          offset, len);
    }
    if ((offset < 0) || (offset > img_info->size)) {
        return 0;
    }
    ssize_t read_count = libvslvm_logical_volume_read_buffer_at_offset((libvslvm_logical_volume_t *) pool_img_info->impl, buf, len, offset, &vslvm_error);

    if (read_count == -1) {
        char error_string[521];
        getError(vslvm_error, error_string);
        tsk_fprintf(stderr, "lvm_logical_volume_img_read: %s\n", error_string);
    }
    return read_count;
}

TSK_IMG_INFO * LVMPoolCompat::getImageInfo(const TSK_POOL_INFO *pool_info, TSK_DADDR_T pvol_block) noexcept try {

    libvslvm_logical_volume_t *lvm_logical_volume = NULL;

    // pvol_block contians the logical volume index + 1
    if (libvslvm_volume_group_get_logical_volume(_lvm_volume_group, pvol_block - 1, &lvm_logical_volume, NULL) != 1 ) {
        return NULL;
    }
    uint64_t logical_volume_size = 0;

    if (libvslvm_logical_volume_get_size(lvm_logical_volume, &logical_volume_size, NULL) != 1 ) {
        return NULL;
    }
    IMG_POOL_INFO *img_pool_info = (IMG_POOL_INFO *)tsk_img_malloc(sizeof(IMG_POOL_INFO));

    if (img_pool_info == NULL) {
        return NULL;
    }
    img_pool_info->pool_info = pool_info;
    img_pool_info->pvol_block = pvol_block;

    img_pool_info->img_info.read = lvm_logical_volume_img_read;
    img_pool_info->img_info.close = lvm_logical_volume_img_close;
    img_pool_info->img_info.imgstat = lvm_logical_volume_img_imgstat;

    img_pool_info->impl = (void *) lvm_logical_volume;

    TSK_IMG_INFO *img_info = (TSK_IMG_INFO *)img_pool_info;

    img_info->tag = TSK_IMG_INFO_TAG;
    img_info->itype = TSK_IMG_TYPE_POOL;

    // Copy original info from the first TSK_IMG_INFO. There was a check in the
    // LVMPool that _members has only one entry.
    IMG_POOL_INFO *pool_img_info = (IMG_POOL_INFO *)img_info;
    const auto pool = static_cast<LVMPoolCompat*>(pool_img_info->pool_info->impl);
    TSK_IMG_INFO *origInfo = pool->_members[0].first;

    img_info->size = logical_volume_size;
    img_info->num_img = origInfo->num_img;
    img_info->sector_size = origInfo->sector_size;
    img_info->page_size = origInfo->page_size;
    img_info->spare_size = origInfo->spare_size;
    img_info->images = origInfo->images;

    tsk_init_lock(&(img_info->cache_lock));

    return img_info;

}
catch (const std::exception &e) {
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_POOL_GENPOOL);
    tsk_error_set_errstr("%s", e.what());
    return NULL;
}

#endif /* HAVE_LIBVSLVM */

