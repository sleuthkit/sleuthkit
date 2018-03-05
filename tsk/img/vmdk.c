/*
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2006-2016 Brian Carrier, Basis Technology.  All rights reserved
 * Copyright (c) 2005 Brian Carrier.  All rights reserved
 *
 * This software is distributed under the Common Public License 1.0
 *
 */

/** \file vmdk.c
 * Internal code for TSK to interface with libvmdk.
 */

#include "tsk_img_i.h"

#if HAVE_LIBVMDK
#include "vmdk.h"

#define TSK_VMDK_ERROR_STRING_SIZE 512


/**
 * Get error string from libvmdk and make buffer empty if that didn't work. 
 * @returns 1 if error message was not set
*/
static uint8_t
getError(libvmdk_error_t * vmdk_error,
    char error_string[TSK_VMDK_ERROR_STRING_SIZE])
{
    int retval;
    error_string[0] = '\0';
    retval = libvmdk_error_backtrace_sprint(vmdk_error,
        error_string, TSK_VMDK_ERROR_STRING_SIZE);
    if (retval)
        return 1;
    return 0;
} 


static ssize_t
vmdk_image_read(TSK_IMG_INFO * img_info, TSK_OFF_T offset, char *buf,
    size_t len)
{
    char error_string[TSK_VMDK_ERROR_STRING_SIZE];
    libvmdk_error_t *vmdk_error = NULL;

    ssize_t cnt;
    IMG_VMDK_INFO *vmdk_info = (IMG_VMDK_INFO *) img_info;

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "vmdk_image_read: byte offset: %" PRIuOFF " len: %" PRIuSIZE
            "\n", offset, len);

    if (offset > img_info->size) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_READ_OFF);
        tsk_error_set_errstr("vmdk_image_read - %" PRIuOFF, offset);
        return -1;
    }

    tsk_take_lock(&(vmdk_info->read_lock));

    cnt = libvmdk_handle_read_buffer_at_offset(vmdk_info->handle,
        buf, len, offset, &vmdk_error);
    if (cnt < 0) {
        char *errmsg = NULL;
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_READ);
        if (getError(vmdk_error, error_string))
            errmsg = strerror(errno);
        else
            errmsg = error_string;

        tsk_error_set_errstr("vmdk_image_read - offset: %" PRIuOFF
            " - len: %" PRIuSIZE " - %s", offset, len, errmsg);
        tsk_release_lock(&(vmdk_info->read_lock));
        return -1;
    }

    tsk_release_lock(&(vmdk_info->read_lock));

    return cnt;
}

static void
vmdk_image_imgstat(TSK_IMG_INFO * img_info, FILE * hFile)
{
    tsk_fprintf(hFile, "IMAGE FILE INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");
    tsk_fprintf(hFile, "Image Type:\t\tvmdk\n");
    tsk_fprintf(hFile, "\nSize of data in bytes:\t%" PRIuOFF "\n",
        img_info->size);
    tsk_fprintf(hFile, "Sector size:\t%d\n", img_info->sector_size);

    return;
}


static void
    vmdk_image_close(TSK_IMG_INFO * img_info)
{
    int i;
    char error_string[TSK_VMDK_ERROR_STRING_SIZE];
    libvmdk_error_t *vmdk_error = NULL;
    char *errmsg = NULL;
    IMG_VMDK_INFO *vmdk_info = (IMG_VMDK_INFO *) img_info;

    if( libvmdk_handle_close(vmdk_info->handle, &vmdk_error ) != 0 )
    {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUX_GENERIC);
        if (getError(vmdk_error, error_string))
            errmsg = strerror(errno);
        else
            errmsg = error_string;

        tsk_error_set_errstr("vmdk_image_close: unable to close handle - %s", errmsg);
    }

    libvmdk_handle_free(&(vmdk_info->handle), NULL);
    if( libvmdk_handle_free(&(vmdk_info->handle), &vmdk_error ) != 1 )
    {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUX_GENERIC);
        if (getError(vmdk_error, error_string))
            errmsg = strerror(errno);
        else
            errmsg = error_string;

        tsk_error_set_errstr("vmdk_image_close: unable to free handle - %s", errmsg);
    }

    for (i = 0; i < vmdk_info->img_info.num_img; i++) {
        free(vmdk_info->img_info.images[i]);
    }
    free(vmdk_info->img_info.images);

    tsk_deinit_lock(&(vmdk_info->read_lock));
    tsk_img_free(img_info);
}

TSK_IMG_INFO *
vmdk_open(int a_num_img,
    const TSK_TCHAR * const a_images[], unsigned int a_ssize)
{
    char error_string[TSK_VMDK_ERROR_STRING_SIZE];
    libvmdk_error_t *vmdk_error = NULL;
    int i;

    IMG_VMDK_INFO *vmdk_info = NULL;
    TSK_IMG_INFO *img_info = NULL;

    if (tsk_verbose) {
        libvmdk_notify_set_verbose(1);
        libvmdk_notify_set_stream(stderr, NULL);
    }

    if ((vmdk_info =
            (IMG_VMDK_INFO *) tsk_img_malloc(sizeof(IMG_VMDK_INFO))) ==
        NULL) {
        return NULL;
    }
    vmdk_info->handle = NULL;
    img_info = (TSK_IMG_INFO *) vmdk_info;
 
    vmdk_info->img_info.num_img = a_num_img;
    if ((vmdk_info->img_info.images =
        (TSK_TCHAR **) tsk_malloc(a_num_img *
        sizeof(TSK_TCHAR *))) == NULL) {
            tsk_img_free(vmdk_info);
            return NULL;
    }
    for (i = 0; i < a_num_img; i++) {
        if ((vmdk_info->img_info.images[i] =
            (TSK_TCHAR *) tsk_malloc((TSTRLEN(a_images[i]) +
            1) * sizeof(TSK_TCHAR))) == NULL) {
                tsk_img_free(vmdk_info);
                return NULL;
        }
        TSTRNCPY(vmdk_info->img_info.images[i], a_images[i],
            TSTRLEN(a_images[i]) + 1);
    }

    if (libvmdk_handle_initialize(&(vmdk_info->handle), &vmdk_error) != 1) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_OPEN);

        getError(vmdk_error, error_string);
        tsk_error_set_errstr("vmdk_open file: %" PRIttocTSK
            ": Error initializing handle (%s)", a_images[0], error_string);
        libvmdk_error_free(&vmdk_error);

        tsk_img_free(vmdk_info);

        if (tsk_verbose != 0) {
            tsk_fprintf(stderr, "Unable to create vmdk handle\n");
        }
        return (NULL);
    }
#if defined( TSK_WIN32 )
    if (libvmdk_handle_open_wide(vmdk_info->handle,
            (const wchar_t *) vmdk_info->img_info.images[0],
            LIBVMDK_OPEN_READ, &vmdk_error) != 1)
#else
    if (libvmdk_handle_open(vmdk_info->handle,
            (const char *) vmdk_info->img_info.images[0],
            LIBVMDK_OPEN_READ, &vmdk_error) != 1)
#endif
    {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_OPEN);

        getError(vmdk_error, error_string);
        tsk_error_set_errstr("vmdk_open file: %" PRIttocTSK
            ": Error opening (%s)", a_images[0], error_string);
        libvmdk_error_free(&vmdk_error);

        tsk_img_free(vmdk_info);

        if (tsk_verbose != 0) {
            tsk_fprintf(stderr, "Error opening vmdk file\n");
        }
        return (NULL);
    }
    if( libvmdk_handle_open_extent_data_files(vmdk_info->handle, &vmdk_error ) != 1 )
	{
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_OPEN);

        getError(vmdk_error, error_string);
        tsk_error_set_errstr("vmdk_open file: %" PRIttocTSK
            ": Error opening extent data files for image (%s)", a_images[0],
            error_string);
        libvmdk_error_free(&vmdk_error);

        tsk_img_free(vmdk_info);

        if (tsk_verbose != 0) {
            tsk_fprintf(stderr, "Error opening vmdk extent data files\n");
        }
        return (NULL);
    }
    if (libvmdk_handle_get_media_size(vmdk_info->handle,
            (size64_t *) & (img_info->size), &vmdk_error) != 1) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_OPEN);

        getError(vmdk_error, error_string);
        tsk_error_set_errstr("vmdk_open file: %" PRIttocTSK
            ": Error getting size of image (%s)", a_images[0],
            error_string);
        libvmdk_error_free(&vmdk_error);

        tsk_img_free(vmdk_info);

        if (tsk_verbose != 0) {
            tsk_fprintf(stderr, "Error getting size of vmdk file\n");
        }
        return (NULL);
    }

    if (a_ssize != 0) {
        img_info->sector_size = a_ssize;
    }
    else {
        img_info->sector_size = 512;
    }
    img_info->itype = TSK_IMG_TYPE_VMDK_VMDK;
    img_info->read = &vmdk_image_read;
    img_info->close = &vmdk_image_close;
    img_info->imgstat = &vmdk_image_imgstat;

    // initialize the read lock
    tsk_init_lock(&(vmdk_info->read_lock));

    return (img_info);
}

#endif /* HAVE_LIBVMDK */
