/*
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2006-2016 Brian Carrier, Basis Technology.  All rights reserved
 * Copyright (c) 2005 Brian Carrier.  All rights reserved
 *
 * This software is distributed under the Common Public License 1.0
 *
 */


/** \file vhd.c
 * Internal code for TSK to interface with libvhdi.
 */

#include "tsk_img_i.h"

#if HAVE_LIBVHDI
#include "vhd.h"

#define TSK_VHDI_ERROR_STRING_SIZE 512

/**
 * Get error string from libvhdi and make buffer empty if that didn't work. 
 * @returns 1 if error message was not set
*/
static uint8_t
getError(libvhdi_error_t * vhdi_error,
    char error_string[TSK_VHDI_ERROR_STRING_SIZE])
{
    int retval;
    error_string[0] = '\0';
    retval = libvhdi_error_backtrace_sprint(vhdi_error,
        error_string, TSK_VHDI_ERROR_STRING_SIZE);
    if (retval)
        return 1;
    return 0;
} 


static ssize_t
vhdi_image_read(TSK_IMG_INFO * img_info, TSK_OFF_T offset, char *buf,
    size_t len)
{
    char error_string[TSK_VHDI_ERROR_STRING_SIZE];
    libvhdi_error_t *vhdi_error = NULL;

    ssize_t cnt;
    IMG_VHDI_INFO *vhdi_info = (IMG_VHDI_INFO *) img_info;

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "vhdi_image_read: byte offset: %" PRIuOFF " len: %" PRIuSIZE
            "\n", offset, len);

    if (offset > img_info->size) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_READ_OFF);
        tsk_error_set_errstr("vhdi_image_read - %" PRIuOFF, offset);
        return -1;
    }

    tsk_take_lock(&(vhdi_info->read_lock));

    cnt = libvhdi_file_read_buffer_at_offset(vhdi_info->handle,
        buf, len, offset, &vhdi_error);
    if (cnt < 0) {
        char *errmsg = NULL;
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_READ);
        if (getError(vhdi_error, error_string))
            errmsg = strerror(errno);
        else
            errmsg = error_string;

        tsk_error_set_errstr("vhdi_image_read - offset: %" PRIuOFF
            " - len: %" PRIuSIZE " - %s", offset, len, errmsg);
        tsk_release_lock(&(vhdi_info->read_lock));
        return -1;
    }

    tsk_release_lock(&(vhdi_info->read_lock));

    return cnt;
}

static void
vhdi_image_imgstat(TSK_IMG_INFO * img_info, FILE * hFile)
{
    tsk_fprintf(hFile, "IMAGE FILE INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");
    tsk_fprintf(hFile, "Image Type:\t\tvhdi\n");
    tsk_fprintf(hFile, "\nSize of data in bytes:\t%" PRIuOFF "\n",
        img_info->size);
    tsk_fprintf(hFile, "Sector size:\t%d\n", img_info->sector_size);

    return;
}


static void
    vhdi_image_close(TSK_IMG_INFO * img_info)
{
    int i;
    char error_string[TSK_VHDI_ERROR_STRING_SIZE];
    libvhdi_error_t *vhdi_error = NULL;
    char *errmsg = NULL;
    IMG_VHDI_INFO *vhdi_info = (IMG_VHDI_INFO *) img_info;

    if( libvhdi_file_close(vhdi_info->handle, &vhdi_error ) != 0 )
    {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUX_GENERIC);
        if (getError(vhdi_error, error_string))
            errmsg = strerror(errno);
        else
            errmsg = error_string;

        tsk_error_set_errstr("vhdi_image_close: unable to close handle - %s", errmsg);
    }

    libvhdi_file_free(&(vhdi_info->handle), NULL);
    if( libvhdi_file_free(&(vhdi_info->handle), &vhdi_error ) != 1 )
    {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUX_GENERIC);
        if (getError(vhdi_error, error_string))
            errmsg = strerror(errno);
        else
            errmsg = error_string;

        tsk_error_set_errstr("vhdi_image_close: unable to free handle - %s", errmsg);
    }

    for (i = 0; i < vhdi_info->img_info.num_img; i++) {
        free(vhdi_info->img_info.images[i]);
    }
    free(vhdi_info->img_info.images);

    tsk_deinit_lock(&(vhdi_info->read_lock));
    tsk_img_free(img_info);
}

TSK_IMG_INFO *
vhdi_open(int a_num_img,
    const TSK_TCHAR * const a_images[], unsigned int a_ssize)
{
    char error_string[TSK_VHDI_ERROR_STRING_SIZE];
    libvhdi_error_t *vhdi_error = NULL;
    int i;

    IMG_VHDI_INFO *vhdi_info = NULL;
    TSK_IMG_INFO *img_info = NULL;

    if (tsk_verbose) {
        libvhdi_notify_set_verbose(1);
        libvhdi_notify_set_stream(stderr, NULL);
    }

    if ((vhdi_info =
            (IMG_VHDI_INFO *) tsk_img_malloc(sizeof(IMG_VHDI_INFO))) ==
        NULL) {
        return NULL;
    }
    vhdi_info->handle = NULL;
    img_info = (TSK_IMG_INFO *) vhdi_info;
 
    vhdi_info->img_info.num_img = a_num_img;
    if ((vhdi_info->img_info.images =
        (TSK_TCHAR **) tsk_malloc(a_num_img *
        sizeof(TSK_TCHAR *))) == NULL) {
            tsk_img_free(vhdi_info);
            return NULL;
    }
    for (i = 0; i < a_num_img; i++) {
        if ((vhdi_info->img_info.images[i] =
            (TSK_TCHAR *) tsk_malloc((TSTRLEN(a_images[i]) +
            1) * sizeof(TSK_TCHAR))) == NULL) {
                tsk_img_free(vhdi_info);
                return NULL;
        }
        TSTRNCPY(vhdi_info->img_info.images[i], a_images[i],
            TSTRLEN(a_images[i]) + 1);
    }

    if (libvhdi_file_initialize(&(vhdi_info->handle), &vhdi_error) != 1) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_OPEN);

        getError(vhdi_error, error_string);
        tsk_error_set_errstr("vhdi_open file: %" PRIttocTSK
            ": Error initializing handle (%s)", a_images[0], error_string);
        libvhdi_error_free(&vhdi_error);

        tsk_img_free(vhdi_info);

        if (tsk_verbose != 0) {
            tsk_fprintf(stderr, "Unable to create vhdi handle\n");
        }
        return (NULL);
    }
    // Check the file signature before we call the library open
#if defined( TSK_WIN32 )
    if( libvhdi_check_file_signature_wide((const wchar_t *) vhdi_info->img_info.images[0], &vhdi_error ) != 1 )
#else
    if( libvhdi_check_file_signature((const char *) vhdi_info->img_info.images[0], &vhdi_error) != 1)
#endif
	{
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_OPEN);

        getError(vhdi_error, error_string);
        tsk_error_set_errstr("vhdi_open file: %" PRIttocTSK
            ": Error checking file signature for image (%s)", a_images[0],
            error_string);
        libvhdi_error_free(&vhdi_error);

        tsk_img_free(vhdi_info);

        if (tsk_verbose != 0) {
            tsk_fprintf(stderr, "Error checking file signature for vhd file\n");
        }
        return (NULL);
    }
#if defined( TSK_WIN32 )
    if (libvhdi_file_open_wide(vhdi_info->handle,
            (const wchar_t *) vhdi_info->img_info.images[0],
            LIBVHDI_OPEN_READ, &vhdi_error) != 1)
#else
    if (libvhdi_file_open(vhdi_info->handle,
            (const char *) vhdi_info->img_info.images[0],
            LIBVHDI_OPEN_READ, &vhdi_error) != 1)
#endif
    {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_OPEN);

        getError(vhdi_error, error_string);
        tsk_error_set_errstr("vhdi_open file: %" PRIttocTSK
            ": Error opening (%s)", a_images[0], error_string);
        libvhdi_error_free(&vhdi_error);

        tsk_img_free(vhdi_info);

        if (tsk_verbose != 0) {
            tsk_fprintf(stderr, "Error opening vhdi file\n");
        }
        return (NULL);
    }
    if (libvhdi_file_get_media_size(vhdi_info->handle,
            (size64_t *) & (img_info->size), &vhdi_error) != 1) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_OPEN);

        getError(vhdi_error, error_string);
        tsk_error_set_errstr("vhdi_open file: %" PRIttocTSK
            ": Error getting size of image (%s)", a_images[0],
            error_string);
        libvhdi_error_free(&vhdi_error);

        tsk_img_free(vhdi_info);

        if (tsk_verbose != 0) {
            tsk_fprintf(stderr, "Error getting size of vhdi file\n");
        }
        return (NULL);
    }

    if (a_ssize != 0) {
        img_info->sector_size = a_ssize;
    }
    else {
        img_info->sector_size = 512;
    }
    img_info->itype = TSK_IMG_TYPE_VHD_VHD;
    img_info->read = &vhdi_image_read;
    img_info->close = &vhdi_image_close;
    img_info->imgstat = &vhdi_image_imgstat;

    // initialize the read lock
    tsk_init_lock(&(vhdi_info->read_lock));

    return (img_info);
}

#endif /* HAVE_LIBVHDI */
