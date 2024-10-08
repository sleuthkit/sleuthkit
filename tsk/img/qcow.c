/*
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2006-2016 Brian Carrier, Basis Technology.  All rights reserved
 * Copyright (c) 2005 Brian Carrier.  All rights reserved
 *
 * This software is distributed under the Common Public License 1.0
 *
 */


/** \file qcow.c
 * Internal code for TSK to interface with libqcow.
 */

#include "tsk_img_i.h"

#if HAVE_LIBQCOW
#include "qcow.h"

#define TSK_QCOW_ERROR_STRING_SIZE 512

/**
 * Get error string from libqcow and make buffer empty if that didn't work.
 * @returns 1 if error message was not set
*/
static uint8_t
getError(libqcow_error_t * qcow_error,
    char error_string[TSK_QCOW_ERROR_STRING_SIZE])
{
    int retval;
    error_string[0] = '\0';
    retval = libqcow_error_backtrace_sprint(qcow_error,
        error_string, TSK_QCOW_ERROR_STRING_SIZE);
    libqcow_error_free(&qcow_error);
    return retval ? 1 : 0;
}


static ssize_t
qcow_image_read(TSK_IMG_INFO * img_info, TSK_OFF_T offset, char *buf,
    size_t len)
{
    char error_string[TSK_QCOW_ERROR_STRING_SIZE];
    libqcow_error_t *qcow_error = NULL;

    ssize_t cnt;
    IMG_QCOW_INFO *qcow_info = (IMG_QCOW_INFO *) img_info;

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "qcow_image_read: byte offset: %" PRIdOFF " len: %" PRIuSIZE
            "\n", offset, len);

    if (offset > img_info->size) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_READ_OFF);
        tsk_error_set_errstr("qcow_image_read - %" PRIdOFF, offset);
        return -1;
    }

    tsk_take_lock(&(qcow_info->read_lock));

    cnt = libqcow_file_read_buffer_at_offset(qcow_info->handle,
        buf, len, offset, &qcow_error);
    if (cnt < 0) {
        char *errmsg = NULL;
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_READ);
        if (getError(qcow_error, error_string))
            errmsg = strerror(errno);
        else
            errmsg = error_string;

        tsk_error_set_errstr("qcow_image_read - offset: %" PRIdOFF
            " - len: %" PRIuSIZE " - %s", offset, len, errmsg);
        tsk_release_lock(&(qcow_info->read_lock));
        return -1;
    }

    tsk_release_lock(&(qcow_info->read_lock));

    return cnt;
}

static void
qcow_image_imgstat(TSK_IMG_INFO * img_info, FILE * hFile)
{
    tsk_fprintf(hFile, "IMAGE FILE INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");
    tsk_fprintf(hFile, "Image Type:\t\tqcow\n");
    tsk_fprintf(hFile, "\nSize of data in bytes:\t%" PRIuSIZE "\n",
        img_info->size);
    tsk_fprintf(hFile, "Sector size:\t%d\n", img_info->sector_size);
}


static void
    qcow_image_close(TSK_IMG_INFO * img_info)
{
    char error_string[TSK_QCOW_ERROR_STRING_SIZE];
    libqcow_error_t *qcow_error = NULL;
    char *errmsg = NULL;
    IMG_QCOW_INFO *qcow_info = (IMG_QCOW_INFO *) img_info;

    if (libqcow_file_close(qcow_info->handle, &qcow_error) != 0)
    {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUX_GENERIC);
        if (getError(qcow_error, error_string))
            errmsg = strerror(errno);
        else
            errmsg = error_string;

        tsk_error_set_errstr("qcow_image_close: unable to close handle - %s", errmsg);
    }

    if (libqcow_file_free(&(qcow_info->handle), &qcow_error) != 1)
    {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUX_GENERIC);
        if (getError(qcow_error, error_string))
            errmsg = strerror(errno);
        else
            errmsg = error_string;

        tsk_error_set_errstr("qcow_image_close: unable to free handle - %s", errmsg);
    }

    tsk_deinit_lock(&(qcow_info->read_lock));
    tsk_img_free(img_info);
}

TSK_IMG_INFO *
qcow_open(int a_num_img,
    const TSK_TCHAR * const a_images[], unsigned int a_ssize)
{
    if (a_num_img != 1) {
        tsk_error_set_errstr("qcow_open file: %" PRIttocTSK
            ": expected one image filename, was given %d", a_images[0], a_num_img);

        if (tsk_verbose != 0) {
            tsk_fprintf(stderr, "qcow requires exactly 1 image filename for opening\n");
        }
        return NULL;
    }

    char error_string[TSK_QCOW_ERROR_STRING_SIZE];
    libqcow_error_t *qcow_error = NULL;

    IMG_QCOW_INFO *qcow_info = NULL;
    TSK_IMG_INFO *img_info = NULL;

    if (tsk_verbose) {
        libqcow_notify_set_verbose(1);
        libqcow_notify_set_stream(stderr, NULL);
    }

    if ((qcow_info =
            (IMG_QCOW_INFO *) tsk_img_malloc(sizeof(IMG_QCOW_INFO))) ==
        NULL) {
        return NULL;
    }
    qcow_info->handle = NULL;
    img_info = (TSK_IMG_INFO *) qcow_info;

    if (!tsk_img_copy_image_names(img_info, a_images, a_num_img)) {
        goto on_error;
    }

    if (libqcow_file_initialize(&(qcow_info->handle), &qcow_error) != 1) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_OPEN);

        getError(qcow_error, error_string);
        tsk_error_set_errstr("qcow_open file: %" PRIttocTSK
            ": Error initializing handle (%s)", a_images[0], error_string);

        if (tsk_verbose != 0) {
            tsk_fprintf(stderr, "Unable to create qcow handle\n");
        }
        goto on_error;
    }
    // Check the file signature before we call the library open
#if defined( TSK_WIN32 )
    if (libqcow_check_file_signature_wide((const wchar_t *) qcow_info->img_info.images[0], &qcow_error) != 1)
#else
    if (libqcow_check_file_signature((const char *) qcow_info->img_info.images[0], &qcow_error) != 1)
#endif
	{
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_OPEN);

        getError(qcow_error, error_string);
        tsk_error_set_errstr("qcow_open file: %" PRIttocTSK
            ": Error checking file signature for image (%s)", a_images[0],
            error_string);

        if (tsk_verbose != 0) {
            tsk_fprintf(stderr, "Error checking file signature for qcow file\n");
        }
        goto on_error;
    }
#if defined( TSK_WIN32 )
    if (libqcow_file_open_wide(qcow_info->handle,
            (const wchar_t *) qcow_info->img_info.images[0],
            LIBQCOW_OPEN_READ, &qcow_error) != 1)
#else
    if (libqcow_file_open(qcow_info->handle,
            (const char *) qcow_info->img_info.images[0],
            LIBQCOW_OPEN_READ, &qcow_error) != 1)
#endif
    {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_OPEN);

        getError(qcow_error, error_string);
        tsk_error_set_errstr("qcow_open file: %" PRIttocTSK
            ": Error opening (%s)", a_images[0], error_string);

        if (tsk_verbose != 0) {
            tsk_fprintf(stderr, "Error opening qcow file\n");
        }
        goto on_error;
    }
    if (libqcow_file_get_media_size(qcow_info->handle,
            (size64_t *) & (img_info->size), &qcow_error) != 1) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_OPEN);

        getError(qcow_error, error_string);
        tsk_error_set_errstr("qcow_open file: %" PRIttocTSK
            ": Error getting size of image (%s)", a_images[0],
            error_string);

        if (tsk_verbose != 0) {
            tsk_fprintf(stderr, "Error getting size of qcow file\n");
        }
        goto on_error;
    }

    if (a_ssize != 0) {
        img_info->sector_size = a_ssize;
    }
    else {
        img_info->sector_size = 512;
    }
    img_info->itype = TSK_IMG_TYPE_QCOW_QCOW;
    img_info->read = &qcow_image_read;
    img_info->close = &qcow_image_close;
    img_info->imgstat = &qcow_image_imgstat;

    // initialize the read lock
    tsk_init_lock(&(qcow_info->read_lock));

    return img_info;

on_error:
    if (qcow_info->handle) {
        libqcow_file_close(qcow_info->handle, NULL);
    }
    libqcow_file_free(&(qcow_info->handle), NULL);
    tsk_img_free(qcow_info);
    return NULL;
}

#endif /* HAVE_LIBQCOW */
