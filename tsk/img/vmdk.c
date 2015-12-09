/*
 * The Sleuth Kit - Add on for VMDK (Virtual Machine Disk) image support
 *
 * Copyright (c) 2006, 2011 Joachim Metz <jbmetz@users.sourceforge.net>
 *
 * This software is distributed under the Common Public License 1.0
 *
 * Based on raw image support of the Sleuth Kit from
 * Brian Carrier.
 */

/** \file vmdk.c
 * Internal code for TSK to interface with libvmdk.
 */

#include "tsk_img_i.h"

#if HAVE_LIBVMDK
#include "vmdk.h"

#define TSK_VMDK_ERROR_STRING_SIZE 512


/**
 * Get error string from libvmdk and make buffer emtpy if that didn't work. 
 * @returns 1 if error message was not set
*/
static uint8_t
getError(libcerror_error_t * vmdk_error,
    char error_string[TSK_VMDK_ERROR_STRING_SIZE])
{
    int retval;
    error_string[0] = '\0';
    retval = libcerror_error_backtrace_sprint(vmdk_error,
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
    libcerror_error_t *vmdk_error = NULL;

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
    vmdk_image_close(TSK_IMG_INFO * img_info)
{
    int i;
    libcerror_error_t *error = NULL;
    char *errmsg = NULL;
    IMG_VMDK_INFO *vmdk_info = (IMG_VMDK_INFO *) img_info;

    if( libvmdk_handle_close(vmdk_info->handle, &error ) != 0 )
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
    if( libvmdk_handle_free(&(vmdk_info->handle), &error ) != 1 )
    {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUX_GENERIC);
        if (getError(vmdk_error, error_string))
            errmsg = strerror(errno);
        else
            errmsg = error_string;

        tsk_error_set_errstr("vmdk_image_close: unable to free handle - %s", errmsg);
    }

    // ELTODO: this stuff crashes in libewf. keep an eye. See ewf.c.
    for (i = 0; i < vmdk_info->num_imgs; i++) {
        free(vmdk_info->images[i]);
    }
    free(vmdk_info->images);

    tsk_deinit_lock(&(vmdk_info->read_lock));
    tsk_img_free(img_info);
}


#endif /* HAVE_LIBVMDK */
