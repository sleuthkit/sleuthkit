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

    // ELTODO: this stuff crashes in libvmdk. keep an eye. See vmdk.c.
    for (i = 0; i < vmdk_info->num_imgs; i++) {
        free(vmdk_info->images[i]);
    }
    free(vmdk_info->images);

    tsk_deinit_lock(&(vmdk_info->read_lock));
    tsk_img_free(img_info);
}



TSK_IMG_INFO *
vmdk_open(int a_num_img,
    const TSK_TCHAR * const a_images[], unsigned int a_ssize)
{
    char error_string[TSK_VMDK_ERROR_STRING_SIZE];
    libcerror_error_t *vmdk_error = NULL;
    int result = 0;

    IMG_VMDK_INFO *vmdk_info = NULL;
    TSK_IMG_INFO *img_info = NULL;

    if (tsk_verbose) {
        libvmdk_notify_set_verbose(1);
        libvmdk_notify_set_stream(stderr, NULL);    // ELTODO: stderr
    }

    if ((vmdk_info =
            (IMG_VMDK_INFO *) tsk_img_malloc(sizeof(IMG_VMDK_INFO))) ==
        NULL) {
        return NULL;
    }
    img_info = (TSK_IMG_INFO *) vmdk_info;

    // See if they specified only the first of the set...    
    if (a_num_img == 1) {
        // ELTODO: ewf calls some kind of "glob" here to figure out number of segments.
        // Perhaps use libvmdk_handle_get_number_of_extents()?
        /*if (tsk_verbose)
            tsk_fprintf(stderr,
                "vmdk_open: found %d segment files via libvmdk_glob\n",
                vmdk_info->num_imgs);*/
    }
    else {
        int i;
        vmdk_info->num_imgs = a_num_img;
        if ((vmdk_info->images =
                (TSK_TCHAR **) tsk_malloc(a_num_img *
                    sizeof(TSK_TCHAR *))) == NULL) {
            tsk_img_free(vmdk_info);
            return NULL;
        }
        for (i = 0; i < a_num_img; i++) {
            if ((vmdk_info->images[i] =
                    (TSK_TCHAR *) tsk_malloc((TSTRLEN(a_images[i]) +
                            1) * sizeof(TSK_TCHAR))) == NULL) {
                tsk_img_free(vmdk_info);
                return NULL;
            }
            TSTRNCPY(vmdk_info->images[i], a_images[i],
                TSTRLEN(a_images[i]) + 1);
        }
    }


#if defined( HAVE_LIBvmdk_V2_API )

    // Check the file signature before we call the library open
#if defined( TSK_WIN32 )
    if (libvmdk_check_file_signature_wide(a_images[0], &vmdk_error) != 1)
#else
    if (libvmdk_check_file_signature(a_images[0], &vmdk_error) != 1)
#endif
    {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_MAGIC);

        getError(vmdk_error, error_string);
        tsk_error_set_errstr("vmdk_open: Not an vmdk file (%s)",
            error_string);
        libvmdk_error_free(&vmdk_error);

        tsk_img_free(vmdk_info);

        if (tsk_verbose != 0) {
            tsk_fprintf(stderr, "Not an vmdk file\n");
        }
        return (NULL);
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
            (wchar_t * const *) vmdk_info->images,
            vmdk_info->num_imgs, LIBvmdk_OPEN_READ, &vmdk_error) != 1)
#else
    if (libvmdk_handle_open(vmdk_info->handle,
            (char *const *) vmdk_info->images,
            vmdk_info->num_imgs, LIBvmdk_OPEN_READ, &vmdk_error) != 1)
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
    result = libvmdk_handle_get_utf8_hash_value_md5(vmdk_info->handle,
        (uint8_t *) vmdk_info->md5hash, 33, &vmdk_error);

    if (result == -1) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_OPEN);

        getError(vmdk_error, error_string);
        tsk_error_set_errstr("vmdk_open file: %" PRIttocTSK
            ": Error getting MD5 of image (%s)", a_images[0],
            error_string);
        libvmdk_error_free(&vmdk_error);

        tsk_img_free(vmdk_info);

        if (tsk_verbose != 0) {
            tsk_fprintf(stderr, "Error getting size of vmdk file\n");
        }
        return (NULL);
    }
    vmdk_info->md5hash_isset = result;

#else                           // V1 API

    // Check the file signature before we call the library open
#if defined( TSK_WIN32 )
    if (libvmdk_check_file_signature_wide(a_images[0]) != 1)
#else
    if (libvmdk_check_file_signature(a_images[0]) != 1)
#endif
    {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_MAGIC);
        tsk_error_set_errstr("vmdk_open: Not an vmdk file");
        tsk_img_free(vmdk_info);
        if (tsk_verbose)
            tsk_fprintf(stderr, "Not an vmdk file\n");

        return NULL;
    }

#if defined( TSK_WIN32 )
    vmdk_info->handle = libvmdk_open_wide(
        (wchar_t * const *) vmdk_info->images, vmdk_info->num_imgs,
        LIBvmdk_OPEN_READ);
#else
    vmdk_info->handle = libvmdk_open(
        (char *const *) vmdk_info->images, vmdk_info->num_imgs,
        LIBvmdk_OPEN_READ);
#endif
    if (vmdk_info->handle == NULL) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_OPEN);
        tsk_error_set_errstr("vmdk_open file: %" PRIttocTSK
            ": Error opening", vmdk_info->images[0]);
        tsk_img_free(vmdk_info);

        if (tsk_verbose != 0) {
            tsk_fprintf(stderr, "Error opening vmdk file\n");
        }
        return (NULL);
    }
#if defined( LIBvmdk_STRING_DIGEST_HASH_LENGTH_MD5 )
    // 2007 version
    img_info->size = libvmdk_get_media_size(vmdk_info->handle);

    vmdk_info->md5hash_isset = libvmdk_get_stored_md5_hash(vmdk_info->handle,
        vmdk_info->md5hash, LIBvmdk_STRING_DIGEST_HASH_LENGTH_MD5);
#else
    // libvmdk-20080322 version
    if (libvmdk_get_media_size(vmdk_info->handle,
            (size64_t *) & (img_info->size)) != 1) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_OPEN);
        tsk_error_set_errstr("vmdk_open file: %" PRIttocTSK
            ": Error getting size of image", vmdk_info->images[0]);
        tsk_img_free(vmdk_info);
        if (tsk_verbose) {
            tsk_fprintf(stderr, "Error getting size of vmdk file\n");
        }
        return (NULL);
    }
    if (libvmdk_get_md5_hash(vmdk_info->handle, md5_hash, 16) == 1) {
        int md5_string_iterator = 0;
        int md5_hash_iterator = 0;

        for (md5_hash_iterator = 0;
            md5_hash_iterator < 16; md5_hash_iterator++) {
            int digit = md5_hash[md5_hash_iterator] / 16;

            if (digit <= 9) {
                vmdk_info->md5hash[md5_string_iterator++] =
                    '0' + (char) digit;
            }
            else {
                vmdk_info->md5hash[md5_string_iterator++] =
                    'a' + (char) (digit - 10);
            }
            digit = md5_hash[md5_hash_iterator] % 16;

            if (digit <= 9) {
                vmdk_info->md5hash[md5_string_iterator++] =
                    '0' + (char) digit;
            }
            else {
                vmdk_info->md5hash[md5_string_iterator++] =
                    'a' + (char) (digit - 10);
            }
        }
        vmdk_info->md5hash_isset = 1;
    }
#endif                          /* defined( LIBvmdk_STRING_DIGEST_HASH_LENGTH_MD5 ) */
#endif                          /* defined( HAVE_LIBvmdk_V2_API ) */
    if (a_ssize != 0) {
        img_info->sector_size = a_ssize;
    }
    else {
        img_info->sector_size = 512;
    }
    img_info->itype = TSK_IMG_TYPE_vmdk_vmdk;
    img_info->read = &vmdk_image_read;
    img_info->close = &vmdk_image_close;
    img_info->imgstat = &vmdk_image_imgstat;

    // initialize the read lock
    tsk_init_lock(&(vmdk_info->read_lock));

    return (img_info);
}

#endif /* HAVE_LIBVMDK */
