/*
 * The Sleuth Kit - Add on for Expert Witness Compression Format (EWF) image support
 *
 * Copyright (c) 2006, 2011 Joachim Metz <jbmetz@users.sourceforge.net>
 *
 * This software is distributed under the Common Public License 1.0
 *
 * Based on raw image support of the Sleuth Kit from
 * Brian Carrier.
 */

/** \file ewf.c
 * Internal code for TSK to interface with libewf.
 */

#include "tsk_img_i.h"

#if HAVE_LIBEWF
#include "ewf.h"

#define TSK_EWF_ERROR_STRING_SIZE 512


#if defined( HAVE_LIBEWF_V2_API )
/**
 * Get error string from libewf and make buffer empty if that didn't work. 
 * @returns 1 if error message was not set
 */
static uint8_t
getError(libewf_error_t * ewf_error,
    char error_string[TSK_EWF_ERROR_STRING_SIZE])
{
    int retval;
    error_string[0] = '\0';
    retval = libewf_error_backtrace_sprint(ewf_error,
        error_string, TSK_EWF_ERROR_STRING_SIZE);
    return retval <= 0;
}
#endif

static ssize_t
ewf_image_read(TSK_IMG_INFO * img_info, TSK_OFF_T offset, char *buf,
    size_t len)
{
#if defined( HAVE_LIBEWF_V2_API )
    char error_string[TSK_EWF_ERROR_STRING_SIZE];
    libewf_error_t *ewf_error = NULL;
#endif

    ssize_t cnt;
    IMG_EWF_INFO *ewf_info = (IMG_EWF_INFO *) img_info;

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "ewf_image_read: byte offset: %" PRIuOFF " len: %" PRIuSIZE
            "\n", offset, len);

    if (offset > img_info->size) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_READ_OFF);
        tsk_error_set_errstr("ewf_image_read - %" PRIuOFF, offset);
        return -1;
    }

    tsk_take_lock(&(ewf_info->read_lock));
#if defined( HAVE_LIBEWF_V2_API )
    cnt = libewf_handle_read_random(ewf_info->handle,
        buf, len, offset, &ewf_error);
    if (cnt < 0) {
        char *errmsg = NULL;
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_READ);
        if (getError(ewf_error, error_string))
            errmsg = strerror(errno);
        else
            errmsg = error_string;

        tsk_error_set_errstr("ewf_image_read - offset: %" PRIuOFF
            " - len: %" PRIuSIZE " - %s", offset, len, errmsg);
        tsk_release_lock(&(ewf_info->read_lock));
        return -1;
    }
#else
    cnt = libewf_read_random(ewf_info->handle, buf, len, offset);
    if (cnt < 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_READ);
        tsk_error_set_errstr("ewf_image_read - offset: %" PRIuOFF
            " - len: %" PRIuSIZE " - %s", offset, len, strerror(errno));
        tsk_release_lock(&(ewf_info->read_lock));
        return -1;
    }
#endif
    tsk_release_lock(&(ewf_info->read_lock));

    return cnt;
}

static void
ewf_image_imgstat(TSK_IMG_INFO * img_info, FILE * hFile)
{
    IMG_EWF_INFO *ewf_info = (IMG_EWF_INFO *) img_info;

    tsk_fprintf(hFile, "IMAGE FILE INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");
    tsk_fprintf(hFile, "Image Type:\t\tewf\n");
    tsk_fprintf(hFile, "\nSize of data in bytes:\t%" PRIuOFF "\n",
        img_info->size);
    tsk_fprintf(hFile, "Sector size:\t%d\n", img_info->sector_size);

    if (ewf_info->md5hash_isset == 1) {
        tsk_fprintf(hFile, "MD5 hash of data:\t%s\n", ewf_info->md5hash);
    }
    return;
}

static void
ewf_image_close(TSK_IMG_INFO * img_info)
{
    IMG_EWF_INFO *ewf_info = (IMG_EWF_INFO *) img_info;

#if defined ( HAVE_LIBEWF_V2_API)
    libewf_handle_close(ewf_info->handle, NULL);
    libewf_handle_free(&(ewf_info->handle), NULL);

#else
    libewf_close(ewf_info->handle);
#endif

    // this stuff crashes if we used glob. v2 of the API has a free method.
    // not clear from the docs what we should do in v1...
    // @@@ Probably a memory leak in v1 unless libewf_close deals with it
    if (ewf_info->used_ewf_glob == 0) {
        int i;
        for (i = 0; i < ewf_info->img_info.num_img; i++) {
            free(ewf_info->img_info.images[i]);
        }
        free(ewf_info->img_info.images);
    }
    else {
        libewf_error_t *error;
#ifdef TSK_WIN32
        libewf_glob_wide_free( ewf_info->img_info.images, ewf_info->img_info.num_img, &error);
#else
        libewf_glob_free( ewf_info->img_info.images, ewf_info->img_info.num_img, &error);
#endif
    }

    tsk_deinit_lock(&(ewf_info->read_lock));
    tsk_img_free(ewf_info);
}

/* Tests if the image file header against the
 * header (magic) signature specified.
 * Returns a 0 on no match and a 1 on a match, and -1 on error.
 */
#if 0
static int
img_file_header_signature_ncmp(const char *filename,
    const char *file_header_signature, int size_of_signature)
{
    int match;
    ssize_t read_count = 0;
    char header[512];
    int fd;

    if ((filename == NULL) || (file_header_signature == NULL)) {
        return (0);
    }
    if (size_of_signature <= 0) {
        return (0);
    }

    if ((fd = open(filename, O_RDONLY | O_BINARY)) < 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_OPEN);
        tsk_error_set_errstr("ewf magic testing: %s", filename);
        return -1;
    }
    read_count = read(fd, header, 512);

    if (read_count != 512) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_READ);
        tsk_error_set_errstr("ewf magic testing: %s", filename);
        return -1;
    }
    close(fd);

    match = strncmp(file_header_signature, header, size_of_signature) == 0;

    return (match);
}
#endif



TSK_IMG_INFO *
ewf_open(int a_num_img,
    const TSK_TCHAR * const a_images[], unsigned int a_ssize)
{
    int is_error;
#if defined( HAVE_LIBEWF_V2_API )
    char error_string[TSK_EWF_ERROR_STRING_SIZE];

    libewf_error_t *ewf_error = NULL;
    int result = 0;
#elif !defined( LIBEWF_STRING_DIGEST_HASH_LENGTH_MD5 )
    uint8_t md5_hash[16];
#endif

    IMG_EWF_INFO *ewf_info = NULL;
    TSK_IMG_INFO *img_info = NULL;

#if !defined( HAVE_LIBEWF_V2_API)
    if (tsk_verbose)
        libewf_set_notify_values(stderr, 1);
#endif

    if ((ewf_info =
            (IMG_EWF_INFO *) tsk_img_malloc(sizeof(IMG_EWF_INFO))) ==
        NULL) {
        return NULL;
    }
    img_info = (TSK_IMG_INFO *) ewf_info;

    // See if they specified only the first of the set...
    ewf_info->used_ewf_glob = 0;
    if (a_num_img == 1) {
#if defined( HAVE_LIBEWF_V2_API)
#ifdef TSK_WIN32
        is_error = (libewf_glob_wide(a_images[0], TSTRLEN(a_images[0]),
                LIBEWF_FORMAT_UNKNOWN, &ewf_info->img_info.images,
                &ewf_info->img_info.num_img, &ewf_error) == -1);
#else
        is_error = (libewf_glob(a_images[0], TSTRLEN(a_images[0]),
                LIBEWF_FORMAT_UNKNOWN, &ewf_info->img_info.images,
                &ewf_info->img_info.num_img, &ewf_error) == -1);
#endif
        if (is_error){
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_IMG_MAGIC);

            getError(ewf_error, error_string);
            tsk_error_set_errstr("ewf_open: Not an E01 glob name (%s)",
                error_string);
            libewf_error_free(&ewf_error);
            tsk_img_free(ewf_info);
            return NULL;
        }

#else                           //use v1

#ifdef TSK_WIN32
        ewf_info->img_info.num_img =
            libewf_glob_wide(a_images[0], TSTRLEN(a_images[0]),
            LIBEWF_FORMAT_UNKNOWN, &ewf_info->img_info.images);
#else
        ewf_info->img_info.num_img =
            libewf_glob(a_images[0], TSTRLEN(a_images[0]),
            LIBEWF_FORMAT_UNKNOWN, &ewf_info->img_info.images);
#endif
        if (ewf_info->img_info.num_img <= 0) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_IMG_MAGIC);
            tsk_error_set_errstr("ewf_open: Not an E01 glob name");

            tsk_img_free(ewf_info);
            return NULL;
        }
#endif                          // end v1

        ewf_info->used_ewf_glob = 1;
        if (tsk_verbose)
            tsk_fprintf(stderr,
                "ewf_open: found %d segment files via libewf_glob\n",
                ewf_info->img_info.num_img);
    }
    else {
        int i;
        ewf_info->img_info.num_img = a_num_img;
        if ((ewf_info->img_info.images =
                (TSK_TCHAR **) tsk_malloc(a_num_img *
                    sizeof(TSK_TCHAR *))) == NULL) {
            tsk_img_free(ewf_info);
            return NULL;
        }
        for (i = 0; i < a_num_img; i++) {
            if ((ewf_info->img_info.images[i] =
                    (TSK_TCHAR *) tsk_malloc((TSTRLEN(a_images[i]) +
                            1) * sizeof(TSK_TCHAR))) == NULL) {
                tsk_img_free(ewf_info);
                return NULL;
            }
            TSTRNCPY(ewf_info->img_info.images[i], a_images[i],
                TSTRLEN(a_images[i]) + 1);
        }
    }


#if defined( HAVE_LIBEWF_V2_API )

    // Check the file signature before we call the library open
#if defined( TSK_WIN32 )
    is_error = (libewf_check_file_signature_wide(a_images[0], &ewf_error) != 1);
#else
    is_error = (libewf_check_file_signature(a_images[0], &ewf_error) != 1);
#endif
    if (is_error)
    {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_MAGIC);

        getError(ewf_error, error_string);
        tsk_error_set_errstr("ewf_open: Not an EWF file (%s)",
            error_string);
        libewf_error_free(&ewf_error);

        tsk_img_free(ewf_info);

        if (tsk_verbose != 0) {
            tsk_fprintf(stderr, "Not an EWF file\n");
        }
        return (NULL);
    }

    if (libewf_handle_initialize(&(ewf_info->handle), &ewf_error) != 1) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_OPEN);

        getError(ewf_error, error_string);
        tsk_error_set_errstr("ewf_open file: %" PRIttocTSK
            ": Error initializing handle (%s)", a_images[0], error_string);
        libewf_error_free(&ewf_error);

        tsk_img_free(ewf_info);

        if (tsk_verbose != 0) {
            tsk_fprintf(stderr, "Unable to create EWF handle\n");
        }
        return (NULL);
    }
#if defined( TSK_WIN32 )
    is_error = (libewf_handle_open_wide(ewf_info->handle,
            (wchar_t * const *) ewf_info->img_info.images,
            ewf_info->img_info.num_img, LIBEWF_OPEN_READ, &ewf_error) != 1);
#else
    is_error = (libewf_handle_open(ewf_info->handle,
            (char *const *) ewf_info->img_info.images,
            ewf_info->img_info.num_img, LIBEWF_OPEN_READ, &ewf_error) != 1);
#endif
    if (is_error)
    {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_OPEN);

        getError(ewf_error, error_string);
        tsk_error_set_errstr("ewf_open file: %" PRIttocTSK
            ": Error opening (%s)", a_images[0], error_string);
        libewf_error_free(&ewf_error);

        tsk_img_free(ewf_info);

        if (tsk_verbose != 0) {
            tsk_fprintf(stderr, "Error opening EWF file\n");
        }
        return (NULL);
    }
    if (libewf_handle_get_media_size(ewf_info->handle,
            (size64_t *) & (img_info->size), &ewf_error) != 1) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_OPEN);

        getError(ewf_error, error_string);
        tsk_error_set_errstr("ewf_open file: %" PRIttocTSK
            ": Error getting size of image (%s)", a_images[0],
            error_string);
        libewf_error_free(&ewf_error);

        tsk_img_free(ewf_info);

        if (tsk_verbose != 0) {
            tsk_fprintf(stderr, "Error getting size of EWF file\n");
        }
        return (NULL);
    }
    result = libewf_handle_get_utf8_hash_value_md5(ewf_info->handle,
        (uint8_t *) ewf_info->md5hash, 33, &ewf_error);

    if (result == -1) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_OPEN);

        getError(ewf_error, error_string);
        tsk_error_set_errstr("ewf_open file: %" PRIttocTSK
            ": Error getting MD5 of image (%s)", a_images[0],
            error_string);
        libewf_error_free(&ewf_error);

        tsk_img_free(ewf_info);

        if (tsk_verbose != 0) {
            tsk_fprintf(stderr, "Error getting size of EWF file\n");
        }
        return (NULL);
    }
    ewf_info->md5hash_isset = result;

#else                           // V1 API

    // Check the file signature before we call the library open
#if defined( TSK_WIN32 )
    is_error = (libewf_check_file_signature_wide(a_images[0]) != 1);
#else
    is_error = (libewf_check_file_signature(a_images[0]) != 1);
#endif
    if (is_error)
    {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_MAGIC);
        tsk_error_set_errstr("ewf_open: Not an EWF file");
        tsk_img_free(ewf_info);
        if (tsk_verbose)
            tsk_fprintf(stderr, "Not an EWF file\n");

        return NULL;
    }

#if defined( TSK_WIN32 )
    ewf_info->handle = libewf_open_wide(
        (wchar_t * const *) ewf_info->img_info.images, ewf_info->img_info.num_img,
        LIBEWF_OPEN_READ);
#else
    ewf_info->handle = libewf_open(
        (char *const *) ewf_info->img_info.images, ewf_info->img_info.num_img,
        LIBEWF_OPEN_READ);
#endif
    if (ewf_info->handle == NULL) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_OPEN);
        tsk_error_set_errstr("ewf_open file: %" PRIttocTSK
            ": Error opening", ewf_info->img_info.images[0]);
        tsk_img_free(ewf_info);

        if (tsk_verbose != 0) {
            tsk_fprintf(stderr, "Error opening EWF file\n");
        }
        return (NULL);
    }
#if defined( LIBEWF_STRING_DIGEST_HASH_LENGTH_MD5 )
    // 2007 version
    img_info->size = libewf_get_media_size(ewf_info->handle);

    ewf_info->md5hash_isset = libewf_get_stored_md5_hash(ewf_info->handle,
        ewf_info->md5hash, LIBEWF_STRING_DIGEST_HASH_LENGTH_MD5);
#else
    // libewf-20080322 version
    if (libewf_get_media_size(ewf_info->handle,
            (size64_t *) & (img_info->size)) != 1) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_OPEN);
        tsk_error_set_errstr("ewf_open file: %" PRIttocTSK
            ": Error getting size of image", ewf_info->img_info.images[0]);
        tsk_img_free(ewf_info);
        if (tsk_verbose) {
            tsk_fprintf(stderr, "Error getting size of EWF file\n");
        }
        return (NULL);
    }
    if (libewf_get_md5_hash(ewf_info->handle, md5_hash, 16) == 1) {
        int md5_string_iterator = 0;
        int md5_hash_iterator = 0;

        for (md5_hash_iterator = 0;
            md5_hash_iterator < 16; md5_hash_iterator++) {
            int digit = md5_hash[md5_hash_iterator] / 16;

            if (digit <= 9) {
                ewf_info->md5hash[md5_string_iterator++] =
                    '0' + (char) digit;
            }
            else {
                ewf_info->md5hash[md5_string_iterator++] =
                    'a' + (char) (digit - 10);
            }
            digit = md5_hash[md5_hash_iterator] % 16;

            if (digit <= 9) {
                ewf_info->md5hash[md5_string_iterator++] =
                    '0' + (char) digit;
            }
            else {
                ewf_info->md5hash[md5_string_iterator++] =
                    'a' + (char) (digit - 10);
            }
        }
        ewf_info->md5hash_isset = 1;
    }
#endif                          /* defined( LIBEWF_STRING_DIGEST_HASH_LENGTH_MD5 ) */
#endif                          /* defined( HAVE_LIBEWF_V2_API ) */

    // use what they gave us
    if (a_ssize != 0) {
        img_info->sector_size = a_ssize;
    }
    else {
        uint32_t bytes_per_sector = 512;
        // see if the size is stored in the E01 file
        if (-1 == libewf_handle_get_bytes_per_sector(ewf_info->handle,
            &bytes_per_sector, &ewf_error)) {
            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "ewf_image_read: error getting sector size from E01\n");
            img_info->sector_size = 512;
        }
        else {
            // if E01 had size of 0 or non-512 then consider it junk and ignore
            if ((bytes_per_sector == 0) || (bytes_per_sector % 512)) {
                if (tsk_verbose)
                    tsk_fprintf(stderr,
                        "ewf_image_read: Ignoring sector size in E01 (%d)\n",
                        bytes_per_sector);
                bytes_per_sector = 512;
            }
            else {
                if (tsk_verbose)
                    tsk_fprintf(stderr,
                        "ewf_image_read: Using E01 sector size (%d)\n",
                        bytes_per_sector);
            }
            img_info->sector_size = bytes_per_sector;
        }
    }
    img_info->itype = TSK_IMG_TYPE_EWF_EWF;
    img_info->read = &ewf_image_read;
    img_info->close = &ewf_image_close;
    img_info->imgstat = &ewf_image_imgstat;

    // initialize the read lock
    tsk_init_lock(&(ewf_info->read_lock));

    return (img_info);
}
#endif                          /* HAVE_LIBEWF */
