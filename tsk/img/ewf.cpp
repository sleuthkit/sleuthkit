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
#include <cctype>

using std::string;

#define TSK_EWF_ERROR_STRING_SIZE 512

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
    libewf_error_free(&ewf_error);
    return retval <= 0;
}

static ssize_t
ewf_image_read(TSK_IMG_INFO * img_info, TSK_OFF_T offset, char *buf,
    size_t len)
{
    char error_string[TSK_EWF_ERROR_STRING_SIZE];
    libewf_error_t *ewf_error = NULL;

    ssize_t cnt;
    IMG_EWF_INFO *ewf_info = (IMG_EWF_INFO *) img_info;

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "ewf_image_read: byte offset: %" PRIdOFF " len: %" PRIuSIZE
            "\n", offset, len);

    if (offset > img_info->size) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_READ_OFF);
        tsk_error_set_errstr("ewf_image_read - %" PRIdOFF, offset);
        return -1;
    }

    tsk_take_lock(&(ewf_info->read_lock));
#ifdef HAVE_LIBEWF_HANDLE_READ_BUFFER_AT_OFFSET
    cnt = libewf_handle_read_buffer_at_offset(
#else
    cnt = libewf_handle_read_random(
#endif
        ewf_info->handle, buf, len, offset, &ewf_error
    );
    if (cnt < 0) {
        char *errmsg = NULL;
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_READ);
        if (getError(ewf_error, error_string))
            errmsg = strerror(errno);
        else
            errmsg = error_string;

        libewf_error_free(&ewf_error);
        tsk_error_set_errstr("ewf_image_read - offset: %" PRIdOFF
            " - len: %" PRIuSIZE " - %s", offset, len, errmsg);
        tsk_release_lock(&(ewf_info->read_lock));
        return -1;
    }

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
    tsk_fprintf(hFile, "\nSize of data in bytes:\t%" PRIdOFF "\n",
        img_info->size);
    tsk_fprintf(hFile, "Sector size:\t%d\n", img_info->sector_size);

    if (ewf_info->md5hash_isset == 1) {
        tsk_fprintf(hFile, "MD5 hash of data:\t%s\n", ewf_info->md5hash);
    }
}

static void
ewf_glob_free(IMG_EWF_INFO* ewf_info) {
    // Freeing img_info->images ourselves is incorrect if we used glob.
    // v2 of the API has a free method. It's not clear from the docs what we
    // should do in v1...
    // @@@ Probably a memory leak in v1 unless libewf_close deals with it
    if (ewf_info->used_ewf_glob != 0) {
#ifdef TSK_WIN32
        libewf_glob_wide_free(ewf_info->img_info.images, ewf_info->img_info.num_img, NULL);
#else
        libewf_glob_free(ewf_info->img_info.images, ewf_info->img_info.num_img, NULL);
#endif
        // ensure that tsk_img_free() does not double free images
        ewf_info->img_info.images = NULL;
        ewf_info->img_info.num_img = 0;
    }
}

static void
ewf_image_close(TSK_IMG_INFO * img_info)
{
    IMG_EWF_INFO *ewf_info = (IMG_EWF_INFO *) img_info;

    libewf_handle_close(ewf_info->handle, NULL);
    libewf_handle_free(&(ewf_info->handle), NULL);

    ewf_glob_free(ewf_info);

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
        return 0;
    }
    if (size_of_signature <= 0) {
        return 0;
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

    return match;
}
#endif



TSK_IMG_INFO *
ewf_open(int a_num_img,
    const TSK_TCHAR * const a_images[], unsigned int a_ssize)
{
    int is_error;
    char error_string[TSK_EWF_ERROR_STRING_SIZE];

    libewf_error_t *ewf_error = NULL;
    int result = 0;

    IMG_EWF_INFO *ewf_info = NULL;
    TSK_IMG_INFO *img_info = NULL;

    if ((ewf_info =
            (IMG_EWF_INFO *) tsk_img_malloc(sizeof(IMG_EWF_INFO))) ==
        NULL) {
        return NULL;
    }
    ewf_info->handle = NULL;
    img_info = (TSK_IMG_INFO *) ewf_info;

    // See if they specified only the first of the set...
    ewf_info->used_ewf_glob = 0;
    if (a_num_img == 1) {
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
            goto on_error;
        }

        ewf_info->used_ewf_glob = 1;
        if (tsk_verbose)
            tsk_fprintf(stderr,
                "ewf_open: found %d segment files via libewf_glob\n",
                ewf_info->img_info.num_img);
    }
    else {
        if (!tsk_img_copy_image_names(img_info, a_images, a_num_img)) {
            goto on_error;
        }
    }

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

        if (tsk_verbose) {
            tsk_fprintf(stderr, "Not an EWF file\n");
        }
        goto on_error;
    }

    if (libewf_handle_initialize(&(ewf_info->handle), &ewf_error) != 1) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_OPEN);

        getError(ewf_error, error_string);
        tsk_error_set_errstr("ewf_open file: %" PRIttocTSK
            ": Error initializing handle (%s)", a_images[0], error_string);

        if (tsk_verbose) {
            tsk_fprintf(stderr, "Unable to create EWF handle\n");
        }
        goto on_error;
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

        if (tsk_verbose) {
            tsk_fprintf(stderr, "Error opening EWF file\n");
        }
        goto on_error;
    }
    if (libewf_handle_get_media_size(ewf_info->handle,
            (size64_t *) & (img_info->size), &ewf_error) != 1) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_OPEN);

        getError(ewf_error, error_string);
        tsk_error_set_errstr("ewf_open file: %" PRIttocTSK
            ": Error getting size of image (%s)", a_images[0],
            error_string);

        libewf_handle_close(ewf_info->handle, NULL);

        if (tsk_verbose) {
            tsk_fprintf(stderr, "Error getting size of EWF file\n");
        }
        goto on_error;
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

        libewf_handle_close(ewf_info->handle, NULL);

        if (tsk_verbose) {
            tsk_fprintf(stderr, "Error getting MD5 of EWF file\n");
        }
        goto on_error;
    }
    ewf_info->md5hash_isset = result;

    result = libewf_handle_get_utf8_hash_value_sha1(ewf_info->handle,
        (uint8_t *)ewf_info->sha1hash, 41, &ewf_error);

    if (result == -1) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_OPEN);

        getError(ewf_error, error_string);
        tsk_error_set_errstr("ewf_open file: %" PRIttocTSK
            ": Error getting SHA1 of image (%s)", a_images[0],
            error_string);
        libewf_error_free(&ewf_error);

        tsk_img_free(ewf_info);

        if (tsk_verbose) {
            tsk_fprintf(stderr, "Error getting SHA1 of EWF file\n");
        }
        return NULL;
    }
    ewf_info->sha1hash_isset = result;

    // use what they gave us
    if (a_ssize != 0) {
        img_info->sector_size = a_ssize;
    }
    else {
        uint32_t bytes_per_sector = 512;
        // see if the size is stored in the E01 file
        if (-1 == libewf_handle_get_bytes_per_sector(ewf_info->handle,
            &bytes_per_sector, NULL)) {
            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "ewf_image_read: error getting sector size from E01\n");
            img_info->sector_size = 512;
            libewf_error_free(&ewf_error);
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

    return img_info;

on_error:
    if (ewf_info->handle) {
        libewf_handle_close(ewf_info->handle, NULL);
    }
    libewf_handle_free(&(ewf_info->handle), NULL);
    ewf_glob_free(ewf_info);
    tsk_img_free(ewf_info);
    return NULL;
}



static int is_blank(const char* str) {
    while (*str != '\0') {
        if (!isspace((unsigned char)*str)) {
            return 0;
        }
        str++;
    }
    return 1;
}

/**
* Reads from libewf what is left in the buffer after the addition of the key and new line
 * @param handle
  * @param result_buffer Buffer to read results into
  * @param buffer_size Size of buffer

  * @param identifier Name of value to get from E01
  * @param key Display name of the value (with a space at end)
*/
static char* read_libewf_header_value(libewf_handle_t *handle, char* result_buffer, const size_t buffer_size, const uint8_t *identifier,  const char* key) {
    result_buffer[0] = '\0';
    size_t identifier_length = strlen((char *)identifier);
    strcpy(result_buffer, key);
    size_t key_len = strlen(key);

    //buffer_size - key_len - 1 for the new line at the end
    int result = libewf_handle_get_utf8_header_value(handle, identifier, identifier_length, (uint8_t *)(result_buffer + key_len), buffer_size - key_len - 1, NULL);
    if (result != -1 && !is_blank(result_buffer + key_len)) {
        strcat(result_buffer, "\n");
    }
    else {
        //if blank or error, return nothing!
        result_buffer[0] = '\0';
    }

    return result_buffer;
}

static char* libewf_read_description(libewf_handle_t *handle, char* result_buffer, const size_t buffer_size) {
    return read_libewf_header_value(handle, result_buffer, buffer_size, (uint8_t *) "description", "Description: ");
}

static char* libewf_read_case_number(libewf_handle_t *handle, char* result_buffer, size_t buffer_size) {
    return read_libewf_header_value(handle, result_buffer, buffer_size, (uint8_t *) "case_number", "Case Number: ");
}

static char* libewf_read_evidence_number(libewf_handle_t *handle, char* result_buffer, size_t buffer_size) {
    return read_libewf_header_value(handle, result_buffer, buffer_size, (uint8_t *) "evidence_number", "Evidence Number: ");
}

static char* libewf_read_examiner_name(libewf_handle_t *handle, char* result_buffer, size_t buffer_size) {
    return read_libewf_header_value(handle, result_buffer, buffer_size, (uint8_t *) "examiner_name", "Examiner Name: ");
}

static char* libewf_read_notes(libewf_handle_t *handle, char* result_buffer, size_t buffer_size) {
    return read_libewf_header_value(handle, result_buffer, buffer_size, (uint8_t *) "notes", "Notes: ");
}

static char* libewf_read_model(libewf_handle_t *handle, char* result_buffer, size_t buffer_size) {
    return read_libewf_header_value(handle, result_buffer, buffer_size, (uint8_t *) "model", "Model: ");
}

static char* libewf_read_serial_number(libewf_handle_t *handle, char* result_buffer, size_t buffer_size) {
    return read_libewf_header_value(handle, result_buffer, buffer_size, (uint8_t *) "serial_number", "Serial Number: ");
}

static char* libewf_read_device_label(libewf_handle_t *handle, char* result_buffer, size_t buffer_size) {
    return read_libewf_header_value(handle, result_buffer, buffer_size, (uint8_t *) "device_label", "Device Label:");
}

static char* libewf_read_version(libewf_handle_t *handle, char* result_buffer, size_t buffer_size) {
    return read_libewf_header_value(handle, result_buffer, buffer_size, (uint8_t *) "version", "Version: ");
}

static char* libewf_read_platform(libewf_handle_t *handle, char* result_buffer, size_t buffer_size) {
    return read_libewf_header_value(handle, result_buffer, buffer_size, (uint8_t *) "platform", "Platform: ");
}

static char* libewf_read_acquired_date(libewf_handle_t *handle, char* result_buffer, size_t buffer_size) {
    return read_libewf_header_value(handle, result_buffer, buffer_size, (uint8_t *) "acquiry_date", "Acquired Date: ");
}

static char* libewf_read_system_date(libewf_handle_t *handle, char* result_buffer, size_t buffer_size) {
    return read_libewf_header_value(handle, result_buffer, buffer_size, (uint8_t *) "system_date", "System Date: ");
}

static char* libewf_read_acquiry_operating_system(libewf_handle_t *handle, char* result_buffer, size_t buffer_size) {
    return read_libewf_header_value(handle, result_buffer, buffer_size, (uint8_t *) "acquiry_operating_system", "Acquiry Operating System: ");
}

static char* libewf_read_acquiry_software_version(libewf_handle_t *handle, char* result_buffer, size_t buffer_size) {
    return read_libewf_header_value(handle, result_buffer, buffer_size, (uint8_t *) "acquiry_software_version", "Acquiry Software Version: ");
}



/**
 * Return text with name/value pairs from the E01 image.
 */
std::string ewf_get_details(IMG_EWF_INFO *ewf_info) {
    //Need 1MB for libewf read and extra 100 bytes for header name and formatting
    const size_t buffer_size = 1024100;

    char* result = (char*)tsk_malloc(buffer_size);
    if (result == NULL) {
        return NULL;
    }

    string collectionDetails = "";
    //Populate all of the libewf header values for the acquisition details column
    collectionDetails.append(libewf_read_description(ewf_info->handle, result, buffer_size));
    collectionDetails.append(libewf_read_case_number(ewf_info->handle, result, buffer_size));
    collectionDetails.append(libewf_read_evidence_number(ewf_info->handle, result, buffer_size));
    collectionDetails.append(libewf_read_examiner_name(ewf_info->handle, result, buffer_size));
    collectionDetails.append(libewf_read_notes(ewf_info->handle, result, buffer_size));
    collectionDetails.append(libewf_read_model(ewf_info->handle, result, buffer_size));
    collectionDetails.append(libewf_read_serial_number(ewf_info->handle, result, buffer_size));
    collectionDetails.append(libewf_read_device_label(ewf_info->handle, result, buffer_size));
    collectionDetails.append(libewf_read_version(ewf_info->handle, result, buffer_size));
    collectionDetails.append(libewf_read_platform(ewf_info->handle, result, buffer_size));
    collectionDetails.append(libewf_read_acquired_date(ewf_info->handle, result, buffer_size));
    collectionDetails.append(libewf_read_system_date(ewf_info->handle, result, buffer_size));
    collectionDetails.append(libewf_read_acquiry_operating_system(ewf_info->handle, result, buffer_size));
    collectionDetails.append(libewf_read_acquiry_software_version(ewf_info->handle, result, buffer_size));
    free(result);
    return collectionDetails;
}
#endif                          /* HAVE_LIBEWF */
