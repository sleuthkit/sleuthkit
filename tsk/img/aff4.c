/*
 * The Sleuth Kit - Add on for AFF4 image support
 *
 * This software is distributed under the Common Public License 1.0
 *
 * Based on ewf image support of the Sleuth Kit from
 * Brian Carrier.
 */

/** \file aff4.c
 * Internal code for TSK to interface with libaff4.
 */

#include "tsk_img_i.h"

#if HAVE_LIBAFF4
#include "aff4.h"

static ssize_t
aff4_image_read(TSK_IMG_INFO * img_info, TSK_OFF_T offset, char *buf,
    size_t len)
{

    ssize_t cnt;
    IMG_AFF4_INFO *aff4_info = (IMG_AFF4_INFO *) img_info;

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "aff4_image_read: byte offset: %" PRIuOFF " len: %" PRIuSIZE
            "\n", offset, len);

    if (offset > img_info->size) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_READ_OFF);
        tsk_error_set_errstr("aff4_image_read - %" PRIuOFF, offset);
        return -1;
    }

    tsk_take_lock(&(aff4_info->read_lock));
    cnt = AFF4_read(aff4_info->handle, offset, buf, len);
    if (cnt < 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_READ);
        tsk_error_set_errstr("aff4_image_read - offset: %" PRIuOFF
            " - len: %" PRIuSIZE " - %s", offset, len, strerror(errno));
        tsk_release_lock(&(aff4_info->read_lock));
        return -1;
    }
    tsk_release_lock(&(aff4_info->read_lock));
    return cnt;
}

static void
aff4_image_imgstat(TSK_IMG_INFO * img_info, FILE * hFile)
{

	tsk_fprintf(hFile, "IMAGE FILE INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");
    tsk_fprintf(hFile, "Image Type:\t\taff4\n");
    tsk_fprintf(hFile, "\nSize of data in bytes:\t%" PRIuOFF "\n", img_info->size);

    // TODO: Expand on this when C API expands to allow dumping TURTLE to FILE*
    return;
}

static void
aff4_image_close(TSK_IMG_INFO * img_info)
{
    IMG_AFF4_INFO *aff4_info = (IMG_AFF4_INFO *) img_info;

    AFF4_close(aff4_info->handle);

    tsk_deinit_lock(&(aff4_info->read_lock));
    tsk_img_free(aff4_info);
}

static int aff4_check_file_signature(char* filename)
{
	// Implement.
	return 0;
}

TSK_IMG_INFO *
aff4_open(int a_num_img,
    const TSK_TCHAR * const a_images[], unsigned int a_ssize)
{
    int is_error;

    IMG_AFF4_INFO *aff4_info = NULL;
    TSK_IMG_INFO *img_info = NULL;

    if ((aff4_info =
            (IMG_AFF4_INFO *) tsk_img_malloc(sizeof(IMG_AFF4_INFO))) ==
        NULL) {
        return NULL;
    }
    img_info = (TSK_IMG_INFO *) aff4_info;

    // libaff4 only deals with UTF-8... if Win32 convert wchar_t to utf-8.
    char* filename = NULL;
#if defined ( TSK_WIN32)
    size_t newsize = (wcslen(a_images[0]) + 1) * 2;
    filename = tsk_malloc(newsize);
    if(filename == NULL){
    	tsk_error_set_errno(TSK_ERR_IMG_CONVERT);
    	tsk_error_set_errstr("aff4_open: Unable to convert filename to UTF-8");
    	return NULL;
    }
    // TODO: Possible refactor to tsk_UTF16toUTF8?
    wcstombs(a_images[0], filename, newsize);
#else
    filename = a_images[0];
#endif

    // Check the file extension. (bad I know).
    is_error = aff4_check_file_signature(filename);
    if (is_error)
    {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_MAGIC);
        tsk_error_set_errstr("aff4_open: Not an AFF4 file");
        tsk_img_free(aff4_info);
        if (tsk_verbose)
            tsk_fprintf(stderr, "Not an AFF4 file\n");
#if defined ( TSK_WIN32)
        free(filename);
#endif
        return NULL;
    }

    // Attempt to open the file.
    aff4_info->handle = AFF4_open(filename);
    if (aff4_info->handle == -1) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_OPEN);
        tsk_error_set_errstr("aff4_open file: %" PRIttocTSK
            ": Error opening", a_images[0]);
        tsk_img_free(aff4_info);

        if (tsk_verbose != 0) {
            tsk_fprintf(stderr, "Error opening AFF4 file\n");
        }
#if defined ( TSK_WIN32)
        free(filename);
#endif
        return (NULL);
    }

    // get image size
    img_info->size = AFF4_object_size(aff4_info->handle);
    if (img_info->size == 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_OPEN);
        tsk_error_set_errstr("aff4_open file: %" PRIttocTSK
            ": Error getting size of image", a_images[0]);
        tsk_img_free(aff4_info);
        if (tsk_verbose) {
            tsk_fprintf(stderr, "Error getting size of AFF4 file\n");
        }
#if defined ( TSK_WIN32)
        free(filename);
#endif
        return (NULL);
    }

    aff4_info->images = a_images;
    img_info->sector_size = 512;
    img_info->itype = TSK_IMG_TYPE_AFF4_AFF4;
    img_info->read = &aff4_image_read;
    img_info->close = &aff4_image_close;
    img_info->imgstat = &aff4_image_imgstat;

#if defined ( TSK_WIN32)
        free(filename);
#endif

    // initialize the read lock
    tsk_init_lock(&(aff4_info->read_lock));
    return (img_info);
}

#endif                          /* HAVE_LIBAFF4 */
