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

#include <aff4/libaff4-c.h>

#include <string.h>

static char* get_messages(AFF4_Message* msg) {
    // find total message length
    size_t len = 0;
    for (const AFF4_Message* m = msg; m; m = m->next) {
        len += strlen(m->message) + 1;
    }

    if (len == 0) {
        return NULL;
    }

    char* ret = (char*) tsk_malloc(len);

    // copy the messages to one string
    char* p = ret;
    size_t mlen;

    for (const AFF4_Message* m = msg; m; m = m->next) {
        mlen = strlen(m->message);
        strcpy(p, m->message);
        p += mlen;
        *p++ = '\n';
    }
    ret[len-1] = '\0';

    return ret;
}

static void free_image_names(TSK_IMG_INFO* img_info) {
    for (int i = 0; i < img_info->num_img; ++i) {
        free(img_info->images[i]);
    }
    free(img_info->images);
}

>>>>>>> ff70c2d76 (Adjustments to aff4 handle for updated libaff4 C API.)
static ssize_t
aff4_image_read(TSK_IMG_INFO* img_info, TSK_OFF_T offset, char* buf,
    size_t len)
{
    if (tsk_verbose)
        tsk_fprintf(stderr,
            "aff4_image_read: byte offset: %" PRIdOFF " len: %" PRIuSIZE
            "\n", offset, len);

    if (offset > img_info->size) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_READ_OFF);
        tsk_error_set_errstr("aff4_image_read - %" PRIdOFF, offset);
        return -1;
    }

    IMG_AFF4_INFO* aff4_info = (IMG_AFF4_INFO*) img_info;
    AFF4_Message* msg = NULL;

    tsk_take_lock(&(aff4_info->read_lock));
    const ssize_t cnt = AFF4_read(aff4_info->handle, offset, buf, len, &msg);
    if (cnt < 0) {
        char* aff4_msgs = get_messages(msg);
        AFF4_free_messages(msg);
        tsk_release_lock(&(aff4_info->read_lock));

        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_READ);
        tsk_error_set_errstr("aff4_image_read - offset: %" PRIdOFF
            " - len: %" PRIuSIZE " - %s: %s",
            offset, len, strerror(errno), aff4_msgs ? aff4_msgs : "");
        free(aff4_msgs);
        return -1;
    }
    AFF4_free_messages(msg);
    tsk_release_lock(&(aff4_info->read_lock));
    return cnt;
}

static void
aff4_image_imgstat(TSK_IMG_INFO* img_info, FILE* hFile)
{

	tsk_fprintf(hFile, "IMAGE FILE INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");
    tsk_fprintf(hFile, "Image Type:\t\taff4\n");
    tsk_fprintf(hFile, "\nSize of data in bytes:\t%" PRIuSIZE "\n", img_info->size);

    // TODO: Expand on this when C API expands to allow dumping TURTLE to FILE*
    return;
}

static void
aff4_image_close(TSK_IMG_INFO* img_info)
{
    IMG_AFF4_INFO* aff4_info = (IMG_AFF4_INFO*) img_info;

    tsk_take_lock(&(aff4_info->read_lock));
    AFF4_close(aff4_info->handle, NULL);
    tsk_release_lock(&(aff4_info->read_lock));
    tsk_deinit_lock(&(aff4_info->read_lock));

    free_image_names(img_info);
    tsk_img_free(aff4_info);
}

/*
static int
aff4_check_file_signature(const char* filename)
{
    const char exp_sig[] = "PK\03\04";
    char act_sig[4];

    int fd = open(filename, O_RDONLY | O_BINARY);
    if (fd < 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_OPEN);
        tsk_error_set_errstr("aff4 signature testing failed: %s", filename);
        return -1;
    }

    const ssize_t len = read(fd, act_sig, 4);
    close(fd);

    if (len < 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_READ);
        tsk_error_set_errstr("aff4 signature testing read failed: %s", filename);
        return -1;
    }

    return len == sizeof(exp_sig) &&
           memcmp(act_sig, exp_sig, sizeof(exp_sig)) == 0;
}
*/

TSK_IMG_INFO*
aff4_open(int a_num_img,
    const TSK_TCHAR* const a_images[], unsigned int a_ssize)
{
    IMG_AFF4_INFO* aff4_info = NULL;
    if ((aff4_info =
            (IMG_AFF4_INFO*) tsk_img_malloc(sizeof(IMG_AFF4_INFO))) ==
        NULL) {
        return NULL;
    }
    aff4_info->handle = NULL;

    TSK_IMG_INFO* img_info = (TSK_IMG_INFO*) aff4_info;
    img_info->images = NULL;
    img_info->num_img = 0;

    const char* filename = NULL;

    // copy the image filename into the img_info
    img_info->images = (TSK_TCHAR**) tsk_malloc(sizeof(TSK_TCHAR*));
    if (img_info->images == NULL) {
        goto on_error;
    }

    const size_t len = TSTRLEN(a_images[0]) + 1;
    img_info->images[0] = (TSK_TCHAR*) tsk_malloc(sizeof(TSK_TCHAR) * len);
    if (img_info->images[0] == NULL) {
        goto on_error;
    }

    TSTRNCPY(img_info->images[0], a_images[0], len);
    img_info->num_img = 1; // libaff4 handles image assembly

    // libaff4 only deals with UTF-8... if Win32 convert wchar_t to utf-8.
#if defined (TSK_WIN32)
    char* fn = tsk_malloc(len);
    if (fn == NULL) {
        goto on_error;
    }

    UTF8* utf8 = (UTF8*) fn;
    const UTF16* utf16 = (UTF16*) a_images[0];

    const int ret = tsk_UTF16toUTF8_lclorder(&utf16, utf16 + len, &utf8, utf8 + len, TSKstrictConversion);
    if (ret != TSKconversionOK) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_CONVERT);
        tsk_error_set_errstr("aff4_open: Unable to convert filename to UTF-8");
        goto on_error;
    }

    filename = fn;
#else
    filename = img_info->images[0];
#endif

/*
    // Check the file signature
    switch (aff4_check_file_signature(filename)) {
    case -1:

    case 0:
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_MAGIC);
        tsk_error_set_errstr("aff4_open: file: %" PRIttocTSK
            ": Error opening", a_images[0]);
        if (tsk_verbose)
            tsk_fprintf(stderr, "Error opening AFF4 file\n");
        goto on_error;
    case 0:
        // successful read, signature mismatch
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_MAGIC);
        tsk_error_set_errstr("aff4_open: file: %" PRIttocTSK
            ": Not an AFF4 file", a_images[0]);
        if (tsk_verbose)
            tsk_fprintf(stderr, "Not an AFF4 file\n");
        goto on_error;
    case 1:
        // ok!
    }
*/

    // Attempt to open the file.
    AFF4_Message* msg = NULL;

    aff4_info->handle = AFF4_open(filename, &msg);
    if (!aff4_info->handle) {
        char* aff4_msgs = get_messages(msg);
        AFF4_free_messages(msg);

        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_OPEN);
        tsk_error_set_errstr("aff4_open file: %" PRIttocTSK
            ": Error opening%s", a_images[0], aff4_msgs ? aff4_msgs : "");
        free(aff4_msgs);
        if (tsk_verbose) {
            tsk_fprintf(stderr, "Error opening AFF4 file\n");
        }
        goto on_error;
    }

    AFF4_free_messages(msg);
    msg = NULL;

    // get image size
    img_info->size = AFF4_object_size(aff4_info->handle, &msg);
    if (img_info->size == 0) {
        char* aff4_msgs = get_messages(msg);
        AFF4_free_messages(msg);

        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_OPEN);
        tsk_error_set_errstr("aff4_open file: %" PRIttocTSK
            ": Error getting size of image%s",
            a_images[0], aff4_msgs ? aff4_msgs : "");
        free(aff4_msgs);
        if (tsk_verbose) {
            tsk_fprintf(stderr, "Error getting size of AFF4 file\n");
        }
        AFF4_close(aff4_info->handle, NULL);
        goto on_error;
    }

    AFF4_free_messages(msg);
    msg = NULL;

    img_info->sector_size = 512;
    img_info->itype = TSK_IMG_TYPE_AFF4_AFF4;
    img_info->read = &aff4_image_read;
    img_info->close = &aff4_image_close;
    img_info->imgstat = &aff4_image_imgstat;

#if defined (TSK_WIN32)
    free(filename);
#endif

    // initialize the API lock
    tsk_init_lock(&(aff4_info->read_lock));

    return img_info;

on_error:
#if defined (TSK_WIN32)
    free(filename);
#endif
    free_image_names(img_info);
    tsk_img_free(aff4_info);
    return NULL;
}

#endif /* HAVE_LIBAFF4 */
