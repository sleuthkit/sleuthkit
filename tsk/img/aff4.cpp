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
    // count the messages
    size_t count = 0;
    for (const AFF4_Message* m = msg; m; m = m->next, ++count);

    if (count == 0) {
      return NULL;
    }

    // get message lengths and total length
    const size_t maxlen = 1024;
    size_t* lengths = (size_t*) tsk_malloc(count * sizeof(size_t));
    size_t total_len = 0;

    int i = 0;
    for (const AFF4_Message* m = msg; m; m = m->next, ++i) {
        total_len += lengths[i] = strnlen(m->message, maxlen);
    }

    // copy the messages to one string
    char* ret = (char*) tsk_malloc(total_len + count);
    char* p = ret;
    i = 0;
    for (const AFF4_Message* m = msg; m; m = m->next, ++i) {
        strncpy(p, m->message, lengths[i]);
        p += lengths[i];
        *p++ = '\n';
    }
    *(p-1) = '\0';

    free(lengths);
    return ret;
}

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
aff4_open(
  int a_num_img,
  const TSK_TCHAR* const a_images[],
  [[maybe_unused]] unsigned int a_ssize)
{
   if (a_num_img != 1) {
        tsk_error_set_errstr("aff4_open file: %" PRIttocTSK
            ": expected one image filename, was given %d", a_images[0], a_num_img);

        if (tsk_verbose != 0) {
            tsk_fprintf(stderr, "aff4 requires exactly 1 image filename for opening\n");
        }
        return NULL;
    }

    IMG_AFF4_INFO* aff4_info = NULL;
    if ((aff4_info =
            (IMG_AFF4_INFO*) tsk_img_malloc(sizeof(IMG_AFF4_INFO))) ==
        NULL) {
        return NULL;
    }
    aff4_info->handle = NULL;

    AFF4_Message* msg = NULL;
    const char* filename;

    TSK_IMG_INFO* img_info = (TSK_IMG_INFO*) aff4_info;
    img_info->images = NULL;
    img_info->num_img = 0;

    if (!tsk_img_copy_image_names(img_info, a_images, a_num_img)) {
       goto on_error;
    }

    // libaff4 only deals with UTF-8... if Win32 convert wchar_t to utf-8.
#if defined (TSK_WIN32)
    const size_t len = TSTRLEN(a_images[0]) + 1;
    char* fn = (char*) tsk_malloc(len);
    if (fn == NULL) {
        goto on_error;
    }

    {
      UTF8* utf8 = (UTF8*) fn;
      const UTF16* utf16 = (UTF16*) a_images[0];

      const int ret = tsk_UTF16toUTF8_lclorder(&utf16, utf16 + len, &utf8, utf8 + len, TSKstrictConversion);
      if (ret != TSKconversionOK) {
          tsk_error_reset();
          tsk_error_set_errno(TSK_ERR_IMG_CONVERT);
          tsk_error_set_errstr("aff4_open: Unable to convert filename to UTF-8");
          goto on_error;
      }
    }

    filename = fn;
#else
    filename = a_images[0];
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

#if defined (TSK_WIN32)
    free(fn);
#endif

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
        goto on_error;
    }

    AFF4_free_messages(msg);
    msg = NULL;

    img_info->sector_size = 512;
    img_info->itype = TSK_IMG_TYPE_AFF4_AFF4;
    img_info->read = &aff4_image_read;
    img_info->close = &aff4_image_close;
    img_info->imgstat = &aff4_image_imgstat;

    // initialize the API lock
    tsk_init_lock(&(aff4_info->read_lock));

    return img_info;

on_error:
#if defined (TSK_WIN32)
    free(fn);
#endif
    if (aff4_info->handle) {
        AFF4_close(aff4_info->handle, NULL);
    }
    tsk_img_free(aff4_info);
    return NULL;
}

#endif /* HAVE_LIBAFF4 */
