/*
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2006-2011 Brian Carrier, Basis Technology.  All rights reserved
 *
 * This software is distributed under the Common Public License 1.0
 */

/**
 * \file aff.c
 * Internal code to interface with afflib to read and open AFF image files
 */

#include "tsk_img_i.h"

#if HAVE_LIBAFFLIB

typedef int bool;

#include "aff.h"

/* Note: The routine -assumes- we are under a lock on &(img_info->cache_lock)) */
static ssize_t
aff_read(TSK_IMG_INFO * img_info, TSK_OFF_T offset, char *buf, size_t len)
{
    ssize_t cnt;
    IMG_AFF_INFO *aff_info = (IMG_AFF_INFO *) img_info;

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "aff_read: byte offset: %" PRIuOFF " len: %" PRIuOFF
            "\n", offset, len);

    if (offset > img_info->size) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_READ_OFF);
        tsk_error_set_errstr("aff_read - %" PRIuOFF, offset);
        return -1;
    }

    if (aff_info->seek_pos != offset) {
        if (af_seek(aff_info->af_file, offset, SEEK_SET) != offset) {
            tsk_error_reset();
            // @@@ ADD more specific error messages
            tsk_error_set_errno(TSK_ERR_IMG_SEEK);
            tsk_error_set_errstr("aff_read - %" PRIuOFF " - %s", offset,
                strerror(errno));
            return -1;

        }
        aff_info->seek_pos = offset;
    }

    cnt = af_read(aff_info->af_file, (unsigned char *) buf, len);
    if (cnt < 0) {
        // @@@ Add more specific error message
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_READ);
        tsk_error_set_errstr("aff_read - offset: %" PRIuOFF " - len: %"
            PRIuSIZE " - %s", offset, len, strerror(errno));
        return -1;
    }

    /* AFF will return 0 if the page does not exist -- fill the 
     * buffer with zeros in this case */
    if (cnt == 0) {
        // @@@ We could improve this if there is an AFF call
        // to see if the data exists or not
        if ((af_eof(aff_info->af_file) == 0) &&
            (offset + len < img_info->size)) {
            memset(buf, 0, len);
            cnt = len;
        }
    }

    aff_info->seek_pos += cnt;
    return cnt;
}

static void
aff_imgstat(TSK_IMG_INFO * img_info, FILE * hFile)
{
    IMG_AFF_INFO *aff_info = (IMG_AFF_INFO *) img_info;
    unsigned char buf[512];
    size_t buf_len = 512;


    tsk_fprintf(hFile, "IMAGE FILE INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");
    tsk_fprintf(hFile, "Image Type: ");
    switch (aff_info->type) {
    case AF_IDENTIFY_AFF:
        tsk_fprintf(hFile, "AFF\n");
        break;
    case AF_IDENTIFY_AFD:
        tsk_fprintf(hFile, "AFD\n");
        break;
    case AF_IDENTIFY_AFM:
        tsk_fprintf(hFile, "AFM\n");
        break;
    default:
        tsk_fprintf(hFile, "AFFLIB (%d)\n", aff_info->type);
        break;
    }

    tsk_fprintf(hFile, "\nSize in bytes: %" PRIuOFF "\n", img_info->size);

    // we won't have the rest of the info for the non-AFF formats.
    if (img_info->itype == TSK_IMG_TYPE_AFF_ANY)
        return;

    tsk_fprintf(hFile, "\nMD5: ");
    if (af_get_seg(aff_info->af_file, AF_MD5, NULL, buf, &buf_len) == 0) {
        int i;
        for (i = 0; i < 16; i++) {
            tsk_fprintf(hFile, "%x", buf[i]);
        }
        tsk_fprintf(hFile, "\n");
    }
    else {
        tsk_fprintf(hFile, "Segment not found\n");
    }

    buf_len = 512;
    tsk_fprintf(hFile, "SHA1: ");
    if (af_get_seg(aff_info->af_file, AF_SHA1, NULL, buf, &buf_len) == 0) {
        int i;
        for (i = 0; i < 20; i++) {
            tsk_fprintf(hFile, "%x", buf[i]);
        }
        tsk_fprintf(hFile, "\n");
    }
    else {
        tsk_fprintf(hFile, "Segment not found\n");
    }

    /* Creator segment */
    buf_len = 512;
    if (af_get_seg(aff_info->af_file, AF_CREATOR, NULL, buf,
            &buf_len) == 0) {
        buf[buf_len] = '\0';
        tsk_fprintf(hFile, "Creator: %s\n", buf);
    }

    buf_len = 512;
    if (af_get_seg(aff_info->af_file, AF_CASE_NUM, NULL, buf,
            &buf_len) == 0) {
        buf[buf_len] = '\0';
        tsk_fprintf(hFile, "Case Number: %s\n", buf);
    }

    buf_len = 512;
    if (af_get_seg(aff_info->af_file, AF_IMAGE_GID, NULL, buf,
            &buf_len) == 0) {
        unsigned int i;
        tsk_fprintf(hFile, "Image GID: ");
        for (i = 0; i < buf_len; i++) {
            tsk_fprintf(hFile, "%X", buf[i]);
        }
        tsk_fprintf(hFile, "\n");
    }

    buf_len = 512;
    if (af_get_seg(aff_info->af_file, AF_ACQUISITION_DATE, NULL, buf,
            &buf_len) == 0) {
        buf[buf_len] = '\0';
        tsk_fprintf(hFile, "Acquisition Date: %s\n", buf);
    }

    buf_len = 512;
    if (af_get_seg(aff_info->af_file, AF_ACQUISITION_NOTES, NULL, buf,
            &buf_len) == 0) {
        buf[buf_len] = '\0';
        tsk_fprintf(hFile, "Acquisition Notes: %s\n", buf);
    }

    buf_len = 512;
    if (af_get_seg(aff_info->af_file, AF_ACQUISITION_DEVICE, NULL, buf,
            &buf_len) == 0) {
        buf[buf_len] = '\0';
        tsk_fprintf(hFile, "Acquisition Device: %s\n", buf);
    }

    buf_len = 512;
    if (af_get_seg(aff_info->af_file, AF_AFFLIB_VERSION, NULL, buf,
            &buf_len) == 0) {
        buf[buf_len] = '\0';
        tsk_fprintf(hFile, "AFFLib Version: %s\n", buf);
    }

    buf_len = 512;
    if (af_get_seg(aff_info->af_file, AF_DEVICE_MANUFACTURER, NULL, buf,
            &buf_len) == 0) {
        buf[buf_len] = '\0';
        tsk_fprintf(hFile, "Device Manufacturer: %s\n", buf);
    }

    buf_len = 512;
    if (af_get_seg(aff_info->af_file, AF_DEVICE_MODEL, NULL, buf,
            &buf_len) == 0) {
        buf[buf_len] = '\0';
        tsk_fprintf(hFile, "Device Model: %s\n", buf);
    }

    buf_len = 512;
    if (af_get_seg(aff_info->af_file, AF_DEVICE_SN, NULL, buf,
            &buf_len) == 0) {
        buf[buf_len] = '\0';
        tsk_fprintf(hFile, "Device SN: %s\n", buf);
    }

    return;
}

static void
aff_close(TSK_IMG_INFO * img_info)
{
    int i;
    IMG_AFF_INFO *aff_info = (IMG_AFF_INFO *) img_info;
    af_close(aff_info->af_file);
	for (i = 0; i < img_info->num_img; i++) {
		if (img_info->images[i])
			free(img_info->images[i]);
	}
	free(img_info->images);
    tsk_img_free(aff_info);
}


TSK_IMG_INFO *
aff_open(const TSK_TCHAR * const images[], unsigned int a_ssize)
{
    IMG_AFF_INFO *aff_info;
    TSK_IMG_INFO *img_info;
    int type;
    char *image;

#ifdef TSK_WIN32
    // convert wchar_t* image path to char* to conform to
    // the AFFLIB API
    UTF16 *utf16 = (UTF16 *) images[0];
    size_t ilen = wcslen(utf16);
    size_t olen = ilen * 4 + 1;
    UTF8 *utf8 = (UTF8 *) tsk_malloc(olen);

    image = (char *) utf8;
    if (image == NULL)
        return NULL;
    TSKConversionResult retval =
        tsk_UTF16toUTF8_lclorder((const UTF16 **) &utf16,
        &utf16[ilen], &utf8,
        &utf8[olen], TSKlenientConversion);
    *utf8 = '\0';
    if (retval != TSKconversionOK) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_UNICODE);
        tsk_error_set_errstr("aff_open file: %" PRIttocTSK
            ": Error converting path to UTF-8 %d\n", images[0], retval);
        free(image);
        return NULL;
    }
    utf8 = (UTF8 *) image;
    while (*utf8) {
        if (*utf8 > 127) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_UNICODE);
            tsk_error_set_errstr("aff_open file: %" PRIttocTSK
                ": Non-Latin paths are not supported for AFF images\n",
                images[0]);
            free(image);
            return NULL;
        }
        utf8++;
    }
#else
    image = (char *) tsk_malloc(strlen(images[0]) + 1);
    if (image == NULL)
        return NULL;
    strncpy(image, images[0], strlen(images[0]) + 1);
#endif

    if ((aff_info =
            (IMG_AFF_INFO *) tsk_img_malloc(sizeof(IMG_AFF_INFO))) ==
        NULL) {
        free(image);
        return NULL;
    }

    img_info = (TSK_IMG_INFO *) aff_info;
    img_info->read = aff_read;
    img_info->close = aff_close;
    img_info->imgstat = aff_imgstat;

    // Save the image path in TSK_IMG_INFO - this is mostly for consistency with the other
    // image types and is not currently used
    img_info->num_img = 1;
    img_info->images =
        (TSK_TCHAR **)tsk_malloc(sizeof(TSK_TCHAR *) * img_info->num_img);
    if (img_info->images == NULL) {
        free(image);
        return NULL;
    }
    size_t len = TSTRLEN(images[0]);
    img_info->images[0] =
        (TSK_TCHAR *)tsk_malloc(sizeof(TSK_TCHAR) * (len + 1));
    if (img_info->images[0] == NULL) {
        free(img_info->images);
        free(image);
        return NULL;
    }
    TSTRNCPY(img_info->images[0], images[0], len + 1);

    img_info->sector_size = 512;
    if (a_ssize)
        img_info->sector_size = a_ssize;

    type = af_identify_file_type(image, 1);
    if ((type == AF_IDENTIFY_ERR) || (type == AF_IDENTIFY_NOEXIST)) {
        if (tsk_verbose) {
            tsk_fprintf(stderr,
                "aff_open: Error determining type of file: %" PRIttocTSK
                "\n", images[0]);
            perror("aff_open");
        }
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_OPEN);
        tsk_error_set_errstr("aff_open file: %" PRIttocTSK
            ": Error checking type", images[0]);
        tsk_img_free(aff_info);
        free(image);
        return NULL;
    }
    else if (type == AF_IDENTIFY_AFF) {
        img_info->itype = TSK_IMG_TYPE_AFF_AFF;
    }
    else if (type == AF_IDENTIFY_AFD) {
        img_info->itype = TSK_IMG_TYPE_AFF_AFD;
    }
    else if (type == AF_IDENTIFY_AFM) {
        img_info->itype = TSK_IMG_TYPE_AFF_AFM;
    }
    else {
        img_info->itype = TSK_IMG_TYPE_AFF_ANY;
    }

    aff_info->af_file = af_open(image, O_RDONLY | O_BINARY, 0);
    if (!aff_info->af_file) {
        // @@@ Need to check here if the open failed because of an incorrect password. 
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_OPEN);
        tsk_error_set_errstr("aff_open file: %" PRIttocTSK
            ": Error opening - %s", images[0], strerror(errno));
        tsk_img_free(aff_info);
        if (tsk_verbose) {
            tsk_fprintf(stderr, "Error opening AFF/AFD/AFM file\n");
            perror("aff_open");
        }
        free(image);
        return NULL;
    }
    // verify that a password was given and we can read encrypted data. 
    if (af_cannot_decrypt(aff_info->af_file)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_PASSWD);
        tsk_error_set_errstr("aff_open file: %" PRIttocTSK, images[0]);
        tsk_img_free(aff_info);
        if (tsk_verbose) {
            tsk_fprintf(stderr,
                "Error opening AFF/AFD/AFM file (incorrect password)\n");
        }
        free(image);
        return NULL;
    }

    aff_info->type = type;

    img_info->size = af_imagesize(aff_info->af_file);

    af_seek(aff_info->af_file, 0, SEEK_SET);
    aff_info->seek_pos = 0;
    free(image);
    return img_info;
}
#endif
