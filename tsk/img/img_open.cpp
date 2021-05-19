/*
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2006-2011 Brian Carrier, Basis Technology.  All Rights reserved
 * Copyright (c) 2005 Brian Carrier.  All rights reserved
 *
 * tsk_img_open
 *
 * This software is distributed under the Common Public License 1.0
 */

/**
 * \file img_open.c
 * Contains the basic img_open function call, that interfaces with
 * the format specific _open calls
 */

#include "tsk_img_i.h"

#include "raw.h"

#if HAVE_LIBAFFLIB
#include "aff.h"
#endif

#if HAVE_LIBEWF
#include "ewf.h"
#endif

#if HAVE_LIBVMDK
#include "vmdk.h"
#endif

#if HAVE_LIBVHDI
#include "vhd.h"
#endif

/**
 * \ingroup imglib
 * Opens a single (non-split) disk image file so that it can be read.  This is a
 * wrapper around tsk_img_open().  See it for more details on detection etc. See
 * tsk_img_open_sing_utf8() for a version of this function that always takes
 * UTF-8 as input.
 *
 * @param a_image The path to the image file
 * @param type The disk image type (can be autodetection)
 * @param a_ssize Size of device sector in bytes (or 0 for default)
 *
 * @return Pointer to TSK_IMG_INFO or NULL on error
 */
TSK_IMG_INFO *
tsk_img_open_sing(const TSK_TCHAR * a_image, TSK_IMG_TYPE_ENUM type,
    unsigned int a_ssize)
{
    const TSK_TCHAR *const a = a_image;
    return tsk_img_open(1, &a, type, a_ssize);
}


/**
 * \ingroup imglib
 * Opens one or more disk image files so that they can be read.  If a file format
 * type is specified, this function will call the specific routine to open the file.
 * Otherwise, it will detect the type (it will default to raw if no specific type can
 * be detected).   This function must be called before a disk image can be read from.
 * Note that the data type used to store the image paths is a TSK_TCHAR, which changes
 * depending on a Unix or Windows build.  If you will always have UTF8, then consider
 * using tsk_img_open_utf8().
 *
 * @param num_img The number of images to open (will be > 1 for split images).
 * @param images The path to the image files (the number of files must
 * be equal to num_img and they must be in a sorted order)
 * @param type The disk image type (can be autodetection)
 * @param a_ssize Size of device sector in bytes (or 0 for default)
 *
 * @return Pointer to TSK_IMG_INFO or NULL on error
 */
TSK_IMG_INFO *
tsk_img_open(int num_img,
    const TSK_TCHAR * const images[], TSK_IMG_TYPE_ENUM type,
    unsigned int a_ssize)
{
    TSK_IMG_INFO *img_info = NULL;

    // Get rid of any old error messages laying around
    tsk_error_reset();

    if ((num_img == 0) || (images[0] == NULL)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_NOFILE);
        tsk_error_set_errstr("tsk_img_open");
        return NULL;
    }

    if ((a_ssize > 0) && (a_ssize < 512)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_ARG);
        tsk_error_set_errstr("sector size is less than 512 bytes (%d)",
            a_ssize);
        return NULL;
    }

    if ((a_ssize % 512) != 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_ARG);
        tsk_error_set_errstr("sector size is not a multiple of 512 (%d)",
            a_ssize);
        return NULL;
    }

    if (tsk_verbose)
        TFPRINTF(stderr,
            _TSK_T("tsk_img_open: Type: %d   NumImg: %d  Img1: %s\n"),
            type, num_img, images[0]);


    switch (type) {
    case TSK_IMG_TYPE_DETECT:
    {
        /* If no type is given, then we use the autodetection methods
         * In case the image file matches the signatures of multiple formats,
         * we try all of the embedded formats
         */
        TSK_IMG_INFO *img_set = NULL;
#if HAVE_LIBAFFLIB || HAVE_LIBEWF || HAVE_LIBVMDK || HAVE_LIBVHDI
        const char *set = NULL;
#endif

        // we rely on tsk_errno, so make sure it is 0
        tsk_error_reset();

        /* Try the non-raw formats first */
#if HAVE_LIBAFFLIB
        if ((img_info = aff_open(images, a_ssize)) != NULL) {
            /* we don't allow the "ANY" when autodetect is used because
             * we only want to detect the tested formats. */
            if (img_info->itype == TSK_IMG_TYPE_AFF_ANY) {
                img_info->close(img_info);
            }
            else {
                set = "AFF";
                img_set = img_info;
            }
        }
        else {
            // If AFF is otherwise happy except for a password,
            // stop trying to guess
            if (tsk_error_get_errno() == TSK_ERR_IMG_PASSWD) {
                return NULL;
            }
            tsk_error_reset();
        }
#endif

#if HAVE_LIBEWF
        if ((img_info = ewf_open(num_img, images, a_ssize)) != NULL) {
            if (set == NULL) {
                set = "EWF";
                img_set = img_info;
            }
            else {
                img_set->close(img_set);
                img_info->close(img_info);
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_IMG_UNKTYPE);
                tsk_error_set_errstr("EWF or %s", set);
                return NULL;
            }
        }
        else {
            tsk_error_reset();
        }
#endif

#if HAVE_LIBVMDK
        if ((img_info = vmdk_open(num_img, images, a_ssize)) != NULL) {
            if (set == NULL) {
                set = "VMDK";
                img_set = img_info;
            }
            else {
                img_set->close(img_set);
                img_info->close(img_info);
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_IMG_UNKTYPE);
                tsk_error_set_errstr("VMDK or %s", set);
                return NULL;
            }
        }
        else {
            tsk_error_reset();
        }
#endif

#if HAVE_LIBVHDI
        if ((img_info = vhdi_open(num_img, images, a_ssize)) != NULL) {
            if (set == NULL) {
                set = "VHD";
                img_set = img_info;
            }
            else {
                img_set->close(img_set);
                img_info->close(img_info);
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_IMG_UNKTYPE);
                tsk_error_set_errstr("VHD or %s", set);
                return NULL;
            }
        }
        else {
            tsk_error_reset();
        }
#endif

        // if any of the non-raw formats were detected, then use it.
        if (img_set != NULL) {
            img_info = img_set;
            break;
        }

        // otherwise, try raw
        if ((img_info = raw_open(num_img, images, a_ssize)) != NULL) {
            break;
        }
        else if (tsk_error_get_errno() != 0) {
            return NULL;
        }

        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_UNKTYPE);
        return NULL;
    }

#if HAVE_LIBVHDI
    case TSK_IMG_TYPE_VHD_VHD:
        img_info = vhdi_open(num_img, images, a_ssize);
        break;
#endif

#if HAVE_LIBVMDK
    case TSK_IMG_TYPE_VMDK_VMDK:
        img_info = vmdk_open(num_img, images, a_ssize);
        break;
#endif

    case TSK_IMG_TYPE_RAW:
        img_info = raw_open(num_img, images, a_ssize);
        break;

#if HAVE_LIBAFFLIB
    case TSK_IMG_TYPE_AFF_AFF:
    case TSK_IMG_TYPE_AFF_AFD:
    case TSK_IMG_TYPE_AFF_AFM:
    case TSK_IMG_TYPE_AFF_ANY:
        img_info = aff_open(images, a_ssize);
        break;
#endif

#if HAVE_LIBEWF
    case TSK_IMG_TYPE_EWF_EWF:
        img_info = ewf_open(num_img, images, a_ssize);
        break;
#endif

    default:
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_UNSUPTYPE);
        tsk_error_set_errstr("%d", type);
        return NULL;
    }

    /* check if img_info is good */
    if (img_info == NULL) {
        return NULL;
    }

    /* we have a good img_info, set up the cache lock */
    tsk_init_lock(&(img_info->cache_lock));
    return img_info;
}


/**
* \ingroup imglib
 * Opens a single (non-split) disk image file so that it can be read.  This version
 * always takes a UTF-8 encoding of the disk image.  See tsk_img_open_sing() for a
 * version that takes a wchar_t or char depending on the platform.
 * This is a wrapper around tsk_img_open().  See it for more details on detection etc.
 *
 * @param a_image The UTF-8 path to the image file
 * @param type The disk image type (can be autodetection)
 * @param a_ssize Size of device sector in bytes (or 0 for default)
 *
 * @return Pointer to TSK_IMG_INFO or NULL on error
 */
TSK_IMG_INFO *
tsk_img_open_utf8_sing(const char *a_image,
    TSK_IMG_TYPE_ENUM type, unsigned int a_ssize)
{
    const char *const a = a_image;
    return tsk_img_open_utf8(1, &a, type, a_ssize);
}


/**
 * \ingroup imglib
 * Opens one or more disk image files so that they can be read.  This is a wrapper
 * around tsk_img_open() and this version always takes a UTF-8 encoding of the
 * image files.  See its description for more details.
 *
 * @param num_img The number of images to open (will be > 1 for split images).
 * @param images The path to the UTF-8 encoded image files (the number of files must
 * be equal to num_img and they must be in a sorted order)
 * @param type The disk image type (can be autodetection)
 * @param a_ssize Size of device sector in bytes (or 0 for default)
 *
 * @return Pointer to TSK_IMG_INFO or NULL on error
 */
TSK_IMG_INFO *
tsk_img_open_utf8(int num_img,
    const char *const images[], TSK_IMG_TYPE_ENUM type,
    unsigned int a_ssize)
{
#ifdef TSK_WIN32
    {
        /* Note that there is an assumption in this code that wchar_t is 2-bytes.
         * this is a correct assumption for Windows, but not for all systems... */

        TSK_IMG_INFO *retval = NULL;
        wchar_t **images16;
        int i;

        // allocate a buffer to store the UTF-16 version of the images.
        if ((images16 =
                (wchar_t **) tsk_malloc(sizeof(wchar_t *) *
                    num_img)) == NULL) {
            return NULL;
        }

        for (i = 0; i < num_img; i++) {
            size_t ilen;
            UTF16 *utf16;
            UTF8 *utf8;
            TSKConversionResult retval2;

            // we allocate the buffer with the same number of chars as the UTF-8 length
            ilen = strlen(images[i]);
            if ((images16[i] =
                    (wchar_t *) tsk_malloc((ilen +
                            1) * sizeof(wchar_t))) == NULL) {
                goto tsk_utf8_cleanup;
            }

            utf8 = (UTF8 *) images[i];
            utf16 = (UTF16 *) images16[i];

            retval2 =
                tsk_UTF8toUTF16((const UTF8 **) &utf8, &utf8[ilen],
                &utf16, &utf16[ilen], TSKlenientConversion);
            if (retval2 != TSKconversionOK) {
                tsk_error_set_errno(TSK_ERR_IMG_CONVERT);
                tsk_error_set_errstr
                    ("tsk_img_open_utf8: Error converting image %s %d",
                    images[i], retval2);
                goto tsk_utf8_cleanup;
            }
            *utf16 = '\0';
        }

        retval = tsk_img_open(num_img, images16, type, a_ssize);

        // free up the memory
      tsk_utf8_cleanup:
        for (i = 0; i < num_img; i++) {
            free(images16[i]);
        }
        free(images16);

        if (retval) {
            tsk_init_lock(&(retval->cache_lock));
        }
        return retval;
    }
#else
    return tsk_img_open(num_img, images, type, a_ssize);
#endif
}

/**
* \ingroup imglib
 * Opens an an image of type TSK_IMG_TYPE_EXTERNAL. The void pointer parameter
 * must be castable to a TSK_IMG_INFO pointer.  It is up to 
 * the caller to set the tag value in ext_img_info.  This 
 * method will initialize the cache lock. 
 *
 * @param ext_img_info Pointer to the partially initialized disk image
 * structure, having a TSK_IMG_INFO as its first member
 * @param size Total size of image in bytes
 * @param sector_size Sector size of device in bytes
 * @param read Pointer to user-supplied read function
 * @param close Pointer to user-supplied close function
 * @param imgstat Pointer to user-supplied imgstat function
 *
 * @return Pointer to TSK_IMG_INFO or NULL on error
 */
TSK_IMG_INFO *
tsk_img_open_external(
  void* ext_img_info,
  TSK_OFF_T size,
  unsigned int sector_size,
  ssize_t(*read) (TSK_IMG_INFO * img, TSK_OFF_T off, char *buf, size_t len),
  void (*close) (TSK_IMG_INFO *),
  void (*imgstat) (TSK_IMG_INFO *, FILE *)
)
{
    TSK_IMG_INFO *img_info;
    // sanity checks
    if (!ext_img_info) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_ARG);
        tsk_error_set_errstr("external image info pointer was null");
        return NULL;
    }

    if (!read) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_ARG);
        tsk_error_set_errstr("external image read pointer was null");
        return NULL;
    }

    if (!close) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_ARG);
        tsk_error_set_errstr("external image close pointer was null");
        return NULL;
    }

    if (!imgstat) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_ARG);
        tsk_error_set_errstr("external image imgstat pointer was null");
        return NULL;
    }

    if (sector_size > 0 && sector_size < 512) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_ARG);
        tsk_error_set_errstr("sector size is less than 512 bytes (%d)",
            sector_size);
        return NULL;
    }

    if (sector_size % 512 != 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_ARG);
        tsk_error_set_errstr("sector size is not a multiple of 512 (%d)",
            sector_size);
        return NULL;
    }

    // set up the TSK_IMG_INFO members
    img_info = (TSK_IMG_INFO *) ext_img_info;

    img_info->tag = TSK_IMG_INFO_TAG;
    img_info->itype = TSK_IMG_TYPE_EXTERNAL;
    img_info->size = size;
    img_info->sector_size = sector_size ? sector_size : 512;
    img_info->read = read;
    img_info->close = close;
    img_info->imgstat = imgstat;

    tsk_init_lock(&(img_info->cache_lock));
    return img_info;
}

#if 0
/* This interface needs some more thought because the size of wchar is not standard.
 * If the goal i to provide a constant wchar interface, then we need to incorporate
 * UTF-32 to UTF-8 support as well.  If the goal is to provide a standard UTF-16
 * interface, we should use another type besides wchar_t.
 */
TSK_IMG_INFO *
tsk_img_open_utf16(int num_img,
    wchar_t * const images[], TSK_IMG_TYPE_ENUM type)
{
#if TSK_WIN32
    return tsk_img_open(num_img, images, type);
#else
    {
        TSK_IMG_INFO *retval;
        int i;
        char **images8;
        TSK_ENDIAN_ENUM endian;
        uint16_t tmp1;

        /* The unicode conversion routines are primarily to convert Unicode
         * in file and volume system images, which means they could be in
         * an endian ordering different from the local one.  We need to figure
         * out our local ordering so we can give it the right flag */
        tmp1 = 1;
        if (tsk_guess_end_u16(&endian, (uint8_t *) & tmp1, 1)) {
            // @@@@
            return NULL;
        }


        // convert UTF16 to UTF8
        if ((images8 =
                (char **) tsk_malloc(sizeof(char *) * num_img)) == NULL) {
            return NULL;
        }

        for (i = 0; i < num_img; i++) {
            size_t ilen;
            UTF16 *utf16;
            UTF8 *utf8;
            TSKConversionResult retval2;


            // we allocate the buffer to be four times the utf-16 length.
            ilen = wcslen(images[i]);
            ilen <<= 2;

            if ((images8[i] = (char *) tsk_malloc(ilen)) == NULL) {
                return NULL;
            }

            utf16 = (UTF16 *) images[i];
            utf8 = (UTF8 *) images8[i];

            retval2 =
                tsk_UTF16toUTF8_lclorder((const UTF16 **) &utf16,
                &utf16[wcslen(images[i]) + 1], &utf8,
                &utf8[ilen + 1], TSKlenientConversion);
            if (retval2 != TSKconversionOK) {
                tsk_error_set_errno(TSK_ERR_IMG_CONVERT);
                tsk_error_set_errstr
                    ("tsk_img_open_utf16: Error converting image %d %d",
                    i, retval2);
                return NULL;
            }
            *utf8 = '\0';
        }

        retval = tsk_img_open(num_img, (const TSK_TCHAR **) images8, type);

        for (i = 0; i < num_img; i++) {
            free(images8[i]);
        }
        free(images8);

        return retval;
    }
#endif
}
#endif




/**
 * \ingroup imglib
 * Closes an open disk image.
 * @param a_img_info Pointer to the open disk image structure.
 */
void
tsk_img_close(TSK_IMG_INFO * a_img_info)
{
    if (a_img_info == NULL) {
        return;
    }
    tsk_deinit_lock(&(a_img_info->cache_lock));
    a_img_info->close(a_img_info);
}
