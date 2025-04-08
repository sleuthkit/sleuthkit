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
#include "img_open.h"
#include "legacy_cache.h"

#include "raw.h"
#include "logical_img.h"

#if HAVE_LIBAFFLIB
#include "aff.h"
#endif

#if HAVE_LIBEWF
#include "ewf.h"
#endif

#if HAVE_LIBQCOW
#include "qcow.h"
#endif

#if HAVE_LIBVMDK
#include "vmdk.h"
#endif

#if HAVE_LIBVHDI
#include "vhd.h"
#endif

#if HAVE_LIBAFF4
#include "aff4.h"
#endif

#include <cstring>
#include <memory>
#include <new>
#include <numeric>
#include <vector>
#include <utility>

const TSK_IMG_OPTIONS DEFAULT_IMG_OPTIONS{
};

bool sector_size_ok(unsigned int sector_size) {
    if (sector_size > 0 && sector_size < 512) {
        tsk_error_set_errno(TSK_ERR_IMG_ARG);
        tsk_error_set_errstr("sector size is less than 512 bytes (%d)",
            sector_size);
        return false;
    }

    if (sector_size % 512 != 0) {
        tsk_error_set_errno(TSK_ERR_IMG_ARG);
        tsk_error_set_errstr("sector size is not a multiple of 512 (%d)",
            sector_size);
        return false;
    }

    return true;
}

void img_info_deleter(TSK_IMG_INFO* img_info) {
    reinterpret_cast<IMG_INFO*>(img_info)->close(img_info);
}

std::unique_ptr<TSK_IMG_INFO, decltype(&img_info_deleter)>
img_open_by_type(
    int num_img,
    const TSK_TCHAR* const images[],
    TSK_IMG_TYPE_ENUM type,
    unsigned int a_ssize
)
{
    switch (type) {
    case TSK_IMG_TYPE_RAW:
        return { raw_open(num_img, images, a_ssize), img_info_deleter };

#if HAVE_LIBAFFLIB
    case TSK_IMG_TYPE_AFF_AFF:
    case TSK_IMG_TYPE_AFF_AFD:
    case TSK_IMG_TYPE_AFF_AFM:
    case TSK_IMG_TYPE_AFF_ANY:
        return { aff_open(num_img, images, a_ssize), img_info_deleter };
#endif

#if HAVE_LIBEWF
    case TSK_IMG_TYPE_EWF_EWF:
        return { ewf_open(num_img, images, a_ssize), img_info_deleter };
#endif

#if HAVE_LIBVMDK
    case TSK_IMG_TYPE_VMDK_VMDK:
        return { vmdk_open(num_img, images, a_ssize), img_info_deleter };
#endif

#if HAVE_LIBVHDI
    case TSK_IMG_TYPE_VHD_VHD:
        return { vhdi_open(num_img, images, a_ssize), img_info_deleter };
#endif

#if HAVE_LIBAFF4
    case TSK_IMG_TYPE_AFF4_AFF4:
        return { aff4_open(num_img, images, a_ssize), img_info_deleter };
#endif

#if HAVE_LIBQCOW
    case TSK_IMG_TYPE_QCOW_QCOW:
        return { qcow_open(num_img, images, a_ssize), img_info_deleter };
#endif

    case TSK_IMG_TYPE_LOGICAL:
		    return { logical_open(num_img, images, a_ssize), img_info_deleter };

    default:
        tsk_error_set_errno(TSK_ERR_IMG_UNSUPTYPE);
        tsk_error_set_errstr("%d", type);
        return { nullptr, img_info_deleter };
    }
}

const char* type_name(TSK_IMG_TYPE_ENUM t) {
    switch (t) {
    case TSK_IMG_TYPE_AFF_AFF:
    case TSK_IMG_TYPE_AFF_AFD:
    case TSK_IMG_TYPE_AFF_AFM:
    case TSK_IMG_TYPE_AFF_ANY:
        return "AFF";
    case TSK_IMG_TYPE_EWF_EWF:
        return "EWF";
    case TSK_IMG_TYPE_VMDK_VMDK:
        return "VMDK";
    case TSK_IMG_TYPE_VHD_VHD:
        return "VHD";
    case TSK_IMG_TYPE_AFF4_AFF4:
        return "AFF4";
    case TSK_IMG_TYPE_QCOW_QCOW:
        return "QCOW";
    default:
        // should be impossible
        return "";
    }
}

std::unique_ptr<TSK_IMG_INFO, decltype(&img_info_deleter)>
img_open_detect_type(
    int num_img,
    const TSK_TCHAR* const images[],
    unsigned int a_ssize
)
{
    // Attempt to determine the image format

    std::unique_ptr<TSK_IMG_INFO, decltype(&img_info_deleter)> img_info{
        nullptr,
        img_info_deleter
    };

    std::unique_ptr<TSK_IMG_INFO, decltype(&img_info_deleter)> img_guess{
        nullptr,
        img_info_deleter
    };

    std::vector<TSK_IMG_TYPE_ENUM> guesses;

    enum Result { OK, UNRECOGNIZED, FAIL };

#if HAVE_LIBEWF || HAVE_LIBAFF4 || HAVE_LIBVMDK || HAVE_LIBVHDI || HAVE_LIBQCOW
    const auto ok_nonnull = [](TSK_IMG_INFO* img_info) {
        return img_info ? OK : UNRECOGNIZED;
    };
#endif

#if HAVE_LIBAFFLIB
    const auto ok_aff = [](TSK_IMG_INFO* img_info) {
        if (img_info) {
            /* we don't allow the "ANY" when autodetect is used because
             * we only want to detect the tested formats. */
            return img_info->itype == TSK_IMG_TYPE_AFF_ANY ? UNRECOGNIZED : OK;
        }

        // If AFF is otherwise happy except for a password,
        // stop trying to guess
        return tsk_error_get_errno() == TSK_ERR_IMG_PASSWD ? FAIL : UNRECOGNIZED;
    };
#endif

    /* Try the non-raw formats first */
    const std::vector<std::pair<TSK_IMG_TYPE_ENUM, Result (*)(TSK_IMG_INFO*)>> types{
#if HAVE_LIBAFFLIB
        { TSK_IMG_TYPE_AFF_ANY, ok_aff },
#endif
#if HAVE_LIBEWF
        { TSK_IMG_TYPE_EWF_EWF, ok_nonnull },
#endif
#if HAVE_LIBAFF4
        { TSK_IMG_TYPE_AFF4_AFF4, ok_nonnull },
#endif
#if HAVE_LIBVMDK
        { TSK_IMG_TYPE_VMDK_VMDK, ok_nonnull },
#endif
#if HAVE_LIBVHDI
        { TSK_IMG_TYPE_VHD_VHD, ok_nonnull },
#endif
#if HAVE_LIBQCOW
        { TSK_IMG_TYPE_QCOW_QCOW, ok_nonnull },
#endif
    };

    for (auto i = types.begin(); i != types.end(); ++i) {
        tsk_error_reset();
        img_info = img_open_by_type(num_img, images, i->first, a_ssize);
        switch (i->second(img_info.get())) {
        case OK:
            guesses.push_back(img_info->itype);
            img_guess = std::move(img_info);
            break;

        case UNRECOGNIZED:
            break;

        case FAIL:
            // error should already be set by check function
            img_info.reset();
            return img_info;
        }
    }

    switch (guesses.size()) {
    case 0:
        // no guesses, try raw as a last resort
        img_info.reset(raw_open(num_img, images, a_ssize));
        if (!img_info) {
            // raw failed too, who knows what type this is
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_IMG_UNKTYPE);
        }
        return img_info;

    case 1:
        // a non-raw format was detected
        return img_guess;

    default:
        // too many guesses, image type is abmgiugous
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_UNKTYPE);

        // build comma-separated guesses string
        const auto ambiguous = std::accumulate(
            std::next(guesses.begin()),
            guesses.end(),
            std::string(type_name(guesses[0])),
            [](std::string a, TSK_IMG_TYPE_ENUM b) {
                return std::move(a) + ", " + type_name(b);
            }
        );

        tsk_error_set_errstr("%s", ambiguous.c_str());
        img_info.reset();
        return img_info;
    }
}

TSK_IMG_INFO* img_open(
  int num_img,
  const TSK_TCHAR* const images[],
  TSK_IMG_TYPE_ENUM type,
  unsigned int a_ssize,
  [[maybe_unused]] const TSK_IMG_OPTIONS* opts
)
{
    if (tsk_verbose)
        TFPRINTF(stderr,
            _TSK_T("tsk_img_open: Type: %d   NumImg: %d  Img1: %" PRIttocTSK "\n"),
            type, num_img, images[0]);

    auto img_info = type == TSK_IMG_TYPE_DETECT ?
      img_open_detect_type(num_img, images, a_ssize) :
      img_open_by_type(num_img, images, type, a_ssize);

    if (!img_info) {
        return nullptr;
    }

    IMG_INFO* iif = reinterpret_cast<IMG_INFO*>(img_info.get());

    /* we have a good img_info, set up the cache lock */
    iif->cache = new LegacyCache();
    iif->cache_read = tsk_img_read_legacy;

    return img_info.release();
}

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
TSK_IMG_INFO*
tsk_img_open_sing(
  const TSK_TCHAR* a_image,
  TSK_IMG_TYPE_ENUM type,
  unsigned int a_ssize)
{
    return tsk_img_open_sing_opt(a_image, type, a_ssize, &DEFAULT_IMG_OPTIONS);
}

TSK_IMG_INFO*
tsk_img_open_sing_opt(
  const TSK_TCHAR* a_image,
  TSK_IMG_TYPE_ENUM type,
  unsigned int a_ssize,
  const TSK_IMG_OPTIONS* opts)
{
    const TSK_TCHAR *const a = a_image;
    return tsk_img_open_opt(1, &a, type, a_ssize, opts);
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
tsk_img_open(
  int num_img,
  const TSK_TCHAR* const images[],
  TSK_IMG_TYPE_ENUM type,
  unsigned int a_ssize)
{
    return tsk_img_open_opt(num_img, images, type, a_ssize, &DEFAULT_IMG_OPTIONS);
}

TSK_IMG_INFO*
tsk_img_open_opt(
  int num_img,
  const TSK_TCHAR* const images[],
  TSK_IMG_TYPE_ENUM type,
  unsigned int a_ssize,
  const TSK_IMG_OPTIONS* opt)
{
    // Get rid of any old error messages laying around
    tsk_error_reset();

    if (!images_ok(num_img, images) || !sector_size_ok(a_ssize)) {
        return nullptr;
    }

    return img_open(num_img, images, type, a_ssize, opt);
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
TSK_IMG_INFO*
tsk_img_open_utf8_sing(
  const char* a_image,
  TSK_IMG_TYPE_ENUM type,
  unsigned int a_ssize)
{
    return tsk_img_open_utf8_sing_opt(a_image, type, a_ssize, &DEFAULT_IMG_OPTIONS);
}

TSK_IMG_INFO*
tsk_img_open_utf8_sing_opt(
  const char* a_image,
  TSK_IMG_TYPE_ENUM type,
  unsigned int a_ssize,
  const TSK_IMG_OPTIONS* opts)
{
    const char *const a = a_image;
    return tsk_img_open_utf8_opt(1, &a, type, a_ssize, opts);
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
tsk_img_open_utf8(
    int num_img,
    const char *const images[],
    TSK_IMG_TYPE_ENUM type,
    unsigned int a_ssize)
{
    return tsk_img_open_utf8_opt(num_img, images, type, a_ssize, &DEFAULT_IMG_OPTIONS);
}

TSK_IMG_INFO*
tsk_img_open_utf8_opt(
  int num_img,
  const char *const images[],
  TSK_IMG_TYPE_ENUM type,
  unsigned int a_ssize,
  const TSK_IMG_OPTIONS* opts)
{
    // Get rid of any old error messages laying around
    tsk_error_reset();

    if (!images_ok(num_img, images) || !sector_size_ok(a_ssize)) {
        return nullptr;
    }

#ifdef TSK_WIN32
    /* Note that there is an assumption in this code that wchar_t is 2-bytes.
     * this is a correct assumption for Windows, but not for all systems... */

    // allocate a buffer to store the UTF-16 version of the images.
    std::vector<std::unique_ptr<wchar_t[]>> images16_vec;
    for (auto i = 0; i < num_img; ++i) {
        // we allocate the buffer with the same number of chars as the UTF-8 length
        const size_t ilen = std::strlen(images[i]);

        images16_vec.emplace_back(new(std::nothrow) wchar_t[ilen + 1]);
        if (!images16_vec.back()) {
            return nullptr;
        }

        UTF8* utf8 = (UTF8 *) images[i];
        UTF16* utf16 = (UTF16 *) images16_vec.back().get();

        const TSKConversionResult retval2 =
            tsk_UTF8toUTF16((const UTF8 **) &utf8, &utf8[ilen],
            &utf16, &utf16[ilen], TSKlenientConversion);
        if (retval2 != TSKconversionOK) {
            tsk_error_set_errno(TSK_ERR_IMG_CONVERT);
            tsk_error_set_errstr
                ("tsk_img_open_utf8: Error converting image %s %d",
                images[i], retval2);
            return nullptr;
        }
        *utf16 = '\0';
    }

    std::unique_ptr<wchar_t*[]> images16{
        new(std::nothrow) wchar_t*[num_img]
    };
    if (!images16) {
        return nullptr;
    }
    for (auto i = 0; i < num_img; ++i) {
        images16[i] = images16_vec[i].get();
    }

    const TSK_TCHAR* const* imgs = images16.get();
#else
    const TSK_TCHAR* const* imgs = images;
#endif
    return img_open(num_img, imgs, type, a_ssize, opts);
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
    tsk_error_reset();

    // sanity checks
    if (!sector_size_ok(sector_size)) {
        return nullptr;
    }

    if (!ext_img_info) {
        tsk_error_set_errno(TSK_ERR_IMG_ARG);
        tsk_error_set_errstr("external image info pointer was null");
        return nullptr;
    }

    if (!read) {
        tsk_error_set_errno(TSK_ERR_IMG_ARG);
        tsk_error_set_errstr("external image read pointer was null");
        return nullptr;
    }

    if (!close) {
        tsk_error_set_errno(TSK_ERR_IMG_ARG);
        tsk_error_set_errstr("external image close pointer was null");
        return nullptr;
    }

    if (!imgstat) {
        tsk_error_set_errno(TSK_ERR_IMG_ARG);
        tsk_error_set_errstr("external image imgstat pointer was null");
        return nullptr;
    }

    // set up the TSK_IMG_INFO members
    TSK_IMG_INFO* img_info = (TSK_IMG_INFO *) ext_img_info;

    img_info->tag = TSK_IMG_INFO_TAG;
    img_info->itype = TSK_IMG_TYPE_EXTERNAL;
    img_info->size = size;
    img_info->sector_size = sector_size ? sector_size : 512;

    IMG_INFO* iif = reinterpret_cast<IMG_INFO*>(img_info);
    iif->cache_read = tsk_img_read_legacy;
    iif->read = read;
    iif->close = close;
    iif->imgstat = imgstat;

    iif->cache = new LegacyCache();

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

void tsk_img_free_image_names(TSK_IMG_INFO* img_info) {
    for (int i = img_info->num_img - 1; i >= 0; --i) {
        free(img_info->images[i]);
    }
    free(img_info->images);
    img_info->images = nullptr;
    img_info->num_img = 0;
}

int tsk_img_copy_image_names(TSK_IMG_INFO* img_info, const TSK_TCHAR* const images[], int num) {
    if (!(img_info->images = (TSK_TCHAR**) tsk_malloc(num * sizeof(TSK_TCHAR*)))) {
        return 0;
    }
    img_info->num_img = num;
    memset(img_info->images, 0, sizeof(num * sizeof(TSK_TCHAR*)));

    for (int i = 0; i < num; ++i) {
        const size_t len = TSTRLEN(images[i]);
        if (!(img_info->images[i] = (TSK_TCHAR*) tsk_malloc((len+1)*sizeof(TSK_TCHAR)))) {
            tsk_img_free_image_names(img_info);
            return 0;
        }
        TSTRNCPY(img_info->images[i], images[i], len + 1);
    }
    return 1;
}

/**
 * \ingroup imglib
 * Closes an open disk image.
 * @param a_img_info Pointer to the open disk image structure.
 */
void
tsk_img_close(TSK_IMG_INFO * a_img_info)
{
    if (!a_img_info) {
        return;
    }

    IMG_INFO* iif = reinterpret_cast<IMG_INFO*>(a_img_info);

    auto cache = static_cast<LegacyCache*>(iif->cache);
    delete cache;

    iif->close(a_img_info);
}

/* tsk_img_malloc - tsk_malloc, then set image tag
 * This is for img module and all its inheritances
 */
void *
tsk_img_malloc(size_t a_len)
{
    TSK_IMG_INFO *imgInfo;
    if (!(imgInfo = (TSK_IMG_INFO *) tsk_malloc(a_len))) {
        return nullptr;
    }
    imgInfo->tag = TSK_IMG_INFO_TAG;
    reinterpret_cast<IMG_INFO*>(imgInfo)->cache = nullptr;
    return imgInfo;
}

/* tsk_img_free - unset image tag, then free memory
 * This is for img module and all its inheritances
 */
void
tsk_img_free(void *a_ptr)
{
    TSK_IMG_INFO *imgInfo = (TSK_IMG_INFO *) a_ptr;
    imgInfo->tag = 0;
    tsk_img_free_image_names(imgInfo);
    free(imgInfo);
}
