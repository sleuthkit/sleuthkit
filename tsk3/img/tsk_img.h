/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2005-2008 Brian Carrier.  All rights reserved 
 *
 * This software is distributed under the Common Public License 1.0
 */
#ifndef _TSK_IMG_H
#define _TSK_IMG_H


/**
 * \file tsk_img.h
 * Contains the external library definitions for the disk image functions.  
 * Note that this file is not meant to be directly included.  
 * It is included by both libtsk.h and tsk_img_i.h.
 */

/**
 * \defgroup imglib Disk Image Functions
 */

#ifdef __cplusplus
extern "C" {
#endif

    /**
     * \ingroup imglib
     * Macro that takes a image type and returns 1 if the type
     * is for a raw file format. */
#define TSK_IMG_TYPE_ISRAW(t) \
    ((((t) & TSK_IMG_TYPE_RAW_SING) || ((t) & TSK_IMG_TYPE_RAW_SPLIT))?1:0)

    /**
     * \ingroup imglib
     * Macro that takes a image type and returns 1 if the type
     * is for an AFF file format. */
#define TSK_IMG_TYPE_ISAFF(t) \
    ((((t) & TSK_IMG_TYPE_AFF_AFF) || ((t) & TSK_IMG_TYPE_AFF_AFD)  || ((t) & TSK_IMG_TYPE_AFF_AFM) || \
    ((t) & TSK_IMG_TYPE_AFF_ANY))?1:0)

    /**
     * \ingroup imglib
     * Macro that takes a image type and returns 1 if the type
     * is for an EWF file format. */
#define TSK_IMG_TYPE_ISEWF(t) \
    ((((t) & TSK_IMG_TYPE_EWF_EWF))?1:0)


    /** 
     * Flag values for the disk image format type.  Each type has a
     * bit associated with it.  There are TSK_IMG_TYPE_ISXXX macros
     * to determine the broad group of the type (raw vs aff etc.)
     */
    typedef enum {
        TSK_IMG_TYPE_DETECT = 0x0000,   ///< Use autodetection methods

        TSK_IMG_TYPE_RAW_SING = 0x0001, ///< Raw single disk image
        TSK_IMG_TYPE_RAW_SPLIT = 0x0002,        ///< Raw split image

        TSK_IMG_TYPE_AFF_AFF = 0x0004,  ///< AFF AFF Format
        TSK_IMG_TYPE_AFF_AFD = 0x0008,  ///< AFD AFF Format
        TSK_IMG_TYPE_AFF_AFM = 0x0010,  ///< AFM AFF Format
        TSK_IMG_TYPE_AFF_ANY = 0x0020,  ///< Any format supported by AFFLIB (including beta ones)

        TSK_IMG_TYPE_EWF_EWF = 0x0040,  ///< EWF version

        TSK_IMG_TYPE_UNSUPP = 0xffff,   ///< Unsupported disk image type
    } TSK_IMG_TYPE_ENUM;

#define TSK_IMG_INFO_CACHE_NUM  4
#define TSK_IMG_INFO_CACHE_LEN  65536

    typedef struct TSK_IMG_INFO TSK_IMG_INFO;

    /**
     * Created when a disk image has been opened and stores general information and handles.
     */
    struct TSK_IMG_INFO {

        TSK_IMG_TYPE_ENUM itype;        ///< Type of disk image format
        TSK_OFF_T size;         ///< Total size of image in bytes
        unsigned int sector_size;       ///< sector size of device in bytes (typically 512)

        char cache[TSK_IMG_INFO_CACHE_NUM][TSK_IMG_INFO_CACHE_LEN];     ///< read cache
        TSK_OFF_T cache_off[TSK_IMG_INFO_CACHE_NUM];    ///< starting byte offset of corresponding cache entry
        int cache_age[TSK_IMG_INFO_CACHE_NUM];  ///< "Age" of corresponding cache entry, higher means more recently used
        size_t cache_len[TSK_IMG_INFO_CACHE_NUM];       ///< Length of cache entry used (0 if never used)

         ssize_t(*read) (TSK_IMG_INFO * img, TSK_OFF_T off, char *buf, size_t len);     ///< \internal External progs should call tsk_img_read() 
        void (*close) (TSK_IMG_INFO *); ///< \internal Progs should call tsk_img_close()
        void (*imgstat) (TSK_IMG_INFO *, FILE *);       ///< Pointer to file type specific function
    };

    // open and close functions
    extern TSK_IMG_INFO *tsk_img_open_sing(const TSK_TCHAR * a_image,
        TSK_IMG_TYPE_ENUM type, unsigned int a_ssize);
    extern TSK_IMG_INFO *tsk_img_open(int,
        const TSK_TCHAR * const images[], TSK_IMG_TYPE_ENUM, 
        unsigned int a_ssize);
    extern TSK_IMG_INFO *tsk_img_open_utf8_sing(const char *a_image,
        TSK_IMG_TYPE_ENUM type, unsigned int a_ssize);
    extern TSK_IMG_INFO *tsk_img_open_utf8(int num_img,
        const char *const images[], TSK_IMG_TYPE_ENUM type, 
        unsigned int a_ssize);

    extern void tsk_img_close(TSK_IMG_INFO *);

    // read functions
    extern ssize_t tsk_img_read(TSK_IMG_INFO * img, TSK_OFF_T off,
        char *buf, size_t len);

    // type conversion functions
    extern TSK_IMG_TYPE_ENUM tsk_img_type_toid(const TSK_TCHAR *);
    extern const char *tsk_img_type_toname(TSK_IMG_TYPE_ENUM);
    extern const char *tsk_img_type_todesc(TSK_IMG_TYPE_ENUM);
    extern TSK_IMG_TYPE_ENUM tsk_img_type_supported();
    extern void tsk_img_type_print(FILE *);

#ifdef __cplusplus
}
#endif
#endif
