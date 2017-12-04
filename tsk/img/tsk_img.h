/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2005-2011 Brian Carrier.  All rights reserved
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
 * \defgroup imglib C Disk Image Functions
 * \defgroup imglib_cpp C++ Disk Image Classes
 */

#ifdef __cplusplus
extern "C" {
#endif
    /**
     * \ingroup imglib
     * Macro that takes a image type and returns 1 if the type
     * is for a raw file format. */
#define TSK_IMG_TYPE_ISRAW(t) \
    ((((t) & TSK_IMG_TYPE_RAW))?1:0)

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

        TSK_IMG_TYPE_RAW = 0x0001,      ///< Raw disk image (single or split)
        TSK_IMG_TYPE_RAW_SING = TSK_IMG_TYPE_RAW,       ///< Raw single (backward compatibility) depreciated
        TSK_IMG_TYPE_RAW_SPLIT = TSK_IMG_TYPE_RAW,      ///< Raw single (backward compatibility) depreciated

        TSK_IMG_TYPE_AFF_AFF = 0x0004,  ///< AFF AFF Format
        TSK_IMG_TYPE_AFF_AFD = 0x0008,  ///< AFD AFF Format
        TSK_IMG_TYPE_AFF_AFM = 0x0010,  ///< AFM AFF Format
        TSK_IMG_TYPE_AFF_ANY = 0x0020,  ///< Any format supported by AFFLIB (including beta ones)

        TSK_IMG_TYPE_EWF_EWF = 0x0040,   ///< EWF version
        TSK_IMG_TYPE_VMDK_VMDK = 0x0080, ///< VMDK version
        TSK_IMG_TYPE_VHD_VHD = 0x0100,   ///< VHD version
        TSK_IMG_TYPE_EXTERNAL = 0x1000,  ///< external defined format which at least implements TSK_IMG_INFO, used by pytsk

        TSK_IMG_TYPE_UNSUPP = 0xffff,   ///< Unsupported disk image type
    } TSK_IMG_TYPE_ENUM;

#define TSK_IMG_INFO_CACHE_NUM  32
#define TSK_IMG_INFO_CACHE_LEN  65536

    typedef struct TSK_IMG_INFO TSK_IMG_INFO;
#define TSK_IMG_INFO_TAG 0x39204231

    /**
     * Created when a disk image has been opened and stores general information and handles.
     */
    struct TSK_IMG_INFO {
        uint32_t tag;           ///< Set to TSK_IMG_INFO_TAG when struct is alloc
        TSK_IMG_TYPE_ENUM itype;        ///< Type of disk image format
        TSK_OFF_T size;         ///< Total size of image in bytes
        int num_img;            ///< Number of image files
        unsigned int sector_size;       ///< sector size of device in bytes (typically 512)
        unsigned int page_size;         ///< page size of NAND page in bytes (defaults to 2048)
        unsigned int spare_size;        ///< spare or OOB size of NAND in bytes (defaults to 64)

        // the following are protected by cache_lock in IMG_INFO
        TSK_TCHAR **images;    ///< Image names

        tsk_lock_t cache_lock;  ///< Lock for cache and associated values
        char cache[TSK_IMG_INFO_CACHE_NUM][TSK_IMG_INFO_CACHE_LEN];     ///< read cache (r/w shared - lock) 
        TSK_OFF_T cache_off[TSK_IMG_INFO_CACHE_NUM];    ///< starting byte offset of corresponding cache entry (r/w shared - lock) 
        int cache_age[TSK_IMG_INFO_CACHE_NUM];  ///< "Age" of corresponding cache entry, higher means more recently used (r/w shared - lock) 
        size_t cache_len[TSK_IMG_INFO_CACHE_NUM];       ///< Length of cache entry used (0 if never used) (r/w shared - lock) 

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
    extern TSK_IMG_INFO *tsk_img_open_external(void* ext_img_info,
        TSK_OFF_T size, unsigned int sector_size,
        ssize_t(*read) (TSK_IMG_INFO * img, TSK_OFF_T off, char *buf, size_t len),
        void (*close) (TSK_IMG_INFO *),
        void (*imgstat) (TSK_IMG_INFO *, FILE *));
    extern void tsk_img_close(TSK_IMG_INFO *);

    // read functions
    extern ssize_t tsk_img_read(TSK_IMG_INFO * img, TSK_OFF_T off,
        char *buf, size_t len);

    // type conversion functions
    extern TSK_IMG_TYPE_ENUM tsk_img_type_toid_utf8(const char *);
    extern TSK_IMG_TYPE_ENUM tsk_img_type_toid(const TSK_TCHAR *);
    extern const char *tsk_img_type_toname(TSK_IMG_TYPE_ENUM);
    extern const char *tsk_img_type_todesc(TSK_IMG_TYPE_ENUM);
    extern TSK_IMG_TYPE_ENUM tsk_img_type_supported();
    extern void tsk_img_type_print(FILE *);

#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
/**
 \ingroup imglib_cpp
* Stores information about an image that is open and being analyzed.
* To use this object, open() should be called first.  Otherwise, the get()
* methods will return undefined values.
*/ class TskImgInfo {
    friend class TskFsInfo;
    friend class TskVsInfo;

  private:
     TSK_IMG_INFO * m_imgInfo;
    bool m_opened;              // true if open() was called and we need to free it    
     TskImgInfo(const TskImgInfo & rhs);
     TskImgInfo & operator=(const TskImgInfo & rhs);

  public:
     TskImgInfo() {
        m_imgInfo = NULL;
        m_opened = false;
    };

    ~TskImgInfo() {
        if (m_imgInfo == NULL) {
            return;
        }
        m_imgInfo->close(m_imgInfo);
    };

    TskImgInfo(TSK_IMG_INFO * a_imgInfo) {
        m_imgInfo = a_imgInfo;
        m_opened = false;
    };

    /**
    * Opens a single (non-split) disk image file so that it can be read.
    * See tsk_img_open_sing() for more details.
    *
    * @param a_image The path to the image file
    * @param a_type The disk image type (can be autodetection)
    * @param a_ssize Size of device sector in bytes (or 0 for default)
    *
    * @return 1 on error and 0 on success
    */
    uint8_t open(const TSK_TCHAR * a_image, TSK_IMG_TYPE_ENUM a_type,
        unsigned int a_ssize) {
        if ((m_imgInfo =
                tsk_img_open_sing(a_image, a_type, a_ssize)) != NULL) {
            m_opened = true;
            return 0;
        }
        else {
            return 1;
        }
    };

    /**
    * Opens one or more disk image files so that they can be read. e UTF8, then consider
    * See tsk_img_open() for more details.
    *
    * @param a_num_img The number of images to open (will be > 1 for split images).
    * @param a_images The path to the image files (the number of files must
    * be equal to num_img and they must be in a sorted order)
    * @param a_type The disk image type (can be autodetection)
    * @param a_ssize Size of device sector in bytes (or 0 for default)
    *
    * @return 1 on error and 0 on success
    */
    uint8_t open(int a_num_img, const TSK_TCHAR * const a_images[],
        TSK_IMG_TYPE_ENUM a_type, unsigned int a_ssize) {
        if ((m_imgInfo =
                tsk_img_open(a_num_img, a_images, a_type,
                    a_ssize)) != NULL) {
            m_opened = true;
            return 0;
        }
        else {
            return 1;
        }

    };

#ifdef TSK_WIN32
    /**
    * Opens a single (non-split) disk image file so that it can be read.  This version
    * always takes a UTF-8 encoding of the disk image.  See tsk_img_open_utf8_sing() for details.
    *
    * @param a_image The UTF-8 path to the image file
    * @param a_type The disk image type (can be autodetection)
    * @param a_ssize Size of device sector in bytes (or 0 for default)
    *
    * @return 1 on error and 0 on success
    */
    uint8_t open(const char *a_image, TSK_IMG_TYPE_ENUM a_type,
        unsigned int a_ssize) {
        if ((m_imgInfo =
                tsk_img_open_utf8_sing(a_image, a_type,
                    a_ssize)) != NULL) {
            m_opened = true;
            return 0;
        }
        else {
            return 1;
        }

    };

    /**
    * Opens one or more disk image files so that they can be read.  This
    * version always takes a UTF-8 encoding of the image files.  See tsk_img_open_utf8()
    * for more details.
    *
    * @param a_num_img The number of images to open (will be > 1 for split images).
    * @param a_images The path to the UTF-8 encoded image files (the number of files must
    * be equal to a_num_img and they must be in a sorted order)
    * @param a_type The disk image type (can be autodetection)
    * @param a_ssize Size of device sector in bytes (or 0 for default)
    *
    * @return 1 on error and 0 on success
    */
    uint8_t open(int a_num_img, const char *const a_images[],
        TSK_IMG_TYPE_ENUM a_type, unsigned int a_ssize) {
        if ((m_imgInfo =
                tsk_img_open_utf8(a_num_img, a_images, a_type,
                    a_ssize)) != NULL) {
            m_opened = true;
            return 0;
        }
        else {
            return 1;
        }

    };
#endif

    /**
    * Reads data from an open disk image
    *
    * @param a_off Byte offset to start reading from
    * @param a_buf Buffer to read into
    * @param a_len Number of bytes to read into buffer
    * @returns number of bytes read or -1 on error
    */
    ssize_t read(TSK_OFF_T a_off, char *a_buf, size_t a_len) {
        return tsk_img_read(m_imgInfo, a_off, a_buf, a_len);
    };


   /**
    * returns the image format type.
    * @returns image format type
    */
    TSK_IMG_TYPE_ENUM getType() const {
        if (m_imgInfo != NULL)
            return m_imgInfo->itype;
        else
            return (TSK_IMG_TYPE_ENUM) 0;
    };

    /**
    * Returns the size of the image.
    * @returns total size of image in bytes
    */
    TSK_OFF_T getSize() const {
        if (m_imgInfo != NULL)
            return m_imgInfo->size;
        else
            return 0;
    };

    /**
    * Returns the sector size of the disk
    * @returns sector size of original device in bytes
    */
    unsigned int getSectorSize() const {
        if (m_imgInfo != NULL)
            return m_imgInfo->sector_size;
        else
            return 0;
    };


    /**
    * Parses a string that specifies an image format to determine the
    * associated type ID.  This is used by the TSK command line tools to
    * parse the type given on the command line.
    *
    * @param a_str String of image format type
    * @return ID of image type
    */
    static TSK_IMG_TYPE_ENUM typeToId(const TSK_TCHAR * a_str) {
        return tsk_img_type_toid(a_str);
    };

    /**
    * Returns the name of an image format type, given its type ID.
    * @param a_type ID of image type
    * @returns Pointer to string of the name.
    */
    static const char *typeToName(TSK_IMG_TYPE_ENUM a_type) {
        return tsk_img_type_toname(a_type);
    };

    /**
    * Returns the description of an image format type, given its type ID.
    * @param a_type ID of image type
    * @returns Pointer to string of the description
    */
    static const char *typeToDesc(TSK_IMG_TYPE_ENUM a_type) {
        return tsk_img_type_todesc(a_type);
    };

    /**
    * Returns the supported file format types.
    * @returns A bit in the return value is set to 1 if the type is supported.
    */
    static TSK_IMG_TYPE_ENUM typeSupported() {
        return tsk_img_type_supported();
    };

    /**
    * Prints the name and description of the supported image types to a handle.
    * This is used by the TSK command line tools to print the supported types
    * to the console.
    * @param a_file Handle to print names and descriptions to.
    */
    static void typePrint(FILE * a_file) {
        tsk_img_type_print(a_file);
    };
};

#endif                          //__cplusplus
#endif                          //_TSK_IMG_H
