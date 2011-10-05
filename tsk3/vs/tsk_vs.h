/*
* The Sleuth Kit
*
* Brian Carrier [carrier <at> sleuthkit [dot] org]
* Copyright (c) 2003-2011 Brian Carrier.  All rights reserved
*
* This software is distributed under the Common Public License 1.0
*
*/

/**
* \file tsk_vs.h
* External header file for media management (volume system) support.
* Note that this file is not meant to be directly included.  
* It is included by both libtsk.h and tsk_vs_i.h.
*/

/**
* \defgroup vslib C Volume System Functions
 * \defgroup vslib_cpp C++ Volume System Classes
*/
#ifndef _TSK_VS_H
#define _TSK_VS_H

#ifdef __cplusplus
extern "C" {
#endif

    /* Structures */
    typedef struct TSK_VS_INFO TSK_VS_INFO;
    typedef struct TSK_VS_PART_INFO TSK_VS_PART_INFO;

    /** 
    * Definition for callback function that vs_part_walk() calls for
    * each partition that it walks.  
    *
    * @param a_vs Pointer to volume system being analyzed
    * @param a_vs_part Pointer to current partition in the walk
    * @param a_ptr Pointer that was passed to vs_part_walk by caller
    * @return Status on whether the vs_part_walk() function should 
    * continue, stop, or error. 
    */
    typedef TSK_WALK_RET_ENUM(*TSK_VS_PART_WALK_CB) (TSK_VS_INFO *
        a_vs, const TSK_VS_PART_INFO * a_vs_part, void *a_ptr);

    /**
    * Flags for the partition type.  
    */
    typedef enum {
        TSK_VS_TYPE_DETECT = 0x0000,    ///< Use autodetection methods
        TSK_VS_TYPE_DOS = 0x0001,       ///< DOS Partition table
        TSK_VS_TYPE_BSD = 0x0002,       ///< BSD Partition table
        TSK_VS_TYPE_SUN = 0x0004,       ///< Sun VTOC
        TSK_VS_TYPE_MAC = 0x0008,       ///< Mac partition table
        TSK_VS_TYPE_GPT = 0x0010,       ///< GPT partition table
        TSK_VS_TYPE_DBFILLER = 0x00F0,  ///< fake partition table type for loaddb (for images that do not have a volume system)
        TSK_VS_TYPE_UNSUPP = 0xffff,    ///< Unsupported
    } TSK_VS_TYPE_ENUM;

    /**
    * Data structure used to store state and basic information
    * for open volume systems.
    */
    struct TSK_VS_INFO {
        int tag;                ///< \internal Will be set to TSK_VS_INFO_TAG if structure is still allocated, 0 if not
        TSK_IMG_INFO *img_info; ///< Pointer to disk image that VS is in
        TSK_VS_TYPE_ENUM vstype;        ///< Type of volume system / media management
        TSK_DADDR_T offset;     ///< Byte offset where VS starts in disk image
        unsigned int block_size;        ///< Size of blocks in bytes

        TSK_ENDIAN_ENUM endian; ///< Endian ordering of data

        TSK_VS_PART_INFO *part_list;    ///< Linked list of partitions

        TSK_PNUM_T part_count;  ///< number of partitions 

        void (*close) (TSK_VS_INFO *);  ///< \internal Progs should call tsk_vs_close().
    };

#define TSK_VS_INFO_TAG  0x52301642


    /***************************************************************
    * Generic structures  for partitions / slices
    */

    /** 
    * Flag values that describe the partitions in the VS.  Refer
    * to \ref vs_open2 for more details. 
    */
    typedef enum {
        TSK_VS_PART_FLAG_ALLOC = 0x01,  ///< Sectors are allocated to a volume in the volume system
        TSK_VS_PART_FLAG_UNALLOC = 0x02,        ///< Sectors are not allocated to a volume 
        TSK_VS_PART_FLAG_META = 0x04,   ///< Sectors contain volume system metadata and could also be ALLOC or UNALLOC
        TSK_VS_PART_FLAG_ALL = 0x07,    ///< Show all sectors in the walk. 
    } TSK_VS_PART_FLAG_ENUM;

    /**
    * Linked list entry that describes a volume in a generic way. 
    */
    struct TSK_VS_PART_INFO {
        int tag;
        TSK_VS_PART_INFO *prev; ///< Pointer to previous partition (or NULL)
        TSK_VS_PART_INFO *next; ///< Pointer to next partition (or NULL)
        TSK_VS_INFO *vs;        ///< Pointer to parent volume system handle

        TSK_DADDR_T start;      ///< Sector offset of start of partition
        TSK_DADDR_T len;        ///< Number of sectors in partition
        char *desc;             ///< UTF-8 description of partition (volume system type-specific)
        int8_t table_num;       ///< Table address that describes this partition
        int8_t slot_num;        ///< Entry in the table that describes this partition
        TSK_PNUM_T addr;        ///< Address of this partition
        TSK_VS_PART_FLAG_ENUM flags;    ///< Flags for partition
    };

#define TSK_VS_PART_INFO_TAG  0x40121253

    // to and from type ids and names
    extern TSK_VS_TYPE_ENUM tsk_vs_type_toid(const TSK_TCHAR *);
    extern TSK_VS_TYPE_ENUM tsk_vs_type_toid_utf8(const char *);
    extern const char *tsk_vs_type_toname(TSK_VS_TYPE_ENUM);
    extern const char *tsk_vs_type_todesc(TSK_VS_TYPE_ENUM);
    extern TSK_VS_TYPE_ENUM tsk_vs_type_supported();
    extern void tsk_vs_type_print(FILE *);

    // open a volume system
    extern TSK_VS_INFO *tsk_vs_open(TSK_IMG_INFO *, TSK_DADDR_T,
        TSK_VS_TYPE_ENUM);
    extern void tsk_vs_close(TSK_VS_INFO *);

    // read data in the volume system
    extern ssize_t tsk_vs_read_block(TSK_VS_INFO * a_vs,
        TSK_DADDR_T a_addr, char *buf, size_t len);

    // open a partition
    extern const TSK_VS_PART_INFO *tsk_vs_part_get(const TSK_VS_INFO *,
        TSK_PNUM_T idx);
    extern uint8_t tsk_vs_part_walk(TSK_VS_INFO * vs, TSK_PNUM_T start,
        TSK_PNUM_T last, TSK_VS_PART_FLAG_ENUM flags,
        TSK_VS_PART_WALK_CB action, void *ptr);

    // read data in partitions
    extern ssize_t tsk_vs_part_read(const TSK_VS_PART_INFO *
        a_vs_part, TSK_OFF_T a_off, char *buf, size_t len);
    extern ssize_t tsk_vs_part_read_block(const TSK_VS_PART_INFO *
        a_vs_part, TSK_DADDR_T a_addr, char *buf, size_t len);

#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
class TskVsInfo;
class TskVsPartInfo;

/** 
* Definition for callback function that vs_part_walk() calls for
* each partition that it walks.  
*
* @param a_vs Pointer to volume system being analyzed
* @param a_vs_part Pointer to current partition in the walk
* @param a_ptr Pointer that was passed to vs_part_walk by caller
* @return Status on whether the vs_part_walk() function should 
* continue, stop, or error. 
*/
typedef TSK_WALK_RET_ENUM(*TSK_VS_PART_WALK_CPP_CB) (TskVsInfo *
    a_vs, const TskVsPartInfo * a_vs_part, void *a_ptr);
/** \internal
* Internal structure to pass C++ volume system part walk data into C block walk call back.
*/
typedef struct {
    TSK_VS_PART_WALK_CPP_CB cppAction;  // pointer C++ callback
    void *cPtr;                 // pointer to data that was passed into C++ walk method
} TSK_VS_PART_WALK_CPP_DATA;

/** \internal
* Internal function used to call C++ Block Walk callback from C callback.
*/
extern TSK_WALK_RET_ENUM tsk_vs_part_walk_cpp_c_cb(TSK_VS_INFO * a_vs,
    const TSK_VS_PART_INFO * a_vs_part, void *a_ptr);

/** 
 * \ingroup vslib_cpp
* Stores information about a volume / partition inside of an open volume
* system. 
*/
class TskVsPartInfo {
    friend class TskFsInfo;

  private:
     TSK_VS_PART_INFO * m_vsPartInfo;
     TskVsPartInfo(const TskVsPartInfo & rhs);
     TskVsPartInfo & operator=(const TskVsPartInfo & rhs);

  public:

    /**
     * Create an object from its C struct.
     * @param a_vsPartInfo Pointer to C struct for partition.  If NULL, the
     * remaining getX() methods will be undefined.
     */
     TskVsPartInfo(TSK_VS_PART_INFO * a_vsPartInfo) {
        m_vsPartInfo = a_vsPartInfo;
    };

    /**
    * Reads data starting at a byte address relative to the start of a VOLUME in a volume system.
    * See tsk_vs_part_read() for details.
    * @param a_off Byte offset to read from, relative to start of VOLUME in volume system.
    * @param a_buf Buffer to store data in
    * @param a_len Amount of data to read (in bytes)
    * @return Number of bytes read or -1 on error 
    */
    ssize_t read(TSK_OFF_T a_off, char *a_buf, size_t a_len) {
        if (m_vsPartInfo != NULL)
            return tsk_vs_part_read(m_vsPartInfo, a_off, a_buf, a_len);
        else
            return 0;
    };

    /**
    * Reads one or more blocks of data with an address relative to the start of a VOLUME in a volume system.
    * See tsk_vs_part_read_block() for details.
    * @param a_addr Block address to start reading from, relative to start of VOLUME in volume system.
    * @param a_buf Buffer to store data in
    * @param a_len Amount of data to read (in bytes - must be a multiple of block_size)
    * @return Number of bytes read or -1 on error 
    */
    ssize_t readBlock(TSK_DADDR_T a_addr, char *a_buf, size_t a_len) {
        if (m_vsPartInfo != NULL)
            return tsk_vs_part_read_block(m_vsPartInfo, a_addr, a_buf,
                a_len);
        else
            return 0;
    };

    /**
    * Return sector offset of start of partition
    * @return sector offset of start of partition
    */
    TSK_DADDR_T getStart() const {
        if (m_vsPartInfo != NULL)
            return m_vsPartInfo->start;
        else
            return 0;
    };

    /**
    * Return number of sectors in partition
    * @return number of sectors in partition
    */
    TSK_DADDR_T getLen() const {
        if (m_vsPartInfo != NULL)
            return m_vsPartInfo->len;
        else
            return 0;
    };

    /**
    * Return UTF-8 description of partition (volume system type-specific)
    * @return description of partition
    */
    const char *getDesc() const {
        if (m_vsPartInfo != NULL)
            return m_vsPartInfo->desc;
        else
            return NULL;
    };

    /**
    * Return table address that describes this partition
    * @return table address that describes this partition
    */
    int8_t getTableNum() const {
        if (m_vsPartInfo != NULL)
            return m_vsPartInfo->table_num;
        else
            return 0;
    };

    /**
    * Return entry in the table that describes this partition
    * @return entry in the table that describes this partition
    */
    int8_t getSlotNum() const {
        if (m_vsPartInfo != NULL)
            return m_vsPartInfo->slot_num;
        else
            return 0;
    };

    /**
    * Return address of this partition
    * @return address of this partition
    */
    TSK_PNUM_T getAddr() const {
        if (m_vsPartInfo != NULL)
            return m_vsPartInfo->addr;
        else
            return 0;
    };

    /**
    * Return flags for partition
    * @return flags for partition
    */
    TSK_VS_PART_FLAG_ENUM getFlags() const {
        if (m_vsPartInfo != NULL)
            return m_vsPartInfo->flags;
        else
            return (TSK_VS_PART_FLAG_ENUM) 0;
    };
};


/**
 * \ingroup vslib_cpp
* Stores information about an open volume system. 
* To use this object, open() should be called first.
*/
class TskVsInfo {
  private:
    TSK_VS_INFO * m_vsInfo;
    bool m_opened;              // true if open() was called and we need to free it
     TskVsInfo(const TskVsInfo & rhs);
     TskVsInfo & operator=(const TskVsInfo & rhs);

  public:
     TskVsInfo(TSK_VS_INFO * a_vsInfo) {
        m_vsInfo = a_vsInfo;
        m_opened = false;
    };

    TskVsInfo() {
        m_vsInfo = NULL;
        m_opened = false;
    };

    ~TskVsInfo() {
        close();
    };

    /** 
    * Walk a range of partitions and pass the data to a callback function. 
    * See tsk_vs_part_walk() for details.
    * @param a_start Address of first partition to walk from.
    * @param a_last Address of last partition to walk to.
    * @param a_flags Flags that are used to identify which of the partitions in the range should be returned (if 0, all partitions will be returned).
    * @param a_action Callback action to call for each partition.
    * @param a_ptr Pointer to data that will be passed to callback.
    * @return 1 on error and 0 on success
    */
    uint8_t vsPartWalk(TSK_PNUM_T a_start, TSK_PNUM_T a_last,
        TSK_VS_PART_FLAG_ENUM a_flags, TSK_VS_PART_WALK_CPP_CB a_action,
        void *a_ptr) {
        TSK_VS_PART_WALK_CPP_DATA vsPartData;
        vsPartData.cppAction = a_action;
        vsPartData.cPtr = a_ptr;
        return tsk_vs_part_walk(m_vsInfo, a_start, a_last,
            a_flags, tsk_vs_part_walk_cpp_c_cb, &vsPartData);
    };

    /**
    * Open a disk image and process the media management system
    * data. See tsk_vs_open() for details.
    *
    * @param a_imgInfo The opened disk image.
    * @param a_offset Byte offset in the disk image to start analyzing from.
    * @param a_type Type of volume system (including auto detect)
    *
    * @return 1 on error and 0 on success. 
    */
    uint8_t open(TskImgInfo * a_imgInfo, TSK_DADDR_T a_offset,
        TSK_VS_TYPE_ENUM a_type) {
        if ((m_vsInfo =
                tsk_vs_open(a_imgInfo->m_imgInfo, a_offset,
                    a_type)) != NULL) {
            m_opened = true;
            return 0;
        }
        else {
            return 1;
        }
    };

    /**
    * Reads one or more blocks of data with an address relative to the start of the volume system.
    * See tsk_vs_read_block() for details.
    * @param a_addr Sector address to read from, relative to start of VOLUME SYSTEM.
    * @param a_buf Buffer to store data in
    * @param a_len Amount of data to read (in bytes - must be a multiple of block_size)
    * @return Number of bytes read or -1 on error 
    */
    ssize_t readBlock(TSK_DADDR_T a_addr, char *a_buf, size_t a_len) {
        if (m_vsInfo != NULL)
            return tsk_vs_read_block(m_vsInfo, a_addr, a_buf, a_len);
        else
            return 0;
    };

    /**
    * Closes an open volume system. See for tsk_vs_close() details.
    */
    void close() {
        if ((m_vsInfo) && (m_opened))
            tsk_vs_close(m_vsInfo);
        m_vsInfo = NULL;
    };

    /**
    * Return the byte offset where volume system starts in disk image
    * @return byte offset
    */
    TSK_DADDR_T getOffset() const {
        if (m_vsInfo != NULL)
            return m_vsInfo->offset;
        else
            return 0;
    };

    /**
    * Return size of volume system blocks in bytes
    * @return size of a block in bytes
    */
    unsigned int getBlockSize() const {
        if (m_vsInfo != NULL)
            return m_vsInfo->block_size;
        else
            return 0;
    };

    /**
    * Return number of partitions
    * @return number of partitions
    */
    TSK_PNUM_T getPartCount() const {
        if (m_vsInfo != NULL)
            return m_vsInfo->part_count;
        else
            return 0;
    };

    /**
    * Get reference to a volume in the volume system.
    * See tsk_vs_part_get() for details.
    * @param a_idx Index for volume to return (0-based)
    * @return Pointer to partition or NULL on error.  Caller is responsible for freeing object.
    */
    const TskVsPartInfo *getPart(TSK_PNUM_T a_idx) const {
        // @@@ Error handling.
        return new TskVsPartInfo(const_cast <
            TSK_VS_PART_INFO * >(tsk_vs_part_get(m_vsInfo, a_idx)));
    };

    /**
    * Get a reference to the parent image object. 
    * @return Pointer to object or NULL on error.  Caller is responsible for freeing object.
    */
    const TskImgInfo *getImgInfo() const {
        if (m_vsInfo == NULL)
            return 0;
        return new TskImgInfo(m_vsInfo->img_info);
    };

    /**
    * Return type of volume system / media management
    * @return type of volume system / media management
    */
    TSK_VS_TYPE_ENUM getVsType() const {
        if (m_vsInfo != NULL)
            return m_vsInfo->vstype;
        else
            return (TSK_VS_TYPE_ENUM) 0;
    };

    /**
     * Parse a string with the volume system type and return its internal ID.
     * See tsk_vs_type_toid() for details.
     * @param a_str String to parse.
     * @return ID of string (or unsupported if the name is unknown)
     */
    static TSK_VS_TYPE_ENUM typeToId(const TSK_TCHAR * a_str) {
        return tsk_vs_type_toid(a_str);
    };
    /**
     * Print the supported volume system type names to an open handle.
     * See tsk_vs_type_print() for details.
     * @param a_hFile Handle to print to.
     */
    static void typePrint(FILE * a_hFile) {
        tsk_vs_type_print(a_hFile);
    };

    /**
     * Return the supported volume system types. 
     * See tsk_vs_type_supported() for details.
     * @return The bit in the return value is 1 if the type is supported.
     */
    static TSK_VS_TYPE_ENUM typeSupported() {
        return tsk_vs_type_supported();
    };

    /**
     * Return the string name of a partition type ID.
     * See tsk_vs_type_toname() for details.
     * @param a_type Volume system type
     * @return name of type or NULL on error
     */
    static const char *typeToName(TSK_VS_TYPE_ENUM a_type) {
        return tsk_vs_type_toname(a_type);
    };

    /**
     * Return the string description of a partition type ID.
     * See tsk_vs_type_todesc() for details.
     * @param a_type Volume system type
     * @return description of type or NULL on error
     */
    static const char *typeToDesc(TSK_VS_TYPE_ENUM a_type) {
        return tsk_vs_type_todesc(a_type);
    };
};

#endif
#endif
