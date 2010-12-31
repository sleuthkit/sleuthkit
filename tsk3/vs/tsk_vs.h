/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2003-2008 Brian Carrier.  All rights reserved
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
 * \defgroup vslib Volume System Functions
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
     * @returns Status on whether the vs_part_walk() function should 
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
        TSK_IMG_INFO *img_info; ///< Pointer to disk image that VS is in
        TSK_VS_TYPE_ENUM vstype;        ///< Type of volume system / media management
        TSK_DADDR_T offset;     ///< Byte offset where VS starts in disk image
        unsigned int block_size;        ///< Size of blocks in bytes

        TSK_ENDIAN_ENUM endian; ///< Endian ordering of data

        TSK_VS_PART_INFO *part_list;    ///< Linked list of partitions

        TSK_PNUM_T part_count;  ///< number of partitions 

        void (*close) (TSK_VS_INFO *);  ///< \internal Progs should call tsk_vs_close().
    };




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


    // to and from type ids and names
    extern TSK_VS_TYPE_ENUM tsk_vs_type_toid(const TSK_TCHAR *);
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
#endif
