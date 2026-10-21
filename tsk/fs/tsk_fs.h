Warning: truncated output (original token count: 28879)
Total output lines: 3129

/*
** The Sleuth Kit
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2003-2012 Brian Carrier.  All rights reserved
**
** Matt Stillerman [matt@atc-nycorp.com]
** Copyright (c) 2012 ATC-NY.  All rights reserved.
** This file contains data developed with support from the National
** Institute of Justice, Office of Justice Programs, U.S. Department of Justice.
**
** TASK
** Copyright (c) 2002 @stake Inc.  All rights reserved
**
** Copyright (c) 1997,1998,1999, International Business Machines
** Corporation and others. All Rights Reserved.
*/

/** \file tsk_fs.h
* External header file for file system support.
* Note that this file is not meant to be directly included.
* It is included by both libtsk.h and tsk_fs_i.h.
*/

/* LICENSE
* .ad
* .fi
*	This software is distributed under the IBM Public License.
* AUTHOR(S)
*	Wietse Venema
*	IBM T.J. Watson Research
*	P.O. Box 704
*	Yorktown Heights, NY 10598, USA
--*/

/**
* \defgroup fslib C File System Functions
* \defgroup fslib_cpp C++ File System Classes
 */

#ifndef _TSK_FS_H
#define _TSK_FS_H

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

    typedef struct TSK_FS_INFO TSK_FS_INFO;
    typedef struct TSK_FS_FILE TSK_FS_FILE;
    typedef struct _TSK_POOL_INFO TSK_POOL_INFO;




    /**************** BLOCK Structure *******************/

    /** \name Generic File System Block Data Structure */
    //@{

    /** Flags that are used in TSK_FS_BLOCK and in callback of file_walk.
    * Note that some of these are dependent. A block can be either TSK_FS_BLOCK_FLAG_ALLOC
    * or TSK_FS_BLOCK_FLAG_UNALLOC.  It can be one of TSK_FS_BLOCK_FLAG_RAW, TSK_FS_BLOCK_FLAG_BAD,
    * TSK_FS_BLOCK_FLAG_RES, TSK_FS_BLOCK_FLAG_SPARSE, or TSK_FS_BLOCK_FLAG_COMP.  Note that some of
    * these are set only by file_walk because they are file-level details, such as compression and sparse.
    */
    enum TSK_FS_BLOCK_FLAG_ENUM {
        TSK_FS_BLOCK_FLAG_UNUSED = 0x0000,      ///< Used to show that TSK_FS_BLOCK structure has no data in it
        TSK_FS_BLOCK_FLAG_ALLOC = 0x0001,       ///< Block is allocated (and not TSK_FS_BLOCK_FLAG_UNALLOC)
        TSK_FS_BLOCK_FLAG_UNALLOC = 0x0002,     ///< Block is unallocated (and not TSK_FS_BLOCK_FLAG_ALLOC)
        TSK_FS_BLOCK_FLAG_CONT = 0x0004,        ///< Block (could) contain file content (and not TSK_FS_BLOCK_FLAG_META)
        TSK_FS_BLOCK_FLAG_META = 0x0008,        ///< Block (could) contain file system metadata (and not TSK_FS_BLOCK_FLAG_CONT)
        TSK_FS_BLOCK_FLAG_BAD = 0x0010, ///< Block has been marked as bad by the file system
        TSK_FS_BLOCK_FLAG_RAW = 0x0020, ///< The data has been read raw from the disk (and not COMP or SPARSE)
        TSK_FS_BLOCK_FLAG_SPARSE = 0x0040,      ///< The data passed in the file_walk callback was stored as sparse (all zeros) (and not RAW or COMP)
        TSK_FS_BLOCK_FLAG_COMP = 0x0080,        ///< The data passed in the file_walk callback was stored in a compressed form (and not RAW or SPARSE)
        TSK_FS_BLOCK_FLAG_RES = 0x0100, ///< The data passed in the file_walk callback is from an NTFS resident file
        TSK_FS_BLOCK_FLAG_AONLY = 0x0200        /// < The buffer in TSK_FS_BLOCK has no content (it could be non-empty, but should be ignored), but the flags and such are accurate
    };
    typedef enum TSK_FS_BLOCK_FLAG_ENUM TSK_FS_BLOCK_FLAG_ENUM;


    /**
    * Flags that are used to specify which blocks to call the tsk_fs_block_walk() callback function with.
    */
    enum TSK_FS_BLOCK_WALK_FLAG_ENUM {
        TSK_FS_BLOCK_WALK_FLAG_NONE = 0x00,     ///< No Flags
        TSK_FS_BLOCK_WALK_FLAG_ALLOC = 0x01,    ///< Allocated blocks
        TSK_FS_BLOCK_WALK_FLAG_UNALLOC = 0x02,  ///< Unallocated blocks
        TSK_FS_BLOCK_WALK_FLAG_CONT = 0x04,     ///< Blocks that could store file content
        TSK_FS_BLOCK_WALK_FLAG_META = 0x08,     ///< Blocks that could store file system metadata
        TSK_FS_BLOCK_WALK_FLAG_AONLY = 0x10     ///< Do not include content in callback only address and allocation status
    };
    typedef enum TSK_FS_BLOCK_WALK_FLAG_ENUM TSK_FS_BLOCK_WALK_FLAG_ENUM;


#define TSK_FS_BLOCK_TAG 0x1b7c3f4a
    /**
    * Generic data structure to hold block data with metadata
    */
    typedef struct {
        int tag;                ///< \internal Will be set to TSK_FS_BLOCK_TAG if structure is valid / allocated
        TSK_FS_INFO *fs_info;   ///< Pointer to file system that block is from
        char *buf;              ///< Buffer with block data (of size TSK_FS_INFO::block_size)
        TSK_DADDR_T addr;       ///< Address of block
        TSK_FS_BLOCK_FLAG_ENUM flags;   /// < Flags for block (alloc or unalloc)
    } TSK_FS_BLOCK;


    /**
    * Function definition used for callback to tsk_fs_block_walk().
    *
    * @param a_block Pointer to block structure that holds block content and flags
    * @param a_ptr Pointer that was supplied by the caller who called tsk_fs_block_walk
    * @returns Value to identify if walk should continue, stop, or stop because of error
    */
    typedef TSK_WALK_RET_ENUM(*TSK_FS_BLOCK_WALK_CB) (const TSK_FS_BLOCK *
        a_block, void *a_ptr);


    // external block-level functions
    extern void tsk_fs_block_free(TSK_FS_BLOCK * a_fs_block);
    extern TSK_FS_BLOCK *tsk_fs_block_get(TSK_FS_INFO * fs,
        TSK_FS_BLOCK * fs_block, TSK_DADDR_T addr);
    extern TSK_FS_BLOCK *tsk_fs_block_get_flag(TSK_FS_INFO * a_fs,
        TSK_FS_BLOCK * a_fs_block, TSK_DADDR_T a_addr,
        TSK_FS_BLOCK_FLAG_ENUM a_flags);
    extern uint8_t tsk_fs_block_walk(TSK_FS_INFO * a_fs,
        TSK_DADDR_T a_start_blk, TSK_DADDR_T a_end_blk,
        TSK_FS_BLOCK_WALK_FLAG_ENUM a_flags, TSK_FS_BLOCK_WALK_CB a_action,
        void *a_ptr);

    //@}

    /**************** DATA and DATA_LIST Structures ************/

    /** \name Generic File System File Content Data Structures */
    //@{

    /* The location of "most" file content is stored in the generic TSK
     * data structures as runs (starting address and length).
     */

    /**
    * Flags used for a TSK_FS_ATTR_RUN entry.
    */
    typedef enum {
        TSK_FS_ATTR_RUN_FLAG_NONE = 0x00,       ///< No Flag
        TSK_FS_ATTR_RUN_FLAG_FILLER = 0x01,     ///< Entry is a filler for a run that has not been seen yet in the processing (or has been lost)
        TSK_FS_ATTR_RUN_FLAG_SPARSE = 0x02,     ///< Entry is a sparse run where all data in the run is zeros
        TSK_FS_ATTR_RUN_FLAG_ENCRYPTED = 0x04   ///< Entry is arun where the data is encrypted
    } TSK_FS_ATTR_RUN_FLAG_ENUM;


    typedef struct TSK_FS_ATTR_RUN TSK_FS_ATTR_RUN;

    /**
    * Holds information about a single data run, which has a starting address and length.
    * A run describes a consecutive list of blocks that have been allocated to a file.
    * A file may have many such runs and they are stringed together in a linked list.
    * The entries in the list must be stored in sequential order (based on offset in file).
    */
    struct TSK_FS_ATTR_RUN {
        TSK_FS_ATTR_RUN *next;  ///< Pointer to the next run in the attribute (or NULL)
        TSK_DADDR_T offset;     ///< Offset (in blocks) of this run in the file
        TSK_DADDR_T addr;       ///< Starting block address (in file system) of run
        TSK_DADDR_T len;        ///< Number of blocks in run (0 when entry is not in use)
        TSK_DADDR_T crypto_id;  ///< Starting block number used for XTS encryption IV
        TSK_FS_ATTR_RUN_FLAG_ENUM flags;        ///< Flags for run
    };

    extern void tsk_fs_attr_run_free(TSK_FS_ATTR_RUN *);

    /**
    * Flags used for the TSK_FS_ATTR structure, which is used to
    * store file content metadata.
    */
    typedef enum {
        TSK_FS_ATTR_FLAG_NONE = 0x00,   ///< No Flag
        TSK_FS_ATTR_INUSE = 0x01,       ///< data structure is in use
        TSK_FS_ATTR_NONRES = 0x02,      ///< Contains non-resident data (i.e. located in blocks)
        TSK_FS_ATTR_RES = 0x04, ///< Contains resident data (i.e. in a small buffer)
        TSK_FS_ATTR_ENC = 0x10, ///< Contains encrypted data
        TSK_FS_ATTR_COMP = 0x20,        ///< Contains compressed data
        TSK_FS_ATTR_SPARSE = 0x40,      ///< Contains sparse data
        TSK_FS_ATTR_RECOVERY = 0x80,    ///< Data was determined in file recovery mode
    } TSK_FS_ATTR_FLAG_ENUM;

    /**
    * File walk callback function definition.  This is called for
    * chunks of content in the file being processed.
    * @param a_fs_file Pointer to file being processed
    * @param a_off Byte offset in file that this data is for
    * @param a_addr Address of data being passed (valid only if a_flags have RAW set)
    * @param a_buf Pointer to buffer with file content
    * @param a_len Size of data in buffer (in bytes)
    * @param a_flags Flags about the file content
    * @param a_ptr Pointer that was specified by caller to inode_walk
    * @returns Value that tells file walk to continue or stop
    */
    typedef TSK_WALK_RET_ENUM(*TSK_FS_FILE_WALK_CB) (TSK_FS_FILE *
        a_fs_file, TSK_OFF_T a_off, TSK_DADDR_T a_addr, char *a_buf,
        size_t a_len, TSK_FS_BLOCK_FLAG_ENUM a_flags, void *a_ptr);

    /**
    * Flags used by tsk_fs_file_walk to determine when the callback function should
    * be used. */
    typedef enum {
        TSK_FS_FILE_WALK_FLAG_NONE = 0x00,      ///< No Flag
        TSK_FS_FILE_WALK_FLAG_SLACK = 0x01,     ///< Include the file's slack space in the callback.
        TSK_FS_FILE_WALK_FLAG_NOID = 0x02,      ///< Ignore the Id argument given in the API (use only the type)
        TSK_FS_FILE_WALK_FLAG_AONLY = 0x04,     ///< Provide callback with only addresses and no file content.
        TSK_FS_FILE_WALK_FLAG_NOSPARSE = 0x08,  ///< Do not include sparse blocks in the callback.
    } TSK_FS_FILE_WALK_FLAG_ENUM;


    /**
    * These are based on the NTFS type values.
    * Added types for HFS+.
    * NOTE: Update bindings/java/src/org/sleuthkit/datamodel/TskData.java
    * with any changes.
    */
    typedef enum {
        TSK_FS_ATTR_TYPE_NOT_FOUND = 0x00,      // 0
        TSK_FS_ATTR_TYPE_DEFAULT = 0x01,        // 1
        TSK_FS_ATTR_TYPE_NTFS_SI = 0x10,        // 16
        TSK_FS_ATTR_TYPE_NTFS_ATTRLIST = 0x20,  // 32
        TSK_FS_ATTR_TYPE_NTFS_FNAME = 0x30,     // 48
        TSK_FS_ATTR_TYPE_NTFS_VVER = 0x40,      // 64 (NT)
        TSK_FS_ATTR_TYPE_NTFS_OBJID = 0x40,     // 64 (2K)
        TSK_FS_ATTR_TYPE_NTFS_SEC = 0x50,       // 80
        TSK_FS_ATTR_TYPE_NTFS_VNAME = 0x60,     // 96
        TSK_FS_ATTR_TYPE_NTFS_VINFO = 0x70,     // 112
        TSK_FS_ATTR_TYPE_NTFS_DATA = 0x80,      // 128
        TSK_FS_ATTR_TYPE_NTFS_IDXROOT = 0x90,   // 144
        TSK_FS_ATTR_TYPE_NTFS_IDXALLOC = 0xA0,  // 160
        TSK_FS_ATTR_TYPE_NTFS_BITMAP = 0xB0,    // 176
        TSK_FS_ATTR_TYPE_NTFS_SYMLNK = 0xC0,    // 192 (NT)
        TSK_FS_ATTR_TYPE_NTFS_REPARSE = 0xC0,   // 192 (2K)
        TSK_FS_ATTR_TYPE_NTFS_EAINFO = 0xD0,    // 208
        TSK_FS_ATTR_TYPE_NTFS_EA = 0xE0,        // 224
        TSK_FS_ATTR_TYPE_NTFS_PROP = 0xF0,      //  (NT)
        TSK_FS_ATTR_TYPE_NTFS_LOG = 0x100,      //  (2K)
        TSK_FS_ATTR_TYPE_UNIX_INDIR = 0x1001,   //  Indirect blocks for UFS and ExtX file systems
        TSK_FS_ATTR_TYPE_UNIX_EXTENT = 0x1002,  //  Extents for Ext4 file system

        // Types for HFS+ File Attributes
        TSK_FS_ATTR_TYPE_HFS_DEFAULT = 0x01,    // 1    Data fork of fs special files and misc
        TSK_FS_ATTR_TYPE_HFS_DATA = 0x1100,     // 4352 Data fork of regular files
        TSK_FS_ATTR_TYPE_HFS_RSRC = 0x1101,     // 4353 Resource fork of regular files
        TSK_FS_ATTR_TYPE_HFS_EXT_ATTR = 0x1102, // 4354 Extended Attributes, except compression records
        TSK_FS_ATTR_TYPE_HFS_COMP_REC = 0x1103, // 4355 Compression records

        // Types for APFS File Attributes (alias to HFS+)
        TSK_FS_ATTR_TYPE_APFS_DATA = TSK_FS_ATTR_TYPE_HFS_DATA,
        TSK_FS_ATTR_TYPE_APFS_RSRC = TSK_FS_ATTR_TYPE_HFS_RSRC,
        TSK_FS_ATTR_TYPE_APFS_EXT_ATTR = TSK_FS_ATTR_TYPE_HFS_EXT_ATTR,
        TSK_FS_ATTR_TYPE_APFS_COMP_REC = TSK_FS_ATTR_TYPE_HFS_COMP_REC,
    } TSK_FS_ATTR_TYPE_ENUM;

#define TSK_FS_ATTR_ID_DEFAULT  0       ///< Default Data ID used if file system does not assign one.

    typedef struct TSK_FS_ATTR TSK_FS_ATTR;
    /**
    * Holds information about the location of file content (or a file attribute). For most file systems, a file
    * has only a single attribute that stores the file content.
    * Other file systems, such as NTFS, have multiple
    * attributes.  If multiple attributes exist, they are stored in a linked list.
    * Attributes can be "resident", which means the data is stored
    * in a small buffer instead of being stored in a full file system block.
    * "Non-resident" attributes store data in blocks and they are stored in
    * the data structure as a series of runs.
    * This structure is used to represent both of these cases.
    *
    * The non-resident data has several size values.
    * \verbatim
    * |--------------------------------------------------------------------|
    * |skiplen|---------------allocsize------------------------------------|
    * |skiplen|---------------size-----------------------------------|
    * |skiplen|---------------initsize------------|
    * \endverbatim
    */
    struct TSK_FS_ATTR {
        TSK_FS_ATTR *next;      ///< Pointer to next attribute in list
        TSK_FS_FILE *fs_file;   ///< Pointer to the file that this is from
        TSK_FS_ATTR_FLAG_ENUM flags;    ///< Flags for attribute
        char *name;             ///< Name of attribute (in UTF-8).  Will be NULL if attribute doesn't have a name.
        size_t name_size;       ///< Number of bytes allocated to name
        TSK_FS_ATTR_TYPE_ENUM type;     ///< Type of attribute
        uint16_t id;            ///< Id of attribute

        TSK_OFF_T size;         ///< Size in bytes of the attribute resident and non-resident content (does not include skiplen for non-resident attributes)

        /**
        * Data associated with a non-resident file / attribute.
        * The data is stored in one or more data runs.
        */
        struct {
            TSK_FS_ATTR_RUN *run;       ///< Linked list of runs for non-resident attributes
            TSK_FS_ATTR_RUN *run_end;   ///< Pointer to final run in the list
            uint32_t skiplen;   ///< Number of initial bytes in run to skip before content begins. The size field does not include this length.
            TSK_OFF_T allocsize;        ///< Number of bytes that are allocated in all clusters of non-resident run (will be larger than size - does not include skiplen).  This is defined when the attribute is created and used to determine slack space.
            TSK_OFF_T initsize; ///< Number of bytes (starting from offset 0) that have data (including FILLER) saved for them (smaller then or equal to size).  This is defined when the attribute is created.
            uint32_t compsize;  ///< Size of compression units (needed only if NTFS file is compressed)
        } nrd;

        /**
        * Data associated with a resident attribute / file.
        * The data is stored in a buffer.
        */
        struct {
            uint8_t *buf;       ///< Buffer for resident data
            size_t buf_size;    ///< Number of bytes allocated to buf
            TSK_OFF_T offset;   ///< Starting offset in bytes relative to start of file system (NOT YET IMPLEMENTED)
        } rd;

        /* Special file (compressed, encrypted, etc.) */
         ssize_t(*r) (const TSK_FS_ATTR * fs_attr,
            TSK_OFF_T a_offset, char *a_buf, size_t a_len);
         uint8_t(*w) (const TSK_FS_ATTR * fs_attr,
            int flags, TSK_FS_FILE_WALK_CB, void *);
    };


    /**
    * Structure used as the head of an attribute list.
    */
    typedef struct {
        TSK_FS_ATTR *head;
    } TSK_FS_ATTRLIST;

    extern uint8_t tsk_fs_attr_walk(const TSK_FS_ATTR * a_fs_attr,
        TSK_FS_FILE_WALK_FLAG_ENUM a_flags, TSK_FS_FILE_WALK_CB a_action,
        void *a_ptr);

    //@}


    /**************** META_NAME_LIST Structure *******************/

    /** \name Generic File System File Metadata Data Structures */
    //@{

    /**
    * Size of name array in TSK_FS_META_NAME_LIST structure
    */
#define TSK_FS_META_NAME_LIST_NSIZE    512


    typedef struct TSK_FS_META_NAME_LIST TSK_FS_META_NAME_LIST;
    /**
    * Relatively generic structure to hold file names that are stored with
    * the file metadata.  Note that this is different from the
    * file name stored in the directory heirarchy, which is
    * part of the tsk_fs_name_... code.  This is currently
    * used for NTFS and FAT file systems only.
    */
    struct TSK_FS_META_NAME_LIST {
        TSK_FS_META_NAME_LIST *next;    ///< Pointer to next name (or NULL)
        char name[TSK_FS_META_NAME_LIST_NSIZE]; ///< Name in UTF-8 (does not include parent directory name)
        TSK_INUM_T par_inode;   ///< Inode address of parent directory (NTFS only)
        uint32_t par_seq;       ///< Sequence number of parent directory (NTFS only)
    };



    /****************** META Structure ***************/

    /**
    * Metadata flags used in TSK_FS_META.flags and in request to inode_walk
    */
    enum TSK_FS_META_FLAG_ENUM {
        TSK_FS_META_FLAG_ALLOC = 0x01,   ///< Metadata structure is currently in an allocated state
        TSK_FS_META_FLAG_UNALLOC = 0x02, ///< Metadata structure is currently in an unallocated state
        TSK_FS_META_FLAG_USED = 0x04,    ///< Metadata structure has been allocated at least once
        TSK_FS_META_FLAG_UNUSED = 0x08,  ///< Metadata structure has never been allocated.
        TSK_FS_META_FLAG_COMP = 0x10,    ///< The file contents are compressed.
        TSK_FS_META_FLAG_ORPHAN = 0x20,  ///< Return only metadata structures that have no file name pointing to the (inode_walk flag only)
    };
    typedef enum TSK_FS_META_FLAG_ENUM TSK_FS_META_FLAG_ENUM;

    enum TSK_FS_META_ATTR_FLAG_ENUM {
        TSK_FS_META_ATTR_EMPTY,   ///< The data in the attributes (if any) is not for this file
        TSK_FS_META_ATTR_STUDIED, ///< The data in the attributes are for this file
        TSK_FS_META_ATTR_ERROR,   ///< The attributes for this file could not be loaded
    };
    typedef enum TSK_FS_META_ATTR_FLAG_ENUM TSK_FS_META_ATTR_FLAG_ENUM;


    /**
    * Values for the mode field -- which identifies the file type
    * and permissions.
    */
    enum TSK_FS_META_TYPE_ENUM {
        TSK_FS_META_TYPE_UNDEF = 0x00,
        TSK_FS_META_TYPE_REG = 0x01,    ///< Regular file
        TSK_FS_META_TYPE_DIR = 0x02,    ///< Directory file
        TSK_FS_META_TYPE_FIFO = 0x03,   ///< Named pipe (fifo)
        TSK_FS_META_TYPE_CHR = 0x04,    ///< Character device
        TSK_FS_META_TYPE_BLK = 0x05,    ///< Block device
        TSK_FS_META_TYPE_LNK = 0x06,    ///< Symbolic link
        TSK_FS_META_TYPE_SHAD = 0x07,   ///< SOLARIS ONLY
        TSK_FS_META_TYPE_SOCK = 0x08,   ///< UNIX domain socket
        TSK_FS_META_TYPE_WHT = 0x09,    ///< Whiteout
        TSK_FS_META_TYPE_VIRT = 0x0a,   ///< "Virtual File" created by TSK for file system areas
        TSK_FS_META_TYPE_VIRT_DIR = 0x0b,   ///< "Virtual Directory" created by TSK to hold data like orphan files
    };
    typedef enum TSK_FS_META_TYPE_ENUM TSK_FS_META_TYPE_ENUM;

#define TSK_FS_META_TYPE_STR_MAX 0x0c   ///< Number of file types in shortname array
    extern char tsk_fs_meta_type_str[TSK_FS_META_TYPE_STR_MAX][2];

#define TSK_FS_IS_DIR_META(x) ((x == TSK_FS_META_TYPE_DIR) || (x == TSK_FS_META_TYPE_VIRT_DIR))

    enum TSK_FS_META_MODE_ENUM {
        /* The following describe the file permissions */
        TSK_FS_META_MODE_UNSPECIFIED = 0000000,       ///< unspecified

        TSK_FS_META_MODE_ISUID = 0004000,       ///< set user id on execution
        TSK_FS_META_MODE_ISGID = 0002000,       ///< set group id on execution
        TSK_FS_META_MODE_ISVTX = 0001000,       ///< sticky bit

        TSK_FS_META_MODE_IRUSR = 0000400,       ///< R for owner
        TSK_FS_META_MODE_IWUSR = 0000200,       ///< W for owner
        TSK_FS_META_MODE_IXUSR = 0000100,       ///< X for owner

        TSK_FS_META_MODE_IRGRP = 0000040,       ///< R for group
        TSK_FS_META_MODE_IWGRP = 0000020,       ///< W for group
        TSK_FS_META_MODE_IXGRP = 0000010,       ///< X for group

        TSK_FS_META_MODE_IROTH = 0000004,       ///< R for other
        TSK_FS_META_MODE_IWOTH = 0000002,       ///< W for other
        TSK_FS_META_MODE_IXOTH = 0000001        ///< X for other
    };
    typedef enum TSK_FS_META_MODE_ENUM TSK_FS_META_MODE_ENUM;

    typedef enum TSK_FS_META_CONTENT_TYPE_ENUM {
        TSK_FS_META_CONTENT_TYPE_DEFAULT = 0x0,
        TSK_FS_META_CONTENT_TYPE_EXT4_EXTENTS = 0x1,     ///< Ext4 with extents instead of individual pointers
        TSK_FS_META_CONTENT_TYPE_EXT4_INLINE = 0x02      ///< Ext4 with inline data
    } TSK_FS_META_CONTENT_TYPE_ENUM;


#define TSK_FS_META_TAG 0x13524635
    /**
    * TSK data structure to store general file and directory metadata.
    * Note that the file in the file
    * system may have more metadata than is stored here.
    * For performance reasons, the run list of the file content is not always known
    * when the file is loaded.  It may be loaded only when needed by the internal code.
    * The TSK_FS_META::content_ptr pointer contains file system-specific data that will be
    * used to determine the full run. After it has been loaded, the TSK_FS_META::attr field
    * will contain that info.
    */
    typedef struct {
        int tag;                ///< \internal Will be set to TSK_FS_META_TAG if structure is allocated

        TSK_FS_META_FLAG_ENUM flags;    ///< Flags for this file for its allocation status etc.
        TSK_INUM_T addr;        ///< Address of the meta data structure for this file

        TSK_FS_META_TYPE_ENUM type;     ///< File type
        TSK_FS_META_MODE_ENUM mode;     ///< Unix-style permissions
        int nlink;              ///< link count (number of file names pointing to this)
        TSK_OFF_T size;         ///< file size (in bytes)
        TSK_UID_T uid;          ///< owner id
        TSK_GID_T gid;          ///< group id

        /* @@@ Need to make these 64-bits ... ? */
        time_t mtime;           ///< last file content modification time (stored in number of seconds since Jan 1, 1970 UTC)
        uint32_t mtime_nano;    ///< nano-second resolution in addition to m_time
        time_t atime;           ///< last file content accessed time (stored in number of seconds since Jan 1, 1970 UTC)
        uint32_t atime_nano;    ///< nano-second resolution in addition to a_time
        time_t ctime;           ///< last file / metadata status change time (stored in number of seconds since Jan 1, 1970 UTC)
        uint32_t ctime_nano;    ///< nano-second resolution in addition to c_time
        time_t crtime;          ///< Created time (stored in number of seconds since Jan 1, 1970 UTC)
        uint32_t crtime_nano;   ///< nano-second resolution in addition to cr_time

        /* filesystem specific times */
        union {
            struct {
                time_t dtime;   ///< Linux deletion time
                uint32_t dtime_nano;    ///< nano-second resolution in addition to d_time
            } ext2;
            struct {
                time_t bkup_time;       ///< HFS+ backup time
                uint32_t bkup_time_nano;        ///< nano-second resolution in addition to bkup_time
            } hfs;
            struct {
                time_t fn_crtime;   ///< NTFS Created time stored in FILE_NAME
                time_t fn_crtime_nano;   ///< NTFS Created time stored in FILE_NAME in nano-second resolution
                time_t fn_mtime;   ///< NTFS mod (content) stored in FILE_NAME
                time_t fn_mtime_nano;   ///< NTFS mod time stored in FILE_NAME in nano-second resolution
                time_t fn_atime;   ///< NTFS access time stored in FILE_NAME
                time_t fn_atime_nano;   ///< NTFS access time stored in FILE_NAME in nano-second resolution
                time_t fn_ctime;   ///< NTFS change (MFT Entry) time stored in FILE_NAME
                time_t fn_ctime_nano;   ///< NTFS change (MFT Entry) time stored in FILE_NAME in nano-second resolution
                uint16_t fn_id; ///< Attribute ID used to populate FN times.
            } ntfs;
        } time2;

        void *content_ptr;      ///< Pointer to file system specific data that is used to store references to file content
        size_t content_len;     ///< size of content  buffer
        TSK_FS_META_CONTENT_TYPE_ENUM content_type;     ///< File system-specific and describes type of data in content_ptr in case file systems have multiple ways of storing things.
        void (*reset_content)(void *); ///< \internal Optional callback used for any internal cleanup needed before freeing content_ptr
        uint32_t seq;           ///< Sequence number for file (NTFS only, is incremented when entry is reallocated)

        /** Contains run data on the file content (specific locations where content is stored).
        * Check attr_state to determine if data in here is valid because not all file systems
        * load this data when a file is loaded.  It may not be loaded until needed by one
        * of the APIs. Most file systems will have only one attribute, but NTFS will have several. */
        TSK_FS_ATTRLIST *attr;
        TSK_FS_META_ATTR_FLAG_ENUM attr_state;  ///< State of the data in the TSK_FS_META::attr structure

        TSK_FS_META_NAME_LIST *name2;   ///< Name of file stored in metadata (FATXX and NTFS Only)
        char *link;             ///< Name of target file if this is a symbolic link
    } TSK_FS_META;



    /** String that is prepended to orphan FAT & NTFS files when the file
    * name is known, but the parent is not */
#define TSK_FS_ORPHAN_STR "-ORPHAN_FILE-"

    /* we are using the last inode as the special inode for the orphan directory.  Note that this
     * macro is defined to abstract this convention, but there are many places in the code where
     * there is implied logic about this convention. For example, inode_walks will stop before
     * this value so that special handling can occur. */
#define TSK_FS_ORPHANDIR_INUM(fs_info) \
    (fs_info->last_inum)


    /**
    * inode walk callback function definition.  This is called for every file
    * that meets the criteria specified when inode_walk was called.
    * @param a_fs_file Pointer to the current file
    * @param a_ptr Pointer that was specified by caller to inode_walk
    * @returns Value that tells inode walk to continue or stop
    */
    typedef TSK_WALK_RET_ENUM(*TSK_FS_META_WALK_CB) (TSK_FS_FILE *
        a_fs_file, void *a_ptr);


    extern uint8_t tsk_fs_meta_walk(TSK_FS_INFO * a_fs, TSK_INUM_T a_start,
        TSK_INUM_T a_end, TSK_FS_META_FLAG_ENUM a_flags,
        TSK_FS_META_WALK_CB a_cb, void *a_ptr);

    extern uint8_t tsk_fs_meta_make_ls(const TSK_FS_META * a_fs_meta,
        char *a_buf, size_t a_len);

    //@}

    /************* NAME / DIR structures **********/

    /** \name Generic File System File Name Data Structures */
    //@{

    /**
    * File name flags that are used when specifying the status of
    * a name in the TSK_FS_NAME structure
    */
    typedef enum {
        TSK_FS_NAME_FLAG_ALLOC = 0x01,  ///< Name is in an allocated state
        TSK_FS_NAME_FLAG_UNALLOC = 0x02,        ///< Name is in an unallocated state
    } TSK_FS_NAME_FLAG_ENUM;


    /**
    * File type values -- as specified in the directory entry structure.
    */
    typedef enum {
        TSK_FS_NAME_TYPE_UNDEF = 0,     ///< Unknown type
        TSK_FS_NAME_TYPE_FIFO = 1,      ///< Named pipe
        TSK_FS_NAME_TYPE_CHR = 2,       ///< Character device
        TSK_FS_NAME_TYPE_DIR = 3,       ///< Directory
        TSK_FS_NAME_TYPE_BLK = 4,       ///< Block device
        TSK_FS_NAME_TYPE_REG = 5,       ///< Regular file
        TSK_FS_NAME_TYPE_LNK = 6,       ///< Symbolic link
        TSK_FS_NAME_TYPE_SOCK = 7,      ///< Socket
        TSK_FS_NAME_TYPE_SHAD = 8,      ///< Shadow inode (solaris)
        TSK_FS_NAME_TYPE_WHT = 9,       ///< Whiteout (openbsd)
        TSK_FS_NAME_TYPE_VIRT = 10,     ///< Special (TSK added "Virtual" files)
        TSK_FS_NAME_TYPE_VIRT_DIR = 11, ///< Special (TSK added "Virtual" directories)
    } TSK_FS_NAME_TYPE_ENUM;

#define TSK_FS_NAME_TYPE_STR_MAX 12     ///< Number of types that have a short string name

    /* ascii representation of above types */
    extern char tsk_fs_name_type_str[TSK_FS_NAME_TYPE_STR_MAX][2];

#define TSK_FS_IS_DIR_NAME(x) \
    ((x == TSK_FS_NAME_TYPE_DIR) || (x == TSK_FS_NAME_TYPE_VIRT_DIR))

#define  TSK_FS_NAME_TAG 0x23147869
    /**
    * Generic structure to store the file name information that is stored in
    * a directory. Most file systems separate the file name from the metadata, but
    * some do not (such as FAT). This structure contains the name and address of the
    * metadata.
    */
    typedef struct {
        int tag;                ///< \internal Set to TSK_FS_NAME_ID if allocated, 0 if not

        char *name;             ///< The name of the file (in UTF-8)
        size_t name_size;       ///< The number of bytes allocated to name

        char *shrt_name;        ///< The short name of the file or null (in UTF-8)
        size_t shrt_name_size;  ///< The number of bytes allocated to shrt_name

        TSK_INUM_T meta_addr;   ///< Address of the metadata structure that the name points to.
        uint32_t meta_seq;      ///< Sequence number for metadata structure (NTFS only)
        TSK_INUM_T par_addr;    ///< Metadata address of parent directory (equal to meta_addr if this entry is for root directory).
        uint32_t par_seq;       ///< Sequence number for parent directory (NTFS only)
        uint64_t date_added;    ///< Time entry was added to a directory (APFS only)

        TSK_FS_NAME_TYPE_ENUM type;     ///< File type information (directory, file, etc.)
        TSK_FS_NAME_FLAG_ENUM flags;    ///< Flags that describe allocation status etc.
    } TSK_FS_NAME;


    /**
    * Definition of callback function that is used by tsk_fs_dir_walk().  This is
    * is called for each file in a directory.
    * @param a_fs_file Pointer to the current file in the directory
    * @param a_path Path of the file
    * @param a_ptr Pointer that was originally passed by caller to tsk_fs_dir_walk.
    * @returns Value to signal if tsk_fs_dir_walk should stop or continue.
    */
    typedef TSK_WALK_RET_ENUM(*TSK_FS_DIR_WALK_CB) (TSK_FS_FILE *
        a_fs_file, const char *a_path, void *a_ptr);


#define TSK_FS_DIR_TAG  0x57531246
    /**
    * A handle to a directory so that its files can be individually accessed.
    */
    typedef struct {
        int tag;                ///< \internal Will be set to TSK_FS_DIR_TAG if structure is still allocated, 0 if not

        TSK_FS_FILE *fs_file;   ///< Pointer to the file structure for the directory.

        TSK_FS_NAME *names;     ///< Pointer to list of names in directory.
        size_t names_used;      ///< Number of name structures in queue being used
        size_t names_alloc;     ///< Number of name structures that were allocated

        TSK_INUM_T addr;        ///< Metadata address of this directory
        uint32_t seq;           ///< Metadata address sequence (NTFS Only)

        TSK_FS_INFO *fs_info;   ///< Pointer to file system the directory is located in
    } TSK_FS_DIR;

    /**
    * Flags that are used when walking names in directories.  These are used to identify
    * which files to call the callback function on.
    */
    typedef enum {
        TSK_FS_DIR_WALK_FLAG_NONE = 0x00,       ///< No Flags
        TSK_FS_DIR_WALK_FLAG_ALLOC = 0x01,      ///< Return allocated names in callback
        TSK_FS_DIR_WALK_FLAG_UNALLOC = 0…12879 tokens truncated…integer form.
    * See tsk_fs_parse_inum() for details
    * @param [in] a_str Input string to parse
    * @param [out] a_inum Pointer to location where inode can be stored.
    * @param [out] a_type Pointer to location where type can be stored (or NULL)
    * @param [out] a_type_used Pointer to location where the value can be set
    * to 1 if the type was set (to differentiate between meanings of 0) (or NULL).
    * @param [out] a_id Pointer to location where id can be stored (or NULL)
    * @param [out] a_id_used Pointer to location where the value can be set
    * to 1 if the id was set (to differentiate between meanings of 0) (or NULL).
    *
    * @return 1 on error or if not an inode and 0 on success
    */
    static int parseINum(const TSK_TCHAR * a_str, TSK_INUM_T * a_inum,
        TSK_FS_ATTR_TYPE_ENUM * a_type, uint8_t * a_type_used,
        uint16_t * a_id, uint8_t * a_id_used) {
        return tsk_fs_parse_inum(a_str, a_inum, a_type, a_type_used, a_id,
            a_id_used);
    };

    /**
        * return byte offset in image that fs starts
    * @return offset in bytes.
    */
    TSK_OFF_T getOffset() const {
        if (m_fsInfo != NULL)
            return m_fsInfo->offset;
        else
            return 0;
    };

    /**
        * return number of metadata addresses in FS
    * @return number of metatdata addresses
    */
    TSK_INUM_T getINumCount() const {
        if (m_fsInfo != NULL)
            return m_fsInfo->inum_count;
        else
            return 0;
    };

    /**
        * return metadata address of root directory
    * @return metadata address of root directory
    */
    TSK_INUM_T getRootINum() const {
        if (m_fsInfo != NULL)
            return m_fsInfo->root_inum;
        else
            return 0;
    };
    /**
        * return first valid metadata address
    * @return first valid metadata address
    */
    TSK_INUM_T getFirstINum() const {
        if (m_fsInfo != NULL)
            return m_fsInfo->first_inum;
        else
            return 0;
    };
    /**
        * return last valid metadata address
    * @return last valid metadata address
    */
    TSK_INUM_T getLastINum() const {
        if (m_fsInfo != NULL)
            return m_fsInfo->last_inum;
        else
            return 0;
    };
    /**
        * return address of journal inode
    * @return address of journal inode
    */
    TSK_INUM_T getJournalINum() const {
        if (m_fsInfo != NULL)
            return m_fsInfo->journ_inum;
        else
            return 0;
    };

    /**
        * return number of blocks in fs
    * @return number of blocks in fs
    */
    TSK_DADDR_T getBlockCount() const {
        if (m_fsInfo != NULL)
            return m_fsInfo->block_count;
        else
            return 0;
    };
    /**
        * return address of first block
    * @return address of first block
    */
    TSK_DADDR_T getFirstBlock() const {
        if (m_fsInfo != NULL)
            return m_fsInfo->first_block;
        else
            return 0;
    };
    /**
        * return address of last block as reported by file system
    * (it is equal to the last block in the image or volume (if image is not complete)
    * @return address of last block
    */
    TSK_DADDR_T getLastBlockAct() const {
        if (m_fsInfo != NULL)
            return m_fsInfo->last_block_act;
        else
            return 0;
    };
    /**
        * return address of last block that is adjusted so that
    * (could be larger than last_block in image if end of image does not exist)
    * @return address of last block
    */
    TSK_DADDR_T getLastBlock() const {
        if (m_fsInfo != NULL)
            return m_fsInfo->last_block;
        else
            return 0;
    };
    /**
        * return size of each file system block (in bytes)
    * @return size of each block
    */
    unsigned int getBlockSize() const {
        if (m_fsInfo != NULL)
            return m_fsInfo->block_size;
        else
            return 0;
    };
    /**
        * return size of device block (typically always 512)
    * @return size of device block
    */
    unsigned int getDeviceSize() const {
        if (m_fsInfo != NULL)
            return m_fsInfo->dev_bsize;
        else
            return 0;
    };

    /**
        * return type of file system
    * @return type of file system
    */
    TSK_FS_TYPE_ENUM getFsType() const {
        if (m_fsInfo != NULL)
            return m_fsInfo->ftype;
        else
            return (TSK_FS_TYPE_ENUM) 0;
    };
    /**
        * return the "name" of data unit type  as a string ("Cluster", for example)
    * @return string "name" of data unit type
    */
    const char *getDataUnitName() const {
        if (m_fsInfo != NULL)
            return m_fsInfo->duname;
        else
            return NULL;
    };

    /**
        * return flags for file system
    * @return flags for file system
    */
    TSK_FS_INFO_FLAG_ENUM getFlags() const {
        if (m_fsInfo != NULL)
            return m_fsInfo->flags;
        else
            return (TSK_FS_INFO_FLAG_ENUM)0;
    };
    /**
        * return file system id (as reported in boot sector).  Use getFsIdLen() to determine how many byts in buffer are used.
    * @return Buffer with file system id
    */
    const uint8_t *getFsId() const {
        if (m_fsInfo != NULL)
            return m_fsInfo->fs_id;
        else
            return 0;
    };

    /**
        * return the number of bytes used in the buffer returned by getFsId().
    * @return number of bytes used.
    */
    size_t getFsIdLen() const {
        if (m_fsInfo == NULL)
            return 0;

        return m_fsInfo->fs_id_used;
    };

    /**
      * Close an open file system. See tsk_fs_close() for details.
     */
    void close() {
        tsk_fs_close(m_fsInfo);
    };


  private:
    const TSK_IMG_INFO *getTskImgInfo() const {
        if (m_fsInfo != NULL)
            return m_fsInfo->img_info;
        else
            return NULL;
}};                             //TskFsInfo



/**
* \ingroup fslib_cpp
* Stores information about a file system block.  Must be created by either
* allocating an empty block and opening one or by passing in a TSK_FS_BLOCK struct.
* If NULL is passed to the constructor and open() is not called, the other methods
* return undefined data. See TSK_FS_BLOCK for more details.
*/
class TskFsBlock {
  private:
    TSK_FS_BLOCK * m_fsBlock;
    bool m_opened;              // true if open() was called and we need to free it

     TskFsBlock(const TskFsBlock & rhs);
     TskFsBlock & operator=(const TskFsBlock & rhs);

  public:
    /**
    * construct a TskFsBlock using a TSK_FS_BLOCK structure
    * @param a_fsBlock a pointer of TSK_FS_BLOCK.  If NULL, the getX() methods return undefined data.
    */
     TskFsBlock(const TSK_FS_BLOCK * a_fsBlock) {
        m_fsBlock = const_cast < TSK_FS_BLOCK * >(a_fsBlock);
        m_opened = false;
    };

    /**
    * default constructor to construct a TskFsBlock.  Must call open() before using other methods.
    */
    TskFsBlock() {
        m_fsBlock = NULL;
    };

    /**
        * Free the memory associated with the TSK_FS_BLOCK structure.
    * See tsk_fs_block_free() for details
    */
    ~TskFsBlock() {
        if (m_opened)
            tsk_fs_block_free(m_fsBlock);
        m_fsBlock = NULL;
    };

    /**
        * Open a block (use only if created with default constructor).
    *
    * @param a_fs The file system to read the block from.
    * @param a_addr The file system address to read.
    * @return 1 on error and 0 on success.
    */
    uint8_t open(TskFsInfo * a_fs, TSK_DADDR_T a_addr) {
        if (m_fsBlock)
            return 1;

        if ((m_fsBlock =
                tsk_fs_block_get(a_fs->m_fsInfo, m_fsBlock,
                    a_addr)) != NULL) {
            m_opened = true;
            return 0;
        }
        else {
            return 1;
        }
    };

    /**
        * Get buffer with block data (of size TSK_FS_INFO::block_size)
    *
    * @return buffer with block data
    */
    const char *getBuf() const {
        if (m_fsBlock != NULL)
            return m_fsBlock->buf;
        else
            return NULL;
    };

    /**
        * Get address of block
    * @return address of block
    */
    TSK_DADDR_T getAddr() const {
        if (m_fsBlock != NULL)
            return m_fsBlock->addr;
        else
            return 0;
    };

    /**
        * Get flags for block (alloc or unalloc)
    * @return flags for block
    */
    TSK_FS_BLOCK_FLAG_ENUM getFlags() const {
        if (m_fsBlock != NULL)
            return m_fsBlock->flags;
        else
            return (TSK_FS_BLOCK_FLAG_ENUM) 0;
    };

  private:
    /**
        * Get pointer to file system that block is from
    * @return pointer to file system that block is from
    */
    const TSK_FS_INFO *getFsInfo() const {
        if (m_fsBlock != NULL)
            return m_fsBlock->fs_info;
        else
            return NULL;
    };
};



/**
 * \ingroup fslib_cpp
 * Stores information about names that are located in metadata structures.  See
 * TSK_FS_META_NAME for more details.
 */
class TskFsMetaName {
  private:
    TSK_FS_META_NAME_LIST * m_fsMetaNameList;
    TskFsMetaName(const TskFsMetaName & rhs);
    TskFsMetaName & operator=(const TskFsMetaName & rhs);

  public:
    /**
     * Allocates an object based on a C struct.
     * @param a_fsMetaNameList C struct of name list. If NULL, get() methods return undefined values.
     */
     TskFsMetaName(TSK_FS_META_NAME_LIST * a_fsMetaNameList) {
        m_fsMetaNameList = a_fsMetaNameList;
    };

    /**
     * Get the text name in UTF-8 (does not include parent directory name).
     * @returns name of file.
     */
    const char *getName() const {
        if (m_fsMetaNameList != NULL)
            return m_fsMetaNameList->name;
        else
            return NULL;
    };

    /**
     * Get the parent inode (NTFS Only)
     * @return Address of parent directory.
     */
    TSK_INUM_T getParInode() const {
        if (m_fsMetaNameList != NULL)
            return m_fsMetaNameList->par_inode;
        else
            return 0;
    };

    /**
     * get the parent sequence (NTFS Only)
     * @return Sequence of parent directory.
     */
    uint32_t getParSeq() const {
        return m_fsMetaNameList->par_seq;
    };
};

/**
 * \ingroup fslib_cpp
 * Stores metadata about a file. See TSK_FS_META for more details.
 */
class TskFsMeta {
  private:
    TSK_FS_META * m_fsMeta;
    TskFsMeta(const TskFsMeta & rhs);
    TskFsMeta & operator=(const TskFsMeta & rhs);

  public:
    /**
          * construct a TskFsMeta object.  If NULL is passed as an argument, the getX() behavior
     * is not defined.
     * @param a_fsMeta a pointer of TSK_FS_META
     */
     TskFsMeta(TSK_FS_META * a_fsMeta) {
        m_fsMeta = a_fsMeta;
#if 0
        if (m_fsMeta != NULL) {
            m_nameList = m_fsMeta->name2;
            size_t numOfList = 0;
            TSK_FS_META_NAME_LIST *nameList = m_nameList;
            while (nameList != NULL) {
                nameList = nameList->next;
                numOfList += 1;
            } m_nameListLen = numOfList;
        }
        else {
            m_nameList = NULL;
            m_nameListLen = 0;
        }
#endif
    };

    ~TskFsMeta() {
    };

    /**
          * Makes the "ls -l" permissions string for a file.
     * See tsk_fs_meta_make_ls() for details
     * @param a_buf [out] Buffer to write results to (must be 12 bytes or longer)
     * @param a_len Length of buffer
     */
    uint8_t getLs(char *a_buf, size_t a_len) const {
        if (m_fsMeta != NULL)
            return tsk_fs_meta_make_ls(m_fsMeta, a_buf, a_len);
        else
            return 0;
    };
    /**
          * get flags for this file for its allocation status etc.
     * @return flags for this file
     */
    TSK_FS_META_FLAG_ENUM getFlags() const {
        if (m_fsMeta != NULL)
            return m_fsMeta->flags;
        else
            return (TSK_FS_META_FLAG_ENUM) 0;
    }
    /**
          * get address of the meta data structure for this file
     * @return address of the meta data structure for this file
     */ TSK_INUM_T getAddr() const {
        if (m_fsMeta != NULL)
            return m_fsMeta->addr;
        else
            return 0;
    };
    /**
          * get file type
     * @return file type
     */
    TSK_FS_META_TYPE_ENUM getType() const {
        if (m_fsMeta != NULL)
            return m_fsMeta->type;
        else
            return (TSK_FS_META_TYPE_ENUM) 0;
    };
    /**
          * get Unix-style permissions
     * @return Unix-style permissions mode
     */
    TSK_FS_META_MODE_ENUM getMode() const {
        if (m_fsMeta != NULL)
            return m_fsMeta->mode;
        else
            return (TSK_FS_META_MODE_ENUM) 0;
    };
    /**
          * get link count (number of file names pointing to this)
     * @return link count
     */
    int getNLink() const {
        if (m_fsMeta != NULL)
            return m_fsMeta->nlink;
        else
            return 0;
    };
    /**
          * get file size (in bytes)
     * @return file size
     */
    TSK_OFF_T getSize() const {
        if (m_fsMeta != NULL)
            return m_fsMeta->size;
        else
            return 0;
    };
    /**
          * get owner id
     * @return owner id
     */
    TSK_UID_T getUid() const {
        if (m_fsMeta != NULL)
            return m_fsMeta->uid;
        else
            return 0;
    };

    /**
          * get group id
     * @return group id
     */
    TSK_GID_T getGid() const {
        if (m_fsMeta != NULL)
            return m_fsMeta->gid;
        else
            return 0;
    };

    /**
          * get last file content modification time (stored in number of seconds since Jan 1, 1970 UTC)
     * @return last file content modification time
     */
    time_t getMTime() const {
        if (m_fsMeta != NULL)
            return m_fsMeta->mtime;
        else
            return 0;
    };

    /**
          * get nano-second resolution of modification time
     * @return nano-second resolution of modification time
     */
    uint32_t getMTimeNano() const {
        if (m_fsMeta != NULL)
            return m_fsMeta->mtime_nano;
        else
            return 0;
    };

    /**
          * get last file content accessed time (stored in number of seconds since Jan 1, 1970 UTC)
     * @return last file content accessed time
     */
    time_t getATime() const {
        if (m_fsMeta != NULL)
            return m_fsMeta->atime;
        else
            return 0;
    };

    /**
          * get nano-second resolution of accessed time
     * @return nano-second resolution of accessed time
     */
    uint32_t getATimeNano() const {
        if (m_fsMeta != NULL)
            return m_fsMeta->atime_nano;
        else
            return 0;
    };

    /**
          * get last file / metadata status change time (stored in number of seconds since Jan 1, 1970 UTC)
     * @return last file / metadata status change time
     */
    time_t getCTime() const {
        if (m_fsMeta != NULL)
            return m_fsMeta->ctime;
        else
            return 0;
    };

    /**
          * get nano-second resolution of change time
     * @return nano-second resolution of change time
     */
    uint32_t getCTimeNano() const {
        if (m_fsMeta != NULL)
            return m_fsMeta->ctime_nano;
        else
            return 0;
    };

    /**
          * get created time (stored in number of seconds since Jan 1, 1970 UTC)
     * @return created time
     */
    time_t getCrTime() const {
        if (m_fsMeta != NULL)
            return m_fsMeta->crtime;
        else
            return 0;
    };

    /**
          * get nano-second resolution of created time
     * @return nano-second resolution of created time
     */
    uint32_t getCrTimeNano() const {
        if (m_fsMeta != NULL)
            return m_fsMeta->crtime_nano;
        else
            return 0;
    };

    /**
          * get linux deletion time
     * @return linux deletion time
     */
    time_t getDTime() const {
        if (m_fsMeta != NULL)
            return m_fsMeta->time2.ext2.dtime;
        else
            return 0;
    };

    /**
          * get nano-second resolution of deletion time
     * @return nano-second resolution of deletion time
     */
    uint32_t getDTimeNano() const {
        if (m_fsMeta != NULL)
            return m_fsMeta->time2.ext2.dtime_nano;
        else
            return 0;
    };

    /**
          * get HFS+ backup time
     * @return HFS+ backup time
     */
    time_t getBackUpTime() const {
        if (m_fsMeta != NULL)
            return m_fsMeta->time2.hfs.bkup_time;
        else
            return 0;
    };

    /**
          * get nano-second resolution of HFS+ backup time
     * @return nano-second resolution of HFS+ backup time
     */
    uint32_t getBackUpTimeNano() const {
        if (m_fsMeta != NULL)
            return m_fsMeta->time2.hfs.bkup_time_nano;
        else
            return 0;
    };

    /**
          * get sequence number for file (NTFS only, is incremented when entry is reallocated)
     * @return sequence number for file, or 0xFFFF on error.
     */
    uint32_t getSeq() const {
        if (m_fsMeta != NULL)
            return m_fsMeta->seq;
        return 0xFFFF;
    };

    /**
          * get name of target file if this is a symbolic link
     * @return name of target file if this is a symbolic link
     */
    const char *getLink() const {
        if (m_fsMeta != NULL)
            return m_fsMeta->link;
        else
            return NULL;
    };

    /**
     * Return the number of names that are stored in the metadata.
     * @returns number of names.
     */
    int getName2Count() const {
        int size = 0;
        if (m_fsMeta != NULL) {
            TSK_FS_META_NAME_LIST *name = m_fsMeta->name2;
            while (name != NULL) {
                size++;
                name = name->next;
        }} return size;
    };

    /**
     * Return a name that is stored in the metadata.
     * @param a_idx Index of the name to return
     * @returns NULL on error.  Caller must free this memory.
     */
    const TskFsMetaName *getName2(int a_idx) const {
        if (m_fsMeta != NULL) {
            TSK_FS_META_NAME_LIST *name = m_fsMeta->name2;
            int i = 0;
            while (name != NULL) {
                if (i == a_idx)
                    return new TskFsMetaName(name);
                i++;
                name = name->next;
        }} return NULL;
    };

  private:
    /**
          * get structure used as the head of an attribute list
     * @return structure used as the head of an attribute list
     */
    const TSK_FS_ATTRLIST *getAttr() const {
        if (m_fsMeta != NULL)
            return m_fsMeta->attr;
        else
            return NULL;
    };
};


/**
 * \ingroup fslib_cpp
* Class that represents an allocated or deleted file. The non-default constructor or
* open method must be called first.  otherwise, the results of the getX() methods are
* undefined. See TSK_FS_FILE for more details.
*/
class TskFsFile {
  friend class TskFsDir;
  private:
    TSK_FS_FILE * m_fsFile;
    bool m_opened;
     TskFsFile(const TskFsFile & rhs);
     TskFsFile & operator=(const TskFsFile & rhs);

  public:
    /**
        * Construct a TskFsFile object from a C struct
    * @param a_fsFile a pointer of TSK_FS_FILE
    */
     TskFsFile(TSK_FS_FILE * a_fsFile) {
        m_fsFile = a_fsFile;
        m_opened = false;
    };

    /**
        * default constructor to construct a TskFsFile object
    */
    TskFsFile() {
        m_fsFile = NULL;
        m_opened = false;
    };

    /**
        * Close an open file.
    */
    ~TskFsFile() {
        close();
    };

    /**
        * Close an open file.
    * See tsk_fs_file_close() for details.
    */
    void close() {
        if (m_opened)
            tsk_fs_file_close(m_fsFile);
        m_fsFile = NULL;
    };

    /**
        *
    * Open a file given its metadata address. This function loads the metadata
    * and returns a handle that can be used to read and process the file.   Note
    * that the returned class will not have the file name set because
    * it was not used to load the file and this function does not search the
    * directory structure to find the name that points to the address.   In general,
    * if you know the metadata address of a file, this function is more efficient
    * then tsk_fs_file_open, which first maps a file name to the metadata address
    * and then open the file using this function.
    * See tsk_fs_file_open_meta() for details
    * @param a_fs File system to analyze
    * @param a_fs_file object to store file data in or NULL to have one allocated.
    * @param a_addr Metadata address of file to lookup
    * @returns 1 on error and 0 on success.
    */
    uint8_t open(TskFsInfo * a_fs, TskFsFile * a_fs_file,
        TSK_INUM_T a_addr) {
        if ((m_fsFile =
                tsk_fs_file_open_meta(a_fs->m_fsInfo, a_fs_file->m_fsFile,
                    a_addr)) != NULL) {
            m_opened = true;
            return 0;
        }
        else {
            return 1;
        }
    };

    /**
        * Return the handle structure for a specific file, given its full path. Note that
    * if you have the metadata address fo the file, then tsk_fs_file_open_meta() is a
    * more efficient approach.
    * See tsk_fs_file_open() for details
    * @param a_fs File system to analyze
    * @param a_fs_file Structure to store file data in or NULL to have one allocated.
    * @param a_path Path of file to open
    * @returns 1 on error and 0 on success.
    */
    uint8_t open(TskFsInfo * a_fs, TskFsFile * a_fs_file,
        const char *a_path) {
        if ((m_fsFile =
                tsk_fs_file_open(a_fs->m_fsInfo, a_fs_file->m_fsFile,
                    a_path))
            != NULL) {
            m_opened = true;
            return 0;
        }
        else {
            return 1;
        }
    };

    /*    * Return the number of attributes in the file.
     * See tsk_fs_file_attr_getsize() for details
     * @returns number of attributes in file
     */
    int getAttrSize() {
        return tsk_fs_file_attr_getsize(m_fsFile);      //m_fsFile is checked by this C function
    };

    /*    * Get a file's attribute based on the 0-based index in the list (and not type, id pair).
     * It's caller's responsibility to free TskFsAttribute*
     * See tsk_fs_file_attr_get_idx() for details
     * @param a_idx 0-based index of attribute to return.
     * @returns Pointer to attribute or NULL on error
     */
    const TskFsAttribute *getAttr(int a_idx) {
        TskFsAttribute *fsAttr = new TskFsAttribute(tsk_fs_file_attr_get_idx(m_fsFile, a_idx)); //m_fsFile is checked by this C function
        return fsAttr;
    };

    /*    * Return the default attribute for the file
     * It's caller's responsibility to free TskFsAttribute*
     * See tsk_fs_file_attr_get() for details
     * @returns Pointer to attribute or NULL on error
     */
    const TskFsAttribute *getAttrDefault() {
        TskFsAttribute *fsAttr = new TskFsAttribute(tsk_fs_file_attr_get(m_fsFile));    //m_fsFile is checked by this C function
        return fsAttr;
    };

    /*    * Return a specific type and id attribute for the file.
     * It's caller's responsibility to free TskFsAttribute*
     * See tsk_fs_file_attr_get_type() for details
     * @param a_type Type of attribute to load
     * @param a_id Id of attribute to load
     * @param a_id_used Set to 1 if ID is actually set or 0 to use default
     * @returns Pointer to attribute or NULL on error
     */
    const TskFsAttribute *getAttr(TSK_FS_ATTR_TYPE_ENUM a_type,
        uint16_t a_id, uint8_t a_id_used) {
        TskFsAttribute *fsAttr = new TskFsAttribute(tsk_fs_file_attr_get_type(m_fsFile, //m_fsFile is checked by this C function
                a_type, a_id, a_id_used));
        return fsAttr;
    };

    /**
        * Process a specific attribute in a file and call a callback function with the file contents.
    * See tsk_fs_file_walk_type() for details
    * @param a_type Attribute type to process
    * @param a_id Id if attribute to process
    * @param a_flags Flags to use while processing file
    * @param a_action Callback action to call with content
    * @param a_ptr Pointer that will passed to callback
    * @returns 1 on error and 0 on success.
    */
    uint8_t walk(TSK_FS_ATTR_TYPE_ENUM a_type, uint16_t a_id,
        TSK_FS_FILE_WALK_FLAG_ENUM a_flags,
        TSK_FS_FILE_WALK_CPP_CB a_action, void *a_ptr) {
        TSK_FS_FILE_WALK_CPP_DATA fileData;
        fileData.cppAction = a_action;
        fileData.cPtr = a_ptr;
        return tsk_fs_file_walk_type(m_fsFile, a_type, a_id, a_flags, tsk_fs_file_cpp_c_cb, &fileData); //m_fsFile is checked by this C function
    };

    /**
     * Process the default attribute for the file and call a callback function with the file contents.
    * See tsk_fs_file_walk_type() for details
    * @param a_flags Flags to use while processing file
    * @param a_action Callback action to call with content
    * @param a_ptr Pointer that will passed to callback
    * @returns 1 on error and 0 on success.
    */
    uint8_t walk(TSK_FS_FILE_WALK_FLAG_ENUM a_flags,
        TSK_FS_FILE_WALK_CPP_CB a_action, void *a_ptr) {
        TSK_FS_FILE_WALK_CPP_DATA fileData;
        fileData.cppAction = a_action;
        fileData.cPtr = a_ptr;
        return tsk_fs_file_walk(m_fsFile, a_flags, tsk_fs_file_cpp_c_cb, &fileData);    //m_fsFile is checked by this C function
    };

    /**
     * Read the contents of a specific attribute of a file using a typical read() type interface.
    * 0s are returned for missing runs of files.
    * See tsk_fs_file_read_type() for details
    * @param a_type The type of attribute to load
    * @param a_id The id of attribute to load (use 0 and set a_flags if you do not care)
    * @param a_offset The byte offset to start reading from.
    * @param a_buf The buffer to read the data into.
    * @param a_len The number of bytes to read from the file.
    * @param a_flags Flags to use while reading
    * @returns The number of bytes read or -1 on error (incl if offset is past EOF).
    */
    ssize_t read(TSK_FS_ATTR_TYPE_ENUM a_type, uint16_t a_id,
        TSK_OFF_T a_offset, char *a_buf, size_t a_len,
        TSK_FS_FILE_READ_FLAG_ENUM a_flags) {
        return tsk_fs_file_read_type(m_fsFile, a_type, a_id, a_offset, a_buf, a_len, a_flags);  //m_fsFile is checked by this C function
    };
    /**
     * Read the contents of the default attribute of a file using a typical read() type interface.
    * 0s are returned for missing runs of files.
    * See tsk_fs_file_read() for details
    * @param a_offset The byte offset to start reading from.
    * @param a_buf The buffer to read the data into.
    * @param a_len The number of bytes to read from the file.
    * @param a_flags Flags to use while reading
    * @returns The number of bytes read or -1 on error (incl if offset is past EOF).
    */
    ssize_t read(TSK_OFF_T a_offset, char *a_buf, size_t a_len,
        TSK_FS_FILE_READ_FLAG_ENUM a_flags) {
        return tsk_fs_file_read(m_fsFile, a_offset, a_buf, a_len, a_flags);     //m_fsFile is checked by this C function
    };

    /**
     * Return pointer to the file's name (or NULL if file was opened using metadata address)
    * @returns pointer to name of file.  It is the caller's responsibility to free this.
    */
    TskFsName *getName() {
        if (m_fsFile != NULL)
            return new TskFsName(m_fsFile->name);
        else
            return NULL;
    };

    /**
     * Return pointer to the file's metadata (or NULL if name has invalid metadata address)
    * @returns pointer metadata of file. It is the caller's responsibility to free this.
    */
    TskFsMeta *getMeta() {
        if (m_fsFile != NULL)
            return new TskFsMeta(m_fsFile->meta);
        else
            return NULL;
    };

    /**
    * Return pointer file system that the file is located in.
    * @returns pointer to file system that the file is located in.
    */
    TskFsInfo *getFsInfo() {
        if (m_fsFile != NULL)
            return new TskFsInfo(m_fsFile->fs_info);
        else
            return NULL;
    };
};                              //TskFsFile

/**
 * \ingroup fslib_cpp
* Stores information about a directory in the file system. The open() method
* must be called before any of hte other methods return defined data. See
* TSK_FS_DIR for more details.
*/
class TskFsDir {
  private:
    TSK_FS_DIR * m_fsDir;
    TskFsDir(const TskFsDir & rhs);
    TskFsDir & operator=(const TskFsDir & rhs);

  public:
     TskFsDir() {
        m_fsDir = NULL;
    };
    /*
     * Close the directory that was opened with tsk_fs_dir_open()
     */
    ~TskFsDir() {
        close();
    }

    /*
     * Open a directory (using its metadata addr) so that each of the files in it can be accessed.
     * See for tsk_fs_dir_open_meta() details.
     * @param a_fs File system to analyze
     * @param a_addr Metadata address of the directory to open
     * @returns 1 on error and 0 on success
     */
    uint8_t open(TskFsInfo * a_fs, TSK_INUM_T a_addr) {
        if ((m_fsDir =
                tsk_fs_dir_open_meta(a_fs->m_fsInfo, a_addr)) != NULL)
            return 0;
        else
            return 1;
    };

    /*
     * Open a directory (using its path) so that each of the files in it can be accessed.
     * See for tsk_fs_dir_open() details.
     * @param a_fs File system to analyze
     * @param a_dir Path of the directory to open
     * @returns 1 on error and 0 on success
     */
    uint8_t open(TskFsInfo * a_fs, const char *a_dir) {
        if ((m_fsDir = tsk_fs_dir_open(a_fs->m_fsInfo, a_dir)) != NULL)
            return 0;
        else
            return 1;
    };

    /*
     * Close the directory that was opened with tsk_fs_dir_open()
     * See tsk_fs_dir_close() for details
     */
    void close() {
        tsk_fs_dir_close(m_fsDir);
    };

    /*
     * Returns the number of files and subdirectories in a directory.
     * See tsk_fs_dir_getsize() for details
     * @returns Number of files and subdirectories (or 0 on error)
     */
    size_t getSize() const {
        return tsk_fs_dir_getsize(m_fsDir);     //m_fsDir is checked by this C function
    };

    /*
     * Return a specific file or subdirectory from an open directory.
     * It's caller's responsibility to free TskFsFile*
     * See tsk_fs_dir_getsize() for details
     * @param a_idx Index of file in directory to open (0-based)
     * @returns NULL on error
     */
    TskFsFile *getFile(size_t a_idx) const {
        TSK_FS_FILE *fs_file = tsk_fs_dir_get(m_fsDir, a_idx);
        if (fs_file != NULL) {
             TskFsFile *f = new TskFsFile(fs_file);
             f->m_opened = true;
             return f;
        } else
             return NULL;
    };

    /*
     * Return metadata address of this directory
     * @returns metadata address of this directory
     */
    TSK_INUM_T getMetaAddr() const {
        if (m_fsDir != NULL)
            return m_fsDir->addr;
        else
            return 0;
    };

    /*
     * Return pointer to the file structure for the directory.
     * @returns NULL on error. it is the caller's responsibility to free this object.
     */
    const TskFsFile *getFsFile() const {
        if (m_fsDir != NULL)
            return new TskFsFile(m_fsDir->fs_file);
        else
            return NULL;
    };

  private:

    /*
     * Return pointer to file system the directory is located in
     * @returns NULL on error
     */
    const TSK_FS_INFO *getFsInfo() const {
        if (m_fsDir != NULL)
            return m_fsDir->fs_info;
        else
            return NULL;
    };
};

#endif
#endif
