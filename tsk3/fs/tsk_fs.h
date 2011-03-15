/*
** The Sleuth Kit 
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2003-2008 Brian Carrier.  All rights reserved
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
 * \defgroup fslib File System Functions
 */

#ifndef _TSK_FS_H
#define _TSK_FS_H

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

    typedef struct TSK_FS_INFO TSK_FS_INFO;
    typedef struct TSK_FS_FILE TSK_FS_FILE;




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
        TSK_FS_BLOCK_FLAG_SPARSE = 0x0040,      ///< The data passed in the file_walk calback was stored as sparse (all zeros) (and not RAW or COMP)
        TSK_FS_BLOCK_FLAG_COMP = 0x0080,        ///< The data passed in the file_walk callback was stored in a compressed form (and not RAW or SPARSE)
        TSK_FS_BLOCK_FLAG_RES = 0x0100  ///< The data passed in the file_walk callback is from an NTFS resident file
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
    };
    typedef enum TSK_FS_BLOCK_WALK_FLAG_ENUM TSK_FS_BLOCK_WALK_FLAG_ENUM;


#define TSK_FS_BLOCK_TAG 0x1b7c3f4a
    /** 
    * Generic data strcture to hold block data with metadata
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
        TSK_FS_ATTR_RUN_FLAG_SPARSE = 0x02      ///< Entry is a sparse run where all data in the run is zeros
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
        TSK_FS_ATTR_RUN_FLAG_ENUM flags;        ///< Flags for run
    };



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
     */
    typedef enum {
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
        TSK_FS_ATTR_TYPE_UNIX_INDIR = 0x1001    //  Indirect blocks for UFS and ExtX file systems
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

        TSK_OFF_T size;         ///< Size in bytes of attribute (does not include skiplen for non-resident)

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
        TSK_FS_META_FLAG_ALLOC = 0x01,  ///< Metadata structure is currently in an allocated state
        TSK_FS_META_FLAG_UNALLOC = 0x02,        ///< Metadata structure is currently in an unallocated state
        TSK_FS_META_FLAG_USED = 0x04,   ///< Metadata structure has been allocated at least once
        TSK_FS_META_FLAG_UNUSED = 0x08, ///< Metadata structure has never been allocated. 
        TSK_FS_META_FLAG_COMP = 0x10,   ///< The file contents are compressed. 
        TSK_FS_META_FLAG_ORPHAN = 0x20, ///< Return only metadata structures that have no file name pointing to the (inode_walk flag only)
    };
    typedef enum TSK_FS_META_FLAG_ENUM TSK_FS_META_FLAG_ENUM;

    enum TSK_FS_META_ATTR_FLAG_ENUM {
        TSK_FS_META_ATTR_EMPTY, ///< The data in the attributes (if any) is not for this file
        TSK_FS_META_ATTR_STUDIED,       ///< The data in the attributes are for this file
        TSK_FS_META_ATTR_ERROR, ///< The attributes for this file could not be loaded
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
    };
    typedef enum TSK_FS_META_TYPE_ENUM TSK_FS_META_TYPE_ENUM;

#define TSK_FS_META_TYPE_STR_MAX 0x0b   ///< Number of file types in shortname array
    extern char tsk_fs_meta_type_str[TSK_FS_META_TYPE_STR_MAX][2];


    enum TSK_FS_META_MODE_ENUM {
        /* The following describe the file permissions */
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
        } time2;

        void *content_ptr;      ///< Pointer to file system specific data that is used to store references to file content
        size_t content_len;     ///< size of content  buffer

        uint32_t seq;           ///< Sequence number for file (NTFS only, is incremented when entry is reallocated) 

        /** Contains run data on the file content (specific locations where content is stored).  
         * Check attr_state to determine if data in here is valid because not all file systems 
         * load this data when a file is loaded.  It may not be loaded until needed by one
         * of the APIs. Most file systems will have only one attribute, but NTFS will have several. */
        TSK_FS_ATTRLIST *attr;
        TSK_FS_META_ATTR_FLAG_ENUM attr_state;  ///< State of the data in the TSK_FS_META::attr structure

        TSK_FS_META_NAME_LIST *name2;   ///< Name of file stored in metadata (FAT and NTFS Only)
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
        * that meets the critera specified when inode_walk was called. 
        * @param a_fs_file Pointer to the current file
        * @param a_ptr Pointer that was specified by caller to inode_walk
        * @returns Value that tells inode walk to continue or stop
        */
    typedef TSK_WALK_RET_ENUM(*TSK_FS_META_WALK_CB) (TSK_FS_FILE *
        a_fs_file, void *a_ptr);


    extern uint8_t tsk_fs_meta_walk(TSK_FS_INFO * a_fs, TSK_INUM_T a_start,
        TSK_INUM_T a_end, TSK_FS_META_FLAG_ENUM a_flags,
        TSK_FS_META_WALK_CB a_cb, void *a_ptr);

    extern uint8_t tsk_fs_meta_make_ls(TSK_FS_META * a_fs_meta,
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
    } TSK_FS_NAME_TYPE_ENUM;

#define TSK_FS_NAME_TYPE_STR_MAX 11     ///< Number of types that have a short string name

    /* ascii representation of above types */
    extern char tsk_fs_name_type_str[TSK_FS_NAME_TYPE_STR_MAX][2];

#define  TSK_FS_NAME_TAG 0x23147869
    /**
     * Generic structure to store the file name information that is stored in
     * a directory. Most file systems seperate the file name from the metadata, but
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


#define TSK_FS_DIR_TAG  0x97531246
    /**
     * A handle to a directory so that its files can be individually accessed.
     */
    typedef struct {
        int tag;                ///< \internal Will be set to TSK_FS_DIR_TAG if structure is still allocated, 0 if not

        TSK_FS_FILE *fs_file;   ///< Pointer to the file structure for the directory.

        TSK_FS_NAME *names;     ///< Pointer to list of names in directory. 
        size_t names_used;      ///< Number of name structures in queue being used
        size_t names_alloc;     ///< Number of name structures that were allocated

        TSK_INUM_T addr;    ///< Metadata address of this directory 

        TSK_FS_INFO *fs_info;   ///< Pointer to file system the directory is located in
    } TSK_FS_DIR;

    /**
     * Flags that are used when walking names in directories.  These are used to identify
     * which files to call the callback function on. 
     */
    typedef enum {
        TSK_FS_DIR_WALK_FLAG_NONE = 0x00,       ///< No Flags
        TSK_FS_DIR_WALK_FLAG_ALLOC = 0x01,      ///< Return allocated names in callback
        TSK_FS_DIR_WALK_FLAG_UNALLOC = 0x02,    ///< Return unallocated names in callback
        TSK_FS_DIR_WALK_FLAG_RECURSE = 0x04,    ///< Recurse into sub-directories 
        TSK_FS_DIR_WALK_FLAG_NOORPHAN = 0x08,   ///< Do not return (or recurse into) the special Orphan directory
    } TSK_FS_DIR_WALK_FLAG_ENUM;


    extern TSK_FS_DIR *tsk_fs_dir_open_meta(TSK_FS_INFO * a_fs,
        TSK_INUM_T a_addr);
    extern TSK_FS_DIR *tsk_fs_dir_open(TSK_FS_INFO * a_fs,
        const char *a_dir);
    extern uint8_t tsk_fs_dir_walk(TSK_FS_INFO * a_fs, TSK_INUM_T a_inode,
        TSK_FS_DIR_WALK_FLAG_ENUM a_flags, TSK_FS_DIR_WALK_CB a_action,
        void *a_ptr);
    extern size_t tsk_fs_dir_getsize(const TSK_FS_DIR *);
    extern TSK_FS_FILE *tsk_fs_dir_get(const TSK_FS_DIR *, size_t);
    extern void tsk_fs_dir_close(TSK_FS_DIR *);

    extern int8_t tsk_fs_path2inum(TSK_FS_INFO * a_fs, const char *a_path,
        TSK_INUM_T * a_result, TSK_FS_NAME * a_fs_name);

    //@}

    /********************* FILE Structure *************************/

    /** \name Generic File System File  Data Structures */
    //@{

#define  TSK_FS_FILE_TAG 0x11212212
    /**
     * Generic structure used to refer to files in the file system.  A file will
     * typically have a name and metadata.  This structure holds that type of information.
     * When deleted files are being processed, this structure may have the name defined
     * but not metadata because it no longer exists. Or, if you are calling meta_walk
     * and are not processing at the name level, then the name will not be defined.  
     * always check these to make sure they are not null before they are read. */
    struct TSK_FS_FILE {
        int tag;                ///< \internal Will be set to TSK_FS_FILE_TAG if structure is allocated

        TSK_FS_NAME *name;      ///< Pointer to name of file (or NULL if file was opened using metadata address)
        TSK_FS_META *meta;      ///< Pointer to metadata of file (or NULL if name has invalid metadata address)

        TSK_FS_INFO *fs_info;   ///< Pointer to file system that the file is located in.
    };

    /**
     * Flags used by tsk_fs_file_read */
    typedef enum {
        TSK_FS_FILE_READ_FLAG_NONE = 0x00,      ///< No Flags
        TSK_FS_FILE_READ_FLAG_SLACK = 0x01,     ///< Allow read access into slack space
        TSK_FS_FILE_READ_FLAG_NOID = 0x02,      ///< Ignore the Id argument given in the API (use only the type)
    } TSK_FS_FILE_READ_FLAG_ENUM;

    extern void tsk_fs_file_close(TSK_FS_FILE * a_fs_file);
    extern TSK_FS_FILE *tsk_fs_file_open(TSK_FS_INFO * a_fs,
        TSK_FS_FILE * a_fs_file, const char *a_path);
    extern TSK_FS_FILE *tsk_fs_file_open_meta(TSK_FS_INFO * fs,
        TSK_FS_FILE * fs_file, TSK_INUM_T addr);
    extern ssize_t
        tsk_fs_file_read(TSK_FS_FILE *, TSK_OFF_T, char *, size_t,
        TSK_FS_FILE_READ_FLAG_ENUM);
    extern ssize_t tsk_fs_file_read_type(TSK_FS_FILE *,
        TSK_FS_ATTR_TYPE_ENUM, uint16_t, TSK_OFF_T, char *, size_t,
        TSK_FS_FILE_READ_FLAG_ENUM);
    extern const TSK_FS_ATTR *tsk_fs_file_attr_get(TSK_FS_FILE *
        a_fs_file);
    extern int tsk_fs_file_attr_getsize(TSK_FS_FILE * a_fs_file);
    extern const TSK_FS_ATTR *tsk_fs_file_attr_get_idx(TSK_FS_FILE *
        a_fs_file, int a_idx);
    extern const TSK_FS_ATTR *tsk_fs_file_attr_get_type(TSK_FS_FILE *
        a_fs_file, TSK_FS_ATTR_TYPE_ENUM, uint16_t, uint8_t);

    extern uint8_t tsk_fs_file_walk(TSK_FS_FILE * a_fs_file,
        TSK_FS_FILE_WALK_FLAG_ENUM a_flags, TSK_FS_FILE_WALK_CB a_action,
        void *a_ptr);
    extern uint8_t tsk_fs_file_walk_type(TSK_FS_FILE * a_fs_file,
        TSK_FS_ATTR_TYPE_ENUM a_type, uint16_t a_id,
        TSK_FS_FILE_WALK_FLAG_ENUM a_flags, TSK_FS_FILE_WALK_CB a_action,
        void *a_ptr);

    extern ssize_t tsk_fs_attr_read(const TSK_FS_ATTR * a_fs_attr,
        TSK_OFF_T a_offset, char *a_buf, size_t a_len,
        TSK_FS_FILE_READ_FLAG_ENUM a_flags);

    extern uint8_t tsk_fs_file_get_owner_sid(TSK_FS_FILE *, char **);

    //@}


/****************** Journal Structures *************/

    /** \name Generic File System Journal Data Structures */
    //@{

    typedef struct {
        TSK_DADDR_T jblk;       /* journal block address */
        TSK_DADDR_T fsblk;      /* fs block that journal entry is about */
    } TSK_FS_JENTRY;

    typedef TSK_WALK_RET_ENUM(*TSK_FS_JBLK_WALK_CB) (TSK_FS_INFO *, char *,
        int, void *);
    typedef TSK_WALK_RET_ENUM(*TSK_FS_JENTRY_WALK_CB) (TSK_FS_INFO *,
        TSK_FS_JENTRY *, int, void *);

    //@}


/******************************* TSK_FS_INFO ******************/

    /** \name Generic File System Handle Data Structure */
    //@{

    /** 
    * Values for the file system type.  Each bit corresponds to a file 
    * system.  
    */
    enum TSK_FS_TYPE_ENUM {
        TSK_FS_TYPE_DETECT = 0x00000000,        ///< Use autodetection methods
        TSK_FS_TYPE_NTFS = 0x00000001,  ///< NTFS file system
        TSK_FS_TYPE_NTFS_DETECT = 0x00000001,   ///< NTFS auto detection
        TSK_FS_TYPE_FAT12 = 0x00000002, ///< FAT12 file system
        TSK_FS_TYPE_FAT16 = 0x00000004, ///< FAT16 file system
        TSK_FS_TYPE_FAT32 = 0x00000008, ///< FAT32 file system
        TSK_FS_TYPE_FAT_DETECT = 0x0000000e,    ///< FAT auto detection
        TSK_FS_TYPE_FFS1 = 0x00000010,  ///< UFS1 (FreeBSD, OpenBSD, BSDI ...)
        TSK_FS_TYPE_FFS1B = 0x00000020, ///< UFS1b (Solaris - has no type)
        TSK_FS_TYPE_FFS2 = 0x00000040,  ///< UFS2 - FreeBSD, NetBSD 
        TSK_FS_TYPE_FFS_DETECT = 0x00000070,    ///< UFS auto detection
        TSK_FS_TYPE_EXT2 = 0x00000080,  ///< Ext2 file system
        TSK_FS_TYPE_EXT3 = 0x00000100,  ///< Ext3 file system
        TSK_FS_TYPE_EXT_DETECT = 0x00000180,    ///< ExtX auto detection
        TSK_FS_TYPE_SWAP = 0x00000200,  ///< SWAP file system
        TSK_FS_TYPE_SWAP_DETECT = 0x00000200,   ///< SWAP auto detection
        TSK_FS_TYPE_RAW = 0x00000400,   ///< RAW file system
        TSK_FS_TYPE_RAW_DETECT = 0x00000400,    ///< RAW auto detection
        TSK_FS_TYPE_ISO9660 = 0x00000800,       ///< ISO9660 file system
        TSK_FS_TYPE_ISO9660_DETECT = 0x00000800,        ///< ISO9660 auto detection
        TSK_FS_TYPE_HFS = 0x00001000,   ///< HFS file system
        TSK_FS_TYPE_HFS_DETECT = 0x00001000,    ///< HFS auto detection
        TSK_FS_TYPE_UNSUPP = 0xffffffff,        ///< Unsupported file system
    };
    typedef enum TSK_FS_TYPE_ENUM TSK_FS_TYPE_ENUM;

    /**
        * \ingroup fslib
     * Macro that takes a file system type and returns 1 if the type
     * is for an NTFS file system. */
#define TSK_FS_TYPE_ISNTFS(ftype) \
    (((ftype) & TSK_FS_TYPE_NTFS_DETECT)?1:0)

        /**
        * \ingroup fslib
         * Macro that takes a file system type and returns 1 if the type
         * is for a FAT file system. */
#define TSK_FS_TYPE_ISFAT(ftype) \
        (((ftype) & TSK_FS_TYPE_FAT_DETECT)?1:0)

        /**
        * \ingroup fslib
         * Macro that takes a file system type and returns 1 if the type
         * is for a FFS file system. */
#define TSK_FS_TYPE_ISFFS(ftype) \
        (((ftype) & TSK_FS_TYPE_FFS_DETECT)?1:0)

        /**
        * \ingroup fslib
         * Macro that takes a file system type and returns 1 if the type
         * is for a ExtX file system. */
#define TSK_FS_TYPE_ISEXT(ftype) \
        (((ftype) & TSK_FS_TYPE_EXT_DETECT)?1:0)

        /**
        * \ingroup fslib
         * Macro that takes a file system type and returns 1 if the type
         * is for a ISO9660 file system. */
#define TSK_FS_TYPE_ISISO9660(ftype) \
        (((ftype) & TSK_FS_TYPE_ISO9660_DETECT)?1:0)

        /**
        * \ingroup fslib
         * Macro that takes a file system type and returns 1 if the type
         * is for a HFS file system. */
#define TSK_FS_TYPE_ISHFS(ftype) \
        (((ftype) & TSK_FS_TYPE_HFS_DETECT)?1:0)

        /**
        * \ingroup fslib
         * Macro that takes a file system type and returns 1 if the type
         * is for a swap "file system". */
#define TSK_FS_TYPE_ISSWAP(ftype) \
        (((ftype) & TSK_FS_TYPE_SWAP_DETECT)?1:0)

        /**
        * \ingroup fslib
         * Macro that takes a file system type and returns 1 if the type
         * is for a raw "file system". */
#define TSK_FS_TYPE_ISRAW(ftype) \
        (((ftype) & TSK_FS_TYPE_RAW_DETECT)?1:0)


    /**
     * Flags for the FS_INFO structure 
     */
    enum TSK_FS_INFO_FLAG_ENUM {
        TSK_FS_INFO_FLAG_NONE = 0x00,   ///< No Flags
        TSK_FS_INFO_FLAG_HAVE_SEQ = 0x01        ///< File system has sequence numbers in the inode addresses.
    };
    typedef enum TSK_FS_INFO_FLAG_ENUM TSK_FS_INFO_FLAG_ENUM;

#define TSK_FS_INFO_TAG  0x10101010
#define TSK_FS_INFO_FS_ID_LEN   32      // set based on largest file system / volume ID supported

/**
 * Stores state information for an open file system. 
 * One of these are generated for each open files system and it contains
 * file system-type specific data.  These values are all filled in by
 * the file system code and not the caller functions. 
 */
    struct TSK_FS_INFO {
        int tag;                ///< \internal Will be set to TSK_FS_INFO_TAG if structure is still allocated, 0 if not
        TSK_IMG_INFO *img_info; ///< Pointer to the image layer state
        TSK_OFF_T offset;       ///< Byte offset into img_info that fs starts 

        /* meta data */
        TSK_INUM_T inum_count;  ///< Number of metadata addresses 
        TSK_INUM_T root_inum;   ///< Metadata address of root directory  
        TSK_INUM_T first_inum;  ///< First valid metadata address
        TSK_INUM_T last_inum;   ///< Last valid metadata address

        /* content */
        TSK_DADDR_T block_count;        ///< Number of blocks in fs
        TSK_DADDR_T first_block;        ///< Address of first block
        TSK_DADDR_T last_block; ///< Address of last block as reported by file system (could be larger than last_block in image if end of image does not exist)
        TSK_DADDR_T last_block_act;     ///< Address of last block -- adjusted so that it is equal to the last block in the image or volume (if image is not complete)
        unsigned int block_size;        ///< Size of each block (in bytes)
        unsigned int dev_bsize; ///< Size of device block (typically always 512)

        /* The following are used for really RAW images that contain data
           before and after the actual user sector. For example, a raw cd
           image may have 16 bytes before the start of each sector.
         */
        unsigned int block_pre_size;    ///< Number of bytes that preceed each block (currently only used for RAW CDs)
        unsigned int block_post_size;    ///< Number of bytes that follow each block (currently only used for RAW CDs)

        /* Journal */
        TSK_INUM_T journ_inum;  ///< Address of journal inode

        TSK_FS_TYPE_ENUM ftype; ///< type of file system 
        const char *duname;     ///< string "name" of data unit type 
        TSK_FS_INFO_FLAG_ENUM flags;    ///< flags for file system
        uint8_t fs_id[TSK_FS_INFO_FS_ID_LEN];   ///< File system id (as reported in boot sector)
        size_t fs_id_used;      ///< Number of bytes in fs_id that are being used

        TSK_ENDIAN_ENUM endian; ///< Endian order of data

        TSK_LIST *list_inum_named;      /**< List of unallocated inodes that
					 * are pointed to by a file name -- 
					 * Used to find orphan files.  Is filled when looking for orphans
                     * or when a full name_walk is performed. 
					 */

        TSK_FS_DIR *orphan_dir; ///< Files and dirs in the top level of the $OrphanFiles directory.  NULL if orphans have not been hunted for yet. 
        uint8_t isOrphanHunting;        ///< Set to 1 if TSK is currently looking for Orphan files

         uint8_t(*block_walk) (TSK_FS_INFO * fs, TSK_DADDR_T start, TSK_DADDR_T end, TSK_FS_BLOCK_WALK_FLAG_ENUM flags, TSK_FS_BLOCK_WALK_CB cb, void *ptr);    ///< FS-specific function: Call tsk_fs_block_walk() instead. 

         TSK_FS_BLOCK_FLAG_ENUM(*block_getflags) (TSK_FS_INFO * a_fs, TSK_DADDR_T a_addr);      ///< \internal

         uint8_t(*inode_walk) (TSK_FS_INFO * fs, TSK_INUM_T start, TSK_INUM_T end, TSK_FS_META_FLAG_ENUM flags, TSK_FS_META_WALK_CB cb, void *ptr);     ///< FS-specific function: Call tsk_fs_meta_walk() instead. 

         uint8_t(*file_add_meta) (TSK_FS_INFO * fs, TSK_FS_FILE * fs_file, TSK_INUM_T addr);    ///< \internal

         TSK_FS_ATTR_TYPE_ENUM(*get_default_attr_type) (const TSK_FS_FILE *);   ///< \internal

         uint8_t(*load_attrs) (TSK_FS_FILE *);  ///< \internal


        /**
         * Pointer to file system specific function that prints details on a specific file to a file handle. 
         *
         * @param fs File system file is located in
         * @param hFile File handle to print text to
         * @param inum Address of file in file system
         * @param numblock The number of blocks in file to force print (can go beyond file size)
         * @param sec_skew Clock skew in seconds to also print times in
         * 
         * @returns 1 on error and 0 on success
         */
         uint8_t(*istat) (TSK_FS_INFO * fs, FILE * hFile, TSK_INUM_T inum,
            TSK_DADDR_T numblock, int32_t sec_skew);

         TSK_RETVAL_ENUM(*dir_open_meta) (TSK_FS_INFO * fs, TSK_FS_DIR ** a_fs_dir, TSK_INUM_T inode);  ///< \internal Call tsk_fs_dir_open_meta() instead. 

         uint8_t(*jopen) (TSK_FS_INFO *, TSK_INUM_T);   ///< \internal

         uint8_t(*jblk_walk) (TSK_FS_INFO *, TSK_DADDR_T, TSK_DADDR_T, int, TSK_FS_JBLK_WALK_CB, void *);       ///< \internal

         uint8_t(*jentry_walk) (TSK_FS_INFO *, int, TSK_FS_JENTRY_WALK_CB, void *);     ///< \internal

         uint8_t(*fsstat) (TSK_FS_INFO * fs, FILE * hFile);     ///< \internal

        int (*name_cmp) (TSK_FS_INFO *, const char *, const char *);    ///< \internal

         uint8_t(*fscheck) (TSK_FS_INFO *, FILE *);     ///< \internal

        void (*close) (TSK_FS_INFO * fs);       ///< FS-specific function: Call tsk_fs_close() instead. 

         uint8_t(*fread_owner_sid) (TSK_FS_FILE *, char **);    // FS-specific function. Call tsk_fs_file_get_owner_sid() instead.
    };


    /* File system level */
    extern TSK_FS_INFO *tsk_fs_open_img(TSK_IMG_INFO *, TSK_OFF_T,
        TSK_FS_TYPE_ENUM);
    extern TSK_FS_INFO *tsk_fs_open_vol(const TSK_VS_PART_INFO *,
        TSK_FS_TYPE_ENUM);
    extern void tsk_fs_close(TSK_FS_INFO *);

    extern TSK_FS_TYPE_ENUM tsk_fs_type_toid(const TSK_TCHAR *);
    extern void tsk_fs_type_print(FILE *);
    extern const char *tsk_fs_type_toname(TSK_FS_TYPE_ENUM);
    extern TSK_FS_TYPE_ENUM tsk_fs_type_supported();

    extern ssize_t tsk_fs_read(TSK_FS_INFO * a_fs, TSK_OFF_T a_off,
        char *a_buf, size_t a_len);
    extern ssize_t tsk_fs_read_block(TSK_FS_INFO * a_fs,
        TSK_DADDR_T a_addr, char *a_buf, size_t a_len);

    //@}


/***** LIBRARY ROUTINES FOR COMMAND LINE FUNCTIONS */
    enum TSK_FS_BLKCALC_FLAG_ENUM {
        TSK_FS_BLKCALC_DD = 0x01,
        TSK_FS_BLKCALC_BLKLS = 0x02,
        TSK_FS_BLKCALC_SLACK = 0x04
    };
    typedef enum TSK_FS_BLKCALC_FLAG_ENUM TSK_FS_BLKCALC_FLAG_ENUM;
    extern int8_t tsk_fs_blkcalc(TSK_FS_INFO * fs,
        TSK_FS_BLKCALC_FLAG_ENUM flags, TSK_DADDR_T cnt);


    enum TSK_FS_BLKCAT_FLAG_ENUM {
        TSK_FS_BLKCAT_NONE = 0x00,
        TSK_FS_BLKCAT_HEX = 0x01,
        TSK_FS_BLKCAT_ASCII = 0x02,
        TSK_FS_BLKCAT_HTML = 0x04,
        TSK_FS_BLKCAT_STAT = 0x08
    };
    typedef enum TSK_FS_BLKCAT_FLAG_ENUM TSK_FS_BLKCAT_FLAG_ENUM;
    extern uint8_t tsk_fs_blkcat(TSK_FS_INFO * fs,
        TSK_FS_BLKCAT_FLAG_ENUM flags, TSK_DADDR_T addr,
        TSK_DADDR_T read_num_units);


    enum TSK_FS_BLKLS_FLAG_ENUM {
        TSK_FS_BLKLS_NONE = 0x00,
        TSK_FS_BLKLS_CAT = 0x01,
        TSK_FS_BLKLS_LIST = 0x02,
        TSK_FS_BLKLS_SLACK = 0x04,
    };
    typedef enum TSK_FS_BLKLS_FLAG_ENUM TSK_FS_BLKLS_FLAG_ENUM;
    extern uint8_t tsk_fs_blkls(TSK_FS_INFO * fs,
        TSK_FS_BLKLS_FLAG_ENUM lclflags, TSK_DADDR_T bstart,
        TSK_DADDR_T bend, TSK_FS_BLOCK_FLAG_ENUM flags);

    extern uint8_t tsk_fs_blkstat(TSK_FS_INFO * fs, TSK_DADDR_T addr,
        TSK_FS_BLOCK_FLAG_ENUM flags);

    enum TSK_FS_FFIND_FLAG_ENUM {
        TSK_FS_FFIND_ALL = 0x01,
    };
    typedef enum TSK_FS_FFIND_FLAG_ENUM TSK_FS_FFIND_FLAG_ENUM;
    extern uint8_t tsk_fs_ffind(TSK_FS_INFO * fs,
        TSK_FS_FFIND_FLAG_ENUM lclflags, TSK_INUM_T inode,
        TSK_FS_ATTR_TYPE_ENUM type, uint8_t type_used,
        uint16_t id, uint8_t id_used, TSK_FS_DIR_WALK_FLAG_ENUM flags);


    enum TSK_FS_FLS_FLAG_ENUM {
        TSK_FS_FLS_NONE = 0x00,
        TSK_FS_FLS_DOT = 0x01,
        TSK_FS_FLS_LONG = 0x02,
        TSK_FS_FLS_FILE = 0x04,
        TSK_FS_FLS_DIR = 0x08,
        TSK_FS_FLS_FULL = 0x10,
        TSK_FS_FLS_MAC = 0x20,
    };
    typedef enum TSK_FS_FLS_FLAG_ENUM TSK_FS_FLS_FLAG_ENUM;
    extern uint8_t tsk_fs_fls(TSK_FS_INFO * fs,
        TSK_FS_FLS_FLAG_ENUM lclflags, TSK_INUM_T inode,
        TSK_FS_DIR_WALK_FLAG_ENUM flags, TSK_TCHAR * pre, int32_t skew);

    extern uint8_t tsk_fs_icat(TSK_FS_INFO * fs,
        TSK_INUM_T inum,
        TSK_FS_ATTR_TYPE_ENUM type, uint8_t type_used,
        uint16_t id, uint8_t id_used, TSK_FS_FILE_WALK_FLAG_ENUM flags);


    enum TSK_FS_IFIND_FLAG_ENUM {
        TSK_FS_IFIND_NONE = 0x00,
        TSK_FS_IFIND_ALL = 0x01,
        TSK_FS_IFIND_PAR_LONG = 0x02,
    };
    typedef enum TSK_FS_IFIND_FLAG_ENUM TSK_FS_IFIND_FLAG_ENUM;
    extern int8_t tsk_fs_ifind_path(TSK_FS_INFO * fs,
        TSK_TCHAR * path, TSK_INUM_T * result);
    extern uint8_t tsk_fs_ifind_data(TSK_FS_INFO * fs,
        TSK_FS_IFIND_FLAG_ENUM flags, TSK_DADDR_T blk);
    extern uint8_t tsk_fs_ifind_par(TSK_FS_INFO * fs,
        TSK_FS_IFIND_FLAG_ENUM flags, TSK_INUM_T par);


    enum TSK_FS_ILS_FLAG_ENUM {
        TSK_FS_ILS_NONE = 0x00,
        TSK_FS_ILS_OPEN = 0x01,
        TSK_FS_ILS_MAC = 0x02,
        TSK_FS_ILS_LINK = 0x04,
        TSK_FS_ILS_UNLINK = 0x08,
    };
    typedef enum TSK_FS_ILS_FLAG_ENUM TSK_FS_ILS_FLAG_ENUM;
    extern uint8_t tsk_fs_ils(TSK_FS_INFO * fs,
        TSK_FS_ILS_FLAG_ENUM lclflags, TSK_INUM_T istart, TSK_INUM_T ilast,
        TSK_FS_META_FLAG_ENUM flags, int32_t skew, const TSK_TCHAR * img);

    /*
     ** Is this string a "." or ".."
     */
#define TSK_FS_ISDOT(str) ( ((str[0] == '.') && \
                             ( ((str[1] == '.') && (str[2] == '\0')) || (str[1] == '\0') ) ) ? 1 : 0 )


    extern int tsk_fs_parse_inum(const TSK_TCHAR * str, TSK_INUM_T *,
        TSK_FS_ATTR_TYPE_ENUM *, uint8_t *, uint16_t *, uint8_t *);

#ifdef __cplusplus
}
#endif
#endif
