/*
** The Sleuth Kit
**
** This software is subject to the IBM Public License ver. 1.0,
** which was displayed prior to download and is included in the readme.txt
** file accompanying the Sleuth Kit files.  It may also be requested from:
** Crucial Security Inc.
** 14900 Conference Center Drive
** Chantilly, VA 20151
**
** Judson Powers [jpowers@atc-nycorp.com]
** Copyright (c) 2008 ATC-NY.  All rights reserved.
** This file contains data developed with support from the National
** Institute of Justice, Office of Justice Programs, U.S. Department of Justice.
** 
** Wyatt Banks [wbanks@crucialsecurity.com]
** Copyright (c) 2005 Crucial Security Inc.  All rights reserved.
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2003-2005 Brian Carrier.  All rights reserved
**
** Copyright (c) 1997,1998,1999, International Business Machines
** Corporation and others. All Rights Reserved.
*/

/* TCT
 * LICENSE
 *      This software is distributed under the IBM Public License.
 * AUTHOR(S)
 *      Wietse Venema
 *      IBM T.J. Watson Research
 *      P.O. Box 704
 *      Yorktown Heights, NY 10598, USA
 --*/

/*
** You may distribute the Sleuth Kit, or other software that incorporates
** part of all of the Sleuth Kit, in object code form under a license agreement,
** provided that:
** a) you comply with the terms and conditions of the IBM Public License
**    ver 1.0; and
** b) the license agreement
**     i) effectively disclaims on behalf of all Contributors all warranties
**        and conditions, express and implied, including warranties or
**        conditions of title and non-infringement, and implied warranties
**        or conditions of merchantability and fitness for a particular
**        purpose.
**    ii) effectively excludes on behalf of all Contributors liability for
**        damages, including direct, indirect, special, incidental and
**        consequential damages such as lost profits.
**   iii) states that any provisions which differ from IBM Public License
**        ver. 1.0 are offered by that Contributor alone and not by any
**        other party; and
**    iv) states that the source code for the program is available from you,
**        and informs licensees how to obtain it in a reasonable manner on or
**        through a medium customarily used for software exchange.
**
** When the Sleuth Kit or other software that incorporates part or all of
** the Sleuth Kit is made available in source code form:
**     a) it must be made available under IBM Public License ver. 1.0; and
**     b) a copy of the IBM Public License ver. 1.0 must be included with
**        each copy of the program.
*/

/**
 * Contains the structures and function APIs for HFS+ file system support.
 */


#ifndef _TSK_HFS_H
#define _TSK_HFS_H


/*
 * All structures created using technote 1150 from Apple.com
 * http://developer.apple.com/technotes/tn/tn1150.html
 */

/*
 * Constants
 */

#define HFS_MAGIC	0x4244  /* BD in big endian */
#define HFSPLUS_MAGIC	0x482b  /* H+ in big endian */
#define HFSX_MAGIC      0x4858  /* HX in big endian */

#define HFSPLUS_VERSION 0x0004  /* all HFS+ volumes are version 4 */
#define HFSX_VERSION    0x0005  /* HFSX volumes start with version 5 */

#define HFSPLUS_MOUNT_VERSION 0x31302e30        /* '10.0 for Mac OS X */
#define HFSJ_MOUNT_VERSION    0x4846534a        /* 'HFSJ' for jounraled HFS+ on Mac OS X */
#define FSK_MOUNT_VERSION     0x46534b21        /* 'FSK!' for failed journal replay */

#define HFS_SBOFF	1024
#define HFS_FILE_CONTENT_LEN 160        // size of two hfs_fork data structures

/* b-tree kind types */
#define HFS_BTREE_LEAF_NODE	-1
#define HFS_BTREE_INDEX_NODE	 0
#define HFS_BTREE_HEADER_NODE	 1
#define HFS_BTREE_MAP_NODE	 2

#define HFS_MAXNAMLEN		765     /* maximum HFS+ name length in bytes, when encoded in UTF8, not including terminating null */

/* catalog file data types */
#define HFS_FOLDER_RECORD	0x0001
#define HFS_FILE_RECORD		0X0002
#define HFS_FOLDER_THREAD	0x0003
#define HFS_FILE_THREAD		0x0004

/*
 * HFS uses its own time system, which is seconds since Jan 1 1904
 * instead of the typical Jan 1 1970.  This number is the seconds between
 * 1 Jan 1904 and 1 Jan 1970 which will make ctime(3) work instead of
 * re-writing the Apple library function to convert this time.
 */
#define NSEC_BTWN_1904_1970	(uint32_t) 2082844800U

#define HFS_BIT_VOLUME_UNMOUNTED	(uint32_t)(1 << 8)      /* set if the volume was unmounted properly; as per TN 1150, modern Macintosh OSes always leave this bit set */
#define HFS_BIT_VOLUME_BADBLOCKS        (uint32_t)(1 << 9)      /* set if there are any bad blocks for this volume (in the Extents B-tree) */
#define HFS_BIT_VOLUME_INCONSISTENT	(uint32_t)(1 << 11)     /* cleared if the volume was unmounted properly */
#define HFS_BIT_VOLUME_JOURNALED	(uint32_t)(1 << 13)
#define HFS_BIT_VOLUME_CNIDS_REUSED     (uint32_t)(1 << 12)     /* set if CNIDs have wrapped around past the maximum value and are being reused; in this case, there are CNIDs on the disk larger than the nextCatalogId field */

/* constants for BTree header record attributes */
#define HFS_BT_BIGKEYS 0x00000002       /* kBTBigKeysMask : key length field is 16 bits */
// NOTE: HFS_BT_BIGKEYS must be set for all HFS+ BTrees
#define HFS_BT_VARKEYS 0x00000004       /* kBTVariableIndexKeysMask : keys in index nodes are variable length */
// NOTE: this bit is required to be set for the Catalog B-tree and cleared
// for the Extents B-tree

/* predefined files */
#define HFS_ROOT_PARENT_ID         1
#define HFS_ROOT_FOLDER_ID         2
#define HFS_EXTENTS_FILE_ID        3
#define HFS_CATALOG_FILE_ID        4
#define HFS_BAD_BLOCK_FILE_ID      5
#define HFS_ALLOCATION_FILE_ID     6
#define HFS_STARTUP_FILE_ID        7
#define HFS_ATTRIBUTES_FILE_ID     8
#define HFS_REPAIR_CATALOG_FILE_ID 14
#define HFS_BOGUS_EXTENT_FILE_ID   15

#define HFS_FIRST_USER_CNID	   16
#define HFS_ROOT_INUM HFS_ROOT_FOLDER_ID

#define HFS_HARDLINK_FILE_TYPE 0x686C6E6B       /* hlnk */
#define HFS_HARDLINK_FILE_CREATOR 0x6866732B    /* hfs+ */

#define HFS_CATALOGNAME "$CatalogFile"
#define HFS_EXTENTSNAME "$ExtentsFile"
#define HFS_ALLOCATIONNAME "$BitMapFile"
#define HFS_STARTUPNAME "$BootFile"
#define HFS_ATTRIBUTESNAME "$AttributesFile"

/*
 * HFS structures
 */

/* File and Folder name struct */
typedef struct {
    uint8_t length[2];
    uint8_t unicode[510];
} hfs_uni_str;

/* access permissions */
typedef struct {
    uint8_t owner[4];           /* file owner */
    uint8_t group[4];           /* file group */
    uint8_t a_flags;            /* admin flags */
    uint8_t o_flags;            /* owner flags */
    uint8_t mode[2];            /* file mode */
    union {
        uint8_t inum[4];        /* inode number */
        uint8_t nlink[4];       /* link count */
        uint8_t raw[4];         /* raw device */
    } special;
} hfs_access_perm;

#define HFS_IN_ISUID   0004000  /* set user id */
#define HFS_IN_ISGID   0002000  /* set group id */
#define HFS_IN_ISVTX   0001000  /* sticky bit (directories only) */
#define HFS_IN_IRUSR   0000400  /* R for user */
#define HFS_IN_IWUSR   0000200  /* W for user */
#define HFS_IN_IXUSR   0000100  /* X for user */
#define HFS_IN_IRGRP   0000040  /* R for group */
#define HFS_IN_IWGRP   0000020  /* W for group */
#define HFS_IN_IXGRP   0000010  /* X for group */
#define HFS_IN_IROTH   0000004  /* R for other */
#define HFS_IN_IWOTH   0000002  /* W for other */
#define HFS_IN_IXOTH   0000001  /* X for other */

#define HFS_IN_IFMT    0170000  /* filetype mask */
#define HFS_IN_IFIFO   0010000  /* named pipe */
#define HFS_IN_IFCHR   0020000  /* character special */
#define HFS_IN_IFDIR   0040000  /* directory */
#define HFS_IN_IFBLK   0060000  /* block special */
#define HFS_IN_IFREG   0100000  /* regular file */
#define HFS_IN_IFLNK   0120000  /* symbolic link */
#define HFS_IN_IFSOCK  0140000  /* socket */
#define HFS_IFWHT      0160000  /* whiteout */
#define HFS_IFXATTR    0200000  /* extended attributes */

/* HFS extent descriptor */
typedef struct {
    uint8_t start_blk[4];       /* start block */
    uint8_t blk_cnt[4];         /* block count */
} hfs_ext_desc;

/* Structre used in the extents tree */
typedef struct {
    hfs_ext_desc extents[8];
} hfs_extents;

/* fork data structure */
typedef struct {
    uint8_t logic_sz[8];        /* The size (in bytes) of the fork */
    uint8_t clmp_sz[4];         /* For forks in volume header, clump size.  For
                                 * catalog files, this is number of blocks read or not used. */
    uint8_t total_blk[4];       /* total blocks in all extents of the fork */
    hfs_ext_desc extents[8];
} hfs_fork;

/*
** Super Block
*/
typedef struct {
    uint8_t signature[2];       /* "H+" for HFS+, "HX" for HFSX */
    uint8_t version[2];         /* 4 for HFS+, 5 for HFSX */
    uint8_t attr[4];            /* volume attributes */
    uint8_t last_mnt_ver[4];    /* last mounted version */
    uint8_t jinfo_blk[4];       /* journal info block */
    uint8_t c_date[4];          /* volume creation date */
    uint8_t m_date[4];          /* volume last modified date */
    uint8_t bkup_date[4];       /* volume last backup date */
    uint8_t chk_date[4];        /* date of last consistency check */
    uint8_t file_cnt[4];        /* number of files on volume */
    uint8_t fldr_cnt[4];        /* number of folders on volume */
    uint8_t blk_sz[4];          /* allocation block size */
    uint8_t blk_cnt[4];         /* number of blocks on disk */
    uint8_t free_blks[4];       /* unused block count */
    uint8_t next_alloc[4];      /* start of next allocation search */
    uint8_t rsrc_clmp_sz[4];    /* default clump size for resource forks */
    uint8_t data_clmp_sz[4];    /* default clump size for data forks */
    uint8_t next_cat_id[4];     /* next catalog id */
    uint8_t write_cnt[4];       /* write count */
    uint8_t enc_bmp[8];         /* encoding bitmap */
    uint8_t finder_info[32];
    hfs_fork alloc_file;        /* location and size of allocation file */
    hfs_fork ext_file;          /* location and size of extents file */
    hfs_fork cat_file;          /* location and size of catalog file */
    hfs_fork attr_file;         /* location and size of attributes file */
    hfs_fork start_file;        /* location and size of startup file */
} hfs_sb;

typedef struct {
    uint8_t key_len[2];
    uint8_t parent_cnid[4];
    hfs_uni_str name;
} hfs_cat_key;

typedef struct {
    uint8_t key_len[2];
    uint8_t fork_type[1];
    uint8_t pad[1];
    uint8_t file_id[4];
    uint8_t start_block[4];
} hfs_ext_key;

typedef struct {
    uint32_t inum;              /* inode number */
    uint32_t parent;            /* parent directory number */
    uint32_t node;              /* btree leaf node */
    TSK_DADDR_T offs;           /* offset of beginning of inode */
} htsk_fs_inode_mode_struct;

typedef struct {
    uint8_t flink[4];           /* next node number */
    uint8_t blink[4];           /* previous node number */
    int8_t kind;                /* type of node */
    uint8_t height;             /* level in B-tree */
    uint8_t num_rec[2];         /* number of records this node */
    uint8_t res[2];             /* reserved */
} hfs_btree_node;

typedef struct {
    uint8_t depth[2];           /* current depth of btree */
    uint8_t root[4];            /* node number of root node */
    uint8_t leaf[4];            /* number of records in leaf nodes */
    uint8_t firstleaf[4];       /* number of first leaf node */
    uint8_t lastleaf[4];        /* number of last leaf node */
    uint8_t nodesize[2];        /* byte size of leaf node (512..32768) */
    uint8_t max_len[2];         /* max key length in an index or leaf node */
    uint8_t total[4];           /* number of nodes in btree (free or in use) */
    uint8_t free[4];            /* unused nodes in btree */
    uint8_t res[2];             /* reserved */
    uint8_t clmp_sz[4];         /* clump size */
    uint8_t bt_type;            /* btree type */
    uint8_t k_type;             /* key compare type */
    uint8_t attr[4];            /* attributes */
    uint8_t res2[64];           /* reserved */
} hfs_btree_header_record;

typedef struct {
    int8_t v[2];
    int8_t h[2];
} hfs_point;

#define HFS_FINDER_FLAG_NAME_LOCKED  0x1000
#define HFS_FINDER_FLAG_HAS_BUNDLE   0x2000
#define HFS_FINDER_FLAG_IS_INVISIBLE 0x4000
#define HFS_FINDER_FLAG_IS_ALIAS     0x8000

typedef struct {
    uint8_t file_type[4];       /* file type */
    uint8_t file_cr[4];         /* file creator */
    uint8_t flags[2];           /* finder flags */
    hfs_point loc;              /* location in the folder */
    uint8_t res[2];             /* reserved */
} hfs_fileinfo;

typedef struct {
    uint8_t res1[8];            /* reserved 1 */
    uint8_t extflags[2];        /* extended finder flags */
    uint8_t res2[2];            /* reserved 2 */
    uint8_t folderid[4];        /* putaway folder id */
} hfs_extendedfileinfo;

#define HFS_FILE_FLAG_LOCKED 0x0001     /* file is locked */
#define HFS_FILE_FLAG_ATTR   0x0004     /* file has extended attributes */
#define HFS_FILE_FLAG_ACL    0x0008     /* file has security data (ACLs) */

typedef struct {
    uint8_t rec_type[2];        /* record type */
    uint8_t flags[2];           /* flags - reserved */
    uint8_t valence[4];         /* valence - items in this folder */
    uint8_t cnid[4];            /* catalog node id */
    uint8_t ctime[4];           /* create date */
    uint8_t cmtime[4];          /* content mod date */
    uint8_t amtime[4];          /* attribute mod date */
    uint8_t atime[4];           /* access date */
    uint8_t bkup_time[4];       /* backup time */
    hfs_access_perm perm;       /* HFS permissions */
    hfs_fileinfo u_info;        /* user info */
    hfs_extendedfileinfo f_info;        /* finder info */
    uint8_t txt_enc[4];         /* text encoding */
    uint8_t res[4];             /* reserved */
} hfs_folder;

typedef struct {
    uint8_t rec_type[2];        /* record type */
    uint8_t flags[2];
    uint8_t res[4];             /* reserved */
    uint8_t cnid[4];            /* catalog node id */
    uint8_t ctime[4];           /* create date */
    uint8_t cmtime[4];          /* content modification date */
    uint8_t attr_mtime[4];      /* attribute mod date */
    uint8_t atime[4];           /* access date */
    uint8_t bkup_date[4];       /* backup date */
    hfs_access_perm perm;       /* permissions */
    hfs_fileinfo u_info;        /* user info */
    hfs_extendedfileinfo f_info;        /* finder info */
    uint8_t text_enc[4];        /* text encoding */
    uint8_t res2[4];            /* reserved 2 */
    hfs_fork data;              /* data fork */
    hfs_fork resource;          /* resource fork */
} hfs_file;

typedef union {
    hfs_folder folder;
    hfs_file file;
} hfs_file_folder;

typedef struct {
    uint8_t record_type[2];     /* == kHFSPlusFolderThreadRecord or kHFSPlusFileThreadRecord */
    uint8_t reserved[2];        /* reserved - initialized as zero */
    uint8_t parent_cnid[4];     /* parent ID for this catalog node */
    hfs_uni_str name;           /* name of this catalog node (variable length) */
} hfs_thread;

typedef struct {
    TSK_FS_INFO fs_info;        /* SUPER CLASS */

    hfs_sb *fs;                 /* cached superblock */

    char is_case_sensitive;

    TSK_FS_FILE *blockmap_file;
    const TSK_FS_ATTR *blockmap_attr;
    char blockmap_cache[4096];
    int blockmap_cache_start;

    TSK_FS_FILE *catalog_file;
    const TSK_FS_ATTR *catalog_attr;
    hfs_btree_header_record catalog_header;

    TSK_FS_FILE *extents_file;
    const TSK_FS_ATTR *extents_attr;
    hfs_btree_header_record extents_header;

} HFS_INFO;

typedef struct {
    hfs_file cat;               /* on-disk catalog record (either hfs_file or hfs_folder) */
    int flags;                  /* flags for on-disk record */
    TSK_INUM_T inum;            /* cnid */
    hfs_thread thread;          /* thread record */
} HFS_ENTRY;

/************** JOURNAL ******************/

/* HFS Journal Info Block */
typedef struct {
    uint8_t flags[4];
    uint8_t dev_sig[32];
    uint8_t offs[8];
    uint8_t size[8];
    uint8_t res[128];
} hfs_journ_sb;

/*
 * Prototypes
 */
extern uint8_t hfs_checked_read_random(TSK_FS_INFO *, char *, size_t,
    TSK_OFF_T);
extern uint8_t hfs_uni2ascii(TSK_FS_INFO *, uint8_t *, int, char *, int);
extern int hfs_unicode_compare(HFS_INFO *, hfs_uni_str *, hfs_uni_str *);

extern TSK_RETVAL_ENUM
hfs_dir_open_meta(TSK_FS_INFO *, TSK_FS_DIR **, TSK_INUM_T);

extern uint8_t hfs_jopen(TSK_FS_INFO *, TSK_INUM_T);
extern uint8_t hfs_jblk_walk(TSK_FS_INFO *, TSK_DADDR_T, TSK_DADDR_T, int,
    TSK_FS_JBLK_WALK_CB, void *);
extern uint8_t hfs_jentry_walk(TSK_FS_INFO *, int, TSK_FS_JENTRY_WALK_CB,
    void *);

/*
extern TSK_OFF_T hfs_cat_find_node_offset(HFS_INFO *, uint32_t);
extern TSK_OFF_T hfs_get_bt_rec_off(HFS_INFO *, TSK_OFF_T, uint16_t,
    uint16_t);
extern TSK_OFF_T hfs_read_key(HFS_INFO *, hfs_btree_header_record *,
    TSK_OFF_T, char *, int, uint8_t);
extern int hfs_compare_catalog_keys(HFS_INFO *, hfs_cat_key *,
    hfs_cat_key *);

extern uint8_t hfs_read_thread_record(HFS_INFO *, TSK_OFF_T,
    hfs_thread *);
extern uint32_t hfs_cat_next_record(HFS_INFO *, uint16_t *, uint16_t *,
    hfs_btree_node *, uint32_t *, TSK_OFF_T *, hfs_btree_header_record *);
extern uint8_t hfs_read_file_folder_record(HFS_INFO *, TSK_OFF_T,
    hfs_file_folder *);
*/
#endif
