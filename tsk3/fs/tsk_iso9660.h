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
** Wyatt Banks [wbanks@crucialsecurity.com]
** Copyright (c) 2005 Crucial Security Inc.  All rights reserved.
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2003-2011 Brian Carrier.  All rights reserved
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

/* 
 * Contains the structures and function APIs for ISO9660 file system support.
 */

/* refernece documents used:
 * IEEE P1281 - System Use Sharing Protocol, version 1.12
 * IEEE P1282 - Rock Ridge Interchange Protocol, version 1.12
 * ECMA-119 - Volume and File Structure of CDROM for Information Interchange,
 * 2nd Edition
 */

#ifndef _TSK_ISO9660_H
#define _TSK_ISO9660_H

/* This part borrowed from the bsd386 isofs */
#define ISODCL(from, to) (to - from + 1)

/*
 * Constants
 */
#define ISO9660_FIRSTINO	0
#define ISO9660_ROOTINO		0
#define ISO9660_FILE_CONTENT_LEN sizeof(TSK_DADDR_T)
#define ISO9660_SBOFF		32768
#define ISO9660_SSIZE_B		2048
#define ISO9660_MIN_BLOCK_SIZE	512
#define ISO9660_MAX_BLOCK_SIZE	2048
#define ISO9660_MAGIC		"CD001"

/* values used in volume descriptor type */
#define ISO9660_BOOT_RECORD		0       /* boot record */
#define ISO9660_PRIM_VOL_DESC		1       /* primary volume descriptor */
#define ISO9660_SUPP_VOL_DESC		2       /* supplementary volume descriptor */
#define ISO9660_VOL_PART_DESC		3       /* volume partition descriptor */
#define ISO9660_RESERVE_FLOOR		4       /* 4-254 are reserved */
#define ISO9660_RESERVE_CEIL		254
#define ISO9660_VOL_DESC_SET_TERM	255     /* volume descriptor set terminator */

#define ISO9660_MAXNAMLEN_STD	128     ///< Maximum length of standard name
#define ISO9660_MAXNAMLEN_JOL   128     ///< maximum UTF-16 joliet name (in bytes)
#define ISO9660_MAXNAMLEN   (ISO9660_MAXNAMLEN_JOL << 1)        // mult jol by 2 to account for UTF-16 to UTF-8 conversion

/* Bits in permissions used in extended attribute records.  */
#define ISO9660_BIT_UR	0x0010
#define ISO9660_BIT_UX	0x0040
#define ISO9660_BIT_GR	0x0100
#define ISO9660_BIT_GX	0x0400
#define ISO9660_BIT_AR	0x1000
#define ISO9660_BIT_AX	0x4000

/* directory descriptor flags */
#define ISO9660_FLAG_HIDE	0x01    /* Hide file -- called EXISTENCE */
#define ISO9660_FLAG_DIR	0x02    /* Directory */
#define ISO9660_FLAG_ASSOC	0x04    /* File is associated */
#define ISO9660_FLAG_RECORD	0X08    /* Record format in extended attr */
#define ISO9660_FLAG_PROT	0X10    /* No read / exec perm in ext attr */
#define ISO9660_FLAG_RES1	0X20    /* reserved */
#define ISO9660_FLAG_RES2	0x40    /* reserved */
#define ISO9660_FLAG_MULT	0X80    /* not final entry of mult ext file */

/* POSIX modes used in ISO9660 not already defined */
#define MODE_IFSOCK 0140000     /* socket */
#define MODE_IFLNK  0120000     /* symbolic link */
#define MODE_IFDIR  0040000     /* directory */
#define MODE_IFIFO  0010000     /* pipe or fifo */
#define MODE_IFBLK  0060000     /* block special */
#define MODE_IFCHR  0020000     /* character special */

/* used to determine if get directory entry function needs to handle Joliet */
#define ISO9660_TYPE_PVD	0
#define ISO9660_TYPE_SVD	1

#define ISO9660_CTYPE_ASCII 0
#define ISO9660_CTYPE_UTF16 1





/* recording date and time */
typedef struct {
    uint8_t year;               /* years since 1900 */
    uint8_t month;              /* 1-12 */
    uint8_t day;                /* 1-31 */
    uint8_t hour;               /* 0-23 */
    uint8_t min;                /* 0-59 */
    uint8_t sec;                /* 0-59 */
    int8_t gmt_off;             /* greenwich mean time offset (in 15 minute intervals) */
} record_data;

/* iso 9660 directory record */
typedef struct {
    uint8_t entry_len;          /* length of directory record */
    uint8_t ext_len;            /* extended attribute record length */
    uint8_t ext_loc_l[4];       /* location of extent - le */
    uint8_t ext_loc_m[4];       /* location of extent - be */
    uint8_t data_len_l[4];      /* data length - le */
    uint8_t data_len_m[4];      /* data length - be */
    record_data rec_time;       /* recording date and time (7 bytes) */
    int8_t flags;               /* file flags */
    uint8_t unit_sz;            /* file unit size */
    uint8_t gap_sz;             /* interleave gap size */
    uint8_t seq[4];             /* volume sequence number (2|16) */
    uint8_t fi_len;             /* length of file identifier in bytes */
} iso9660_dentry;

/* This is a dummy struct used to make reading an entire PVD easier,
 * due to the fact that the root directory has a 1 byte name that
 * wouldn't be worth adding to the regular struct.
 */
typedef struct {
    uint8_t length;             /* length of directory record */
    uint8_t ext_len;            /* extended attribute record length */
    uint8_t ext_loc_l[4];       /* location of extent - le */
    uint8_t ext_loc_m[4];       /* location of extent - be */
    uint8_t data_len_l[4];      /* data length - le */
    uint8_t data_len_m[4];      /* data length - be */
    record_data rec;            /* recording date and time */
    int8_t flags;               /* file flags */
    uint8_t unit_sz;            /* file unit size */
    uint8_t gap_sz;             /* interleave gap size */
    uint8_t seq[4];             /* volume sequence number (2|16) */
    uint8_t len;                /* length of file identifier */
    char name;
} iso9660_root_dentry;


/* data and time format
 * all are stored as "digits" according to specifications for iso9660
 */
typedef struct {
    uint8_t year[4];            /* 1 to 9999 */
    uint8_t month[2];           /* 1 to 12 */
    uint8_t day[2];             /* 1 to 31 */
    uint8_t hour[2];            /* 0 to 23 */
    uint8_t min[2];             /* 0 to 59 */
    uint8_t sec[2];             /* 0 to 59 */
    uint8_t hun[2];             /* hundredths of a second */
    uint8_t gmt_off;            /* GMT offset */
} date_time;


/* generic volume descriptor */
typedef struct {
    uint8_t type;               ///<  volume descriptor type 
    char magic[ISODCL(2, 6)];   ///< magic number. "CD001" 
    char ver[ISODCL(7, 7)];     ///< volume descriptor version 
    char x[ISODCL(8, 2048)];    ///< Depends on descriptor type
} iso9660_gvd;

/* primary volume descriptor */
typedef struct {
    char unused1[ISODCL(1, 8)]; /* should be 0.  unused. */
    char sys_id[ISODCL(9, 40)]; /* system identifier */
    char vol_id[ISODCL(41, 72)];        /* volume identifier */
    char unused2[ISODCL(73, 80)];       /* should be 0.  unused. */
    uint8_t vs_sz_l[ISODCL(81, 84)];    /* volume space size in blocks - le */
    uint8_t vs_sz_m[ISODCL(85, 88)];    /* volume space size in blocks - be */
    char unused3[ISODCL(89, 120)];      /* should be 0.  unused. */
    uint8_t vol_set_l[ISODCL(121, 122)];        /* volume set size - le */
    uint8_t vol_set_m[ISODCL(123, 124)];        /* volume set size - be */
    uint8_t vol_seq_l[ISODCL(125, 126)];        /* volume sequence number -le  */
    uint8_t vol_seq_m[ISODCL(127, 128)];        /* volume sequence number - be */
    uint8_t blk_sz_l[ISODCL(129, 130)]; /* logical block size - le */
    uint8_t blk_sz_m[ISODCL(131, 132)]; /* logical block size - be */
    uint8_t pt_size_l[ISODCL(133, 136)];        /* path table size in bytes - le */
    uint8_t pt_size_m[ISODCL(137, 140)];        /* path table size in bytes - be  */
    uint8_t pt_loc_l[ISODCL(141, 144)]; /* log block addr of type L path tbl. */
    uint8_t pt_opt_loc_l[ISODCL(145, 148)];     /* log block addr of optional L path tbl */
    uint8_t pt_loc_m[ISODCL(149, 152)]; /* log block addr of type M path tbl. */
    uint8_t pt_opt_loc_m[ISODCL(153, 156)];     /* log block addr of optional M path tbl */
    iso9660_root_dentry dir_rec;        /* directory record for root dir */
    char vol_setid[ISODCL(191, 318)];   /* volume set identifier */
    unsigned char pub_id[ISODCL(319, 446)];     /* publisher identifier */
    unsigned char prep_id[ISODCL(447, 574)];    /* data preparer identifier */
    unsigned char app_id[ISODCL(575, 702)];     /* application identifier */
    unsigned char copy_id[ISODCL(703, 739)];    /* copyright file identifier */
    unsigned char abs_id[ISODCL(740, 776)];     /* abstract file identifier */
    unsigned char bib_id[ISODCL(777, 813)];     /* bibliographic file identifier */
    date_time make_date;        /* volume creation date/time */
    date_time mod_date;         /* volume modification date/time */
    date_time exp_date;         /* volume expiration date/time */
    date_time ef_date;          /* volume effective date/time */
    uint8_t fs_ver;             /* file structure version */
    char res[ISODCL(883, 883)]; /* reserved */
    char app_use[ISODCL(884, 1395)];    /* application use */
    char reserv[ISODCL(1396, 2048)];    /* reserved */
} iso9660_pvd;

/* supplementary volume descriptor */
typedef struct {
    uint8_t flags[ISODCL(1, 8)];        /* volume flags */
    char sys_id[ISODCL(9, 40)]; /* system identifier */
    char vol_id[ISODCL(41, 72)];        /* volume identifier */
    char unused2[ISODCL(73, 80)];       /* should be 0.  unused. */
    uint8_t vs_sz_l[ISODCL(81, 84)];    /* volume space size in blocks - le */
    uint8_t vs_sz_m[ISODCL(85, 88)];    /* volume space size in blocks - be */
    uint8_t esc_seq[ISODCL(89, 120)];   /* escape sequences */
    uint8_t vol_set_l[ISODCL(121, 122)];        /* volume set size - le */
    uint8_t vol_set_m[ISODCL(123, 124)];        /* volume set size - be */
    uint8_t vol_seq_l[ISODCL(125, 126)];        /* volume sequence number -le  */
    uint8_t vol_seq_m[ISODCL(127, 128)];        /* volume sequence number - be */
    uint8_t blk_sz_l[ISODCL(129, 130)]; /* logical block size - le */
    uint8_t blk_sz_m[ISODCL(131, 132)]; /* logical block size - be */
    uint8_t pt_size_l[ISODCL(133, 136)];        /* path table size in bytes - le */
    uint8_t pt_size_m[ISODCL(137, 140)];        /* path table size in bytes - be  */
    uint8_t pt_loc_l[ISODCL(141, 144)]; /* log block addr of type L path tbl. */
    uint8_t pt_opt_loc_l[ISODCL(145, 148)];     /* log block addr of optional type L path tbl. */
    uint8_t pt_loc_m[ISODCL(149, 152)]; /* log block addr of type M path tbl. */
    uint8_t pt_opt_loc_m[ISODCL(153, 156)];     /* log block addr of optional type M path tbl. */
    iso9660_root_dentry dir_rec;        /* directory record for root dir */
    char vol_setid[ISODCL(191, 318)];   /* volume set identifier */
    unsigned char pub_id[ISODCL(319, 446)];     /* publisher identifier */
    unsigned char prep_id[ISODCL(447, 574)];    /* data preparer identifier */
    unsigned char app_id[ISODCL(575, 702)];     /* application identifier */
    unsigned char copy_id[ISODCL(703, 739)];    /* copyright file identifier */
    unsigned char abs_id[ISODCL(740, 776)];     /* abstract file identifier */
    unsigned char bib_id[ISODCL(777, 813)];     /* bibliographic file identifier */
    date_time make_date;        /* volume creation date/time */
    date_time mod_date;         /* volume modification date/time */
    date_time exp_date;         /* volume expiration date/time */
    date_time ef_date;          /* volume effective date/time */
    char fs_ver[ISODCL(882, 882)];      /* file structure version */
    char res[ISODCL(883, 883)]; /* reserved */
    char app_use[ISODCL(884, 1395)];    /* application use */
    char reserv[ISODCL(1396, 2048)];    /* reserved */
} iso9660_svd;

/* iso 9660 boot record */
typedef struct {
    char boot_sys_id[ISODCL(8, 39)];    /* boot system identifier */
    char boot_id[ISODCL(40, 71)];       /* boot identifier */
    char system_use[ISODCL(72, 2048)];  /* system use */
} iso_bootrec;

/* path table record */
typedef struct {
    uint8_t len_di;             /* length of directory identifier */
    uint8_t attr_len;           /* extended attribute record length */
    uint8_t ext_loc[4];         /* location of extent */
    uint8_t par_dir[2];         /* parent directory number (its entry in the path table) */
} path_table_rec;

/* extended attribute record */
typedef struct {
    uint8_t uid[ISODCL(1, 4)];  /* owner identification */
    uint8_t gid[ISODCL(5, 8)];  /* group identification */
    uint8_t mode[ISODCL(9, 10)];        /* permissions */
    uint8_t cre[ISODCL(11, 27)];        /* file creation date/time */
    uint8_t mod[ISODCL(28, 44)];        /* file modification d/t */
    uint8_t exp[ISODCL(45, 61)];        /* file expiration d/t */
    uint8_t eff[ISODCL(62, 78)];        /* file effective d/t */
    uint8_t fmt[ISODCL(79, 79)];        /* record format */
    uint8_t attr[ISODCL(80, 80)];       /* record attributes */
    uint8_t len[ISODCL(81, 84)];        /* record length */
    uint8_t sys_id[ISODCL(85, 116)];    /* system identifier */
    uint8_t uns[ISODCL(117, 180)];      /* system use, not specified */
    uint8_t e_ver[ISODCL(181, 181)];    /* extended attribute record version */
    uint8_t len_esc[ISODCL(182, 182)];  /* length of escape sequences */
} ext_attr_rec;


#define ISO_EA_IRSYS    0x0001
#define ISO_EA_IWSYS    0x0002
#define ISO_EA_IXSYS    0x0004
#define ISO_EA_IRUSR    0x0010
#define ISO_EA_IWUSR    0x0020
#define ISO_EA_IXUSR    0x0040
#define ISO_EA_IRGRP    0x0100
#define ISO_EA_IWGRP    0x0200
#define ISO_EA_IXGRP    0x0400
#define ISO_EA_IROTH    0x1000
#define ISO_EA_IWOTH    0x2000
#define ISO_EA_IXOTH    0x4000


/* primary volume descriptor linked list node */
typedef struct iso9660_pvd_node {
    iso9660_pvd pvd;
    struct iso9660_pvd_node *next;
} iso9660_pvd_node;

/* supplementary volume descriptor linked list node */
typedef struct iso9660_svd_node {
    iso9660_svd svd;
    struct iso9660_svd_node *next;
} iso9660_svd_node;

/* RockRidge extension info */
typedef struct {
    TSK_UID_T uid /* owner */ ;
    TSK_GID_T gid;              /* group */
    uint16_t mode;              /* posix file mode */
    uint32_t nlink;             /* number of links */
    char fn[ISO9660_MAXNAMLEN_STD];     /* alternate filename */
} rockridge_ext;

/** \internal
 * Internally used structure to hold basic inode information.
 */
typedef struct {
    iso9660_dentry dr;          /* directory record */
    ext_attr_rec *ea;           /* extended attribute record */
    char fn[ISO9660_MAXNAMLEN + 1];     /* file name */
    rockridge_ext *rr;          /* RockRidge Extensions */
    int version;
    uint8_t is_orphan;          /* 1 if the file was found from processing other volume descriptors besides the first one, 0 otherwise */
    TSK_OFF_T susp_off;         ///< Byte offset in image of SUSP (or NULL)
    TSK_OFF_T susp_len;         ///< Length in bytes of SUSP
} iso9660_inode;

/* inode linked list node */
typedef struct iso9660_inode_node {
    iso9660_inode inode;
    TSK_OFF_T offset;           /* byte offset of first block of file in file system */
    TSK_OFF_T dentry_offset;    /* byte offset of directory entry structure in file system */
    TSK_INUM_T inum;            /* identifier of inode (assigned by TSK) */
    int size;                   /* number of bytes in file */
    int ea_size;                /* length of ext attributes */
    struct iso9660_inode_node *next;
} iso9660_inode_node;

/* The all important ISO_INFO struct */
typedef struct {
    TSK_FS_INFO fs_info;        /* SUPER CLASS */
    uint32_t path_tab_addr;     /* address of path table */
    uint32_t root_addr;         /* address of root dir extent */
    iso9660_pvd_node *pvd;      ///< Head of primary volume descriptor list (there should be only one...)
    iso9660_svd_node *svd;      ///< Head of secondary volume descriptor list 
    iso9660_inode_node *in_list;        /* list of inodes */
    uint8_t rr_found;           /* 1 if rockridge found */
} ISO_INFO;

extern TSK_RETVAL_ENUM iso9660_dir_open_meta(TSK_FS_INFO * a_fs,
    TSK_FS_DIR ** a_fs_dir, TSK_INUM_T a_addr);

extern uint8_t iso9660_dinode_load(ISO_INFO * iso, TSK_INUM_T inum,
    iso9660_inode * dinode);

extern int iso9660_name_cmp(TSK_FS_INFO *, const char *, const char *);

/**********************************************************
 *
 * RockRidge Extensions
 *
 **********************************************************/


typedef struct {
    char sig[2];
    uint8_t len;
    char ver;
} iso9660_susp_head;


/**  \internal
 * SUSP Continuation Entry (CE)
 */
typedef struct {
    char sig[2];
    uint8_t len;
    char ver;
    uint8_t blk_l[4];           ///< Block location of continuation area
    uint8_t blk_m[4];
    uint8_t offset_l[4];        ///< Offset to start of continuation area (in bytes)
    uint8_t offset_m[4];
    uint8_t celen_l[4];         ///< Length of continuation area (in bytes)
    uint8_t celen_m[4];
} iso9660_susp_ce;

/**  \internal
 * SUSP SP entry
 */
typedef struct {
    char sig[2];
    uint8_t len;
    char ver;
    uint8_t chk[2];
    uint8_t skip;
} iso9660_susp_sp;

typedef struct {
    char sig[2];
    uint8_t len;
    char ver;
    uint8_t len_id;             ///< length of extension id (in bytes)
    uint8_t len_des;            ///< length of extension desc (in bytes)
    uint8_t len_src;            ///< Length of extension spec source (in bytes)
    uint8_t ext_ver;            ///< Version id 
    char ext_id[1];             ///< Extension ID text (with length of len_id);
    // next is the extension descriptor text
    // next is the extension source text
} iso9660_susp_er;


/* Rockridge ISO9660 system use field entry */
typedef struct {
    char sig[ISODCL(1, 2)];     /* signature, should be "RR" */
    uint8_t len[ISODCL(3, 3)];  /* length of system use entry */
    uint8_t ver[ISODCL(4, 4)];  /* system use entry version */
    uint8_t foo[ISODCL(5, 5)];  /* foo */
} rr_sys_use;

/* Rockridge PX entry */
typedef struct {
    char sig[ISODCL(1, 2)];     /* signature, should be "PX" */
    uint8_t len;                /* length, should be 44 */
    uint8_t ver;                /* system use entry version (1) */
    uint8_t mode_l[ISODCL(5, 8)];       /* POSIX file mode - le */
    uint8_t mode_m[ISODCL(9, 12)];      /* POSIX file mode - be */
    uint8_t links_l[ISODCL(13, 16)];    /* POSIX file links - le */
    uint8_t links_m[ISODCL(17, 20)];    /* POSIX file links - be */
    uint8_t uid_l[ISODCL(21, 24)];      /* POSIX user id - le */
    uint8_t uid_m[ISODCL(25, 28)];      /* POSIX user id - be */
    uint8_t gid_l[ISODCL(29, 32)];      /* POSIX group id - le */
    uint8_t gid_m[ISODCL(23, 36)];      /* POSIX group id - be */
    /* rockridge docs say this is here, k3b disagrees... hmmmm */
    //      uint8_t serial[ISODCL(37,44)];  /* POSIX file serial number */
} iso9660_rr_px_entry;

/* Rockridge PN entry */
typedef struct {
    char sig[ISODCL(1, 2)];     /* signature, should be "PN" */
    uint8_t len;                /* length, should be 20 */
    uint8_t ver;                /* system use entry version (1) */
    uint8_t dev_h_l[ISODCL(5, 8)];      /* top 32 bits of device # */
    uint8_t dev_h_m[ISODCL(9, 12)];     /* top 32 bits of device # */
    uint8_t dev_l_l[ISODCL(13, 16)];    /* low 32 bits of device # */
    uint8_t dev_l_m[ISODCL(17, 20)];    /* low 32 bits of device # */
} iso9660_rr_pn_entry;

/* Rockridge SL entry */
typedef struct {
    char sig[ISODCL(1, 2)];     /* signature, should be "SL" */
    uint8_t len;                /* length */
    uint8_t ver;                /* system use entry version (1) */
    uint8_t flags;              /* flags */
} iso9660_rr_sl_entry;

/* Rockridge NM entry */
typedef struct {
    char sig[ISODCL(1, 2)];     /* signature, should be "NM" */
    uint8_t len;                /* length of alternate name */
    uint8_t ver[ISODCL(4, 4)];  /* system use entry version (1) */
    uint8_t flags[ISODCL(5, 5)];        /* flags */
    char name[1];               // start of the name
} iso9660_rr_nm_entry;

/* Rockridge CL entry */
typedef struct {
    char sig[ISODCL(1, 2)];     /* signature, should be "CL" */
    uint8_t len[ISODCL(3, 3)];  /* length, should be 12 */
    uint8_t ver[ISODCL(4, 4)];  /* system use entry version (1) */
    uint8_t par_loc[ISODCL(5, 12)];     /* location of parent directory */
} iso9660_rr_cl_entry;

/* Rockridge RE entry */
typedef struct {
    char sig[ISODCL(1, 2)];     /* signature, should be "RE" */
    uint8_t len[ISODCL(3, 3)];  /* length, should be 4 */
    uint8_t ver[ISODCL(4, 4)];  /* system use entry version (1) */
} iso9660_rr_re_entry;

/* Rockridge TF entry */
typedef struct {
    char sig[ISODCL(1, 2)];     /* signature, should be "TF" */
    uint8_t len[ISODCL(3, 3)];  /* length of TF entry */
    uint8_t ver[ISODCL(4, 4)];  /* system use entry version (1) */
    uint8_t flags[ISODCL(5, 5)];        /* flags */
} iso9660_rr_tf_entry;

/* Rockridge SF entry */
typedef struct {
    char sig[ISODCL(1, 2)];     /* signature, should be "SF" */
    uint8_t len[ISODCL(3, 3)];  /* length, should be 21 */
    uint8_t ver[ISODCL(4, 4)];  /* system use entry version (1) */
    uint8_t vfs_h[ISODCL(5, 12)];       /* virtual file size high */
    uint8_t vfs_l[ISODCL(13, 20)];      /* virtual file size low */
    uint8_t depth[ISODCL(21, 21)];      /* table depth */
} iso9660_rr_sf_entry;

#endif
