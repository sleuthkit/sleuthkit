/*
** The Sleuth Kit
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2003-2011 Brian Carrier.  All rights reserved
**
** TASK
** Copyright (c) 2002 @stake Inc.  All rights reserved
**
** This software is distributed under the Common Public License 1.0
*/

/*
 * Contains the structures and function APIs for NTFS file system support.
 */


#ifndef _TSK_NTFS_H
#define _TSK_NTFS_H

#ifdef __cplusplus
extern "C" {
#endif


// the SID code has been buggy on some systems and byitself it does
// not provide much security info.  It is being disabled until fixed. 
#define TSK_USE_SID 1

//#define NTFS_FS_MAGIC 0x5346544E      /* "NTFS" in little endian */
#define NTFS_FS_MAGIC	0xAA55

#define NTFS_MAXNAMLEN	256
#define NTFS_MAXNAMLEN_UTF8	4 * NTFS_MAXNAMLEN

/* location of the Root Directory inode */
#define NTFS_ROOTINO	NTFS_MFT_ROOT
#define NTFS_FIRSTINO	0       /* location of the $Mft Record */
#define NTFS_LAST_DEFAULT_INO	16      /* A guess for right now */

#define NTFS_FILE_CONTENT_LEN 0

/* uncompression values */
#define NTFS_TOKEN_MASK   1
#define NTFS_SYMBOL_TOKEN 0
#define NTFS_TOKEN_LENGTH 8
/* (64 * 1024) = 65536 */
#define NTFS_MAX_UNCOMPRESSION_BUFFER_SIZE 65536



/************************************************************************
 * Update sequence structure.  This is located at upd_off from the
 * begining of the original structure
 */
    typedef struct {
        uint8_t upd_val[2];     // what they should be 
        uint8_t upd_seq;        // array of size 2*(upd_cnt-1) w/orig vals
    } ntfs_upd;


/************************************************************************
 * bootsector
 *
 * located in sector 0 in $Boot
 */
    typedef struct {
        uint8_t f1[3];          // 0
        char oemname[8];        // 3
        uint8_t ssize[2];       // 11   /* sector size in bytes */
        uint8_t csize;          // 13  /* sectors per cluster */
        uint8_t f2[26];         // 14
        uint8_t vol_size_s[8];  // 40   /*size of volume in sectors */
        uint8_t mft_clust[8];   // 48   /* location of MFT */
        uint8_t mftm_clust[8];  // 56    /* location of MFT mirror */
        int8_t mft_rsize_c;     // 64      /* number of clusters per mft record */
        uint8_t f3[3];
        int8_t idx_rsize_c;     // 68      /* number of clus per idx rec */
        uint8_t f4[3];
        uint8_t serial[8];      // 72   /* serial number */
        uint8_t f5[430];        //80
        uint8_t magic[2];
    } ntfs_sb;



/************************************************************************
 * MFT Entry
 *
 * One entry in the MFT - there exists one for each file
 */
    typedef struct {
        uint8_t magic[4];
        uint8_t upd_off[2];     // 4
        uint8_t upd_cnt[2];     // 6  size+1
        uint8_t lsn[8];         // 8  $LogFile Sequence Number
        uint8_t seq[2];         // 16
        uint8_t link[2];        // 18
        uint8_t attr_off[2];    // 20
        uint8_t flags[2];       // 22
        uint8_t size[4];        // 24
        uint8_t alloc_size[4];  //28
        uint8_t base_ref[6];    // 32 
        uint8_t base_seq[2];    // 38 
        uint8_t next_attrid[2]; // 40 The next id to be assigned
        uint8_t f1[2];          // XP Only
        uint8_t entry[4];       // XP Only - Number of this entry
    } ntfs_mft;

/* Magic values for each MFT entry */
#define NTFS_MFT_MAGIC	0x454c4946
#define NTFS_MFT_MAGIC_BAAD	0x44414142
#define NTFS_MFT_MAGIC_ZERO	0x00000000

/* MFT entry flags */
#define NTFS_MFT_INUSE	0x0001
#define NTFS_MFT_DIR	0x0002

/* flags for file_ref */
#define NTFS_MFT_BASE		0       /* set when the base file record */
/* Mask when not zero, which indicates the base file record */
#define NTFS_MFT_FILE_REC	0x00ffffffffffffff

/* DEFINED MFT entries - file system metadata files */
#define NTFS_MFT_MFT	0x0
#define NTFS_MFT_MFTMIR	0x1
#define NTFS_MFT_LOG	0x2
#define NTFS_MFT_VOL	0x3
#define NTFS_MFT_ATTR	0x4
#define NTFS_MFT_ROOT	0x5
#define NTFS_MFT_BMAP	0x6
#define NTFS_MFT_BOOT	0x7
#define NTFS_MFT_BAD	0x8
//#define NTFS_MFT_QUOT 0x9
#define NTFS_MFT_SECURE	0x9
#define NTFS_MFT_UPCASE	0xA



/************************************************************************
 * Attribute Header for resident and non-resident attributes
 */
    typedef struct {
        uint8_t type[4];
        uint8_t len[4];         // 4 - length including header
        uint8_t res;            // 8 - resident flag
        uint8_t nlen;           // 9 - name length
        uint8_t name_off[2];    // 10 - offset to name 
        uint8_t flags[2];       // 12  
        uint8_t id[2];          // 14 - unique identifier

        union {
            /* Resident Values */
            struct {
                uint8_t ssize[4];       // 16 - size of content
                uint8_t soff[2];        // 20 - offset to content (after name)
                uint8_t idxflag[2];     // 22 - indexed flag 
            } r;
            /* Non-resident Values */
            struct {
                uint8_t start_vcn[8];   // 16 - starting VCN of this attribute
                uint8_t last_vcn[8];    // 24
                uint8_t run_off[2];     // 32 - offset to the data runs (after name)
                uint8_t compusize[2];   // 34 - compression unit size (2^x)
                uint8_t f1[4];  // 36
                uint8_t alen[8];        // 40   allocated size of stream
                uint8_t ssize[8];       // 48   actual size of stream
                uint8_t initsize[8];    // 56   initialized steam size
            } nr;
        } c;
    } ntfs_attr;

/* values for the res field */
#define NTFS_MFT_RES	0       /* resident */
#define NTFS_MFT_NONRES	1       /* non-resident */


/* Values for flag field 
 * should only exist for $DATA attributes */
#define NTFS_ATTR_FLAG_COMP	0x0001  /* compressed */
#define NTFS_ATTR_FLAG_ENC	0x4000  /* encrypted */
#define NTFS_ATTR_FLAG_SPAR	0x8000  /* sparse */



/* values for the type field */
/* NOTE that the default TSK attribute types are based on these.
 * Any changes to these should be merged with the defines in tsk_fs.h */
#define NTFS_ATYPE_SI       0x10        // 16
#define NTFS_ATYPE_ATTRLIST 0x20        // 32
#define NTFS_ATYPE_FNAME    0x30        // 48
#define NTFS_ATYPE_VVER     0x40        // 64 (NT)
#define NTFS_ATYPE_OBJID    0x40        // 64 (2K)
#define NTFS_ATYPE_SEC      0x50        // 80
#define NTFS_ATYPE_VNAME    0x60        // 96
#define NTFS_ATYPE_VINFO    0x70        // 112
#define NTFS_ATYPE_DATA     0x80        // 128
#define NTFS_ATYPE_IDXROOT  0x90        // 144
#define NTFS_ATYPE_IDXALLOC 0xA0        // 160
#define NTFS_ATYPE_BITMAP   0xB0        // 176
#define NTFS_ATYPE_SYMLNK   0xC0        // 192 (NT)
#define NTFS_ATYPE_REPARSE  0xC0        // 192 (2K)
#define NTFS_ATYPE_EAINFO   0xD0        // 208
#define NTFS_ATYPE_EA       0xE0        // 224
#define NTFS_ATYPE_PROP     0xF0        //  (NT)
#define NTFS_ATYPE_LOG      0x100       //  (2K)




/************************************************************************
 * File Name Attribute
 */
    typedef struct {
        uint8_t par_ref[6];     /* file reference to base File Record of parent */
        uint8_t par_seq[2];     /* seq num to base File Record of parent */
        uint8_t crtime[8];      /* file creation */
        uint8_t mtime[8];       /* file altered */
        uint8_t ctime[8];       /* mod time for FILE record (MFT Entry) */
        uint8_t atime[8];       /* access time */
        uint8_t alloc_fsize[8];
        uint8_t real_fsize[8];
        uint8_t flags[8];
        uint8_t nlen;           /* length of file name */
        uint8_t nspace;
        uint8_t name;           /* in unicode */
    } ntfs_attr_fname;

/* values for the flags field of attr_fname */
#define	NTFS_FNAME_FLAGS_RO		0x0000000000000001
#define	NTFS_FNAME_FLAGS_HID	0x0000000000000002
#define	NTFS_FNAME_FLAGS_SYS	0x0000000000000004
#define	NTFS_FNAME_FLAGS_ARCH	0x0000000000000020
#define	NTFS_FNAME_FLAGS_DEV	0x0000000000000040
#define	NTFS_FNAME_FLAGS_NORM	0x0000000000000080
#define	NTFS_FNAME_FLAGS_TEMP	0x0000000000000100
#define	NTFS_FNAME_FLAGS_SPAR	0x0000000000000200
#define	NTFS_FNAME_FLAGS_REP	0x0000000000000400
#define	NTFS_FNAME_FLAGS_COMP	0x0000000000000800
#define	NTFS_FNAME_FLAGS_OFF	0x0000000000001000
#define	NTFS_FNAME_FLAGS_NOIDX	0x0000000000002000
#define	NTFS_FNAME_FLAGS_ENC	0x0000000000004000
#define	NTFS_FNAME_FLAGS_DIR		0x0000000010000000
#define	NTFS_FNAME_FLAGS_IDXVIEW	0x0000000020000000


/* values for the name space values of nspace */
#define NTFS_FNAME_POSIX	0       /* case sensitive  and any but NULL and \ */
#define NTFS_FNAME_WIN32	1       // insensitive and restricted
#define NTFS_FNAME_DOS		2       // 8.3 format of 8-bit chars in uppercase
#define NTFS_FNAME_WINDOS	3       // name in WIN32 space that is already DOS




/************************************************************************
 * Standard Information Attribute
 */
    typedef struct {
        uint8_t crtime[8];      /* creation date */
        uint8_t mtime[8];       /* file altered */
        uint8_t ctime[8];       /* MFT Changed */
        uint8_t atime[8];       /* last access (read) */
        uint8_t dos[4];         /* permissions in DOS Format */
        uint8_t maxver[4];
        uint8_t ver[4];
        uint8_t class_id[4];
        uint8_t own_id[4];
        uint8_t sec_id[4];
        uint8_t quota[8];
        uint8_t usn[8];
    } ntfs_attr_si;


/* DOS Flags values */
#define NTFS_SI_RO		0x0001
#define NTFS_SI_HID		0x0002
#define NTFS_SI_SYS		0x0004
#define NTFS_SI_ARCH	0x0020
#define NTFS_SI_DEV		0x0040
#define NTFS_SI_NORM	0x0080
#define NTFS_SI_TEMP	0x0100
#define NTFS_SI_SPAR	0x0200
#define NTFS_SI_REP		0x0400
#define NTFS_SI_COMP	0x0800
#define NTFS_SI_OFF		0x1000
#define NTFS_SI_NOIDX	0x2000
#define NTFS_SI_ENC		0x4000



/************************************************************************
 * Volume Info Attribute
 */
    typedef struct {
        uint8_t f1[8];
        uint8_t maj_ver;
        uint8_t min_ver;
        uint8_t flags[2];
        uint8_t f2[4];
    } ntfs_attr_vinfo;

#define NTFS_VINFO_DIRTY	0x0001  // Dirty
#define NTFS_VINFO_RESLOG	0x0002  // Resize LogFile
#define NTFS_VINFO_UPGRAD	0x0004  // Upgrade on Mount
#define NTFS_VINFO_MNTNT4	0x0008  // Mounted on NT4
#define NTFS_VINFO_DELUSN	0x0010  // Delete USN Underway
#define NTFS_VINFO_REPOBJ	0x0020  // Repair Object Ids
#define NTFS_VINFO_MODCHK	0x8000  // Modified by chkdsk

/* versions 
 * NT = Maj=1 Min=2
 * 2k = Maj=3 Min=0
 * xp = Maj=3 Min=1
 */

#define NTFS_VINFO_NT		0x21
#define NTFS_VINFO_2K		0x03
#define NTFS_VINFO_XP		0x13




/************************************************************************
 * attribute list 
 */
    typedef struct {
        uint8_t type[4];        // Attribute Type
        uint8_t len[2];         // length of entry
        uint8_t nlen;           // number of chars in name
        uint8_t f1;             // 7
        uint8_t start_vcn[8];   // starting VCN or NTFS_ATTRL_RES 
        uint8_t file_ref[6];    // file reference to new MFT entry
        uint8_t seq[2];         // 22
        uint8_t id[2];          // id (also in the attribute header)
        uint8_t name;           // 26  name in unicode
    } ntfs_attrlist;

#define NTFS_ATTRL_RES	0




/************************************************************************
 * runlist
 * 
 * Used to store the non-resident runs for an attribute.
 * It is located in the MFT and pointed to by the run_off in the header
 */

    typedef struct {
        /* lsb 4 bits: num of bytes in run length field
         * msb 4 bits: num of bytes in run offset field - (LCN)
         */
        uint8_t len;
        uint8_t buf[32];
    } ntfs_runlist;

#define NTFS_RUNL_LENSZ(runl)	\
	(uint8_t)(runl->len & 0x0f)

#define NTFS_RUNL_OFFSZ(runl)	\
	(uint8_t)((runl->len & 0xf0) >> 4)


/************************************************************************
 * Index root for directories 
 * 
 * the attribute has two parts.  The header is general to all index entries
 * and applies to $IDX_ALLOC as well. The buffer part contains the
 * index entries that are allocated to $IDX_ROOT.
 *
 */

/*
 * Starting at begin_off is a stream of ntfs_idxentry structures 
 */
    typedef struct {
        uint8_t begin_off[4];   /* offset to start of seq of idx entries */
        uint8_t seqend_off[4];  /* offset to end of seq of idx entries */
        uint8_t bufend_off[4];  /* offset to end of idx buffer */
        uint8_t flags[4];
    } ntfs_idxelist;

/* value for flags */
#define NTFS_IDXELIST_CHILD	0x1     /* children exist below this node */



/* This is general index information and applies to $IDX_ALLOC as well */
    typedef struct {
        uint8_t type[4];        /* ATYPE that tree is sorted by */
        uint8_t collation_rule[4];
        uint8_t idxalloc_size_b[4];     /* index alloc size in bytes */
        uint8_t idx_size_c;     /* index alloc size in clusters */
        uint8_t pad[3];
        ntfs_idxelist list;
    } ntfs_idxroot;



/************************************************************************
 * idxrec
 *
 * this is structure for the nodes of the B+ index trees
 * It contains a list of index entry data structures.  Each
 * buffer corresponds to one node.  The $IDX_ALLOC attribute
 * is an array of these data structures 
 */


    typedef struct {
        uint8_t magic[4];       /* INDX */
        uint8_t upd_off[2];
        uint8_t upd_cnt[2];     /* size + 1 */
        uint8_t lsn[8];         /*  $LogFile Sequence Number */
        uint8_t idx_vcn[8];     /* vcn in idx alloc attr */
        ntfs_idxelist list;
    } ntfs_idxrec;


#define NTFS_IDXREC_MAGIC	0x58444e49      /* INDX */



/************************************************************************
 * This structure exists for each file and directory in the tree */
    typedef struct {
        uint8_t file_ref[6];    /* file reference (invalid for last entry) */
        uint8_t seq_num[2];     /* file reference (invalid for last entry) */
        uint8_t idxlen[2];      /* length of the index entry */
        uint8_t strlen[2];      /* length of stream */
        uint8_t flags;
        uint8_t f1[3];
        uint8_t stream;         /* length of strlen - invalid for last entry */
        /* loc of subnode is found in last 8-bytes
         * of idx entry (idxlen - 8).  use macro 
         */
    } ntfs_idxentry;

#define NTFS_IDX_SUB	0x01    /* Entry points to a sub-node */
#define NTFS_IDX_LAST	0x02    /* last indx entry in the node */

/* return the address of the subnode entry, it is located in the last
 * 8 bytes of the structure 
 */
#define GET_IDXENTRY_SUB(fs, e)	\
	(tsk_getu64(fs->endian, (int)e + tsk_getu16(fs->endian, e->idxlen) - 8))



/************************************************************************
*/

    typedef struct {
        char label[128];        /* label in unicode */
        uint8_t type[4];
        uint8_t disp[4];        /* display rule */
        uint8_t coll[4];        /* collation rule */
        uint8_t flags[4];
        uint8_t minsize[8];     /* minimum size */
        uint8_t maxsize[8];     /* maximum size */
    } ntfs_attrdef;

#define NTFS_ATTRDEF_FLAGS_IDX	0x02
#define NTFS_ATTRDEF_FLAGS_RES	0x40    /* always resident */
#define NTFS_ATTRDEF_FLAGS_NONRES	0x80    /* allowed to be non-resident */



/************************************************************************
 * OBJECT_ID attribute
*/

    typedef struct {
        uint8_t objid1[8];      /* object id of file or directory */
        uint8_t objid2[8];
        uint8_t orig_volid1[8]; /* id of "birth" volume */
        uint8_t orig_volid2[8];
        uint8_t orig_objid1[8]; /* original object id */
        uint8_t orig_objid2[8];
        uint8_t orig_domid1[8]; /* id of "birth" domain */
        uint8_t orig_domid2[8];
    } ntfs_attr_objid;


#if TSK_USE_SID

/************************************************************************
 * Self-relative security descriptor
 */

    typedef struct {
        uint8_t revision;       /* Revision level of the security descriptor. */
        uint8_t pad;
        uint8_t control[2];     /* Flags qualifying the type of
                                   the descriptor as well as the following fields. */

        uint8_t owner[4];       /* Byte offset to a SID representing an object's
                                   owner. If this is NULL, no owner SID is present in
                                   the descriptor. */

        uint8_t group[4];       /* Byte offset to a SID representing an object's
                                   primary group. If this is NULL, no primary group
                                   SID is present in the descriptor. */

        uint8_t sacl[4];        /* Byte offset to a system ACL. Only valid, if
                                   SE_SACL_PRESENT is set in the control field. If
                                   SE_SACL_PRESENT is set but sacl is NULL, a NULL ACL
                                   is specified. */

        uint8_t dacl[4];        /* Byte offset to a discretionary ACL. Only valid, if
                                   SE_DACL_PRESENT is set in the control field. If
                                   SE_DACL_PRESENT is set but dacl is NULL, a NULL ACL
                                   (unconditionally granting access) is specified. */

    } ntfs_self_relative_security_descriptor;




/************************************************************************
 * Structure used in Security Descriptor lookups
 */
    typedef struct {
        char *buffer;           ///< Buffer to store data in
        size_t size;            ///< Number of bytes in buffer
        size_t used;            ///< Number of records used in the buffer (size depends on type of data stored)
    } NTFS_SXX_BUFFER;



/************************************************************************
 * SID attribute
 */

    typedef struct {
        uint8_t revision;       /* Revision */
        uint8_t sub_auth_count; /* Sub Authority Count */
        uint8_t ident_auth[6];  /* NT Authority ::NOTE:: big endian number */
        uint32_t sub_auth[1];   /* At least one sub_auth */
    } ntfs_sid;



/************************************************************************
 * SDS attribute
 */

    typedef struct {
        uint8_t hash_sec_desc[4];       /* Hash of Security Descriptor */
        uint8_t sec_id[4];      /* Security ID */
        uint8_t file_off[8];    /* Offset of this entry in this file */
        uint8_t ent_size[4];    /* Size of this entry */
        ntfs_self_relative_security_descriptor self_rel_sec_desc;       /* Self-relative Security Descriptor */
    } ntfs_attr_sds;


/************************************************************************
 * SDH attribute
 */


    typedef struct {
        uint8_t data_off[2];    /* Offset to data */
        uint8_t size[2];        /* Size of data */
        uint8_t pad1[4];        /* Padding */
        uint8_t ent_size[2];    /* Size of Index Entry */
        uint8_t key_size[2];    /* Size of Index Key */
        uint8_t flags[2];       /* Flags */
        uint8_t pad2[2];        /* Padding */
        uint8_t key_hash_sec_desc[4];   /* Hash of Security Descriptor */
        uint8_t key_sec_id[4];  /* Security ID */
        uint8_t data_hash_sec_desc[4];  /* Hash of Security Descriptor */
        uint8_t data_sec_id[4]; /* Security ID */
        uint8_t sec_desc_off[8];        /* Offset to Security Descriptor (in $SDS) */
        uint8_t sec_desc_size[4];       /* Size of Security Descriptor (in $SDS) */
        uint8_t pad3[4];        /* Padding */
    } ntfs_attr_sdh;


/************************************************************************
 * SII attribute
 */

    typedef struct {
        uint8_t data_off[2];    /* Offset to data */
        uint8_t size[2];        /* Size of data */
        uint8_t pad1[4];        /* Padding */
        uint8_t ent_size[2];    /* Size of Index Entry */
        uint8_t key_size[2];    /* Size of Index Key */
        uint8_t flags[2];       /* Flags */
        uint8_t pad2[2];        /* Padding */
        uint8_t key_sec_id[4];  /* Security ID */
        uint8_t data_hash_sec_desc[4];  /* Hash of Security Descriptor */
        uint8_t data_sec_id[4]; /* Security ID */
        uint8_t sec_desc_off[8];        /* Offset to Security Descriptor (in $SDS) */
        uint8_t sec_desc_size[4];       /* Size of Security Descriptor (in $SDS) */

    } ntfs_attr_sii;


#endif





/************************************************************************
*/
    typedef struct {
        TSK_FS_INFO fs_info;    /* super class */
        ntfs_sb *fs;
        uint8_t ver;            /* version of NTFS - uses the VINFO flag */
        TSK_FS_FILE *mft_file;  /* contains the data for the mft entry for the mft */
        const TSK_FS_ATTR *mft_data;    /* Data run for MFT entry for MFT */
        uint32_t csize_b;       /* number of bytes in a cluster */
        uint16_t ssize_b;       /* number of bytes in a sector */
        uint32_t mft_rsize_b;   /* number of bytes per mft record */
        uint32_t idx_rsize_b;   /* number of bytes per idx record */
        TSK_DADDR_T root_mft_addr;      /* address of first mft entry */

        uint8_t loading_the_MFT;        /* set to 1 when initializing the setup */

        TSK_FS_ATTR_RUN *bmap;  /* Run of bitmap for clusters (linked list) */

        /* lock protects bmap_buf, bmap_buf_off */
        tsk_lock_t lock;
        char *bmap_buf;         /* buffer to hold cached copy of bitmap (r/w shared - lock)  */
        TSK_DADDR_T bmap_buf_off;       /* offset cluster in cached bitmap  (r/w shared - lock) */

        ntfs_attrdef *attrdef;  // buffer of attrdef file contents
        size_t attrdef_len;     // length of addrdef buffer

        /* orphan_map_lock protects orphan_map */
        tsk_lock_t orphan_map_lock;
        void *orphan_map;       // map that lists par directory to its orphans. (r/w shared - lock) 

#if TSK_USE_SID
        /* sid_lock protects sii_data, sds_data */
        tsk_lock_t sid_lock;
        NTFS_SXX_BUFFER sii_data;       // (r/w shared - lock) 
        NTFS_SXX_BUFFER sds_data;       // (r/w shared - lock) 
#endif
    } NTFS_INFO;


    extern uint32_t nt2unixtime(uint64_t ntdate);
    extern uint8_t ntfs_attrname_lookup(TSK_FS_INFO *, uint16_t, char *,
        int);
    extern TSK_RETVAL_ENUM ntfs_dinode_lookup(NTFS_INFO *, char *,
        TSK_INUM_T);
    extern TSK_RETVAL_ENUM ntfs_dir_open_meta(TSK_FS_INFO * a_fs,
        TSK_FS_DIR ** a_fs_dir, TSK_INUM_T a_addr);

    extern void ntfs_orphan_map_free(NTFS_INFO * a_ntfs);

    extern int ntfs_name_cmp(TSK_FS_INFO *, const char *, const char *);

    extern uint8_t ntfs_find_file(TSK_FS_INFO * fs, TSK_INUM_T inode_toid,
        uint32_t type_toid, uint8_t type_used, uint16_t id_toid,
        uint8_t id_used, TSK_FS_DIR_WALK_FLAG_ENUM dir_walk_flags,
        TSK_FS_DIR_WALK_CB action, void *ptr);

#ifdef __cplusplus
}
#endif
#endif
