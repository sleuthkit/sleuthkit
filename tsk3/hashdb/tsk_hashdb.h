/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2003-2008 Brian Carrier.  All rights reserved
 */

/**
 * \file tsk_hashdb.h
 * External header file for hash database support.
 * Note that this file is not meant to be directly included.  
 * It is included by both libtsk.h and tsk_hashdb_i.h.
 */

/**
 * \defgroup hashdblib Hash Database Functions
 */

#ifndef _TSK_HDB_H
#define _TSK_HDB_H


#ifdef __cplusplus
extern "C" {
#endif


/**
 * Flags used for lookups
 */
    enum TSK_HDB_FLAG_ENUM {
        TSK_HDB_FLAG_QUICK = 0x01,      ///< Quickly return if hash is found (do not return file name etc.)
        TSK_HDB_FLAG_EXT = 0x02 ///< Return other details besides only file name (not used
    };
    typedef enum TSK_HDB_FLAG_ENUM TSK_HDB_FLAG_ENUM;


/**
 * Hash algorithm types
 */
    enum TSK_HDB_HTYPE_ENUM {
        TSK_HDB_HTYPE_MD5_ID = 1,       ///< MD5 Algorithm
        TSK_HDB_HTYPE_SHA1_ID = 2,      ///< SHA1 Algorithm
    };
    typedef enum TSK_HDB_HTYPE_ENUM TSK_HDB_HTYPE_ENUM;

#define TSK_HDB_HTYPE_MD5_STR	"md5"   ///< String name for MD5 algorithm
#define TSK_HDB_HTYPE_SHA1_STR	"sha1"  ///< String name for SHA1 algorithm

#define TSK_HDB_HTYPE_SHA1_LEN 40       ///< Length of SHA1 hash
#define TSK_HDB_HTYPE_MD5_LEN 32        ///< Length of MD5 hash
#define TSK_HDB_HTYPE_CRC32_LEN 8       ///< Length of CRC hash


/**
 * Return the name of the hash algorithm, given its ID
 */
#define TSK_HDB_HTYPE_STR(x) \
    ( ((x) & TSK_HDB_HTYPE_MD5_ID) ? (TSK_HDB_HTYPE_MD5_STR) : ( \
	( ((x) & TSK_HDB_HTYPE_SHA1_ID) ? TSK_HDB_HTYPE_SHA1_STR : "") ) )

/**
 * Return the length of a hash, given its ID
 */
#define TSK_HDB_HTYPE_LEN(x) \
    ( ((x) & TSK_HDB_HTYPE_MD5_ID) ? (TSK_HDB_HTYPE_MD5_LEN) : ( \
	( ((x) & TSK_HDB_HTYPE_SHA1_ID) ? TSK_HDB_HTYPE_SHA1_LEN : 0) ) )



/**
 * Hash Database types
 */
    enum TSK_HDB_DBTYPE_ENUM {
        TSK_HDB_DBTYPE_NSRL_ID = 1,     ///< NIST NSRL format
        TSK_HDB_DBTYPE_MD5SUM_ID = 2,   ///< md5sum format
        TSK_HDB_DBTYPE_HK_ID = 3,       ///< hashkeeper format
        TSK_HDB_DBTYPE_IDXONLY_ID = 4   ///< Only the database index was opened -- original dbtype is unknown
    };
    typedef enum TSK_HDB_DBTYPE_ENUM TSK_HDB_DBTYPE_ENUM;


/* String versions of DB types */
#define TSK_HDB_DBTYPE_NSRL_STR		        "nsrl"  ///< NSRL String name
#define TSK_HDB_DBTYPE_NSRL_MD5_STR		"nsrl-md5"      ///< NSRL md5 string name
#define TSK_HDB_DBTYPE_NSRL_SHA1_STR		"nsrl-sha1"     ///< NSRL SHA1 string name
#define TSK_HDB_DBTYPE_MD5SUM_STR		"md5sum"        ///< md5sum db string n ame
#define TSK_HDB_DBTYPE_HK_STR			"hk"    ///< hash keeper string name
/// List of supported data base types
#define TSK_HDB_DBTYPE_SUPPORT_STR		"nsrl-md5, nsrl-sha1, md5sum, hk"


    typedef struct TSK_HDB_INFO TSK_HDB_INFO;

    typedef TSK_WALK_RET_ENUM(*TSK_HDB_LOOKUP_FN) (TSK_HDB_INFO *,
                                                   const char *hash,
                                                   const char *name,
                                                   void *);

/**
 * Holds information about an open hash database. Created by 
 * hdb_open and used for making an index and looking up values.
 */
    struct TSK_HDB_INFO {

        TSK_TCHAR *db_fname;    ///< Name of the database

        TSK_TCHAR *uns_fname;   ///< Name of unsorted index file

        FILE *hDb;              ///< File handle to database (always open)
        FILE *hIdxTmp;          ///< File handle to temp (unsorted) index file (only open during index creation)
        FILE *hIdx;             ///< File handle to index (only open during lookups)

        TSK_OFF_T idx_size;     ///< Size of index file
        uint16_t idx_off;       ///< Offset in index file to first index entry
        size_t idx_llen;        ///< Length of each line in index
        char *idx_lbuf;         ///< Buffer to hold a line from the index
        TSK_TCHAR *idx_fname;   ///< Name of index file

        TSK_HDB_HTYPE_ENUM hash_type;   ///< Type of hash used in index
        uint16_t hash_len;      ///< Length of hash

        TSK_HDB_DBTYPE_ENUM db_type;    ///< Type of database

         uint8_t(*getentry) (TSK_HDB_INFO *, const char *, TSK_OFF_T, TSK_HDB_FLAG_ENUM, TSK_HDB_LOOKUP_FN, void *);    ///< \internal Database-specific function to find entry at a given offset
         uint8_t(*makeindex) (TSK_HDB_INFO *, TSK_TCHAR *);     ///< \internal Database-specific function to make index
    };

    /**
     * Options for opening a hash database
     */
    enum TSK_HDB_OPEN_ENUM {
        TSK_HDB_OPEN_NONE = 0,  ///< No special flags
        TSK_HDB_OPEN_IDXONLY = (0x1 << 0)       ///< Open only the index -- do not look for the original DB
    };
    typedef enum TSK_HDB_OPEN_ENUM TSK_HDB_OPEN_ENUM;


    extern TSK_HDB_INFO *tsk_hdb_open(TSK_TCHAR * db_file,
                                      TSK_HDB_OPEN_ENUM flags);
    extern void tsk_hdb_close(TSK_HDB_INFO * hdb);

    extern uint8_t tsk_hdb_hasindex(TSK_HDB_INFO *, uint8_t htype);
    extern uint8_t tsk_hdb_makeindex(TSK_HDB_INFO *, TSK_TCHAR *);


/* Functions */
    extern int8_t tsk_hdb_lookup_str(TSK_HDB_INFO *, const char *,
                                     TSK_HDB_FLAG_ENUM, TSK_HDB_LOOKUP_FN,
                                     void *);

    extern int8_t tsk_hdb_lookup_raw(TSK_HDB_INFO *, uint8_t * hash,
                                     uint8_t len, TSK_HDB_FLAG_ENUM,
                                     TSK_HDB_LOOKUP_FN, void *);

#ifdef __cplusplus
}
#endif
#endif
