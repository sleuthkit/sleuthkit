/*
* The Sleuth Kit
*
* Brian Carrier [carrier <at> sleuthkit [dot] org]
* Copyright (c) 2003-2014 Brian Carrier.  All rights reserved
*/

/**
* \file tsk_hashdb.h
* External header file for hash database support.
* Note that this file is not meant to be directly included.  
* It is included by both libtsk.h and tsk_hashdb_i.h.
*/

/**
* \defgroup hashdblib C Hash Database Functions
* \defgroup hashdblib_cpp C++ Hash Database Classes
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
        TSK_HDB_FLAG_QUICK = 0x01,  ///< Quickly return if hash is found (do not return file name etc.)
        TSK_HDB_FLAG_EXT = 0x02     ///< Return other details besides only file name (not used
    };
    typedef enum TSK_HDB_FLAG_ENUM TSK_HDB_FLAG_ENUM;

    /**
    * Hash algorithm types
    */
    enum TSK_HDB_HTYPE_ENUM {
        TSK_HDB_HTYPE_INVALID_ID = 0,   ///< Invalid algorithm signals error.
        TSK_HDB_HTYPE_MD5_ID = 1,       ///< MD5 Algorithm
        TSK_HDB_HTYPE_SHA1_ID = 2,      ///< SHA1 Algorithm
        TSK_HDB_HTYPE_SHA2_256_ID = 4,  ///< SHA2-256 (aka SHA-256) Algorithm
    };
    typedef enum TSK_HDB_HTYPE_ENUM TSK_HDB_HTYPE_ENUM;

#define TSK_HDB_HTYPE_MD5_STR "md5"            ///< String name for MD5 algorithm
#define TSK_HDB_HTYPE_SHA1_STR "sha1"          ///< String name for SHA1 algorithm
#define TSK_HDB_HTYPE_SHA2_256_STR "sha2_256"  ///< String name for SHA256 algorithm

#define TSK_HDB_HTYPE_SHA2_256_LEN 64   ///< Length of SHA256 hash
#define TSK_HDB_HTYPE_SHA1_LEN 40       ///< Length of SHA1 hash
#define TSK_HDB_HTYPE_MD5_LEN 32        ///< Length of MD5 hash
#define TSK_HDB_HTYPE_CRC32_LEN 8       ///< Length of CRC hash
#define TSK_HDB_MAX_BINHASH_LEN 32      ///< Half the length of biggest hash

    /**
    * Return the name of the hash algorithm, given its ID
    */
#define TSK_HDB_HTYPE_STR(x) \
    ( ((x) & TSK_HDB_HTYPE_MD5_ID) ? (TSK_HDB_HTYPE_MD5_STR) : ( \
    ( ((x) & TSK_HDB_HTYPE_SHA1_ID) ? (TSK_HDB_HTYPE_SHA1_STR) : ( \
    ( ((x) & TSK_HDB_HTYPE_SHA2_256_ID) ? TSK_HDB_HTYPE_SHA2_256_STR : "") ) ) ) )

    /**
    * Return the length of a hash, given its ID
    */
#define TSK_HDB_HTYPE_LEN(x) \
    ( ((x) & TSK_HDB_HTYPE_MD5_ID) ? (TSK_HDB_HTYPE_MD5_LEN) : ( \
    ( ((x) & TSK_HDB_HTYPE_SHA1_ID) ? (TSK_HDB_HTYPE_SHA1_LEN) : ( \
    ( ((x) & TSK_HDB_HTYPE_SHA2_256_ID) ? TSK_HDB_HTYPE_SHA2_256_LEN : 0) ) ) ) )

    /**
    * Hash Database types
    */
    enum TSK_HDB_DBTYPE_ENUM {
        TSK_HDB_DBTYPE_INVALID_ID = 0,  ///< Invalid type signals error.
        TSK_HDB_DBTYPE_NSRL_ID = 1,     ///< NIST NSRL format
        TSK_HDB_DBTYPE_MD5SUM_ID = 2,   ///< md5sum format
        TSK_HDB_DBTYPE_HK_ID = 3,       ///< hashkeeper format
        TSK_HDB_DBTYPE_IDXONLY_ID = 4,  ///< Only the database index was opened -- original dbtype is unknown
        TSK_HDB_DBTYPE_ENCASE_ID = 5,   ///< EnCase format
        TSK_HDB_DBTYPE_SQLITE_ID = 6    ///< SQLite format
    };
    typedef enum TSK_HDB_DBTYPE_ENUM TSK_HDB_DBTYPE_ENUM;

    /**
    * String versions of DB types 
    */
#define TSK_HDB_DBTYPE_NSRL_STR "nsrl"           ///< NSRL database 
#define TSK_HDB_DBTYPE_NSRL_MD5_STR	"nsrl-md5"   ///< NSRL database with MD5 index
#define TSK_HDB_DBTYPE_NSRL_SHA1_STR "nsrl-sha1" ///< NSRL database with SHA1 index
#define TSK_HDB_DBTYPE_MD5SUM_STR "md5sum"       ///< md5sum
#define TSK_HDB_DBTYPE_HK_STR "hk"               ///< Hash Keeper
#define TSK_HDB_DBTYPE_ENCASE_STR "encase"       ///< EnCase

    /// List of supported hash database types with external indexes; essentially index types.
#define TSK_HDB_DBTYPE_SUPPORT_STR	"nsrl-md5, nsrl-sha1, md5sum, encase, hk"

#define TSK_HDB_NAME_MAXLEN 512 //< Max length for database name

    typedef struct TSK_HDB_INFO TSK_HDB_INFO;

    typedef TSK_WALK_RET_ENUM(*TSK_HDB_LOOKUP_FN) (TSK_HDB_INFO *,
        const char *hash,
        const char *name,
        void *);

    /**
    * Represents an open hash database. Instances are created using the 
    * tsk_hdb_open() API and are passed to hash database API functions.
    */
    struct TSK_HDB_INFO {
        TSK_TCHAR *db_fname;               ///< Database file path, may be NULL for an index only database
        char db_name[TSK_HDB_NAME_MAXLEN]; ///< Name of the database, for callbacks
        TSK_HDB_DBTYPE_ENUM db_type;       ///< Type of database
        tsk_lock_t lock;                   ///< Lock for lazy loading and idx_lbuf
        uint8_t transaction_in_progress;   ///< Flag set and unset when transaction are begun and ended
        const TSK_TCHAR*(*get_db_path)(TSK_HDB_INFO*);
        const char*(*get_display_name)(TSK_HDB_INFO*);
        uint8_t(*uses_external_indexes)();
        const TSK_TCHAR*(*get_index_path)(TSK_HDB_INFO*, TSK_HDB_HTYPE_ENUM);
        uint8_t(*has_index)(TSK_HDB_INFO*, TSK_HDB_HTYPE_ENUM);
        uint8_t(*make_index)(TSK_HDB_INFO*, TSK_TCHAR*);
        uint8_t(*open_index)(TSK_HDB_INFO*, TSK_HDB_HTYPE_ENUM);
        int8_t(*lookup_str)(TSK_HDB_INFO*, const char*, TSK_HDB_FLAG_ENUM, TSK_HDB_LOOKUP_FN, void*);
        int8_t(*lookup_raw)(TSK_HDB_INFO*, uint8_t *, uint8_t, TSK_HDB_FLAG_ENUM, TSK_HDB_LOOKUP_FN, void*);
        int8_t(*lookup_verbose_str)(TSK_HDB_INFO *, const char *, void *);
        uint8_t(*accepts_updates)();
        uint8_t(*add_entry)(TSK_HDB_INFO*, const char*, const char*, const char*, const char*, const char *);
        uint8_t(*begin_transaction)(TSK_HDB_INFO *);
        uint8_t(*commit_transaction)(TSK_HDB_INFO *);
        uint8_t(*rollback_transaction)(TSK_HDB_INFO *);
        void(*close_db)(TSK_HDB_INFO *);
    };

    /** 
    * Represents a text-format hash database (NSRL, EnCase, etc.) with the TSK binary search index. 
    */
    typedef struct TSK_HDB_BINSRCH_INFO {
        TSK_HDB_INFO base;
        FILE *hDb;  ///< File handle to database (always open)
        uint8_t(*get_entry) (TSK_HDB_INFO *, const char *, TSK_OFF_T, TSK_HDB_FLAG_ENUM, TSK_HDB_LOOKUP_FN, void *);    ///< \internal Database-specific function to find entry at a given offset
        TSK_HDB_HTYPE_ENUM hash_type; ///< Type of hash used in currently open index  
        uint16_t hash_len;            ///< Length of hash used in currently open index 
        TSK_TCHAR *idx_fname;         ///< Name of index file, may be NULL for database without external index
        FILE *hIdx;                   ///< File handle to index (only open during lookups)
        FILE *hIdxTmp;                ///< File handle to temp (unsorted) index file (only open during index creation)
        TSK_TCHAR *uns_fname;         ///< Name of unsorted index file
        TSK_OFF_T idx_size;           ///< Size of index file
        uint16_t idx_off;             ///< Offset in index file to first index entry
        size_t idx_llen;              ///< Length of each line in index
        char *idx_lbuf;               ///< Buffer to hold a line from the index  (r/w shared - lock) 
        TSK_TCHAR *idx_idx_fname;     ///< Name of index of index file, may be NULL
        uint64_t *idx_offsets;        ///< Maps the first three bytes of a hash value to an offset in the index file
    } TSK_HDB_BINSRCH_INFO;    

    /**
    * Options for opening a hash database
    */
    enum TSK_HDB_OPEN_ENUM {
        TSK_HDB_OPEN_NONE = 0,             ///< No special flags
        TSK_HDB_OPEN_IDXONLY = (0x1 << 0)  ///< Open only the index -- do not look for the original DB
    };
    typedef enum TSK_HDB_OPEN_ENUM TSK_HDB_OPEN_ENUM;

    /* Hash database API functions */
    extern uint8_t tsk_hdb_create(TSK_TCHAR *);
    extern TSK_HDB_INFO *tsk_hdb_open(TSK_TCHAR *, TSK_HDB_OPEN_ENUM);
    extern const TSK_TCHAR *tsk_hdb_get_db_path(TSK_HDB_INFO * hdb_info);
    extern const char *tsk_hdb_get_display_name(TSK_HDB_INFO * hdb_info);
    extern uint8_t tsk_hdb_is_idx_only(TSK_HDB_INFO *);
    extern uint8_t tsk_hdb_uses_external_indexes(TSK_HDB_INFO *);
    extern uint8_t tsk_hdb_has_idx(TSK_HDB_INFO * hdb_info, TSK_HDB_HTYPE_ENUM);
    extern uint8_t tsk_hdb_make_index(TSK_HDB_INFO *, TSK_TCHAR *);
    extern const TSK_TCHAR *tsk_hdb_get_idx_path(TSK_HDB_INFO *, TSK_HDB_HTYPE_ENUM);
    extern uint8_t tsk_hdb_open_idx(TSK_HDB_INFO *, TSK_HDB_HTYPE_ENUM);
    extern int8_t tsk_hdb_lookup_str(TSK_HDB_INFO *, const char *,
        TSK_HDB_FLAG_ENUM, TSK_HDB_LOOKUP_FN, void *);
    extern int8_t tsk_hdb_lookup_raw(TSK_HDB_INFO *, uint8_t *, uint8_t, 
        TSK_HDB_FLAG_ENUM,  TSK_HDB_LOOKUP_FN, void *);
    extern int8_t tsk_hdb_lookup_verbose_str(TSK_HDB_INFO *, const char *, void *);
    extern uint8_t tsk_hdb_accepts_updates(TSK_HDB_INFO *);
    extern uint8_t tsk_hdb_add_entry(TSK_HDB_INFO *, const char*, const char*, 
        const char*, const char*, const char*);
    extern uint8_t tsk_hdb_begin_transaction(TSK_HDB_INFO *);
    extern uint8_t tsk_hdb_commit_transaction(TSK_HDB_INFO *);
    extern uint8_t tsk_hdb_rollback_transaction(TSK_HDB_INFO *);
    extern void tsk_hdb_close(TSK_HDB_INFO *);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus

/** 
* \ingroup hashdblib_cpp
* Stores information about an open hash database.
* To use this object, open() should be called first. Otherwise, the other
* functions will have undefined return values. 
*/
class TskHdbInfo{
private:
    TSK_HDB_INFO * m_hdbInfo;
    TskHdbInfo(const TskHdbInfo& rhs); 
    TskHdbInfo& operator=(const TskHdbInfo& rhs);

public:
    /**
    * Close an open hash database.
    */
    ~TskHdbInfo() {
        tsk_hdb_close(m_hdbInfo);
    };

    /**
    * Open a hash database. See tsk_hdb_open() for details.
    *
    * @param a_dbFile Path to database.
    * @param a_flags Flags for opening the database.  
    *
    * @return 1 on error and 0 on success
    */
    uint8_t open(TSK_TCHAR * a_dbFile, TSK_HDB_OPEN_ENUM a_flags) {
        if ((m_hdbInfo = tsk_hdb_open(a_dbFile, a_flags)) != NULL)
            return 0;
        else
            return 1;
    };

    /**
    * Search the index for a text/ASCII hash value
    * See tsk_hdb_lookup_str() for details.
    * @param a_hash Hash value to search for (NULL terminated string)

    * @param a_flags Flags to use in lookup
    * @param a_action Callback function to call for each hash db entry 
    * (not called if QUICK flag is given)
    * @param a_ptr Pointer to data to pass to each callback
    *
    * @return -1 on error, 0 if hash value not found, and 1 if value was found.
    */
    int8_t lookupStr(const char *a_hash,
        TSK_HDB_FLAG_ENUM a_flags, TSK_HDB_LOOKUP_FN a_action, void *a_ptr) {
            if (m_hdbInfo != NULL)
                return tsk_hdb_lookup_str(m_hdbInfo, a_hash,
                a_flags, a_action, a_ptr);
            else
                return 0;
    };

    /**
    * Search the index for the given hash value given (in binary form).
    * See tsk_hdb_lookup_raw() for details.
    * @param a_hash Array with binary hash value to search for
    * @param a_len Number of bytes in binary hash value
    * @param a_flags Flags to use in lookup
    * @param a_action Callback function to call for each hash db entry 
    * (not called if QUICK flag is given)
    * @param a_ptr Pointer to data to pass to each callback
    *
    * @return -1 on error, 0 if hash value not found, and 1 if value was found.
    */
    int8_t lookupRaw(uint8_t * a_hash, uint8_t a_len,
        TSK_HDB_FLAG_ENUM a_flags, TSK_HDB_LOOKUP_FN a_action, void *a_ptr) {
            if (m_hdbInfo != NULL)
                return tsk_hdb_lookup_raw(m_hdbInfo, a_hash, a_len, a_flags,
                a_action, a_ptr);
            else
                return 0;
    };

    /**
    * Create an index for an open hash database.
    * See tsk_hdb_makeindex() for details.
    * @param a_type Text of hash database type
    * @return 1 on error
    */
    uint8_t createIndex(TSK_TCHAR * a_type) {
        if (m_hdbInfo != NULL)
            return tsk_hdb_make_index(m_hdbInfo, a_type);
        else
            return 0;
    };

    /**
    * Determine if the open hash database has an index.
    * See tsk_hdb_hasindex for details.
    * @param a_htype Hash type that index should be of
    *
    * @return 1 if index exists and 0 if not
    */
    uint8_t hasIndex(uint8_t a_htype) {
        if (m_hdbInfo != NULL)
            return tsk_hdb_has_idx(m_hdbInfo, (TSK_HDB_HTYPE_ENUM)a_htype);
        else
            return 0;
    };

    /**
    * get type of database
    * @return type of database, or TSK_HDB_DBTYPE_INVALID_ID on error.
    */
    TSK_HDB_DBTYPE_ENUM getDbType() const {
        if (m_hdbInfo != NULL)
            return m_hdbInfo->db_type;
        return TSK_HDB_DBTYPE_INVALID_ID;
    };
};
#endif
#endif
