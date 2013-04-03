/*
* The Sleuth Kit
*
* Brian Carrier [carrier <at> sleuthkit [dot] org]
* Copyright (c) 2003-2011 Brian Carrier.  All rights reserved
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
        TSK_HDB_FLAG_QUICK = 0x01,      ///< Quickly return if hash is found (do not return file name etc.)
        TSK_HDB_FLAG_EXT = 0x02 ///< Return other details besides only file name (not used
    };
    typedef enum TSK_HDB_FLAG_ENUM TSK_HDB_FLAG_ENUM;


    /**
    * Hash algorithm types
    */
    enum TSK_HDB_HTYPE_ENUM {
        TSK_HDB_HTYPE_INVALID_ID = 0,   ///< Invalid algorithm signals error.
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
        TSK_HDB_DBTYPE_INVALID_ID = 0,  ///< Invalid type signals error.
        TSK_HDB_DBTYPE_NSRL_ID = 1,     ///< NIST NSRL format
        TSK_HDB_DBTYPE_MD5SUM_ID = 2,   ///< md5sum format
        TSK_HDB_DBTYPE_HK_ID = 3,       ///< hashkeeper format
        TSK_HDB_DBTYPE_IDXONLY_ID = 4,   ///< Only the database index was opened -- original dbtype is unknown
        TSK_HDB_DBTYPE_ENCASE_ID = 5    ///< EnCase format
    };
    typedef enum TSK_HDB_DBTYPE_ENUM TSK_HDB_DBTYPE_ENUM;


    /* String versions of DB types */
#define TSK_HDB_DBTYPE_NSRL_STR		        "nsrl"  ///< NSRL String name
#define TSK_HDB_DBTYPE_NSRL_MD5_STR		"nsrl-md5"      ///< NSRL md5 string name
#define TSK_HDB_DBTYPE_NSRL_SHA1_STR		"nsrl-sha1"     ///< NSRL SHA1 string name
#define TSK_HDB_DBTYPE_MD5SUM_STR		"md5sum"        ///< md5sum db string n ame
#define TSK_HDB_DBTYPE_HK_STR			"hk"    ///< hash keeper string name
#define TSK_HDB_DBTYPE_ENCASE_STR			"encase"    ///< encase string name
    /// List of supported data base types
#define TSK_HDB_DBTYPE_SUPPORT_STR		"nsrl-md5, nsrl-sha1, md5sum, encase, hk"

#define TSK_HDB_NAME_MAXLEN 512 //< Max length for database name


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

        char db_name[TSK_HDB_NAME_MAXLEN];          ///< Name of the database

        TSK_TCHAR *db_fname;    ///< Name of the database file

        TSK_TCHAR *uns_fname;   ///< Name of unsorted index file

        FILE *hDb;              ///< File handle to database (always open)
        FILE *hIdxTmp;          ///< File handle to temp (unsorted) index file (only open during index creation)
        FILE *hIdx;             ///< File handle to index (only open during lookups) 

        TSK_OFF_T idx_size;     ///< Size of index file
        uint16_t idx_off;       ///< Offset in index file to first index entry
        size_t idx_llen;        ///< Length of each line in index

        /* lock protects idx_lbuf and lazy loading of hIdx */
        tsk_lock_t lock;        ///< Lock for lazy loading and idx_lbuf
        char *idx_lbuf;         ///< Buffer to hold a line from the index  (r/w shared - lock) 
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
            return tsk_hdb_makeindex(m_hdbInfo, a_type);
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
            return tsk_hdb_hasindex(m_hdbInfo, a_htype);
        else
            return 0;
    };
    
    /**
    * get type of hash used in index
    * @return type of hash used in index, or TSK_HDB_HTYPE_INVALID_ID
    *    on error.
    */
    TSK_HDB_HTYPE_ENUM getHashType() const {
        if (m_hdbInfo != NULL)
            return m_hdbInfo->hash_type;
        return TSK_HDB_HTYPE_INVALID_ID;
    };
    
    /**
    * get length of hash
    * @return length of hash
    */
    uint16_t getHashLen() const {
        if (m_hdbInfo != NULL)
            return m_hdbInfo->hash_len;
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
