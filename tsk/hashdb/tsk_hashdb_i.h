/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2003-2011 Brian Carrier.  All rights reserved
 */

/**
 * \file tsk_hashdb_i.h
 * Contains the internal library definitions for the hash database functions.  This should
 * be included by the code in the hash database library.
 */

#ifndef _TSK_HASHDB_I_H
#define _TSK_HASHDB_I_H


// Include the other internal TSK header files
#include "tsk/base/tsk_base_i.h"

// include the external header file
#include "tsk_hashdb.h"

#include <string.h>
#include <ctype.h>
#include <wchar.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <locale.h>

#ifdef TSK_WIN32
#include <io.h>
#include <fcntl.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif


#define TSK_HDB_MAXLEN	512     ///< Default buffer size used in many places

#define TSK_HDB_OFF_LEN 16      ///< Number of digits used in offset field in index


/**
 * Get the length of an index file line - 2 for comma and newline 
 */
#define TSK_HDB_IDX_LEN(x) \
    ( TSK_HDB_HTYPE_LEN(x) + TSK_HDB_OFF_LEN + 2)

/**
 * Strings used in index header.  It is one longer than a 
 * sha-1 hash - so that it always sorts to the top */
#define TSK_HDB_IDX_HEAD_TYPE_STR	"00000000000000000000000000000000000000000"
#define TSK_HDB_IDX_HEAD_NAME_STR	"00000000000000000000000000000000000000001"

/**
 * Properties for the sqlite hash database index
 */
#define IDX_SCHEMA_VER "Schema Version"
#define IDX_VERSION_NUM "1"
#define IDX_HASHSET_NAME "Hashset Filename"
#define IDX_HASHSET_TYPE "Hashset Type"
#define IDX_HASHSET_UPDATEABLE "Updateable"
#define IDX_BINSRCH_HEADER "0000000000000000"
#define IDX_SQLITE_V1_HEADER "SQLite format 3"

// RJCTODO: Get rid of this
// Warning: changing the hash storage type changes the Db schema
//#define IDX_SQLITE_STORE_TEXT 

    // Utils RJCTODO
    extern uint8_t hdb_file_exists(TSK_TCHAR *file_path);

    // "Generic" functions that apply to all types or delegate to hash database type-specific functions. 
    extern uint8_t hdb_setupindex(TSK_HDB_INFO * hdb_info, uint8_t htype); // RJCTODO: Where is the tsk_ ?
    extern void tsk_idx_close(TSK_HDB_INFO * hdb_info);
    extern void tsk_idx_close_file(FILE * idx);
    extern uint8_t tsk_hdb_idxinitialize(TSK_HDB_INFO *, TSK_TCHAR * dbname);
    extern uint8_t tsk_hdb_idxaddentry(TSK_HDB_INFO *, char *hvalue, TSK_OFF_T offset);
    extern uint8_t tsk_hdb_idxaddentry_bin(TSK_HDB_INFO * hdb_info, unsigned char *hvalue, int hlen,TSK_OFF_T offset);
    extern uint8_t tsk_hdb_idxfinalize(TSK_HDB_INFO *);
    extern void tsk_hdb_name_from_path(TSK_HDB_INFO *);

    // Hash database functions common to all text hash databases.
    extern TSK_TEXT_HDB_INFO *text_hdb_open(FILE *hDb, const TSK_TCHAR *db_path);
    extern uint8_t text_hdb_idx_init(TSK_HDB_INFO *, TSK_TCHAR *);
    extern uint8_t text_hdb_idx_add_entry(TSK_HDB_INFO *, char *, TSK_OFF_T);
    extern uint8_t text_hdb_idx_finalize(TSK_HDB_INFO *);

    extern void text_db_close(TSK_HDB_INFO *hdb_info) ;

    // Hash database functions for NSRL hash databases. 
    extern uint8_t nsrl_test(FILE *);
    extern TSK_HDB_INFO *nsrl_open(FILE *hDb, const TSK_TCHAR *db_path);
    extern void nsrl_name(TSK_HDB_INFO *);
    extern uint8_t nsrl_makeindex(TSK_HDB_INFO *, TSK_TCHAR * htype);
    extern uint8_t nsrl_getentry(TSK_HDB_INFO *, const char *, TSK_OFF_T,
                                 TSK_HDB_FLAG_ENUM, TSK_HDB_LOOKUP_FN,
                                 void *);

    // Hash database functions for md5Sum hash databases. 
    extern uint8_t md5sum_test(FILE *);
    extern TSK_HDB_INFO *md5sum_open(FILE *hDb, const TSK_TCHAR *db_path);
    extern void md5sum_name(TSK_HDB_INFO *);
    extern uint8_t md5sum_makeindex(TSK_HDB_INFO *, TSK_TCHAR * htype);
    extern uint8_t md5sum_getentry(TSK_HDB_INFO *, const char *, TSK_OFF_T,
                                   TSK_HDB_FLAG_ENUM, TSK_HDB_LOOKUP_FN,
                                   void *);

    // Hash database functions for EnCase hash databases. 
    extern uint8_t encase_test(FILE *);
    extern TSK_HDB_INFO *encase_open(FILE *hDb, const TSK_TCHAR *db_path);
    extern void encase_name(TSK_HDB_INFO *);
    extern uint8_t encase_makeindex(TSK_HDB_INFO *, TSK_TCHAR * htype);
    extern uint8_t encase_getentry(TSK_HDB_INFO *, const char *, TSK_OFF_T,
                                   TSK_HDB_FLAG_ENUM, TSK_HDB_LOOKUP_FN,
                                   void *);

    // Hash database functions for HashKeeper hash databases. 
    extern uint8_t hk_test(FILE *);
    extern TSK_HDB_INFO *hk_open(FILE *hDb, const TSK_TCHAR *db_path);
    extern void hk_name(TSK_HDB_INFO *);
    extern uint8_t hk_makeindex(TSK_HDB_INFO *, TSK_TCHAR * htype);
    extern uint8_t hk_getentry(TSK_HDB_INFO *, const char *, TSK_OFF_T,
                               TSK_HDB_FLAG_ENUM, TSK_HDB_LOOKUP_FN,
                               void *);

    // Hash database functions for text index files standing in for the original hash databases. 
    extern TSK_HDB_INFO *idxonly_open(const TSK_TCHAR *db_path);
    extern void idxonly_name(TSK_HDB_INFO *);
    extern uint8_t idxonly_makeindex(TSK_HDB_INFO *, TSK_TCHAR * htype);
    extern uint8_t idxonly_getentry(TSK_HDB_INFO *, const char *,
                                    TSK_OFF_T, TSK_HDB_FLAG_ENUM,
                                    TSK_HDB_LOOKUP_FN, void *);

    // Hash database functions for SQLite hash databases.
    extern TSK_HDB_INFO *sqlite_hdb_open(TSK_TCHAR *db_path);
    extern uint8_t sqlite_hdb_set_index_params(TSK_HDB_INFO *hdb_info, TSK_HDB_DBTYPE_ENUM hash_type); 
    extern uint8_t sqlite_hdb_make_index(TSK_HDB_INFO *, TSK_TCHAR * htype);

    // Index functions for ASCII indexes for hash databases. 
    extern uint8_t binsrch_open(TSK_HDB_INFO * hdb_info, uint8_t htype);
    extern void binsrch_close(TSK_HDB_INFO * hdb_info);
    extern uint8_t binsrch_initialize(TSK_HDB_INFO *, TSK_TCHAR *);
    extern uint8_t binsrch_addentry(TSK_HDB_INFO *, char *, TSK_OFF_T);
    extern uint8_t binsrch_addentry_bin(TSK_HDB_INFO *,
            unsigned char *, int, TSK_OFF_T);
    extern uint8_t sqlite_v1_addcomment(TSK_HDB_INFO *, char*, int64_t);
    extern uint8_t sqlite_v1_addfilename(TSK_HDB_INFO *, char*, int64_t);
    extern uint8_t binsrch_finalize(TSK_HDB_INFO *);
    extern int8_t binsrch_lookup_str(TSK_HDB_INFO *, const char *,
                                    TSK_HDB_FLAG_ENUM, TSK_HDB_LOOKUP_FN, void *);
    extern int8_t binsrch_lookup_raw(TSK_HDB_INFO *, uint8_t *, uint8_t,
                                    TSK_HDB_FLAG_ENUM, TSK_HDB_LOOKUP_FN, void *);
    extern int8_t binsrch_get_properties(TSK_HDB_INFO * hdb_info);

    // Hash database and index functions for SQLite hash databases.
    extern uint8_t sqlite_hdb_get_entry(TSK_HDB_INFO *, const char *, TSK_OFF_T, TSK_HDB_FLAG_ENUM, TSK_HDB_LOOKUP_FN, void *);
	extern uint8_t sqlite_hdb_create_db(TSK_TCHAR*);
    extern sqlite3 *sqlite_hdb_open_db(TSK_TCHAR*);
    extern void sqlite_hdb_close(TSK_HDB_INFO*);
    extern int8_t sqlite_v1_lookup_str(TSK_HDB_INFO *, const char *, TSK_HDB_FLAG_ENUM, TSK_HDB_LOOKUP_FN, void *);
    extern int8_t sqlite_v1_lookup_raw(TSK_HDB_INFO *, uint8_t *, uint8_t, TSK_HDB_FLAG_ENUM, TSK_HDB_LOOKUP_FN, void *);
    extern void * sqlite_v1_getAllData(TSK_HDB_INFO *, unsigned long hashId);
    extern int8_t sqlite_v1_get_properties(TSK_HDB_INFO * hdb_info);

#ifdef __cplusplus
}
#endif
#endif
