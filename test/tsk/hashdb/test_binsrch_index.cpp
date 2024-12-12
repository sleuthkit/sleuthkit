#include "tsk/base/tsk_os.h"
#include "tsk/hashdb/tsk_hashdb_i.h"
#include "catch.hpp"

void test_hdb_binsrch_idx_init_hash_type_info(
    const TSK_TCHAR *db_name,
    TSK_HDB_HTYPE_ENUM htype,
    int expected_return,
    int expected_hash_len,
    const TSK_TCHAR *expected_idx_fname,
    const TSK_TCHAR *expected_idx_idx_fname)
{
    TSK_HDB_BINSRCH_INFO hdb_binsrch_info;

    /**
     * setup values:
     * normally, this would be done as a part of opening the hashdb, but not 
     * for this unit test
     **/
    hdb_binsrch_info.hash_type = TSK_HDB_HTYPE_INVALID_ID;
    // this value is read only in hdb_binsrch_idx_init_hash_type_info
    hdb_binsrch_info.base.db_fname = (TSK_TCHAR *)db_name;
    int ret_val = hdb_binsrch_idx_init_hash_type_info(&hdb_binsrch_info, htype);

    REQUIRE(ret_val == expected_return);

    if (expected_return == 0)
    {
        // if successful call, do comparisons
        REQUIRE(hdb_binsrch_info.hash_len == expected_hash_len);
        REQUIRE(TSTRCMP(hdb_binsrch_info.idx_fname, expected_idx_fname) == 0);
        REQUIRE(TSTRCMP(hdb_binsrch_info.idx_idx_fname, expected_idx_idx_fname) == 0);
    }

    /**
     * cleanup allocated items from hdb_binsrch_idx_init_hash_type_info.
     * These are values set by hdb_binsrch_idx_init_hash_type_info during run 
     * that need to be cleaned up. Normally, they would be cleaned up when the
     * hash database is closed, but not for this unit test.
     **/
    if (hdb_binsrch_info.idx_fname != NULL)
    {
        free(hdb_binsrch_info.idx_fname);
    }

    if (hdb_binsrch_info.idx_idx_fname != NULL)
    {
        free(hdb_binsrch_info.idx_idx_fname);
    }
}

TEST_CASE("test hdb_binsrch_idx_init_hash_type_info with md5 db type")
{
    test_hdb_binsrch_idx_init_hash_type_info(
        _TSK_T("C:\\path\\to\\file.txt"),
        TSK_HDB_HTYPE_MD5_ID,
        0,
        TSK_HDB_HTYPE_MD5_LEN,
        _TSK_T("C:\\path\\to\\file.txt-md5.idx"),
        _TSK_T("C:\\path\\to\\file.txt-md5.idx2"));
}

TEST_CASE("test hdb_binsrch_idx_init_hash_type_info with sha1 db type")
{
    test_hdb_binsrch_idx_init_hash_type_info(
        _TSK_T("C:\\path\\to\\file.txt"),
        TSK_HDB_HTYPE_SHA1_ID,
        0,
        TSK_HDB_HTYPE_SHA1_LEN,
        _TSK_T("C:\\path\\to\\file.txt-sha1.idx"),
        _TSK_T("C:\\path\\to\\file.txt-sha1.idx2"));
}

TEST_CASE("test hdb_binsrch_idx_init_hash_type_info with sha256 db type (error)")
{
    test_hdb_binsrch_idx_init_hash_type_info(
        _TSK_T("C:\\path\\to\\file.txt"),
        TSK_HDB_HTYPE_SHA2_256_ID,
        1,
        TSK_HDB_HTYPE_INVALID_ID,
        _TSK_T(""),
        _TSK_T(""));
}

TEST_CASE("test hdb_binsrch_idx_init_hash_type_info with invalid db type (error)")
{
    test_hdb_binsrch_idx_init_hash_type_info(
        _TSK_T("C:\\path\\to\\file.txt"),
        TSK_HDB_HTYPE_INVALID_ID,
        1,
        TSK_HDB_HTYPE_INVALID_ID,
        _TSK_T(""),
        _TSK_T(""));
}