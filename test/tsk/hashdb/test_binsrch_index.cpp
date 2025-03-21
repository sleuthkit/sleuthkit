#include "tsk/base/tsk_os.h"
#include "tsk/hashdb/tsk_hashdb_i.h"
#include "catch.hpp"

void hdb_binsrch_index_close(TSK_HDB_BINSRCH_INFO *hdb_binsrch_info)
{
    hdb_binsrch_close((TSK_HDB_INFO *)hdb_binsrch_info);
}

void test_hdb_binsrch_idx_init_hash_type_info(
    const TSK_TCHAR *db_name,
    TSK_HDB_HTYPE_ENUM htype,
    int expected_return,
    int expected_hash_len,
    const TSK_TCHAR *expected_idx_fname,
    const TSK_TCHAR *expected_idx_idx_fname)
{
    std::unique_ptr<TSK_HDB_BINSRCH_INFO, decltype(&hdb_binsrch_index_close)> hdb_binsrch_info{
        (TSK_HDB_BINSRCH_INFO *)tsk_malloc(sizeof(TSK_HDB_BINSRCH_INFO)),
        &hdb_binsrch_index_close};

    /**
     * setup values:
     * normally, this would be done as a part of opening the hashdb, but not
     * for this unit test
     **/
    hdb_binsrch_info->hash_type = TSK_HDB_HTYPE_INVALID_ID;

    const auto db_name_cpy_len = TSTRLEN(db_name);
    TSK_TCHAR *db_name_cpy = (TSK_TCHAR *)tsk_malloc((db_name_cpy_len + 1) * sizeof(TSK_TCHAR));
    TSTRNCPY(db_name_cpy, db_name, db_name_cpy_len + 1);
    hdb_binsrch_info->base.db_fname = db_name_cpy;

    int ret_val = hdb_binsrch_idx_init_hash_type_info(hdb_binsrch_info.get(), htype);

    CHECK(ret_val == expected_return);

    if (expected_return == 0)
    {
        // if successful call, do comparisons
        CHECK(hdb_binsrch_info->hash_len == expected_hash_len);
        CHECK(TSTRCMP(hdb_binsrch_info->idx_fname, expected_idx_fname) == 0);
        CHECK(TSTRCMP(hdb_binsrch_info->idx_idx_fname, expected_idx_idx_fname) == 0);
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