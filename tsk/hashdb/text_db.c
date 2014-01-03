/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2014 Brian Carrier.  All rights reserved
 *
 *
 * This software is distributed under the Common Public License 1.0
 */

#include "tsk_hashdb_i.h"
#include <assert.h>

/**
 * \file text_hdb.c
 * Functions common to all text hash databases.
 */

void
text_db_close(TSK_HDB_INFO *hdb_info) 
{
    TSK_TEXT_HDB_INFO *text_hdb_info = (TSK_TEXT_HDB_INFO*)hdb_info;

    if (text_hdb_info->hDb) {
        fclose(text_hdb_info->hDb);
    }

    if (hdb_info->db_fname) {
        free(hdb_info->db_fname);
        hdb_info->db_fname = NULL;
    }

    // RJCTODO:
    //if (hdb_info->idx_info) {
    //    tsk_idx_close(hdb_info->idx_info);
    //}

    tsk_deinit_lock(&hdb_info->lock);

    free(hdb_info);
}