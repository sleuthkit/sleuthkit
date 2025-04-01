#!/bin/bash -e

/bin/rm -f apfs_pool.db
"tools/autotools/tsk_loaddb$EXEEXT" -d apfs_pool.db $SLEUTHKIT_TEST_DATA_DIR/apfs/apfs_pool.E01

/bin/rm -f issue_3235.db
"tools/autotools/tsk_loaddb$EXEEXT" -d issue_3235.db $SLEUTHKIT_TEST_DATA_DIR/fuzzing/lvm_test_issue_3235.E01
