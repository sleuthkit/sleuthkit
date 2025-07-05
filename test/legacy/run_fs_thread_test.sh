#!/bin/bash

# This script is called by 'make check'
#
# It runs the fs_thread_test program first with one thread, then with multiple threads,
# and checks to make sure that the output is stable. This is not guaranteed to find multithreading errors,
# but any errors it finds are real

# most of the small test images are in test/data, but the NFS image is big, so it is in
# SLEUTHKIT_TEST_DATA_DIR
EXIT_PASS=0
EXIT_FAIL=1
EXIT_SKIP=77
NOHARDFAIL=yes

set -e

if [ -n "$WINE" ]; then
  EXEEXT=.exe
fi

if [ ! "${srcdir+x}" ]; then
    echo srcdir is not set
    exit 1
fi

DATA_DIR=$srcdir/test/data

if ! test -d ${DATA_DIR} ; then
    echo "Missing image directory: ${DATA_DIR}"
    exit ${EXIT_SKIP}
fi

FS_THREAD_TEST="test/legacy/fs_thread_test$EXEEXT"
if ! test -x ${FS_THREAD_TEST} ; then
    echo "Missing test executable: ${FS_THREAD_TEST}"
    exit ${EXIT_SKIP};
fi

IMAGE_EXT2=$srcdir/test/data/image_ext2.dd
IMAGE_UFS=$srcdir/test/data/image_ufs.dd
IMAGE_NTFS=${SLEUTHKIT_TEST_DATA_DIR}/from_brian/3-kwsrch-ntfs/ntfs-img-kw-1.dd

NTHREADS=4
NITERS=2

check_diffs()
{
    for LOG_FILE in thread-*.log ; do
        echo diff base.log ${LOG_FILE}
        diff base.log ${LOG_FILE} || return ${EXIT_FAIL}
    done

    return ${EXIT_PASS}
}



if test -f ${DATA_DIR}/fat32.dd ; then
    echo testing ${DATA_DIR}/fat32.dd
    rm -f base.log thread-*.log
    ${WINE} ${FS_THREAD_TEST} -f fat ${DATA_DIR}/fat32.dd 1 1
    mv thread-0.log base.log
    ${WINE} ${FS_THREAD_TEST} -f fat ${DATA_DIR}/fat32.dd ${NTHREADS} ${NITERS}

    if ! check_diffs; then
        exit ${EXIT_FAIL}
    fi
else
    echo ${DATA_DIR}/fat32.dd missing
    [ -z "$NOHARDFAIL" ] && exit ${EXIT_SKIP}
fi




IMG=$IMAGE_EXT2
if test -f $IMG ; then
    rm -f base.log thread-*.log
    echo collecting $IMG output with 1 thread 1 iteration.
    echo ${WINE} ${FS_THREAD_TEST} -f ext2 $IMG 1 1
    ${WINE} ${FS_THREAD_TEST} -f ext2 $IMG 1 1
    mv thread-0.log base.log
    echo testing $IMG. threads=$NTHREADS iterations=$NITERS
    ${WINE} ${FS_THREAD_TEST} -f ext2 $IMG ${NTHREADS} ${NITERS}

    if ! check_diffs ; then
        exit ${EXIT_FAIL}
    fi
else
    echo $IMG missing
    [ -z "$NOHARDFAIL" ] && exit ${EXIT_SKIP}
fi

# if test -f ${DATA_DIR}/test_hfs.dmg ; then
#     echo testing ${DATA_DIR}/test_hfs.dmg
#     rm -f base.log thread-*.log
#     ${WINE} ${FS_THREAD_TEST} -f hfs -o 64 ${DATA_DIR}/test_hfs.dmg 1 1
#     mv thread-0.log base.log
#     ${WINE} ${FS_THREAD_TEST} -f hfs -o 64 ${DATA_DIR}/test_hfs.dmg ${NTHREADS} ${NITERS}
#
#     if ! check_diffs ; then
#         exit ${EXIT_FAIL}
#     fi
# else
#     echo ${DATA_DIR}/test_hfs.dmg missing
#     [ -z "$NOHARDFAIL" ] && exit ${EXIT_SKIP}
# fi
#

IMG=$IMAGE_NTFS
if test -f $IMG ; then
    echo collecting $IMG output with 1 thread 1 iteration.
    rm -f base.log thread-*.log
    ${WINE} ${FS_THREAD_TEST} -f ntfs $IMG 1 1
    mv thread-0.log base.log
    echo testing $IMG threads=$NTHREADS iterations=$NITERS
    ${WINE} ${FS_THREAD_TEST} -f ntfs $IMG ${NTHREADS} ${NITERS}

    if ! check_diffs ; then
        exit ${EXIT_FAIL}
    fi
else
    echo $IMG missing
    [ -z "$NOHARDFAIL" ] && exit ${EXIT_SKIP}
fi


exit ${EXIT_PASS}
