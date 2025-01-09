#!/bin/bash

# This script is called by 'make check'
# It curently runs fs_thread_test on a set of images, of which some are public
#

EXIT_SUCCESS=0
EXIT_FAILURE=1
EXIT_IGNORE=77

NOHARDFAIL=yes

IMAGE_DIR=test/from_brian
NTHREADS=1
NITERS=1

if [ -n "$WINE" ]; then
  EXEEXT=.exe
fi

check_diffs()
{
    for LOG_FILE in thread-*.log ; do
        echo diff base.log ${LOG_FILE}
        diff base.log ${LOG_FILE} || return ${EXIT_FAILURE}
    done

    return ${EXIT_SUCCESS}
}

if ! test -d ${IMAGE_DIR} ; then
    echo "Missing image directory: ${IMAGE_DIR}"
    exit ${EXIT_IGNORE}
fi

FS_THREAD_TEST="test/legacy/fs_thread_test$EXEEXT"

if ! test -x ${FS_THREAD_TEST} ; then
    echo "Missing test executable: ${FS_THREAD_TEST}"
    exit ${EXIT_IGNORE};
fi

if test -f ${IMAGE_DIR}/ext2fs.dd ; then
    echo testing ${IMAGE_DIR}/ext2fs.dd
    rm -f base.log thread-*.log
    ${WINE} ${FS_THREAD_TEST} -f ext2 ${IMAGE_DIR}/ext2fs.dd 1 1
    mv thread-0.log base.log
    ${WINE} ${FS_THREAD_TEST} -f ext2 ${IMAGE_DIR}/ext2fs.dd ${NTHREADS} ${NITERS}

    if ! check_diffs ; then
        exit ${EXIT_FAILURE}
    fi
else
    echo ${IMAGE_DIR}/ext2fs.dd missing
    [ -z "$NOHARDFAIL" ] && exit ${EXIT_IGNORE}
fi

if test -f ${IMAGE_DIR}/ext2fs.dd ; then
    echo testing ${IMAGE_DIR}/ext2fs.dd
    rm -f base.log thread-*.log
    ${WINE} ${FS_THREAD_TEST} -f ufs ${IMAGE_DIR}/misc-ufs1.dd 1 1
    mv thread-0.log base.log
    ${WINE} ${FS_THREAD_TEST} -f ufs ${IMAGE_DIR}/misc-ufs1.dd ${NTHREADS} ${NITERS}

    if ! check_diffs ; then
        exit ${EXIT_FAILURE}
    fi
else
    echo ${IMAGE_DIR}/ext2fs.dd missing
    [ -z "$NOHARDFAIL" ] && exit ${EXIT_IGNORE};
fi


if test -f ${IMAGE_DIR}/test_hfs.dmg ; then
    echo testing ${IMAGE_DIR}/test_hfs.dmg
    rm -f base.log thread-*.log
    ${WINE} ${FS_THREAD_TEST} -f hfs -o 64 ${IMAGE_DIR}/test_hfs.dmg 1 1
    mv thread-0.log base.log
    ${WINE} ${FS_THREAD_TEST} -f hfs -o 64 ${IMAGE_DIR}/test_hfs.dmg ${NTHREADS} ${NITERS}

    if ! check_diffs ; then
        exit ${EXIT_FAILURE}
    fi
else
    echo ${IMAGE_DIR}/test_hfs.dmg missing
    [ -z "$NOHARDFAIL" ] && exit ${EXIT_IGNORE}
fi

if test -f ${IMAGE_DIR}/ntfs-img-kw-1.dd ; then
    echo testing ${IMAGE_DIR}/ntfs-img-kw-1.dd
    rm -f base.log thread-*.log
    ${WINE} ${FS_THREAD_TEST} -f ntfs ${IMAGE_DIR}/ntfs-img-kw-1.dd 1 1
    mv thread-0.log base.log
    ${WINE} ${FS_THREAD_TEST} -f ntfs ${IMAGE_DIR}/ntfs-img-kw-1.dd ${NTHREADS} ${NITERS}

    if ! check_diffs ; then
        exit ${EXIT_FAILURE}
    fi
else
    echo ${IMAGE_DIR}/ntfs-img-kw-1.dd missing
    [ -z "$NOHARDFAIL" ] && exit ${EXIT_IGNORE}
fi


if test -f ${IMAGE_DIR}/fat32.dd ; then
    echo testing ${IMAGE_DIR}/fat32.dd
    rm -f base.log thread-*.log
    ${WINE} ${FS_THREAD_TEST} -f fat ${IMAGE_DIR}/fat32.dd 1 1
    mv thread-0.log base.log
    ${WINE} ${FS_THREAD_TEST} -f fat ${IMAGE_DIR}/fat32.dd ${NTHREADS} ${NITERS}

    if ! check_diffs; then
        exit ${EXIT_FAILURE}
    fi
else
    echo ${IMAGE_DIR}/fat32.dd missing
    [ -z "$NOHARDFAIL" ] && exit ${EXIT_IGNORE}
fi


exit ${EXIT_SUCCESS}
