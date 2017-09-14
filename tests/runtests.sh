#!/bin/bash

EXIT_SUCCESS=0;
EXIT_FAILURE=1;
EXIT_IGNORE=77;

IMAGE_DIR=${HOME}/from_brian
NTHREADS=1
NITERS=1

check_diffs()
{
	for LOG_FILE in thread-*.log;
	do
		echo diff base.log ${LOG_FILE};
		diff base.log ${LOG_FILE} || return ${EXIT_FAILURE};
	done;

	return ${EXIT_SUCCESS};
}

if ! test -d ${IMAGE_DIR};
then
	echo "Missing image directory: ${IMAGE_DIR}";

	exit ${EXIT_IGNORE};
fi

FS_THREAD_TEST="./fs_thread_test";

if ! test -x ${FS_THREAD_TEST};
then
	FS_THREAD_TEST="./fs_thread_test.exe";
fi

if ! test -x ${FS_THREAD_TEST};
then
	echo "Missing test executable: ${IMAGE_DIR}";

	exit ${EXIT_IGNORE};
fi

rm -f base.log thread-*.log
${FS_THREAD_TEST} -f ext2 ${IMAGE_DIR}/ext2fs.dd 1 1
mv thread-0.log base.log
${FS_THREAD_TEST} -f ext2 ${IMAGE_DIR}/ext2fs.dd ${NTHREADS} ${NITERS}

if ! check_diffs;
then
	exit ${EXIT_FAILURE};
fi

rm -f base.log thread-*.log
${FS_THREAD_TEST} -f ufs ${IMAGE_DIR}/misc-ufs1.dd 1 1
mv thread-0.log base.log
${FS_THREAD_TEST} -f ufs ${IMAGE_DIR}/misc-ufs1.dd ${NTHREADS} ${NITERS}

if ! check_diffs;
then
	exit ${EXIT_FAILURE};
fi

rm -f base.log thread-*.log
${FS_THREAD_TEST} -f hfs -o 64 ${IMAGE_DIR}/test_hfs.dmg 1 1
mv thread-0.log base.log
${FS_THREAD_TEST} -f hfs -o 64 ${IMAGE_DIR}/test_hfs.dmg ${NTHREADS} ${NITERS}

if ! check_diffs;
then
	exit ${EXIT_FAILURE};
fi

rm -f base.log thread-*.log
${FS_THREAD_TEST} -f ntfs ${IMAGE_DIR}/ntfs-img-kw-1.dd 1 1
mv thread-0.log base.log
${FS_THREAD_TEST} -f ntfs ${IMAGE_DIR}/ntfs-img-kw-1.dd ${NTHREADS} ${NITERS}

if ! check_diffs;
then
	exit ${EXIT_FAILURE};
fi

rm -f base.log thread-*.log
${FS_THREAD_TEST} -f fat ${IMAGE_DIR}/fat32.dd 1 1
mv thread-0.log base.log
${FS_THREAD_TEST} -f fat ${IMAGE_DIR}/fat32.dd ${NTHREADS} ${NITERS}

if ! check_diffs;
then
	exit ${EXIT_FAILURE};
fi

exit ${EXIT_SUCCESS};

