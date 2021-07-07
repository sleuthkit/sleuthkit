#!/bin/bash
#
# This software is distributed under the Common Public License 1.0
#
# Script that runs fls on test images.

EXIT_SUCCESS=0;
EXIT_FAILURE=1;
EXIT_IGNORE=77;

DATA_DIR="dftt";

# Checks the availability of a binary and exits if not available.
#
# Arguments:
#   a string containing the name of the binary
#
assert_availability_binary()
{
	local BINARY=$1;

	which ${BINARY} > /dev/null 2>&1;
	if test $? -ne ${EXIT_SUCCESS};
	then
		echo "Missing binary: ${BINARY}";
		echo "";

		exit ${EXIT_FAILURE};
	fi
}

if ! test -d ${DATA_DIR};
then
	echo "Missing test data directory: ${DATA_DIR}";

	exit ${EXIT_IGNORE};
fi

FLS="../tools/fstools/fls";

if ! test -x ${FLS};
then
	FLS="../tools/fstools/fls.exe";
fi

if ! test -x ${FLS};
then
	echo "Missing test executable: ${FLS}";

	exit ${EXIT_IGNORE};
fi

assert_availability_binary diff;

TMP="tmp.$$";
mkdir -p ${TMP};

# Fail on error
set -e

# TZ override is needed due to https://github.com/sleuthkit/sleuthkit/issues/2317
TZ=UTC ${FLS} -m / -r ${DATA_DIR}/2-fat-img-kw.dd > ${TMP}/2-fat-img-kw.dd.bodyfile;
diff ${DATA_DIR}/2-fat-img-kw.dd.bodyfile ${TMP}/2-fat-img-kw.dd.bodyfile;

${FLS} -m / -r ${DATA_DIR}/3-ntfs-img-kw-1.dd > ${TMP}/3-ntfs-img-kw-1.dd.bodyfile;
diff ${DATA_DIR}/3-ntfs-img-kw-1.dd.bodyfile ${TMP}/3-ntfs-img-kw-1.dd.bodyfile;

${FLS} -m / -r ${DATA_DIR}/4-ext3-img-kw-1.dd > ${TMP}/4-ext3-img-kw-1.dd.bodyfile;
diff ${DATA_DIR}/4-ext3-img-kw-1.dd.bodyfile ${TMP}/4-ext3-img-kw-1.dd.bodyfile;

rm -rf ${TMP};

exit ${EXIT_SUCCESS};

