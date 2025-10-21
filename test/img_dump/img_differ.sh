#!/bin/bash -e

# img_differ program:
# $1 = image to test
#    - $DATA_DIR being replaced with ${srcdir}/test/data
#    - $SLEUTHKIT_TEST_DATA_DIR being replaced with $SLEUTHKIT_TEST_DATA_DIR
# $2 - expected output

# set the default timezone
export TZ=America/New_York


if [[ -z "$2" ]]; then
    echo usage: img_differ.sh image image.json
    exit 1
fi

if [ -n "$WINE" ]; then
  EXEEXT=.exe
fi

# This program uses the img_dump executable which is assumped to be installed in:
IMG_DUMP=test/img_dump/img_dump$EXEEXT

if [ ! -e $IMG_DUMP ]; then
    echo $IMG_DUMP not found
    exit 1
fi

IMG="$1"
IMG="${IMG/\$DATA_DIR/$srcdir/test/data}"
IMG="${IMG/\$SLEUTHKIT_TEST_DATA_DIR/$SLEUTHKIT_TEST_DATA_DIR}"
EXPECTED="$2"
EXPECTED="${EXPECTED/\$DATA_DIR/$srcdir/test/data}"
EXPECTED="${EXPECTED/\$SLEUTHKIT_TEST_DATA_DIR/$SLEUTHKIT_TEST_DATA_DIR}"

if [ ! -e $IMG ]; then
   echo $IMG does not exist
   exit 77
fi

if [ -n "$OVERWRITE" ]; then
    echo "OVERWRITE is set. Overwriting $EXPECTED"
    $WINE $IMG_DUMP "$IMG" | jq -S .> "$EXPECTED"
fi

diff -b "$EXPECTED" <($WINE $IMG_DUMP "$IMG" | jq -S .) \
    && echo "SUCCESS: img_dump $IMG" || { echo "FAILED: img_dump $IMG" EXPECTED=$EXPECTED ; exit 1 ; }
