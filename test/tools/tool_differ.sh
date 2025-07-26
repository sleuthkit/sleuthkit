#!/bin/bash -e
# usage: tool_differ <command> <expected_output>
#   <command>: Full command to run, with the following substitutions:
#     - $EXEEXT is replaced with .exe on Windows
#     - $DATA_DIR is replaced with ${srcdir}/test/data
#     - $SLEUTHKIT_TEST_DATA_DIR is replaced with $SLEUTHKIT_TEST_DATA_DIR
#   <expected_output>: Path to the file containing the expected output for comparison.

# tool_differ program:
# $1 = full command to run, with
#    - $EXEEXT being replaced with .exe on windows
#    - $DATA_DIR being replaced with ${srcdir}/test/data
#    - $SLEUTHKIT_TEST_DATA_DIR being replaced with $SLEUTHKIT_TEST_DATA_DIR
#
# $2 = Expected output.

if [ -n "$WINE" ]; then
  EXEEXT=.exe
fi

DATA_DIR=$srcdir/test/data

CMD="${1/\$EXEEXT/$EXEEXT}"
CMD="${CMD/\$DATA_DIR/$DATA_DIR}"
CMD="${CMD/\$SLEUTHKIT_TEST_DATA_DIR/$SLEUTHKIT_TEST_DATA_DIR}"
EXPECTED="$2"

echo -n "checking '$CMD': "

if [ ! -e $EXPECTED ]; then
    echo $EXPECTED does not exist
    exit 77
fi

DIFF_EXIT=0
# diff, normalizing against basedir (we could/should use srcdir)
basedir=$(realpath "$(dirname $0)/../..")

RESULT=$(diff --strip-trailing-cr -u "$EXPECTED" <($WINE $CMD 2>&1 | sed -e "\|^${basedir}/.*: |d")) || DIFF_EXIT=$?
if [ $DIFF_EXIT -ne 0 ]; then
  echo failed
  echo "$RESULT"
  echo ""
  echo === $1 ===
  $WINE $CMD | cat -vn
  echo ""
  echo === $2 ===
  cat -vn $2
  exit 1
else
  echo ok
fi
