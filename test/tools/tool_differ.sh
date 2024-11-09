#!/bin/bash -e

# get basedir for normalizing output
basedir=$(realpath "$(dirname $0)/../..")

if [ -n "$WINE" ]; then
  EXEEXT=.exe
fi

CMD="${1/\$EXEEXT/$EXEEXT}"
EXP="$2"

echo -n "checking '$CMD': "

DIFF_EXIT=0
# diff, normalizing against basedir
RESULT=$(diff --strip-trailing-cr -u "$EXP" <($WINE $CMD 2>&1 | sed -e "\|^${basedir}/.*: |d")) || DIFF_EXIT=$?
if [ $DIFF_EXIT -ne 0 ]; then
  echo failed
  echo "$RESULT"
  echo ""
  echo === $1 ===
  cat -vn $1
  echo ""
  echo === $2 ===
  cat -vn $2
  exit 1
else
  echo ok
fi
