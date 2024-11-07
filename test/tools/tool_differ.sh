#!/bin/bash -e

# test input is a command in the first column, path to expected output
# in the second column; columns are tab-separated

err=0

# get basedir for normalizing output
basedir=$(realpath "$(dirname $0)/../..")

while IFS= read -r line ; do
  EXP=${line#*$'\t'}
  CMD=${line%$'\t'*}
  echo -n "checking '$CMD': "
  DIFF_EXIT=0
  # diff, normalizing against basedir
  RESULT=$(diff -u "$EXP" <($WINE $CMD 2>&1 | sed -e "s|^${basedir}/||")) || DIFF_EXIT=$?
  if [ $DIFF_EXIT -ne 0 ]; then
    err=1
    echo failed
    echo "$RESULT"
  else
    echo ok
  fi
done <$1

exit $err
