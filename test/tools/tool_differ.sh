#!/bin/bash -e

# test input is a command in the first column, path to expected output
# in the second column; columns are tab-separated

err=0

while IFS= read -r line ; do
  EXP=${line#*$'\t'}
  CMD=${line%$'\t'*}
  echo -n "checking '$CMD': "
  RESULT=$(diff -u "$EXP" <($CMD 2>&1))
  if [ $? -ne 0 ]; then
    err=1
    echo failed
    echo $RESULT
  else
    echo ok
  fi
done <$1

exit $err
