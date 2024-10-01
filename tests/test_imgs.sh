#!/bin/bash -e

ERROR=0

cd tests

# find the correct img_dump executable
if [ -x ./img_dump ]; then
  IMG_DUMP=./img_dump
  WINEDEBUG=
elif [ -x ./img_dump.exe ]; then
  IMG_DUMP='wine img_dump.exe'
  WINEDEBUG=-all
else
  echo "FAILED: no img_dump executable"
  exit 1
fi

for i in $(cat imgs_to_dump) ; do
  diff -b data/dump/$i.json <(TZ=America/New_York $IMG_DUMP data/img/$i) && echo "SUCCESS: img_dump $i" || { echo "FAILED: img_dump $i" ; ERROR=1 ; }
done

exit $ERROR
