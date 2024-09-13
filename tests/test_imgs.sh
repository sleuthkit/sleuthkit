#!/bin/bash -e

ERROR=0

for i in $(cat imgs_to_dump) ; do
  diff data/dump/$i.json <(TZ=America/New_York ./img_dump data/img/$i) && echo "SUCCESS: img_dump $i" || { echo "FAILED: img_dump $i" ; ERROR=1 ; }
done

exit $ERROR
