#!/bin/bash -ex

if [ $1 = './tests/fiwalk_test.exe' ]; then
    echo WINE testing of fiwalk_text.exe is currently disabled > /dev/stderr
    exit 0;
fi

case $1 in
*.exe)
  #SLG removed -d yes. Not sure what it was doing
  #wine $1 -d yes
  wine $1
  ;;
*)
  $1
  ;;
esac
