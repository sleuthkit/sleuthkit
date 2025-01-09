#!/bin/bash -ex

if [ $1 = './tests/fiwalk_test.exe' ]; then
    echo WINE testing of fiwalk_text.exe is currently disabled > /dev/stderr
    exit 0;
fi

case $1 in
*.exe)
  wine $1 -d yes
  ;;
*)
  $1
  ;;
esac
