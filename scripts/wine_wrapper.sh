#!/bin/bash -ex

case $1 in
*.exe)
  wine $1 -d yes
  ;;
*)
  $1
  ;;
esac
