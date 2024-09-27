#!/bin/bash -ex

case $1 in
*.exe)
  wine $1
  ;;
*)
  $1
  ;;
esac
