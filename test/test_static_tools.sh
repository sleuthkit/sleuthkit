#!/bin/bash -e

./test/check_static.sh $(find tools -type f -perm -a+x | grep .libs)

