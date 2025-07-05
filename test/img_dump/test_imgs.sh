#!/bin/bash -e

ID=${srcdir}/test/img_dump/img_differ.sh

$ID '$DATA_DIR/image/image.dd' '$DATA_DIR/image/image.dd.json'
# FIXME: check iso on MinGW after fixing timestamp bug
#$ID ../data/image.iso dump/image.iso.json
