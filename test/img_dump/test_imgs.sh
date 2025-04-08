#!/bin/bash -e

ID=test/img_dump/img_differ.sh

$ID ../data/image.dd dump/image.dd.json
# FIXME: check iso on MinGW after fixing timestamp bug
#$ID ../data/image.iso dump/image.iso.json
