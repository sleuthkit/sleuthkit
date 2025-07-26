#!/bin/bash -e

ID=${srcdir}/test/img_dump/img_differ.sh

$ID '$DATA_DIR/image/image.E01' '$DATA_DIR/image/image.E01.json'
