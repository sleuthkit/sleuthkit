#!/bin/bash -e

ID=${srcdir}/test/img_dump/img_differ.sh

$ID '$DATA_DIR/image/image.dd' '$DATA_DIR/image/image.dd.json'
$ID '$DATA_DIR/image/fat_dst_test.dd' '$DATA_DIR/image/fat_dst_test.dd.json'
