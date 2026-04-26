#!/bin/bash -e

IMAGE_DIFFER=${srcdir}/test/img_dump/img_differ.sh

$IMAGE_DIFFER ${srcdir}/test/data/image/image.dd  ${srcdir}/test/data/image/image.dd.json
$IMAGE_DIFFER ${srcdir}/test/data/fat_dst_test.dd ${srcdir}/test/data/fat_dst_test.dd.json
