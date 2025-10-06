#!/bin/bash -e

if [ ! "${srcdir+x}" ]; then
    echo srcdir is not set
    exit 77                     # autoconf 'SKIP'
fi

IMAGE_DATA=${srcdir}/test/data/image_ext2.dd

if [ ! -r $IMAGE_DATA ]; then
    echo cannot read $IMAGE_DATA
    exit 77
fi

TD=${srcdir}/test/tools/tool_differ.sh

$TD 'tools/fstools/fls$EXEEXT'                          ${srcdir}/test/tools/fstools/fls_output/1
$TD 'tools/fstools/fls$EXEEXT $DATA_DIR/image/image.dd' ${srcdir}/test/tools/fstools/fls_output/2
