#!/bin/bash -e

if [ ! "${srcdir+x}" ]; then
    echo srcdir is not set
    exit 77                     # autoconf 'SKIP'
fi

TD=${srcdir}/test/tools/tool_differ.sh
$TD 'tools/vstools/mmls$EXEEXT -h' ${srcdir}/test/tools/vstools/mmls_output/1
$TD 'tools/vstools/mmls$EXEEXT $DATA_DIR/image-mbr.dd' ${srcdir}/test/tools/vstools/mmls_output/2
