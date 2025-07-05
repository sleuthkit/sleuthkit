#!/bin/bash -e

if [ ! "${srcdir+x}" ]; then
    echo srcdir is not set
    exit 77                     # autoconf 'SKIP'
fi

TD=${srcdir}/test/tools/tool_differ.sh

if [ ! -e ${srcdir}/test/tools/vstools/mmls_output/2 ]; then
    echo ${srcdir}/test/tools/vstools/mmls_output/2 does not exit
    exit 77
fi
$TD 'tools/vstools/mmls$EXEEXT -r $DATA_DIR/image_exfat1.E01' ${srcdir}/test/tools/vstools/mmls_output/2


if [ ! -e ${srcdir}/test/tools/vstools/mmls_output/3 ]; then
    echo ${srcdir}/test/tools/vstools/mmls_output/3 does not exit
    exit 77
fi
$TD 'tools/vstools/mmls$EXEEXT -c $DATA_DIR/image_exfat1.E01' ${srcdir}/test/tools/vstools/mmls_output/3
