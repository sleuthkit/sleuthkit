#!/bin/bash -e

if [ ! "${srcdir+x}" ]; then
    echo srcdir is not set
    exit 77                     # autoconf 'SKIP'
fi

TD=${srcdir}/test/tools/tool_differ.sh

$TD 'tools/vstools/mmls$EXEEXT -r $DATA_DIR/image_exfat1.E01'       ${srcdir}/test/tools/vstools/mmls_output/10
$TD 'tools/vstools/mmls$EXEEXT -c $DATA_DIR/image_exfat1.E01'       ${srcdir}/test/tools/vstools/mmls_output/11
$TD 'tools/vstools/mmls$EXEEXT    $DATA_DIR/gpt_130_partitions.E01' ${srcdir}/test/tools/vstools/mmls_output/12
